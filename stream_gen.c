#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>

#include "include/stream_gen.h"
#include "include/tcp_header.h"
#include "libnids-1.24/src/nids.h"
#include "libnids-1.24/src/hash.h"

#include "include/checksum.h"

/* TODO: need modifing for multi-thread mode */
uint8_t pkt[PACKET_LEN];
struct tcphdr *tcph;
struct iphdr *iph;

#ifdef SEND_THREAD
pthread_t 		    send_threads[NUM_SEND_THREAD];
#else
static uint64_t     pre_tsc;
#endif

char src_ip_addr[16];  //IPv4 address	
char dst_ip_addr[16];

uint8_t src_mac[6] = {0x90, 0xe2, 0xba, 0x13, 0x08, 0xb0}; //b0
uint8_t dst_mac[6] = {0x90, 0xe2, 0xba, 0x16, 0x1a, 0xb1}; //b1


#ifdef USE_DPDK
#define US_TO_TSC(t) ((rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S ) * (t)
/* *
 * Description  : error callback for "rte_eth_tx_buffer()"
 * */
void
dpdk_tx_buffer_unsent_callback(struct rte_mbuf **pkts, uint16_t unsent,	void *userdata)
{
	uint16_t i;
	uint64_t *count = (uint64_t *)userdata;
	uint32_t retry = PKT_RETRY_COUNT;
    
	/* retry while sending failed */
    uint16_t sent = 0;
    /* TODO: deliver pointor to struct */
#if 0
	while ( sent < unsent && (retry--)) {
        rte_delay_us(TX_DELAY_TIME);
		sent += rte_eth_tx_burst(0, 0, &pkts[sent], unsent - sent);
	}
#endif
	/* free unsent packets */
    if (unlikely (unsent > sent)) {
        for (i = 0; i < unsent - sent; i++)
            rte_pktmbuf_free(pkts[i]);
    }
	port_stat.tx += sent;
	*count += unsent - sent;
}
/* * 
 * Description  : delay for a while (used for set a sending interval)
 * */
static void
burst_delay(uint16_t t) 
{
    uint64_t cur_tsc = 0, diff_tsc;
    uint64_t drain_tsc;

    drain_tsc = US_TO_TSC(t);
    while (!force_quit) {     
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - pre_tsc;
        if (unlikely(diff_tsc >= drain_tsc)) {
            break;
        }
    }
    pre_tsc = cur_tsc;
}

/* *
 * Description  : transmit packet with DPDK tx burst
 * */
static void
dpdk_send_burst(uint8_t p, uint16_t q)
{
    uint32_t nb_tx, cnt, retry;

    cnt = tx_mbufs.len;

    nb_tx = rte_eth_tx_burst(p, q, tx_mbufs.m_table, cnt);  //tx_rings = 1, main.c

    /* retry while sending failed */
    if (unlikely (nb_tx < cnt)) {
        retry = PKT_RETRY_COUNT;
        while (nb_tx < cnt && (retry--)) {
            rte_delay_us(TX_DELAY_TIME);
            nb_tx += rte_eth_tx_burst(p, q, &tx_mbufs.m_table[nb_tx], cnt - nb_tx);
        }
    }
    port_stat.tx += nb_tx;
    /* free unsent packets */
    if (unlikely (nb_tx < cnt)) {
        port_stat.dropped += (cnt - nb_tx);
        do {
            rte_pktmbuf_free(tx_mbufs.m_table[nb_tx]);
        } while(++nb_tx < cnt);
    }
}
/* *
 * Description  : flush packets remain in mbufs when exit application 
 * */
void
dpdk_tx_flush(void)
{
#ifndef TX_BUFFER
    if(tx_mbufs.len > 0)
        dpdk_send_burst(snd_port, 0);
#else
    if (tx_buffer->length > 0){ 
        rte_eth_tx_buffer_flush(snd_port, 0, tx_buffer);
    }
#endif
}

/* *
 * Description  : send packets in tx buffer with DPDK
 * */
static inline int
dpdk_send_pkt(uint8_t *pkt, int len, uint8_t p, uint16_t q)
{
    struct rte_mbuf   *m;
    uint32_t ret;

    /* allocate rte_mbuf */
    m  = rte_pktmbuf_alloc(mp);
    if (unlikely(m == NULL)) {
        printf("allocate mbuf failed.\n");
        return -1;
    }
    rte_memcpy((uint8_t *)((uint8_t *)m->buf_addr + m->data_off), (uint8_t *)pkt, len);
    m->pkt_len  = len;
    m->data_len = len;
#ifndef TX_BUFFER
    /* Add packet to the TX list. */
    rte_prefetch0(rte_pktmbuf_mtod(m, void *));
    tx_mbufs.m_table[tx_mbufs.len++] = m;

    /* transmit while reaching tx_burst */
    if (tx_mbufs.len >= burst) {
        /* sending interval (burst = 1) */
        burst_delay(10);        
        dpdk_send_burst(p, q);
        /* update size of tx_mbufs */
        tx_mbufs.len = 0;
    }
#else
    rte_prefetch0(rte_pktmbuf_mtod(m, void *));
    burst_delay(10);
    ret = rte_eth_tx_buffer(p, q, tx_buffer, m);
    if (ret) {
        port_stat.tx += ret;
    }
#endif

    return 1;  
}

#endif

/* Description 	: setting common fields for the same stream
 *              4-tuple, identifier, seq, ack
 * */
static inline void 
set_field(struct buf_node* node)
{
    uint8_t adr_3 = (uint8_t) libnet_get_prand(LIBNET_PR8); /*  0~255 */
	uint8_t adr_4 = (uint8_t) libnet_get_prand(LIBNET_PR8); /*  0~255 */

	sprintf(src_ip_addr, "10.0.%u.%u", adr_3, adr_4);	
	sprintf(dst_ip_addr, "10.0.%u.%u", adr_4, adr_3);	
	
    node->saddr = inet_addr(src_ip_addr);
    node->daddr = inet_addr(dst_ip_addr);

	node->sport = (uint16_t) libnet_get_prand(LIBNET_PRu16);
	if (node->sport <= 1024) node->sport += 1024; // skip reserved port numbers

	node->dport = (uint16_t) libnet_get_prand(LIBNET_PRu16);
	if (node->dport <= 1024) node->dport += 1024;

	node->id = (uint16_t) (libnet_get_prand(LIBNET_PR16) % 32768);
    node->rcv_id = 0;
	
	/* sequence number 
	 * acknowledge number
	 * give a random 32-bit number for initialization temporarily*/
	node->seq = (uint32_t) (libnet_get_prand(LIBNET_PR32) % 100000000 + 10000000); 
	node->ack_seq = (uint32_t) (libnet_get_prand(LIBNET_PR32) % 100000000 + 10000000); 
    /* initialize TCP timestamp (see 'set_start_ts' for assignment)*/
    node->ts = 0;
    node->ts_peer = 0;
}

void 
prepare_header(void) 
{
	struct ethhdr *eth = (struct ethhdr *) pkt;
    int i;

    for (i = 0; i < 6; i++) {
        pkt[i] = dst_mac[i];
    }

	if (syn_flood_set) {
    // While simulating SYN flooding, set packets' source MAC address with MAC address of snd_port        
		int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
		struct ifreq ifr;
		strcpy(ifr.ifr_name, dev);
		ioctl(sock, SIOCGIFHWADDR, &ifr);
        memcpy(&pkt[6], ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);
    } else { 
        for (i = 0; i < 6; i++)
            pkt[i + 6] = src_mac[i];
    }
   
	eth->h_proto = htons(0x0800); /* IP */

    /* set iphdr pointer */
    iph = (struct iphdr *)(eth + 1);
    if (!iph) {
        printf ("initialize iphdr failed.\n");
        return;
    }
     /* Fill in the IP Header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->id = htons(54321); //Id of this packet
    iph->frag_off = htons(0x4000);
    iph->ttl = 64;

	iph->saddr = inet_addr("10.0.0.67");
	iph->daddr = inet_addr("10.0.0.68");
	iph->protocol = IPPROTO_TCP;
    
    /* set tcphdr pointer */
    tcph = (struct tcphdr *)(iph + 1);
    if (!tcph) {
        printf ("initialize tcphdr failed.\n");
        return;
    }
    /* Fill in TCP Header */
    tcph->source = htons(46930);
    tcph->dest = htons(50001);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    
    tcph->res1 = 0;
	tcph->doff = 5;  //tcp header size/* need updating */
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 1;
    tcph->ack = 1;
    tcph->urg = 0;
    tcph->res2 = 0;
    tcph->window = htons(65535); /* maximum allowed window size */
    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;
}

static inline uint16_t
cal_opt_len(uint8_t flags)
{
	uint16_t optlen = 0;

	if (flags & TCP_FLAG_SYN) {
		optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
		optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
#endif /* TCP_OPT_SACK_ENABLED */

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_SACK_ENABLED */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		optlen += TCP_OPT_WSCALE_LEN + 1;

	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_FLAG_SACK) {
			optlen += TCP_OPT_SACK_LEN + 2;
		}
#endif
	}

	if (optlen % 4 != 0) {
        printf("optlen error.\n");
        return 0;
    }

	return optlen;
}

static inline void
generate_timestamp(uint8_t *tcpopt, uint32_t cur_ts, uint32_t ts_recent)
{
	uint32_t *ts = (uint32_t *)(tcpopt + 2);

	tcpopt[0] = TCP_OPT_TIMESTAMP;
	tcpopt[1] = TCP_OPT_TIMESTAMP_LEN;
	ts[0] = htonl(cur_ts);
	ts[1] = htonl(ts_recent);
}

/* * 
 * Descripton   : generate TCP options 
 * */
static inline void
generate_opt(uint32_t cur_ts, uint8_t flags, uint8_t *tcpopt, uint16_t optlen, uint32_t ts_recent)
{
    int i = 0;

	if (flags & TCP_FLAG_SYN) {
		uint16_t mss;

		/* MSS option */
		mss = TCP_DEFAULT_MSS;
		tcpopt[i++] = TCP_OPT_MSS;
		tcpopt[i++] = TCP_OPT_MSS_LEN;
		tcpopt[i++] = mss >> 8;
		tcpopt[i++] = mss % 256;

		/* SACK permit */
#if TCP_OPT_SACK_ENABLED
#if !TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
		tcpopt[i++] = TCP_OPT_SACK_PERMIT;
		tcpopt[i++] = TCP_OPT_SACK_PERMIT_LEN;
#endif /* TCP_OPT_SACK_ENABLED */

		/* Timestamp */
#if TCP_OPT_TIMESTAMP_ENABLED
#if !TCP_OPT_SACK_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_SACK_ENABLED */
		generate_timestamp(tcpopt + i, cur_ts, ts_recent);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		/* Window scale */
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_WSCALE;
		tcpopt[i++] = TCP_OPT_WSCALE_LEN;
		tcpopt[i++] = TCP_DEFAULT_WSCALE;

	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
		generate_timestamp(tcpopt + i, cur_ts, ts_recent);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_OPT_SACK) {
			// TODO: implement SACK support
		}
#endif
	}

	if (i != optlen) {
		printf("denerate TCP options: length error\n");
	}
}

static void
set_start_ts(struct buf_node *node)
{
    struct timeval cur_ts = {0};
    /* TCP timestamp */
    gettimeofday(&cur_ts, NULL);
    node->ts = TIMEVAL_TO_TS(&cur_ts);
    node->ts_peer = node->ts + 1234; //pseudo timestamp
}

/* Description	: send packets for establishing connection
 * 			 	  SYN, SYN/ACK, ACK;
 * */
static inline void
send_syn(struct buf_node* node, uint8_t p, uint16_t q)
{
    uint16_t    optlen = 0;
    uint32_t    ts_recent;

    if (node->state == TCP_ST_CLOSED) {
        /* SYN   '->' */
        optlen = cal_opt_len(TCP_FLAG_SYN);
        set_start_ts(node);

        iph->id = htons(node->id);
        iph->tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN + optlen);
        iph->saddr = node->saddr;
        iph->daddr = node->daddr;
        iph->check = ip_checksum( (struct iphdr *)iph);	
        
        ts_recent = 0;
        generate_opt(node->ts, TCP_FLAG_SYN, (uint8_t *)tcph + TCP_HEADER_LEN, optlen, ts_recent);
        
        tcph->source = htons(node->sport);
        tcph->dest = htons(node->dport);
        tcph->seq = htonl(node->seq);
        tcph->ack_seq = htonl(0);
        tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
        tcph->fin = 0;
        tcph->syn = 1;         // SYN
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->check = tcp_checksum((struct iphdr*)iph, (struct tcphdr*)tcph);	

#ifdef USE_PCAP
        if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
        }
        usleep(1);
#else // DPDK
        dpdk_send_pkt((uint8_t *)pkt, HEADER_LEN + optlen, p, q);
#endif 
        node->state = TCP_ST_SYN_SENT;
    } else if(node->state == TCP_ST_SYN_SENT) {
        /* syn / ack   ' <- '*/
#if 0
        int         i;
        for (i = 0; i < 6; i++) {
            pkt[i] = src_mac[i];
            pkt[i + 6] = dst_mac[i];
        }
#endif
        optlen = cal_opt_len(TCP_FLAG_SYN | TCP_FLAG_ACK);
        iph->id = htons(node->rcv_id++);     //id = 0
        iph->tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN + optlen);
        iph->saddr = node->daddr; //exchange src/dst ip
        iph->daddr = node->saddr;
        iph->check = ip_checksum((struct iphdr *)iph);	
        
        ts_recent = node->ts;
        generate_opt(node->ts_peer, TCP_FLAG_SYN | TCP_FLAG_ACK, (uint8_t *)tcph + TCP_HEADER_LEN, optlen, ts_recent);
        
        tcph->source = htons(node->dport);       // exchange src/dst port
        tcph->dest = htons(node->sport);
        node->ack_seq = (uint32_t)(libnet_get_prand(LIBNET_PR32) % 100000000) + 10000000 ; 
        tcph->seq = htonl(node->ack_seq - 1);
        tcph->ack_seq = htonl(node->seq+1);
        tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
        tcph->fin = 0;
        tcph->syn = 1;           // SYN
        tcph->psh = 0;
        tcph->ack = 1;           // ACK
        tcph->check = tcp_checksum((struct iphdr*)iph, (struct tcphdr*)tcph);	

#ifdef USE_PCAP
        if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
        }
        usleep(1);
#else // DPDK
        dpdk_send_pkt((uint8_t *)pkt, HEADER_LEN + optlen, p, q);
#endif
        node->state = TCP_ST_SYN_RCVD;
    } else if(node->state == TCP_ST_SYN_RCVD) {
        /* ACK    '->' */
#if 0
        int         i;
        for (i = 0; i < 6; i++) {
            pkt[i] = dst_mac[i];
            pkt[i + 6] = src_mac[i];
        }
#endif
        optlen = cal_opt_len(TCP_FLAG_ACK);
        node->id++;
        iph->id = htons(node->id);
        iph->tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN + optlen);
        iph->saddr = node->saddr; //exchange src/dst ip
        iph->daddr = node->daddr;
        iph->check = ip_checksum((struct iphdr *)iph);	
        
        ts_recent = node->ts_peer;
        generate_opt(node->ts, TCP_FLAG_ACK, (uint8_t *)tcph + TCP_HEADER_LEN, optlen, ts_recent);
        
        tcph->source = htons(node->sport);       // exchange src/dst port
        tcph->dest = htons(node->dport);
        node->seq++;
        tcph->seq = htonl(node->seq); 
        tcph->ack_seq = htonl(node->ack_seq);
        tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
        tcph->fin = 0;
        tcph->syn = 0;
        tcph->psh = 0;
        tcph->ack = 1;           // ACK
        tcph->check = tcp_checksum((struct iphdr*)iph, (struct tcphdr*)tcph);	

#ifdef USE_PCAP
        if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
        }
        usleep(1);
        snd_cnt += 3;
#else // DPDK
        dpdk_send_pkt((uint8_t *)pkt, HEADER_LEN + optlen, p, q);
#endif
        tcph->psh = 1;
        node->id++;
        node->state =  TCP_ST_ESTABLISHED; 
    } else {
        printf("Got TCP state fault when establishing stream.\n");
    }
}

/* Description: hash according to 4-tuple */
static inline int
hash_index(struct tuple4 addr)
{
  int hash=mkhash(addr.saddr, addr.source, addr.daddr, addr.dest);
  return hash % nids_params.n_tcp_streams;
}

/* Description	: send packets for closing connection
 * 			 	  FIN, ACK, FIN, ACK;
 * @ q          : tx_queue id
 * */
static inline void
send_fin(struct buf_node* node, uint8_t p, uint16_t q)
{
    int         optlen = 0;
    uint32_t    ts_recent;

    if (node->state == TCP_ST_CLOSING) {
        /* FIN, ACK   '->' */
        optlen = cal_opt_len(TCP_FLAG_FIN |  TCP_FLAG_ACK);
        iph->id = htons(node->id);
        iph->tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN + optlen);
        iph->saddr = node->saddr; //exchange src/dst ip
        iph->daddr = node->daddr;
        iph->check = ip_checksum((struct iphdr *)iph);	
        
        ts_recent = node->ts_peer++;
        generate_opt(++node->ts, TCP_FLAG_FIN | TCP_FLAG_ACK, (uint8_t *)tcph + TCP_HEADER_LEN, optlen, ts_recent);

        tcph->source = htons(node->sport);
        tcph->dest = htons(node->dport);
        tcph->seq = htonl(node->seq);  //same as previous packet
        tcph->ack_seq = htonl(node->ack_seq);
        tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
        tcph->fin = 1;         // FIN
        tcph->syn = 0;
        tcph->psh = 0;
        tcph->ack = 1;
        tcph->check = tcp_checksum((struct iphdr*)iph, (struct tcphdr*)tcph);	

#ifdef USE_PCAP
        if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen ) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
        }
        usleep(1);
#else // DPDK
        dpdk_send_pkt((uint8_t *)pkt, HEADER_LEN + optlen, p, q);
#endif
        node->state = TCP_ST_FIN_SENT_1; 
    } else if (node->state == TCP_ST_FIN_SENT_1){
        /* fin, ack   ' <- '*/
#if 0
        int         i;
        for (i = 0; i < 6; i++) {
            pkt[i] = src_mac[i];
            pkt[i + 6] = dst_mac[i];
        }
#endif
        optlen = cal_opt_len(TCP_FLAG_FIN |  TCP_FLAG_ACK);
        iph->id = htons(node->rcv_id++);     //id = 1, temp!!!
        iph->tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN + optlen);
        iph->saddr = node->daddr; //exchange src/dst ip
        iph->daddr = node->saddr;
        iph->check = ip_checksum((struct iphdr *)iph);	
        
        ts_recent = node->ts++;
        generate_opt(node->ts_peer, TCP_FLAG_FIN | TCP_FLAG_ACK, (uint8_t *)tcph + TCP_HEADER_LEN, optlen, ts_recent);
        
        tcph->source = htons(node->dport);       // exchange src/dst port
        tcph->dest = htons(node->sport);
        tcph->seq = htonl(node->ack_seq); //temp !!!
        tcph->ack_seq = htonl(node->seq + 1);
        tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
        tcph->fin = 1;           // FIN
        tcph->syn = 0;
        tcph->psh = 0;
        tcph->ack = 1;           // ACK
        tcph->check = tcp_checksum((struct iphdr*)iph, (struct tcphdr*)tcph);	

#ifdef USE_PCAP
        if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
        }
        usleep(5);
#else // DPDK
        dpdk_send_pkt((uint8_t *)pkt, HEADER_LEN + optlen, p, q);
#endif
        node->state = TCP_ST_FIN_SENT_2;    
    } else if(node->state == TCP_ST_FIN_SENT_2) {
        /* ACK    '->' */
#if 0
        int         i;
        for (i = 0; i < 6; i++) {
            pkt[i] = dst_mac[i];
            pkt[i + 6] = src_mac[i];
        }
#endif
        optlen = cal_opt_len(TCP_FLAG_ACK);
        node->id++;
        iph->id = htons(node->id);
        iph->tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN + optlen);
        iph->saddr = node->saddr; //exchange src/dst ip
        iph->daddr = node->daddr;
        iph->check = ip_checksum((struct iphdr *)iph);	
        
        ts_recent = node->ts_peer;
        generate_opt(node->ts, TCP_FLAG_ACK, (uint8_t *)tcph + TCP_HEADER_LEN, optlen, ts_recent);
        
        tcph->source = htons(node->sport);       // exchange src/dst port
        tcph->dest = htons(node->dport);
        tcph->seq = htonl(node->seq + 1); 
        tcph->ack_seq = htonl(node->ack_seq + 1);    //temp !!!
        tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
        tcph->fin = 0;          
        tcph->syn = 0;
        tcph->psh = 0;
        tcph->ack = 1;           // ACK
        tcph->check = tcp_checksum((struct iphdr*)iph, (struct tcphdr*)tcph);	

#ifdef USE_PCAP
        if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
        }
        usleep(1);
        snd_cnt += 3;
#else // DPDK
        dpdk_send_pkt((uint8_t *)pkt, HEADER_LEN + optlen, p, q);
#endif
        node->state = TCP_ST_CLOSED;
        /* reset header fields */
        node->offset = 0;
        set_field(node);

        /* To randomizing the sending action
         * 1. remove the node from link list
         * 2. reinsert the node into a different location of link list
         * */
        list_delete_entry(&node->list);
        
        struct tuple4 tup;
        tup.saddr = node->saddr;
        tup.daddr = node->daddr;
        tup.source = node->sport;
        tup.dest = node->dport;
		struct list_head *buf_list_t = &hash_buf.buf_list[hash_index(tup)];

        list_add_head(&node->list, buf_list_t);

    } else {
        printf("Got TCP state fault when ending stream.\n");
    }
}
/* Description	: initialize hash table: hash_buf */
void 
init_hash_buf(void)
{
	int i;
	memset(&hash_buf, 0, sizeof(struct hash_table));

	for (i = 0; i < MAX_HASH_TABLE_SIZE; i++) {
		init_list_head(&hash_buf.buf_list[i]);
	}
    hash_buf.thread = 0;
	pthread_mutex_init(&hash_buf.lock, NULL);
}

/* free hash table */
void
destroy_hash_buf(void)
{
	int i;
    int size = nids_params.n_tcp_streams;
	pthread_mutex_lock(&hash_buf.lock);
	
	for(i = 0; i < size; i++) {
		struct list_head *head = &hash_buf.buf_list[i];
		struct buf_node *buf_entry, *q;
        list_for_each_entry_safe(buf_entry, q, head, list) {
			list_delete_entry(&buf_entry->list);
            free(buf_entry);
        } 
	}
	pthread_mutex_unlock(&hash_buf.lock);
}


/* Description	: free the node_buf when the data held in  node_buf was sent */
static void
flush_buf_node(struct buf_node *node) 
{
	memset(node->tot_buf, 0, MAX_BUFFER_SIZE);
	memset(&node->tup, 0, sizeof(struct tuple4));
	node->len = 0;
}


/*
 * Description	: compare two 4-tuple
 * Return 		: 0, if not equal; 1, if equal
 * */
static int
is_tuple4_equal (struct tuple4 pre, struct tuple4 cur)
{
    if (!(pre.saddr == cur.saddr && pre.daddr == cur.daddr
        && pre.source == cur.source && pre.dest == cur.dest)) {  
		return 0;
        
	} else {
		return 1;
	}
	
}

/* Description	: get buf_node from hash table 
 * Return 		: buf_entry, if get satisfied buf_node;
 * 				  NULL, if has no satisfied buf_node.
 * */
static struct buf_node *
get_buf_node(struct tuple4 tup, int ind)
{
	struct list_head *buf_list_t = &hash_buf.buf_list[ind];
	struct buf_node *buf_entry = NULL;

	list_for_each_entry(buf_entry, buf_list_t, list) {
		if (is_tuple4_equal(tup, buf_entry->tup)) //or use memcmp.
			return buf_entry;
	}
	
	return NULL;
}

/* Description 	: insert buf_node to hash table  
 * @ buf		: data of TCP stream
 * @ length		: length of buf
 * @ tup		: 4-tuple of the TCP stream
 * */
static struct buf_node *
insert_buf_node(struct list_head *buf_list, uint8_t *buf, int length, struct tuple4 tup) 
{
    int size_alloc = MAX_BUFFER_SIZE;
	struct buf_node *buf_entry = malloc(sizeof(struct buf_node));

    /* Used for 'copy_stream_data()' */
    if (length > size_alloc) {
        size_alloc = length + 1;
    }

	buf_entry->tot_buf = (uint8_t *)malloc(size_alloc);

	if(buf_entry == NULL || buf_entry->tot_buf == NULL) {
		fprintf(stderr, "allocate memory for buf_node failed.\n");
		exit(1);
	}
	buf_entry->tup = tup;
	memcpy(buf_entry->tot_buf, buf, length);
	buf_entry->len = length;
    buf_entry->offset = 0;
    buf_entry->state = TCP_ST_CLOSED;

    set_field(buf_entry);
	
    /* lock to be safe */
//	pthread_mutex_lock(&hash_buf.lock);
	list_add_head(&buf_entry->list, buf_list);
//	pthread_mutex_unlock(&hash_buf.lock);

	return buf_entry;
}
/* Generate ACK correspond to PSH/ACK packet sent with send_data_pkt  */
static void
send_ack(struct buf_node *node, uint32_t length, uint8_t p, uint16_t q)
{
	int         optlen = 0;
	int         payload_offset = 0;
    uint32_t    ts_recent;

    optlen = cal_opt_len(TCP_FLAG_ACK);
	iph->id = htons(node->rcv_id++);    
	iph->tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN + optlen);
    iph->saddr = node->daddr;
    iph->daddr = node->saddr;
    iph->check = ip_checksum((struct iphdr *)iph);	
	
	ts_recent = node->ts;
    generate_opt(++(node->ts_peer), TCP_FLAG_ACK, (uint8_t *)tcph + TCP_HEADER_LEN, optlen, ts_recent);
    
    tcph->source = htons(node->dport);
    tcph->dest = htons(node->sport);
	tcph->seq = htonl(node->ack_seq);
	tcph->ack_seq = htonl(node->seq);
    tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
    tcph->syn = 0;
    tcph->fin = 0;
    tcph->ack = 1;
    tcph->psh = 0;
	tcph->check = tcp_checksum((struct iphdr*)iph, (struct tcphdr*)tcph);	

#ifdef USE_PCAP
    if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, (HEADER_LEN + optlen)) != 0) {   
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
    }
	usleep(1);
    snd_cnt++;
#else // DPDK
    dpdk_send_pkt((uint8_t *)pkt, HEADER_LEN + optlen, p, q);
#endif
}

/* Description  : encapsulate data with headers, and send crafted packets out 
 * @ node       : buf_node which contains data to send
 * @ offset     : offset of the sending data
 * @ size       : length of data to send
 * @ p          : network interface
 * @ q          : sending queue of interface
 * */
static void
send_data_pkt(struct buf_node *node, uint32_t length, uint8_t p, uint16_t q)
{
	int         optlen = 0;
	int         payload_offset = 0;
    uint32_t    ts_recent;

    uint32_t    rest_len = node->len - node->offset;
    if (length >= rest_len){
        length = rest_len;
        /* stream is ending */
        node->state = TCP_ST_CLOSING;
    }

    optlen = cal_opt_len(TCP_FLAG_ACK);
	iph->id = htons(node->id);    
	iph->tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN + optlen + length);
    iph->saddr = node->saddr;
    iph->daddr = node->daddr;
    iph->check = ip_checksum((struct iphdr *)iph);	
	
	ts_recent = node->ts_peer;
    generate_opt(++(node->ts), TCP_FLAG_ACK, (uint8_t *)tcph + TCP_HEADER_LEN, optlen, ts_recent);
    
    tcph->source = htons(node->sport);
    tcph->dest = htons(node->dport);
	tcph->seq = htonl(node->seq);
	tcph->ack_seq = htonl(node->ack_seq);
    tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
    tcph->syn = 0;
    tcph->fin = 0;
    tcph->ack = 1;
    tcph->psh = 1;
	tcph->check = tcp_checksum((struct iphdr*)iph, (struct tcphdr*)tcph);	

	/* Fill in the payload */
	payload_offset = HEADER_LEN + optlen;
	memcpy(((uint8_t *)pkt + payload_offset), node->tot_buf + node->offset, length);
    /* update data offset */
    node->offset += length;
    /* update header fields */
    node->id++;
    node->seq += length;

#ifdef USE_PCAP
    if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, (HEADER_LEN + optlen + length)) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
    }
	usleep(1);
    snd_cnt++;
#else // DPDK
    dpdk_send_pkt((uint8_t *)pkt, HEADER_LEN + optlen + length, p, q);
#endif
    send_ack(node, length, p, q);
}

/* Description: cache total data of streams, where data for the same stream will be stored in the same buffer
 * @ tup	: 4-tuple
 * @ data	: data chunk with message for the same stream
 * @ length	: length of data
 * @ flag	: state of nids stream
 * */
int
store_stream_data(struct tuple4 tup, char *data, int length, int flag)
{
	int index;

	index = hash_index(tup);

	if (flag == NIDS_JUST_EST) {
		/* new stream */
	
	} else if (flag == NIDS_DATA) {
		/* receiving data */	
		struct buf_node *node = get_buf_node(tup, index);
		/* data for a new stream */
		if (node == NULL) {
			struct list_head *buf_list_t = &hash_buf.buf_list[index];
            
			/* data length exceeds the buffer size*/
			if (length > MAX_BUFFER_SIZE) {
				node = insert_buf_node(buf_list_t, (uint8_t *)data, MAX_BUFFER_SIZE, tup);

				/* reallocate more memory for large data */
				node->tot_buf = (uint8_t *)realloc(node->tot_buf, length);
                if (node->tot_buf == NULL) {
                    fprintf(stderr, "reallocate memory failed.\n");
                    return 0;
                }
				memcpy(node->tot_buf+node->len, data + MAX_BUFFER_SIZE, length - MAX_BUFFER_SIZE);
				node->len = length;
			} else {
				node = insert_buf_node(buf_list_t, (uint8_t *)data, length, tup);
			}
			return 0;
		}	
		/* find existing buf_node in hash table */	
		/* length of the total data exceeds buffer size*/
		if (node->len + length > MAX_BUFFER_SIZE) {
			/* reallocate more memory for large data */
			node->tot_buf = (uint8_t *)realloc(node->tot_buf, node->len + length);
            if (node->tot_buf == NULL) {
                fprintf(stderr, "reallocate memory failed.\n");
                return 0;
            }
			memcpy(node->tot_buf + node->len, data, length);
			node->len += length;
		} else {
			memcpy(node->tot_buf + node->len, data, length);
			node->len += length;
		}
	} else if (flag == NIDS_CLOSE) {
#if 0
		/* stream finished */
		struct buf_node *node = get_buf_node(tup, index);
		if (node == NULL) {
#ifdef DEBUG_SEGMENTOR
			fprintf(stderr, "stream_segmentor: could not find correspond buf node.\n");
#endif
			return 0;
		}
        int num = 10;    //number of parts to segment, default: 15.
        int loop = nb_reuse;
        while (loop--) {
            /* calling sending function */	
            send_stream(node, num, 0, 0);

            if (++num > 20)
                num = 10;
        }
        /* free node from hash buffer */
		list_delete_entry(&node->list);
		free(node);
#endif
    } else {
	/* other state */
#ifdef DEBUG_SEGMENTOR
		fprintf(stderr, "split_stream.c, stream_segmentor, flag error.\n");
#endif
	}

	return 1; 
}

/* send packet according to TCP state */
static void
send_packet(struct buf_node *node, int n, uint8_t p, uint16_t q)
{
    uint32_t length;

    /* TODO: give a appropriate data length randomly*/
    if (is_len_fixed) {
#if 0
		if (node->len < len_cut) {
			return;
		}
#endif
		length = len_cut;
	} else {
		length = node->len / n;
	}
    if (length < 5) {
        length = node->len;
    } else if (length > MAX_SEG_SIZE) {
        length = MAX_SEG_SIZE;
    }
    /* sending packet according to TCP state */
    if(node->state == TCP_ST_CLOSED) {
        if (node->offset == 0) {
            send_syn(node, p, q);
        } else {
            printf("offset = %d, should be 0 here.\n", node->offset);
        }
    } else if (node->state == TCP_ST_SYN_SENT || node->state == TCP_ST_SYN_RCVD) {
        send_syn(node, p, q);
    } else if (node->state == TCP_ST_ESTABLISHED) {
        send_data_pkt(node, length, p, q);
    } else if (node->state == TCP_ST_CLOSING || node->state == TCP_ST_FIN_SENT_1 
                                             || node->state == TCP_ST_FIN_SENT_2) {
        send_fin(node, p, q);
    } else {
        printf("Sending packet failed, wrong TCP state.\n");
    }
}
/* Copy stream data stored in hash table to get more streams */
static void
copy_stream_data(int nb_copy)
{
    int i;
    int cnt;
    /* TODO: may modify nids_params.n_tcp_streams later*/
    int size = nids_params.n_tcp_streams;
#ifdef USE_DPDK
    cnt = 0;
    while (!force_quit) {
        for (i = size - 1; i > 0; i--) {
            struct list_head *head = &hash_buf.buf_list[i];
            struct buf_node *buf_entry, *q;
            list_for_each_entry_safe(buf_entry, q, head, list) {
                if (buf_entry->len) {
                    struct list_head *head_tmp = &hash_buf.buf_list[rand() % size];
                    /* Giving a same tuple4 does not matter here, 
                     * because tuple4 only matters while reading packets from pcap file.
                     * */
                    insert_buf_node(head_tmp, buf_entry->tot_buf, buf_entry->len, buf_entry->tup);
                    
                    if(++cnt >= nb_copy) {
                        printf("Succeed in generating more stream data.(%d)\n", nb_copy);
                        return;
                    }
                }
            }
        }
    }
#endif
}

static int
counter(void)
{
    int i;
    int cnt;
    /* TODO: may modify nids_params.n_tcp_streams later*/
    int size = nids_params.n_tcp_streams;
    cnt = 0;
    for (i = 0; i < size; i++) {
        struct list_head *head = &hash_buf.buf_list[i];
        struct buf_node *buf_entry, *q;
        list_for_each_entry_safe(buf_entry, q, head, list) {
            cnt++;
        }
    }
    printf("\nCounter, Number of streams : %d\n", cnt);
    return cnt;
}


/* *
 * Description  : send stream stored in buffer table
 *
 * */
void 
send_streams(void)
{
    int i;
    int cnt;
    int n_snd;
    int n_part;     //divide total data of a stream into n_part patitions
    bool reach_concur;
    int size = nids_params.n_tcp_streams;

#ifdef USE_DPDK
    pre_tsc = rte_rdtsc();
    
    srand((int)time(0));
    cnt = counter();
    /* if there is no enough stream data, copy to generate more data*/
    if (cnt < nb_concur - 1) {
        copy_stream_data( nb_concur + 1 - cnt);
    }
    nb_stream = counter();

    /* initialize packet header (ethernet header; IP header; TCP header)*/
	prepare_header();

    n_part = 30;
    while(!force_quit) {
        cnt = 0;
        reach_concur = false;

        /* Sending 'nb_concur' packets */
        for (i = 0; i < size; i++) {
            struct list_head *head = &hash_buf.buf_list[i];
            struct buf_node *buf_entry, *q;
            list_for_each_entry_safe(buf_entry, q, head, list) {
                if (buf_entry->len) {
                    /* Keep sending several packets of a stream */
                    n_snd = rand() % 3 + 1;         // 1 ~ 3
                    while (n_snd--) {
                        /* TODO: modify delivered queue number for multi-threading mode */
                        if (buf_entry->state == TCP_ST_FIN_SENT_2) {
                            send_packet(buf_entry, n_part, snd_port, 0);
                            break;
                        } else {
                            send_packet(buf_entry, n_part, snd_port, 0);
                        }
                    }
                    cnt++;
                    /* Reach concurrency */
                    if(cnt >= nb_concur) {
                        reach_concur = true; 
                        break;
                    }
                }
            }
            if(reach_concur)
                break;
        }
    }
#endif
}

void
SYN_flood_simulator(void)
{
    uint16_t    optlen;
    int         i;   
    uint32_t    ts_recent;
    int         size = nids_params.n_tcp_streams;

    srand((int)time(0));
    prepare_header();

    ts_recent = 0;

    printf(" Attention please!!\nSYN Flood appears...\n");
    while(!force_quit) {
        for (i = 0; i < size; i++) {
            struct list_head *head = &hash_buf.buf_list[i];
            struct buf_node *buf_entry, *q;
            list_for_each_entry_safe(buf_entry, q, head, list) {
                /* SYN   '->' */
                optlen = cal_opt_len(TCP_FLAG_SYN);
                set_start_ts(buf_entry);

                iph->id = htons(buf_entry->id);
                iph->tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN + optlen);                
				iph->saddr = buf_entry->saddr;
                iph->daddr = buf_entry->daddr;
                iph->check = ip_checksum( (struct iphdr *)iph);
                generate_opt(buf_entry->ts, TCP_FLAG_SYN, (uint8_t *)tcph + TCP_HEADER_LEN, optlen, ts_recent);
                tcph->source = htons(buf_entry->sport);
                tcph->dest = htons(buf_entry->dport);
                tcph->seq = htonl(buf_entry->seq);
                tcph->ack_seq = htonl(0);
                tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
                tcph->fin = 0;
                tcph->syn = 1;         // SYN
                tcph->psh = 0;
                tcph->ack = 0;
                tcph->check = tcp_checksum((struct iphdr*)iph, (struct tcphdr*)tcph);
#ifdef USE_PCAP
				if  ((pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen)) != 0) {
					fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
				}
				snd_cnt++;
				usleep(1);
#else // DPDK
                dpdk_send_pkt((uint8_t *)pkt, HEADER_LEN + optlen, snd_port, 0);   
#endif
				set_field(buf_entry);
            }
        }
    }
}

#ifdef SEND_THREAD
/* loop of sending thread */
void *
send_loop(void* args)
{
}

/* Description  : create threads for sending stream to simulate scenario of sending concurrently */
void
run_send_threads(void)
{
}

/* thread exit */
void
destroy_threads(void)
{
}
#endif
