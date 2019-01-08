#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "include/stream_gen.h"
#include "include/tcp_header.h"
#include "nids.h"
#include "libnids-1.24/src/hash.h"

#include "include/checksum.h"


uint8_t pkt[PACKET_LEN];
struct tcphdr tcph;
struct iphdr iph;


#ifdef NET_QUEUE
char label[LIBNET_LABEL_SIZE];
#endif

/* fields need modifying dynamically */
uint16_t sport, dport;
uint16_t id;

char src_ip_addr[16];  //IPv4 address	
char dst_ip_addr[16];

uint8_t src_mac[6] = {0x90, 0xe2, 0xba, 0x13, 0x08, 0xbb}; //b0
uint8_t dst_mac[6] = {0x90, 0xe2, 0xba, 0x16, 0x1a, 0xbc}; //b1

uint32_t seq = 0, ack = 0; //need calculating

struct timeval cur_ts = {0};
uint32_t ts = 0, ts_peer = 0, ts_recent = 0;


#ifdef USE_DPDK
#define US_TO_TSC(t) ((rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S ) * (t)
/* *
 * Description  : error callback for "rte_eth_tx_buffer()"
 * */
void
dpdk_tx_buffer_unsent_callback(struct rte_mbuf **pkts, uint16_t unsent,	void *userdata)
{
	uint32_t i, cnt = unsent;
	uint64_t *count = userdata;
	uint32_t retry = PKT_RETRY_COUNT;
	/* retry while sending failed */
	while ( unsent > 0 && (retry--)) {
		usleep(TX_DELAY_TIME);
		unsent -= rte_eth_tx_burst(0, 0, pkts, unsent);
	}
	/* free unsent packets */
    if (unsent > 0) {
        for (i = 0; i < unsent; i++)
            rte_pktmbuf_free(pkts[i]);
    }
	port_stat.tx += (cnt - unsent);
	*count += unsent;
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
dpdk_send_burst(void)
{
    uint32_t nb_tx, cnt, retry;

    cnt = tx_mbufs.len;

    nb_tx = rte_eth_tx_burst(0, 0, tx_mbufs.m_table, cnt);  //tx_rings = 1, main.c

    /* retry while sending failed */
    if (unlikely (nb_tx < cnt)) {
        retry = PKT_RETRY_COUNT;
        while (nb_tx < cnt && (retry--)) {
            rte_delay_us(TX_DELAY_TIME);
            nb_tx += rte_eth_tx_burst(0, 0, &tx_mbufs.m_table[nb_tx], cnt - nb_tx);
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
    /* flush queued packets to driver */
#ifndef TX_BUFFER
    if(tx_mbufs.len > 0)
        dpdk_send_burst();
    tx_mbufs.len = 0;
#else
    if (tx_buffer->length > 0){ 
        rte_eth_tx_buffer_flush(0, 0, tx_buffer);
    }
#endif
}

/* *
 * Description  : send packets in tx buffer with DPDK
 * */
static inline int
dpdk_send_pkt(uint8_t *pkt, int len)
{
    struct rte_mbuf   *m;
    uint32_t ret;

    /* allocate rte_mbuf */
    m  = rte_pktmbuf_alloc(mp);
    if (unlikely(m == NULL)) {
        printf("allocate mbuf failed.\n");
        return -1;
    }
    rte_memcpy((uint8_t *)(m->buf_addr + m->data_off), (uint8_t *)pkt, len);
    m->pkt_len  = len;
    m->data_len = len;
#ifndef TX_BUFFER
    /* Add packet to the TX list. */
    rte_prefetch0(rte_pktmbuf_mtod(m, void *));
    tx_mbufs.m_table[tx_mbufs.len++] = m;

    /* transmit while reaching tx_burst */
    if (tx_mbufs.len >= burst) {
        /* sending interval (burst = 1) */
        burst_delay(1);        
        dpdk_send_burst();
        /* update size of tx_mbufs */
        tx_mbufs.len = 0;
    }
#else
    rte_prefetch0(rte_pktmbuf_mtod(m, void *));
    burst_delay(1);
    ret = rte_eth_tx_buffer(0, 0, tx_buffer, m);
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
set_field(void)
{
    uint8_t adr_3 = (uint8_t) libnet_get_prand(LIBNET_PR8); /*  0~255 */
	uint8_t adr_4 = (uint8_t) libnet_get_prand(LIBNET_PR8); /*  0~255 */

	sprintf(src_ip_addr, "10.0.%u.%u", adr_3, adr_4);	
	sprintf(dst_ip_addr, "10.0.%u.%u", adr_4, adr_3);	
	
	sport = (uint16_t) libnet_get_prand(LIBNET_PRu16);
	if (sport <= 1024) sport += 1024; // skip reserved port numbers

	dport = (uint16_t) libnet_get_prand(LIBNET_PRu16);
	if (dport <= 1024) dport += 1024;

	id = (uint16_t) (libnet_get_prand(LIBNET_PR16) % 32768);
	
	/* sequence number 
	 * acknowledge number
	 * give a random 32-bit number for initialization temporarily*/
	seq = (uint32_t) (libnet_get_prand(LIBNET_PR32) % 2000000000); 
	ack = (uint32_t) (libnet_get_prand(LIBNET_PR32) % 2000000000); 
    /* timestamp */
    gettimeofday(&cur_ts, NULL);
    ts = TIMEVAL_TO_TS(&cur_ts);
    ts_peer = ts + 1234; //pseudo timestamp
}

void 
prepare_header(void) 
{
	struct ethhdr *eth = (struct ethhdr *) pkt;
    int i;

    for (i = 0; i < 6; i++) {
        pkt[i] = dst_mac[i];
        pkt[i + 6] = src_mac[i];
    }   
	eth->h_proto = htons(0x0800); /* IP */

     /* Fill in the IP Header */
    memset(&iph, 0, sizeof(struct iphdr));
    iph.ihl = 5;
    iph.version = 4;
    iph.tos = 0;
    iph.id = htons(54321); //Id of this packet
    iph.frag_off = 0;
    iph.ttl = 64;

	iph.saddr = inet_addr("10.0.0.67");
	iph.daddr = inet_addr("10.0.0.68");

	iph.protocol = IPPROTO_TCP;
    memcpy((pkt + IPHDR_OFFSET), (char *)&iph, sizeof(struct iphdr));

    /* Fill in TCP Header */
    memset(&tcph, 0, sizeof(struct tcphdr));
    tcph.source = htons(46930);
    tcph.dest = htons(50001);
    tcph.seq = 0;
    tcph.ack_seq = 0;
    
    tcph.res1 = 0;
	tcph.doff = 5;  //tcp header size/* need updating */
    tcph.fin = 0;
    tcph.syn = 0;
    tcph.rst = 0;
    tcph.psh = 1;
    tcph.ack = 1;
    tcph.urg = 0;
    tcph.res2 = 0;
    tcph.window = htons(14600); /* maximum allowed window size */
    tcph.check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph.urg_ptr = 0;
    memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph, sizeof(struct tcphdr));
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
generate_timestamp(uint8_t *tcpopt, uint32_t cur_ts)
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
generate_opt(uint32_t cur_ts, uint8_t flags, uint8_t *tcpopt, uint16_t optlen)
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
		generate_timestamp(tcpopt + i, cur_ts);
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
		generate_timestamp(tcpopt + i, cur_ts);
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
/* Description	: send packets for establishing connection
 * 			 	  SYN, SYN/ACK, ACK;
 * */
static inline void
send_syn(void)
{
    int i;
    uint16_t optlen = 0;

    optlen = cal_opt_len(TCP_FLAG_SYN);
	/* SYN   '->' */
	iph.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen);
	iph.id = htons(id);
	iph.saddr = inet_addr(src_ip_addr);
	iph.daddr = inet_addr(dst_ip_addr);
	iph.check = ip_checksum((struct iphdr *)&iph);	
	memcpy((pkt + IPHDR_OFFSET), (char *)&iph, sizeof(struct iphdr));
	
    ts_recent = 0;
	generate_opt(ts, TCP_FLAG_SYN, (uint8_t *)(&tcph) + TCP_HEADER_LEN, optlen);
    
    tcph.source = htons(sport);
	tcph.dest = htons(dport);
    tcph.doff = (TCP_HEADER_LEN + optlen) >> 2;
	tcph.seq = htonl(seq);
    tcph.psh = 0;
	tcph.ack_seq = htonl(0);
	tcph.syn = 1;         // SYN
	tcph.ack = 0;
	tcph.check = tcp_checksum((struct iphdr*)&iph, (struct tcphdr*)&tcph);	

	memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph,  TCP_HEADER_LEN + optlen);
#ifdef USE_PCAP
    if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
    }
	usleep(1);
#else // DPDK
    dpdk_send_pkt(pkt, HEADER_LEN + optlen);
#endif
	/* SYN / ACK   ' <- '*/

    for (i = 0; i < 6; i++) {
        pkt[i] = src_mac[i];
        pkt[i + 6] = dst_mac[i];
    }   
	iph.id = htons(0x0000);     //id = 0
	iph.saddr = inet_addr(dst_ip_addr); //exchange src/dst ip
	iph.daddr = inet_addr(src_ip_addr);
	iph.check = ip_checksum((struct iphdr *)&iph);	
	memcpy((pkt + IPHDR_OFFSET), (char *)&iph, sizeof(struct iphdr));
	
    ts_recent = ts;
	generate_opt(ts_peer, TCP_FLAG_SYN | TCP_FLAG_ACK, (uint8_t *)(&tcph) + TCP_HEADER_LEN, optlen);
    
	tcph.source = htons(dport);       // exchange src/dst port
	tcph.dest = htons(sport);
    tcph.doff = (TCP_HEADER_LEN + optlen) >> 2;
	ack = (uint32_t)(libnet_get_prand(LIBNET_PR32) % 2000000000) + 1 ; 
	tcph.seq = htonl(ack - 1);
	tcph.ack_seq = htonl(seq+1);
	tcph.syn = 1;           // SYN
	tcph.ack = 1;           // ACK
	tcph.check = tcp_checksum((struct iphdr*)&iph, (struct tcphdr*)&tcph);	

	memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph,  TCP_HEADER_LEN + optlen);

#ifdef USE_PCAP
    if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
    }
	usleep(1);
#else // DPDK
    dpdk_send_pkt(pkt, HEADER_LEN + optlen);
#endif
	/* ACK    '->' */
    optlen = cal_opt_len(TCP_FLAG_ACK);
    for (i = 0; i < 6; i++) {
        pkt[i] = dst_mac[i];
        pkt[i + 6] = src_mac[i];
    }   
	iph.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen);
	id++;
	iph.id = htons(id);
	iph.saddr = inet_addr(src_ip_addr); //exchange src/dst ip
	iph.daddr = inet_addr(dst_ip_addr);
	iph.check = ip_checksum((struct iphdr *)&iph);	
	memcpy((pkt + IPHDR_OFFSET), (char *)&iph, sizeof(struct iphdr));
	
    ts_recent = ts_peer;
	generate_opt(ts, TCP_FLAG_ACK, (uint8_t *)(&tcph) + TCP_HEADER_LEN, optlen);
    
	tcph.source = htons(sport);       // exchange src/dst port
	tcph.dest = htons(dport);
    tcph.doff = (TCP_HEADER_LEN + optlen) >> 2;
    seq++;
	tcph.seq = htonl(seq); 
	tcph.ack_seq = htonl(ack);
	tcph.syn = 0;          
	tcph.ack = 1;           // ACK
	tcph.check = tcp_checksum((struct iphdr*)&iph, (struct tcphdr*)&tcph);	

	memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph,  TCP_HEADER_LEN + optlen);

#ifdef USE_PCAP
    if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
    }
	usleep(1);
    snd_cnt += 3;
#else // DPDK
    dpdk_send_pkt(pkt, HEADER_LEN + optlen);
#endif
//    tcph.psh = 1;
}

/* Description	: send packets for closing connection
 * 			 	  FIN, ACK, FIN, ACK;
 * */
static inline void
send_fin(void)
{
    int i;
    int optlen = 0;

    optlen = cal_opt_len(TCP_FLAG_FIN |  TCP_FLAG_ACK);
	/* FIN, ACK   '->' */
	iph.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen);
	iph.id = htons(id);
	iph.check = ip_checksum((struct iphdr *)&iph);	
	memcpy((pkt + IPHDR_OFFSET), (char *)&iph, sizeof(struct iphdr));
	
    ts_recent = ts_peer;
	generate_opt(++ts, TCP_FLAG_FIN | TCP_FLAG_ACK, (uint8_t *)(&tcph) + TCP_HEADER_LEN, optlen);
    
    tcph.source = htons(sport);
	tcph.dest = htons(dport);
    tcph.doff = (TCP_HEADER_LEN + optlen) >> 2;
	tcph.seq = htonl(seq);  //same as previous packet
	tcph.ack_seq = htonl(ack);
	tcph.fin = 1;         // FIN
    tcph.psh = 0;
	tcph.ack = 1;
	tcph.check = tcp_checksum((struct iphdr*)&iph, (struct tcphdr*)&tcph);	

	memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph,  TCP_HEADER_LEN + optlen);

#ifdef USE_PCAP
    if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
    }
	usleep(1);
#else // DPDK
    dpdk_send_pkt(pkt, HEADER_LEN + optlen);
#endif
	/* FIN, ACK   ' <- '*/
    for (i = 0; i < 6; i++) {
        pkt[i] = src_mac[i];
        pkt[i + 6] = dst_mac[i];
    }   
	iph.id = htons(0x0001);     //id = 1, temp!!!
	iph.saddr = inet_addr(dst_ip_addr); //exchange src/dst ip
	iph.daddr = inet_addr(src_ip_addr);
	iph.check = ip_checksum((struct iphdr *)&iph);	
	memcpy((pkt + IPHDR_OFFSET), (char *)&iph, sizeof(struct iphdr));
	
    ts_recent = ts;
	generate_opt(++ts_peer, TCP_FLAG_FIN | TCP_FLAG_ACK, (uint8_t *)(&tcph) + TCP_HEADER_LEN, optlen);
    
    tcph.doff = (TCP_HEADER_LEN + optlen) >> 2;
	tcph.source = htons(dport);       // exchange src/dst port
	tcph.dest = htons(sport);
	tcph.seq = htonl((uint32_t)(ack)); //temp !!!
	tcph.ack_seq = htonl(seq + 1);
	tcph.fin = 1;           // FIN
	tcph.ack = 1;           // ACK
	tcph.check = tcp_checksum((struct iphdr*)&iph, (struct tcphdr*)&tcph);	

	memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph,  TCP_HEADER_LEN + optlen);

#ifdef USE_PCAP
    if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
    }
	usleep(10);
#else // DPDK
    dpdk_send_pkt(pkt, HEADER_LEN + optlen);
#endif
	/* ACK    '->' */
    optlen = cal_opt_len(TCP_FLAG_ACK);
    for (i = 0; i < 6; i++) {
        pkt[i] = dst_mac[i];
        pkt[i + 6] = src_mac[i];
    }   
	iph.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen);
	id++;
	iph.id = htons(id);
	iph.saddr = inet_addr(src_ip_addr); //exchange src/dst ip
	iph.daddr = inet_addr(dst_ip_addr);
	iph.check = ip_checksum((struct iphdr *)&iph);	
	memcpy((pkt + IPHDR_OFFSET), (char *)&iph, sizeof(struct iphdr));
	
    ts_recent = ts_peer;
	generate_opt(ts, TCP_FLAG_ACK, (uint8_t *)(&tcph) + TCP_HEADER_LEN, optlen);
    
    tcph.doff = (TCP_HEADER_LEN + optlen) >> 2;
	tcph.source = htons(sport);       // exchange src/dst port
	tcph.dest = htons(dport);
	tcph.seq = htonl(seq + 1); 
	tcph.ack_seq = htonl(ack + 1);    //temp !!!
	tcph.fin = 0;          
	tcph.ack = 1;           // ACK
	tcph.check = tcp_checksum((struct iphdr*)&iph, (struct tcphdr*)&tcph);	

	memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph, TCP_HEADER_LEN + optlen);

#ifdef USE_PCAP
    if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, HEADER_LEN + optlen) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
    }
    usleep(1);
    snd_cnt += 3;
#else // DPDK
    dpdk_send_pkt(pkt, HEADER_LEN + optlen);
#endif
}

/* Description: hash according to 4-tuple */
static inline int
hash_index(struct tuple4 addr)
{
  int hash=mkhash(addr.saddr, addr.source, addr.daddr, addr.dest);
  return hash % nids_params.n_tcp_streams;
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
	pthread_mutex_lock(&hash_buf.lock);
	
	for(i = 0; i < MAX_HASH_TABLE_SIZE; i++) {
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
	struct buf_node *buf_entry = malloc(sizeof(struct buf_node));
	buf_entry->tot_buf = (uint8_t *)malloc(MAX_BUFFER_SIZE);

	if(buf_entry == NULL || buf_entry->tot_buf == NULL) {
		fprintf(stderr, "allocate memory for buf_node failed.\n");
		exit(1);
	}
	memcpy(buf_entry->tot_buf, buf, length);
	buf_entry->len = length;
	buf_entry->tup = tup;
	/* lock to be safe */
//	pthread_mutex_lock(&hash_buf.lock);

	list_add_head(&buf_entry->list, buf_list);
	
//	pthread_mutex_unlock(&hash_buf.lock);

	return buf_entry;
}

/* Description	: dump data remains in hash table */
void 
dump_rest_buf(void)
{
	int i;
//	pthread_mutex_lock(&hash_buf.lock);
	for (i = 0; i < MAX_HASH_TABLE_SIZE; i++) {
		struct list_head *head = &hash_buf.buf_list[i];
		struct buf_node *buf_entry, *q;
		list_for_each_entry_safe(buf_entry, q, head, list) {
#if 0
			if (buf_entry->len) {
				set_field();
				send_syn();
				segment(buf_entry, cmode, 12, NIDS_CLOSE);
				send_fin();
			}
#endif
			list_delete_entry(&buf_entry->list);
			free(buf_entry);
		}
	}
//	pthread_mutex_unlock(&hash_buf.lock);
}

/* Description: encapsulate data with headers, and send crafted packets out 
 * @ buffer: data to send
 * @ length: length of data
 * @ flag: stream state
 * */
int
send_buf(uint8_t *buffer, int length, int flag)
{
	int optlen = 0;
	int payload_offset = 0;

    optlen = cal_opt_len(TCP_FLAG_ACK);

	iph.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen + length);
	iph.id = htons(id);    
    iph.check = ip_checksum((struct iphdr *)&iph);	
	memcpy((pkt + IPHDR_OFFSET), (char *)&iph, sizeof(struct iphdr));
	
	generate_opt(++ts, TCP_FLAG_ACK, (uint8_t *)(&tcph) + TCP_HEADER_LEN, optlen);
    
    tcph.doff = (TCP_HEADER_LEN + optlen) >> 2;
	tcph.seq = htonl(seq);
	tcph.ack_seq = htonl(ack);
	tcph.check = tcp_checksum((struct iphdr*)&iph, (struct tcphdr*)&tcph);	

	memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph, (TCP_HEADER_LEN + optlen));
	/* Fill in the payload */
	payload_offset = HEADER_LEN + optlen;
	memcpy((pkt + payload_offset), buffer, length);

#ifdef USE_PCAP
    if (pcap_sendpacket(pcap_hdl, (const unsigned char*)pkt, (HEADER_LEN +optlen + length)) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
    }
	usleep(1);
    snd_cnt++;
#else // DPDK
    dpdk_send_pkt(pkt, HEADER_LEN+optlen+length);
#endif
    return 1;
}


/* Description: cache total data of the same stream, then rip it on demand
 * @ tup	: 4-tuple
 * @ data	: data chunk with message for the same stream
 * @ length	: length of data
 * @ flag	: state of nids stream
 * */
int
stream_segmentor(struct tuple4 tup, char *data, int length, int flag)
{
	int index;
	int num = 10;    //number of parts to segment, default: 15.

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
		/* stream finished */
		struct buf_node *node = get_buf_node(tup, index);
		if (node == NULL) {
#ifdef DEBUG_SEGMENTOR
			fprintf(stderr, "stream_segmentor: could not find correspond buf node.\n");
#endif
			return 0;
		}

        int loop = cycle;
        while (loop--) {
            /* calling sending function */	
            set_field();
            send_syn();
            segment(node, cmode, num, flag);
            send_fin();

            num++;
        }

		list_delete_entry(&node->list);
		free(node);
	} else {
	/* other state */
#ifdef DEBUG_SEGMENTOR
		fprintf(stderr, "split_stream.c, stream_segmentor, flag error.\n");
#endif
	}

	return 1; 
}

/* Description	: divide buffer according to cut_method 
 * @ buf		: buffer  the total data of the same stream
 * @ cut_mehod	: how to cut buffer into fragments
 * @ num		: number of fragments to divide
 * */
void
segment(struct buf_node *node, int mtd, uint32_t num, int flag)
{
	int size;
	int offset = 0;
	int ret;

	if (mtd == EQUAL_DIVIDE) {
		size = node->len / num;
        if (size == 0) {
            num = 0;
        } else if (size > MAX_SEG_SIZE) {
			size = 1450;
			num = node->len / size;
		}
		while(num--) {
			ret = send_buf(node->tot_buf + offset,  size, flag);
			/* update: @ sequence number; @ indentifier */
			seq += size;
			id++;

			offset += size;
		}
		if (offset < node->len) {
			ret = send_buf(node->tot_buf + offset,  node->len - offset, flag);
            /* update */
            seq += (node->len - offset);
            id++;
		}
	} else if (mtd == RANDOM_DIVIDE) {
		size = 50;
		while (offset + size < node->len) {
			ret = send_buf(node->tot_buf + offset,  size, flag);
			/* update */
			seq += size;
			id++;
			
			offset += size;	
			if (size + 50 <	MAX_SEG_SIZE) 
				size += 50;
		}
		if (offset < node->len) {
			ret = send_buf(node->tot_buf + offset,  node->len - offset, flag);
            seq += (node->len - offset);
            id++;
        }
	} else if (mtd == OVERLAP_DIVIDE) {
		size = 50;
		num = 1;
		while (offset + size < node->len) {
			ret = send_buf(node->tot_buf + offset,  size, flag);
			/* update */
			seq += size;
			id++;
			if (num++ % 2 == 0) {
				offset = offset + size - 10;   /* overlap for 10 bytes */
			} else {
				offset += size;
			}
			if (size + 50 <	MAX_SEG_SIZE) 
				size += 50;	
		}
		if (offset < node->len) {
			ret = send_buf(node->tot_buf + offset,  node->len - offset, flag);
            seq += (node->len - offset);
            id++;
        }
	} else {
		fprintf(stderr, "error: invalid division method.\n");
	//	exit(1);
	}
#ifdef NET_QUEUE
	for_each_context_in_cq(hdl) {
		if((ret = libnet_write(hdl)) == -1) {
			fprintf(stderr, "libnet_write failed.\n");
		}
		libnet_destroy(hdl);
	}
#endif
}
