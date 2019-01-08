#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "stream_gen.h"
#include "nids.h"
#include "hash.h"

#ifdef USE_PCAP
#include "include/checksum.h"

char pkt[PACKET_LEN];
struct tcphdr tcph;
struct iphdr iph;
#endif


#ifdef NET_QUEUE
char label[LIBNET_LABEL_SIZE];
#endif

/* fields need modifying dynamically */
uint16_t sport, dport;
uint16_t id;

char src_ip_addr[16];  //IPv4 address	
char dst_ip_addr[16];

uint8_t src_mac[6] = {0x90, 0xe2, 0xba, 0x15, 0xcd, 0xd0};
uint8_t dst_mac[6] = {0x10, 0x1b, 0x54, 0x84, 0x83, 0xd6};

uint32_t seq = 0, ack = 0; //need calculating

/* Description 	: setting common fields for the same stream
 *              4-tuple, identifier, seq, ack
 * */
void 
set_field(void)
{
	int adr_3 = (uint8_t) libnet_get_prand(LIBNET_PR8); /*  0~255 */
	int adr_4 = (uint8_t) libnet_get_prand(LIBNET_PR8); /*  0~255 */

	sprintf(src_ip_addr, "192.168.%d.%d", adr_3, adr_4);	
	sprintf(dst_ip_addr, "192.168.%d.%d", adr_4, adr_3);	
	
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
}

#ifdef USE_PCAP
void 
prepare_header(void) 
{
	struct ethhdr *eth = (struct ethhdr *) pkt;
    unsigned long src_addr;
    char dest_addr[16];
    int i;

    for (i = 0; i < 6; i++) {
        pkt[i] = dst_mac[i];
        pkt[i + 6] = src_mac[i];
    }   
	eth->h_proto = htons(0x0800);

     /* Fill in the IP Header */
    memset(&iph, 0, sizeof(struct iphdr));
    iph.ihl = 5;
    iph.version = 4;
    iph.tos = 0;
    iph.id = htons(54321); //Id of this packet
    iph.frag_off = 0;
    iph.ttl = 255;

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
    
	tcph.doff = 5;  //tcp header size
    tcph.fin = 0;
    tcph.syn = 0;
    tcph.rst = 0;
    tcph.psh = 1;
    tcph.ack = 1;
    tcph.urg = 0;
    tcph.window = htons(14600); /* maximum allowed window size */
    tcph.check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph.urg_ptr = 0;
    memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph, sizeof(struct tcphdr));
}
#endif

/* Description: hash according to 4-tuple */
static int
hash_index(struct tuple4 addr)
{
  int hash=mkhash(addr.saddr, addr.source, addr.daddr, addr.dest);
  return hash % nids_params.n_tcp_streams;
}

/* Description	: initialize hash table: hash_buf */
int 
init_hash_buf(void)
{
	int i;
	memset(&hash_buf, 0, sizeof(struct hash_table));

	for (i = 0; i < MAX_HASH_TABLE_SIZE; i++) {
		init_list_head(&hash_buf.buf_list[i]);
	}
	pthread_mutex_init(&hash_buf.lock, NULL);

	if (&hash_buf == NULL) {
		return 0;
	}

	return 1;
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
			if (buf_entry->len) {
				set_field();
				segment(buf_entry, cmode, 12, NIDS_CLOSE);
			}
			list_delete_entry(&buf_entry->list);
            free(buf_entry);
        } 
	}
	pthread_mutex_unlock(&hash_buf.lock);
}


/* Description	: free the node_buf when the data held in  node_buf was sent */
void
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
int
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
struct buf_node *
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
struct buf_node *
insert_buf_node(struct list_head *buf_list, char *buf, int length, struct tuple4 tup) 
{
	struct buf_node *buf_entry = malloc(sizeof(struct buf_node));
	buf_entry->tot_buf = (char *)malloc(MAX_BUFFER_SIZE);

	if(buf_entry == NULL || buf_entry->tot_buf == NULL) {
		fprintf(stderr, "allocate memory for buf_node failed.\n");
		exit(1);
	}
	memcpy(buf_entry->tot_buf, buf, length);
	buf_entry->len = length;
	buf_entry->tup = tup;
	/* lock to be safe */
	pthread_mutex_lock(&hash_buf.lock);

	list_add_head(&buf_entry->list, buf_list);
	
	pthread_mutex_unlock(&hash_buf.lock);

	return buf_entry;
}

/* Description	: dump data remains in hash table */
void 
dump_rest_buf()
{
	int i;
//	pthread_mutex_lock(&hash_buf.lock);

	for (i = 0; i < MAX_HASH_TABLE_SIZE; i++) {
		struct list_head *head = &hash_buf.buf_list[i];
		struct buf_node *buf_entry, *q;
		list_for_each_entry_safe(buf_entry, q, head, list) {
			if (buf_entry->len) {
				set_field();
                send_syn();
				segment(buf_entry, cmode, 12, NIDS_CLOSE);
                send_fin();
			}
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
#ifndef USE_PCAP
int
send_buf(char *buffer, int length, int flag)
{
	int ret;   // size of data sent
	libnet_ptag_t tcp_tag, ip_tag, eth_tag;
	uint32_t src_ip, dst_ip;
	uint16_t win;
	uint8_t proto = IPPROTO_TCP;
	uint16_t frag_off = 0;    // do not fragment for now!!

    //struct timespec ts, te;

	src_ip = libnet_name2addr4(hdl, src_ip_addr, LIBNET_RESOLVE);
	dst_ip = libnet_name2addr4(hdl, dst_ip_addr, LIBNET_RESOLVE);

	win = 14600;   // for now!!!
    /* initialize libnet */
    //clock_gettime(CLOCK_REALTIME, &ts);

    if ((hdl = libnet_init(LIBNET_LINK, dev, error)) == NULL) {
        fprintf(stderr, "initializing libnet failed, error: %s\n", error);
		exit(1);
    } 	
    //clock_gettime(CLOCK_REALTIME, &te);
    //printf("time of initialization: %dus \n", (te.tv_sec - ts.tv_sec)*1000000 + (te.tv_nsec - ts.tv_nsec) / 1000);
	tcp_tag = libnet_build_tcp(
				sport,
				dport,
				seq,
				ack,
				TH_PUSH|TH_ACK,
				win,
				0,			/* checksum, 0 for auomatically calculation */
				0,			/* urgent pointer */
				LIBNET_TCP_H + length,
				buffer,
				length,
				hdl,
				0			/* building a new packet */
			);
	if (tcp_tag == -1) {
	 	fprintf(stderr, "libnet builds tcp header failed.\n");
		goto badhandle;
	}

	ip_tag = libnet_build_ipv4 (
				LIBNET_IPV4_H + LIBNET_TCP_H + length,
				0,   /* tos */
				id, /* id, 0~65535 */
				frag_off,
				(uint8_t) libnet_get_prand(LIBNET_PR8), /* ttl, 0~255 */
				proto,
				0,   /*checksum, 0 for automatically calculation*/
				src_ip,
				dst_ip,
				NULL,  /* payload */
				0,     /* length of payload */
				hdl,
				0   /* new packet */
			);
	if (ip_tag == -1) {
	 	fprintf(stderr, "libnet builds ip header failed.\n");
		goto badhandle;
	}

	eth_tag = libnet_build_ethernet( 
				dst_mac,
				src_mac,
				ETHERTYPE_IP,
				NULL,  /*payload */
				0,     /* length */
				hdl,
				0      /* new packet */
			);
	if (eth_tag == -1) {
	 	fprintf(stderr, "libnet builds ethernet header failed.\n");
		goto badhandle;
	}

	ret = libnet_write(hdl);
	if (ret == -1) {
		fprintf(stderr, "libnet writing error.\n");
		/* close handle, and restart adapter */
		libnet_destroy(hdl);

		if ((hdl = libnet_init(LIBNET_LINK, dev, error)) == NULL) {
			fprintf(stderr, "stream_gen.c, initialize libnet failed, error:%s\n", error);
			exit(1);
		}
		/* resend */
		if((ret = libnet_write(hdl)) == -1) {
			fprintf(stderr, "resend failed.\n");
		}
	}
    snd_cnt++;
#ifndef NET_QUEUE
	/* close handle, for now!!! */
	libnet_destroy(hdl);
#else
	sprintf(label, "No %d. ", id);
	if (libnet_cq_add(hdl, label) == -1) {
		//fprintf(stderr, "libnet_cq_add failed.\n");
		//goto badhandle;
	}
#endif
	return 1;

badhandle:
#ifdef NET_QUEUE
	libnet_cq_destroy();
#endif
	libnet_destroy(hdl);
	exit(1);
}

#else   //use libpcap

int
send_buf(char *buffer, int length, int flag)
{
	iph.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + length);
	iph.id = htons(id);
	iph.saddr = inet_addr(src_ip_addr);
	iph.daddr = inet_addr(dst_ip_addr);
	iph.check = ip_checksum((struct iphdr *)&iph);	
	memcpy((pkt + IPHDR_OFFSET), (char *)&iph, sizeof(struct iphdr));
	
	tcph.source = htons(sport);
	tcph.dest = htons(dport);
	tcph.seq = htonl(seq);
	tcph.ack_seq = htonl(ack);
	tcph.check = tcp_checksum((struct iphdr*)&iph, (struct tcphdr*)&tcph);	

	memcpy((pkt + TCPHDR_OFFSET), (char *)&tcph, sizeof(struct tcphdr));
	/* Fill in the payload */
	memcpy((pkt + PAYLOAD_OFFSET), buffer, length);

    if (pcap_sendpacket(pcap_hdl, pkt, (HEADER_LEN + length)) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap_hdl));
    }
    snd_cnt++;
    usleep(5);
}
#endif


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
	int num = 15;    //number of parts to segment, default: 15.

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
				node = insert_buf_node(buf_list_t, (char *)data, MAX_BUFFER_SIZE, tup);

				/* reallocate more memory for large data */
				node->tot_buf = (char *)realloc(node->tot_buf, length);
				memcpy(node->tot_buf+node->len, data + MAX_BUFFER_SIZE, length - MAX_BUFFER_SIZE);
				node->len = length;
			} else {
				node = insert_buf_node(buf_list_t, (char *)data, length, tup);
			}
			return 0;
		}	
		/* find existing buf_node in hash table */	
		/* length of the total data exceeds buffer size*/
		if (node->len + length > MAX_BUFFER_SIZE) {
			/* reallocate more memory for large data */
			node->tot_buf = (char *)realloc(node->tot_buf, node->len + length);
			memcpy(node->tot_buf+node->len, data, length);
			node->len += length;
		} else {
			memcpy(node->tot_buf+node->len, data, length);
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

		/* calling sending function */	
		set_field();
		segment(node, cmode, num, flag);
		
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
	int i, size;
	int offset = 0;
	int ret;

	if (mtd == EQUAL_DIVIDE) {
		size = node->len / num;
		if (size > 	MAX_SEG_SIZE) {
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
		if (offset < node->len)
			ret = send_buf(node->tot_buf + offset,  node->len - offset, flag);
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
		if (offset < node->len)
			ret = send_buf(node->tot_buf + offset,  node->len - offset, flag);
	} else {
		fprintf(stderr, "error: invalid division method.\n");
	//	exit(1);
	}
#ifdef NET_QUEUE
	for_each_context_in_cq(hdl) {
		if((ret = libnet_write(hdl)) == -1) {
			fprintf(stderr, "libnet_write failed.\n");
		}
	}
		libnet_destroy(hdl);
#endif
}
