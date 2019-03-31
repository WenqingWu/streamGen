#ifndef __STREAM_GEN__
#define __STREAM_GEN__


#define __USE_GNU
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>

#include <libnet.h>
#include <pcap/pcap.h>

#include "../libnids-1.24/src/nids.h"
#include "list.h"
#include "checksum.h"


/* DPDK */
#ifdef USE_DPDK
#include <stdint.h>
#include <inttypes.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_atomic.h>

#define DEFAULT_BURST_SIZE  1
#define MAX_BURST           128
#define PKT_RETRY_COUNT     10
#define TX_DELAY_TIME       20

#define RX_RING_SIZE 		128
#define TX_RING_SIZE 		512

#define NUM_MBUFS 			1024
#define MBUF_CACHE_SIZE 	256
#define MAX_MBUF_PER_THREAD 1024
#endif

#define PACKET_LEN 			1600     /* a little bigger than MTU */

#define TCP_OPT_TIMESTAMP_ENABLED   1	/* enabled for rtt measure */
#define TCP_OPT_SACK_ENABLED        0	/* not implemented */

#define MAX_BUFFER_SIZE 	20000
#define MAX_HASH_TABLE_SIZE	1100

#define MAX_SEG_SIZE		1435  	//MSS
#define MAX_CONCURRENCY     5000

#define NUM_SEND_THREAD		8 		//maximal number of sending thread

/* cut mode */
#define	EQUAL_DIVIDE        1  	 	// divide buffer into several equal part
#define	RANDOM_DIVIDE		2		// divide buffer into fragments with random length
#define	OVERLAP_DIVIDE      3		// divide buffer into fragments which may overlap with other ones

// #define SEND_THREAD

/* total data of a stream is store in a buf_node struct */
struct buf_node {
	struct list_head    list;
	struct      tuple4 tup;
	uint8_t*    tot_buf;
	int	        len;					// size for the whole data for now
    int         offset;                 // offset of data to send
    uint8_t     state;                  // state of TCP stream
    uint16_t    id;                     // identification
    uint16_t    rcv_id;                     // identification
    uint32_t    saddr;
    uint32_t    daddr;
    uint16_t    sport;
    uint16_t    dport;
    uint32_t    seq;
    uint32_t    ack_seq;
    uint32_t    ts;                 // timestamp
    uint32_t    ts_peer;            // timestamp in packets of the opposite direction
};

struct hash_table {
	struct list_head    buf_list[MAX_HASH_TABLE_SIZE];
	pthread_t           thread;
	pthread_mutex_t     lock;
};
extern struct hash_table hash_buf;      // hash table used to retrieve buf_node 

extern int      nb_concur;  // concurrency
extern int      nb_stream;  // number of streams stored in buffer 
extern int      nb_snd_thread;
extern int      len_cut;
extern bool     is_len_fixed;
extern uint64_t snd_cnt;
extern bool		syn_flood_set;
extern volatile bool    force_quit;
extern char 	dev[20];

#ifdef USE_PCAP
extern char     error[LIBNET_ERRBUF_SIZE];
extern pcap_t*  pcap_hdl;
#endif


#ifdef USE_DPDK
struct mbuf_table {
	uint16_t len;                           // number of rte_mbuf 
	struct rte_mbuf *m_table[MAX_BURST];    //mbuf table of packets to send
};

/* Per-port statistics struct */
struct dpdk_port_statistics {
	uint64_t tx;                // number of packets sent
	uint64_t dropped;           // number of packets dropped
} __rte_cache_aligned;

extern struct   rte_eth_dev_tx_buffer   *tx_buffer;

extern int              snd_port;
extern uint16_t         burst;

extern struct   rte_mempool* mp; //mempool used for initializing ports

void dpdk_tx_flush(void);
void dpdk_tx_buffer_unsent_callback(struct rte_mbuf **pkts, uint16_t unsent, void *userdata);

#ifdef SEND_THREAD
struct thread_info {
    pthread_t               thread_id;
    struct rte_mempool*     mbuf_pool;
    struct mbuf_table       tx_mbufs;
    uint8_t                 pkt[PACKET_LEN];
    uint64_t                pre_tsc;
    
    struct tcphdr*          tcph;
    struct iphdr*           iph;
    struct buf_node**       nodes;

    struct dpdk_port_statistics   stats;
};
extern struct thread_info   th_info[NUM_SEND_THREAD];

void run_send_threads(void);
void wait_threads(void);
void destroy_threads(void);
void prepare_header(int id);
#else
extern struct   mbuf_table              tx_mbufs;
extern struct   dpdk_port_statistics    port_stat;

void prepare_header(void);
#endif //SEND_THREAD
#endif //USE_DPDK

void init_hash_buf(void);
void destroy_hash_buf(void);
void dump_rest_buf(void);
void SYN_flood_simulator(void);

void segment(struct buf_node *node, int mtd, uint32_t num, uint8_t p, uint16_t q);
int  store_stream_data(struct tuple4 tup, char *data, int length, int flag);
void send_streams(void);

#endif 
