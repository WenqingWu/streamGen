/*
Copyright (c) Wenqing Wu  <wuwenqing@ict.ac.cn>. All rights reserved.
See the file COPYING for license details.
*/
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>

#include <getopt.h>
#include <pcap/pcap.h>
#include "libnids-1.24/src/nids.h"

#include "include/stream_gen.h"

#ifdef USE_DPDK
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#ifdef RTE_LIBRTE_PDUMP
#include <rte_pdump.h>
#endif

static const struct rte_eth_conf port_conf_default = { 
    .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

volatile bool force_quit;

#ifdef SEND_THREAD
struct thread_info              th_info[NUM_SEND_THREAD];
#else
struct mbuf_table               tx_mbufs;
struct dpdk_port_statistics     port_stat = {0};
#endif
int                             snd_port = 0;
uint16_t                        burst = DEFAULT_BURST_SIZE;           // tx burst, default 64
struct rte_mempool*             mp;
struct rte_eth_dev_tx_buffer*   tx_buffer;
#endif //USE_DPDK

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

struct hash_table               hash_buf;          //hash table
int         nb_stream;
uint64_t    snd_cnt;
/* commandline arguments */
int         nb_concur = 10;
int         nb_snd_thread = 2;
int         cmode = 1;
int         len_cut = 5;
bool 		is_len_fixed = false;
#ifdef USE_PCAP
char        dev[20] = "eth0";    // network interface for sending packets
char        error[LIBNET_ERRBUF_SIZE];
pcap_t     *pcap_hdl;
#endif

static void
print_stat(void)
{
#ifdef USE_DPDK
#ifdef SEND_THREAD
    int i;
    uint64_t tx_total = 0, drop_total = 0;
    for (i = 0; i < nb_snd_thread; ++i) {
        tx_total += th_info[i].stats.tx;
        drop_total += th_info[i].stats.dropped;
    }
    printf("total send: %ld\n", tx_total);
    printf("dropped: %ld\n", drop_total);
#else
    printf("total send: %ld\n", port_stat.tx);
    printf("dropped: %ld\n", port_stat.dropped);
#endif
#else
    printf("total send: %ld\n", snd_cnt);
#endif
}


static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
                signum);

#ifdef USE_DPDK
        force_quit = true;
#endif

#ifdef RTE_LIBRTE_PDUMP
		/* uninitialize packet capture framework */
		rte_pdump_uninit();
#endif

#ifdef USE_PCAP
        pcap_close(pcap_hdl);
#endif

#ifdef SEND_THREAD
        wait_threads();
#endif

        /* free hash table */
        destroy_hash_buf();
        
        /* print statistics */
        print_stat();

		/* exit with the expected status */
		signal(signum, SIG_DFL);
		kill(getpid(), signum);
    }   
}


/* struct tuple4 contains addresses and port numbers of the TCP connections
 * the following auxiliary function produces a string looking like
 * 10.0.0.1,1024,10.0.0.2,23
 */
static char *
adres (struct tuple4 addr)
{
	static char buf[256];
	strcpy (buf, int_ntoa (addr.saddr));
	sprintf (buf + strlen (buf), ",%i,", addr.source);
	strcat (buf, int_ntoa (addr.daddr));
	sprintf (buf + strlen (buf), ",%i", addr.dest);
	return buf;
}

void
tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
{
    struct      tuple4 tp4;
	char        buf[1024];

    memset(buf, 0, 1024);
	strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
	if (a_tcp->nids_state == NIDS_JUST_EST) {
		/* connection described by a_tcp is established
		 * here we decide, if we wish to follow this stream
		 * sample condition: if (a_tcp->addr.dest!=23) return;
		 * in this simple app we follow each stream, so..
		 */
		/* we want data received by a client */
		a_tcp->client.collect++; 
		/* and by a server, too */
		a_tcp->server.collect++; 
		/* we want urgent data received by a server */
		a_tcp->server.collect_urg++; 
								   
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
		/* if we don't increase this value, we won't be notified of urgent data arrival */
		a_tcp->client.collect_urg++; 
#endif
#ifdef DEBUG_SEGMENTOR
		fprintf (stderr, "%s established\n", buf);
#endif
		return;
	}
	if (a_tcp->nids_state == NIDS_CLOSE) {
		/* connection has been closed normally */
#ifdef DEBUG_SEGMENTOR
		fprintf (stderr, "%s closing\n", buf);
#endif
		/* TODO, determine in what direction (dual direction for now!!)*/
		/* same direction  */
		tp4 = a_tcp->addr;
		store_stream_data(tp4, NULL, 0, NIDS_CLOSE);	
		/* opposite direction */
		tp4.source = a_tcp->addr.dest;
		tp4.dest = a_tcp->addr.source;
		tp4.saddr = a_tcp->addr.daddr;
		tp4.daddr = a_tcp->addr.saddr;
		store_stream_data(tp4, NULL, 0, NIDS_CLOSE);	
		
		return;
	}
	if (a_tcp->nids_state == NIDS_RESET) {
		/* connection has been closed by RST */
#ifdef DEBUG_SEGMENTOR
		fprintf (stderr, "%s reset\n", buf);
#endif
		return;
	}

	if (a_tcp->nids_state == NIDS_DATA) {
		/* new data has arrived; gotta determine in what direction
		 * and if it's urgent or not
		 */
		struct half_stream *hlf = NULL;

		if (a_tcp->server.count_new_urg) {
			/* new byte of urgent data has arrived*/ 
			strcat(buf,"(urgent->)");
			buf[strlen(buf)+1]=0;
			buf[strlen(buf)]=a_tcp->server.urgdata;
#ifdef DEBUG_SEGMENTOR	
			write(1,buf,strlen(buf));
#endif
			tp4.source = a_tcp->addr.dest;
			tp4.dest = a_tcp->addr.source;
			tp4.saddr = a_tcp->addr.daddr;
			tp4.daddr = a_tcp->addr.saddr;

			/* TODO: call for segmentation function */
			/* segment data buffer */
//			store_stream_data(tp4, (char *)hlf->data, hlf->count - hlf->offset, NIDS_DATA);	

			return;
		}
		/* *
         * We don't have to check if urgent data to client has arrived,
		 * because we haven't increased a_tcp->client.collect_urg variable.
		 * So, we have some normal data to take care of.
		 * */
        /* Note!
         * data of two direcroty( client -> server; server -> client) is seperated into two parts,
         * see "if...else..." for details.
         * */
		if (a_tcp->client.count_new) {
			/* new data for client */
			tp4 = a_tcp->addr;
			
			/* from now on, we will deal with hlf var
   			 * which will point to client side of conn symbolic direction 
			 * of data
             */
			hlf = &a_tcp->client; 
			strcat (buf, "(<-)"); 
		} else {
			tp4.source = a_tcp->addr.dest;
			tp4.dest = a_tcp->addr.source;
			tp4.saddr = a_tcp->addr.daddr;
			tp4.daddr = a_tcp->addr.saddr;

			hlf = &a_tcp->server; // analogical
			strcat (buf, "(->)");
		}
		/* we print the connection parameters:
		 * (saddr, daddr, sport, dport) accompanied by data flow direction (-> or <-)
		 */
#ifdef DEBUG_SEGMENTOR
		fprintf(stderr,"%s",buf); 
#endif
		/* segment data buffer */
		store_stream_data(tp4, (char *)hlf->data, hlf->count - hlf->offset, NIDS_DATA);	
#ifdef DEBUG_SEGMENTOR	
		write(2,hlf->data,hlf->count - hlf->offset); // we print the newly arrived data
#endif
 	}
	return ;
}

#ifdef USE_DPDK
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = NUM_SEND_THREAD;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;

    if (port >= rte_eth_dev_count())
        return -1;

    /* Configure the Ethernet device. */
    fflush(stdout);
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval < 0) {
        fprintf(stderr, "rte_eth_dev_configure failed.\n");
        return retval;
    }

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval < 0) {
        fprintf(stderr, "rte_eth_dev_configure failed.\n");
        return retval;
    }
    /* no need for packet generator for now */
    /* Allocate and set up 1 RX queue per Ethernet port. */
    fflush(stdout);
    q = 0;
    retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                    rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0)
        return retval;
    
    /* Allocate and set up 1 TX queue per Ethernet port. */
    fflush(stdout);
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                        rte_eth_dev_socket_id(port), NULL);
        if (retval < 0)
            return retval;
    }
# ifdef TX_BUFFER      /* Note: not used for now!! */
	/* Initialize TX buffers */
	tx_buffer = rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(burst), 0, rte_eth_dev_socket_id(port));
    if (tx_buffer == NULL) {
		printf("Cannot allocate buffer for tx on port %u\n", (unsigned) port);
        exit(1);
    }
	rte_eth_tx_buffer_init(tx_buffer, burst);

	retval = rte_eth_tx_buffer_set_err_callback(tx_buffer,
			dpdk_tx_buffer_unsent_callback, &port_stat.dropped);
	if (retval < 0) {
		printf("Cannot set error callback for tx buffer on port %u\n", (unsigned) port);
        exit(1);
    }
#endif	
    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
	struct ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    return 0;
}
#endif

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static void
lcore_main(void)
{
    /* store stream data read from pcap file */
    printf("\nReading stream data from pcap file...\n");
    nids_run();
	
    printf("\nStart sending packets. [Ctrl+C to quit]\n");
#ifdef SEND_THREAD
    /* send streams concurrently with multi-thread*/
    run_send_threads();
    wait_threads();
#else
    /* send streams concurrently */
    send_streams();
#endif
}

/* display usage infomation */
static void
print_usage(const char * prgname)
{
    printf("Usage: %s [EAL options] -- [options] [input file]\n"
        "\n\t[options]:\n"
        "\t-h help: display usage infomation\n"
        "\t-i PCAP FILE:\n"
        "\t\tget input packets from file\n"
        "\t-o INTERFACE:\n"
        "\t\tinterface for sending packets\n"
        "\t\t(e.g. 1 for port1 with DPDK, eth1 for libpcap, default 0)\n"
        "\t-c concurrency: concurrency of sending streams.(default 10)\n"
        "\t-t sending threads:\n"
        "\t\tnumber of sending threads (default 1, maximum 8)\n"
        "\t-l payload length: give a fixed length of payload for packets with payload\n"
        "\t-b tx_burst: \n"
        "\t\ttransmiting burst while sending with DPDK (default 1, maximum 128)\n"
        "\t-m CUT MODE(Not used for now):\n"
        "\t\t1, equal mode\n"
        "\t\t2, random mode\n"
        "\t\t3, overlap mode\n\n",
        prgname);
}

/* parse commandline options */
static int 
get_options(int argc, char *argv[])
{
    int opt = 0;

    while ((opt = getopt(argc, argv, "hi:o:m:b:c:l:t:")) != -1) {
        switch(opt) {
            case 'h':
                print_usage(argv[0]);
                exit(0);
            case 'i':
				nids_params.filename = (char *)malloc(strlen(optarg));
                strcpy(nids_params.filename, optarg);
                break;
            case 'o':
#ifdef USE_PCAP
              	strcpy(dev, (const char *)optarg);
#else
                snd_port = atoi(optarg);
#endif
              	break;
            case 'c':
              	nb_concur = atoi(optarg);
              	break;
            case 'b':
#ifdef USE_DPDK
              	burst = (uint16_t)atoi(optarg);
                if (burst >= MAX_BURST) {
                    printf("Burst number exceed MAX_BURST(128).\n");
                    exit(1);
                }
#endif
              	break;
            case 'm':
              	cmode = atoi(optarg);
              	break;
            case 't':
              	nb_snd_thread = atoi(optarg);
              	break;
            case 'l':
              	len_cut = atoi(optarg);
				is_len_fixed = true;
              	break;
	        default:
				print_usage(argv[0]);	
				return -1;
        }   
    }   

    return 1;
}


int 
main (int argc, char *argv[])
{
    int ret;
    int i;
#ifdef USE_DPDK
    //struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    //uint16_t portid;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	}

    argc -= ret;
    argv += ret;
	
    force_quit = false;
    is_len_fixed = false;
#ifdef RTE_LIBRTE_PDUMP
	/* initialize packet capture framework */
	rte_pdump_init(NULL);
    printf ("pdump server initialized.\n");
#endif

#endif
	signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

	/* here we can alter libnids params, for instance:
	 * nids_params.n_hosts=256;
	 */
	if(argc < 3) {
		fprintf(stderr, "start failed, too few arguments for commandline. \n\n");
		print_usage(argv[0]);
		exit(1);
	}
	
	ret = get_options(argc, argv);
	if (ret < 0 ) {
		fprintf(stderr, "get options failed,Invalid arguments.\n");
        exit(1);
	}

	init_hash_buf();
    snd_cnt = 0;
    nb_stream = 0;
    
#ifdef USE_DPDK
    /* number of ports */
	nb_ports = rte_eth_dev_count();
    printf("nb_port:%d\n", nb_ports);
	if (nb_ports <= 0) {
		rte_exit(EXIT_FAILURE, "Error: no ports available\n");
	}

    printf("NUMA info, socket id: %d, port 0 socket id: %d\n", rte_socket_id(), rte_eth_dev_socket_id(0));
	/* Creates a new mempool in memory to hold the mbufs. */
    mp = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mp == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize all ports. */
    if (port_init(snd_port, mp) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port 0\n");
#endif //USE_DPDK

#ifdef USE_PCAP
    /* Open the adapter */
    if ((pcap_hdl = pcap_open_live(dev,   /* name of the interface(device) */
                    65535,                          /* portion of the packet to capture */
                    1,                              /* promiscuous mode (nonzero means promiscuous) */
                    1000,                           /* read timeout */
                    error)) == NULL) {
        fprintf(stderr, "Could not open %s, error: %s\n", dev, error);
        exit(1);
    }
#endif

	if (!nids_init ()) {
		fprintf(stderr,"error, %s\n",nids_errbuf);
		goto outdoor;
	}
	
	nids_register_tcp (tcp_callback);
    lcore_main(); 
	
#ifdef SEND_THREAD
    destroy_threads();
#endif
#ifdef USE_DPDK
	/* sent out or drop rest data remains in hash table,
	 * and free hash table 
	 * */
    dpdk_tx_flush();
#endif
    print_stat();

outdoor:
    printf("finishing ...\n");
	destroy_hash_buf();
#ifdef USE_PCAP
	pcap_close(pcap_hdl);
#endif
	return 0;
}

