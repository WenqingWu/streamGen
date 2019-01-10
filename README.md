## streamGen

stream generator

### Files

./   
 |__ main.c   
 |__ stream_gen.c   
 |__ stream_gen-multi-thread.c   
 |__ include/   
 |__ libnids-1.24/   
 |__ pcapfiles/  
 |__ Makefile   
 |__ setup.sh   
 |__ run.sh   

### Dependency

libpcap libnet libnids numa-devel 

### Build

1. Set environment variables

Before building streamGen, you need to compile and deploy [DPDK](https://github.com/DPDK/dpdk) first. 

```bash
$ export RTE_SDK=<path-to-dpdk>
$ export RTE_TARGET=x86_64-native-linuxapp-gcc
```


2. Compile

```bash
$ cd <path-to-streamGen>
$ cd libnids-1.24/
$ make
$ cd ..
$ make
```

### Run

You may run "./build/app/streamGen-dpdk -c 0x1 -n 1 -- -h" for help information.

To start streamGen, you need to give a pcap file as input, for example,

```bash
$ ./build/app/streamGen-dpdk -c 0x1 -n 1 -- -i pcapfiles/dump5.pcap -o 0 -c 1000
```

```bash
-i pcap file	: Input file which provides network trace.
-o interface	: Interface used to send packets.
		(e.g. 1 for port1 with DPDK, eth1 for libpcap, default 0)
-c concurrency	: Concurrency when sending streams.(default 10)  
```

### To run with Multiple thread

```bash
1. Uncomment "LIBS_CFLAGS += -DSEND_THREAD" in Makefile
2. Uncomment "MODE := multi-thread" in Makefile
3. Rebuild project
```

### Q&A
