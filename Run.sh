#!/bin/bash

sudo ./build/app/streamGen-dpdk -c 0x1 -n 1 -- -i pcapfiles/dump5.pcap -o 0 -c 100 -t  2
