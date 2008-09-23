#!/bin/bash
# for i in $(arp -na | sed -e "s/.*(//; s/).*//"); do arp -d $i; done; ping -c 1 192.168.10.4
for i in $(arp -na | sed -e "s/.*(//; s/).*//")
do
	arp -d $i
done
ping -c 1 $1
