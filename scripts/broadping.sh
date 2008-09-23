for addr in $(arp -n | awk '{ print $1 }' | grep -v 'Addre')
do
	arp -d $addr
done
ping -b 255.255.255.255
