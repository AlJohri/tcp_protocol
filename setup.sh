#! /bin/bash

# boilerplate junk
IFS=

# configuration values #

NIC="br0"
MAC_ADDR=`./scripts/get_addr.pl ${NIC}`

IP_ADDR=`ifconfig ${NIC} | grep 'inet addr:'| grep -v '127.0.0.1' | cut -d: -f2 | awk '{ print $1}'`
if [ ! -n $MINET_IPADDR ]; then
	echo "*************************************************"
	echo "Warning: Failed to fetch IP address automatically"
	echo "*************************************************"

	exit
fi

MSS=256
MIP=512
MTU=500


DEBUG_LEVEL=10
DISPLAY=xterm
MONITOR_TYPE=text


MODS="monitor \
device_driver \
ethernet_mux \
arp_module \
ip_module \
other_module \
ip_mux \
icmp_module \
udp_module \
tcp_module \
ipother_module \
sock_module \
socklib_module"

MONITORED_MODS="device_driver \
ethernet_mux \
arp_module \
other_module \
ip_module \
ip_mux \
icmp_module \
udp_module \
tcp_module \
ipother_module \
sock_module \
socklib_module"


##########################################
####   End Configuration Parameters   ####
##########################################

if [ -z $1 ]; then
    CFG_FILE="./minet.cfg"
fi

echo "" > ${CFG_FILE}


write_cfg() {
    echo $* >> ${CFG_FILE}
}




write_cfg MINET_ETHERNETDEVICE=\"${NIC}\"
write_cfg MINET_IPADDR=\"${IP_ADDR}\"
write_cfg MINET_ETHERNETADDR=\"${MAC_ADDR}\"
write_cfg MINET_DEBUGLEVEL=\"${DEBUG_LEVEL}\"
write_cfg MINET_DISPLAY=\"${DISPLAY}\"
write_cfg MINET_MODULES=\"${MODS}\"
write_cfg MINET_MONITOR=\"${MONITORED_MODS}\"
write_cfg MINET_MONITORTYPE=\"${MONITOR_TYPE}\"
write_cfg MINET_MSS=${MSS}
write_cfg MINET_MIP=${MIP}
write_cfg MINET_MTU=${MTU}


echo "Configuration Written to \"${CFG_FILE}\":"
cat ${CFG_FILE}

if [ -e fifos ]; then
    rm -rf fifos
fi

echo "Making fifos for communication between stack components in ./fifos"

mkdir fifos
    
mkfifo fifos/ether2mux 
mkfifo fifos/mux2ether
    
mkfifo fifos/mux2arp
mkfifo fifos/arp2mux
    
mkfifo fifos/mux2ip
mkfifo fifos/ip2mux
    
mkfifo fifos/mux2other
mkfifo fifos/other2mux
    
mkfifo fifos/ip2arp
mkfifo fifos/arp2ip
    
mkfifo fifos/ip2ipmux
mkfifo fifos/ipmux2ip
    
mkfifo fifos/udp2ipmux
mkfifo fifos/ipmux2udp

mkfifo fifos/tcp2ipmux
mkfifo fifos/ipmux2tcp

mkfifo fifos/icmp2ipmux
mkfifo fifos/ipmux2icmp

mkfifo fifos/other2ipmux
mkfifo fifos/ipmux2other

mkfifo fifos/udp2sock
mkfifo fifos/sock2udp

mkfifo fifos/tcp2sock
mkfifo fifos/sock2tcp

mkfifo fifos/icmp2sock
mkfifo fifos/sock2icmp

mkfifo fifos/ipother2sock
mkfifo fifos/sock2ipother

mkfifo fifos/app2sock
mkfifo fifos/sock2app

mkfifo fifos/sock2socklib
mkfifo fifos/socklib2sock

mkfifo fifos/reader2mon
mkfifo fifos/writer2mon
mkfifo fifos/ether2mon
mkfifo fifos/ethermux2mon
mkfifo fifos/arp2mon
mkfifo fifos/ip2mon
mkfifo fifos/other2mon
mkfifo fifos/ipmux2mon
mkfifo fifos/udp2mon
mkfifo fifos/tcp2mon
mkfifo fifos/icmp2mon
mkfifo fifos/ipother2mon
mkfifo fifos/sock2mon
mkfifo fifos/socklib2mon
mkfifo fifos/app2mon

echo "Done!"
