
export MINET_ETHERNETDEVICE="br0"
export MINET_IPADDR="10.10.145.15"
export MINET_ETHERNETADDR="78:2B:CB:9E:6C:9B"
export MINET_DEBUGLEVEL="10"
export MINET_DISPLAY="xterm"
export MINET_MODULES="monitor device_driver ethernet_mux arp_module ip_module other_module ip_mux icmp_module udp_module tcp_module ipother_module sock_module socklib_module"
export MINET_MONITOR="device_driver ethernet_mux arp_module other_module ip_module ip_mux icmp_module udp_module tcp_module ipother_module sock_module socklib_module"
export MINET_MONITORTYPE="text"
export MINET_MSS=256
export MINET_MIP=512
export MINET_MTU=500

xterm -fg cyan -bg black -sb -sl 5000 -T monitor -e bin/monitor & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T device_driver2 -e bin/device_driver2 & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T ethernet_mux -e bin/ethernet_mux & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T arp_module -e bin/arp_module $MINET_IPADDR $MINET_ETHERNETADDR & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T ip_module -e bin/ip_module & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T other_module -e bin/other_module & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T ip_mux -e bin/ip_mux & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T icmp_module -e bin/icmp_module & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T udp_module -e bin/udp_module & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T tcp_module -e bin/tcp_module & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T ipother_module -e bin/ipother_module & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T sock_module -e bin/sock_module & echo $! >> pids_client
xterm -fg cyan -bg black -sb -sl 5000 -T tcp_client -e "bin/tcp_client u tlab-14.eecs.northwestern.edu 10085" & echo $! >> pids_client
#xterm -fg cyan -bg black -sb -sl 5000 -T tcp_client -e "bin/tcp_client u tlab-14.eecs.northwestern.edu 10085" & echo $! >> pids_client
