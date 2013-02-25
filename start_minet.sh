#!/bin/sh

# boilerplate junk
IFS=

if [ -f pids ]; then
    echo "PID file exists. Is Minet already running?"
    exit
fi

rm -f pids

if [ ! -f minet.cfg ]; then
    echo "Minet configuration file not present. Please run setup.sh"
    exit
fi

IFS="
" # no, you can't actually use "\n" to specify a newline....

for cfg in `cat minet.cfg`; do
    if  [ ! -z ${cfg} ]; then
        #export ${cfg}
        #echo ${cfg}
        echo export ${cfg} >> minet.cfg.export
    fi
done
IFS=

source ./minet.cfg.export
##rm -f minet.cfg.export

#export MINET_ETHERNETDEVICE="br0"
#export MINET_IPADDR="10.10.145.5"
#export MINET_ETHERNETADDR="78:2B:CB:9E:6C:1D"
#export MINET_DEBUGLEVEL="10"
#export MINET_DISPLAY="xterm"
#export MINET_MODULES="monitor device_driver ethernet_mux arp_module ip_module other_module ip_mux icmp_module udp_module tcp_module ipother_module sock_module socklib_module"
#export MINET_MONITOR="device_driver ethernet_mux arp_module other_module ip_module ip_mux icmp_module udp_module tcp_module ipother_module sock_module socklib_module"
#export MINET_MONITORTYPE="text"
#export MINET_MSS=256
#export MINET_MIP=512
#export MINET_MTU=500

if [ -z "${MINET_DISPLAY}" ]; then
    export MINET_DISPLAY=xterm
fi



run_module() {
    cmd="bin/"$*
    case $MINET_DISPLAY in
	none)
           $cmd 1> /dev/null 2> /dev/null &
           echo $! >> pids
        ;;
        log)
           $cmd 1> $1.stdout.log 2> $1.stderr.log &
           echo $! >> pids
        ;;
        gdb)
            xterm -fg cyan -bg black -sb -sl 5000 -T gdb-$1 -e gdb bin/${1} &
            echo $! >> pids
        ;;
        xterm_pause)
            xterm -fg cyan -bg black -sb -sl 5000 -T $1 -e xterm_pause.sh $cmd &
            echo $! >> pids
        ;;
        xterm | *)
#            echo "xterm -fg cyan -bg black -sb -sl 5000 -T $1 -e $cmd &"
            xterm -fg cyan -bg black -sb -sl 5000 -T $1 -e $cmd &
            echo $! >> pids
        ;;
    esac
}


# start monitor
run_module monitor
#xterm -fg cyan -bg black -sb -sl 5000 -T monitor -e bin/monitor & echo $! >> pids

#case "foo$MINET_MONITORTYPE" in
#   foo) run_module monitor;;
#   footext) run_module monitor;;
#   foojavagui) java -jar mmonitor.jar & echo $! >> pids;
#esac

echo "Starting Minet modules..."
# start modules

if [ ! bin/device_driver2 -o -z `find bin/device_driver2 -user root` ] 
then 
    echo ""
    echo "Error: Incorrect permissions on bin/device_driver2. Please make it owned by root and SUID."
    echo ""
    echo "Stopping Minet..."
    ./stop_minet.sh
    exit
fi


run_module device_driver2
#xterm -fg cyan -bg black -sb -sl 5000 -T device_driver2 -e bin/device_driver2 & echo $! >> pids
run_module ethernet_mux
run_module arp_module \ $MINET_IPADDR \ $MINET_ETHERNETADDR
run_module ip_module 
run_module other_module
run_module ip_mux
run_module icmp_module
run_module udp_module 
run_module tcp_module 
run_module ipother_module
run_module sock_module 

case "foo$*" in
  foo)  run_module app;;
  foo?*)  run_module $* ;;
esac






