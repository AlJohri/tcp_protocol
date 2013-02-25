#!/bin/sh

if [ ! -f pids_client ]; then
    echo "No PID file found. Is Minet Running?"
    exit
fi


kill `cat pids_client`
killall reader
killall writer

rm -f pids_client
