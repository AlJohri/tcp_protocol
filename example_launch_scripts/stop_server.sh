#!/bin/sh

if [ ! -f pids_server ]; then
    echo "No PID file found. Is Minet Running?"
    exit
fi


kill `cat pids_server`
killall reader
killall writer

rm -f pids_server
