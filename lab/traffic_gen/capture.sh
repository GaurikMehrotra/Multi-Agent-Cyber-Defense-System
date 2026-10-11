#!/bin/sh
set -eu
# Capture this container's own traffic only, never host interfaces.
tcpdump -Z root -i eth0 -U -w /output/lab.pcap 'net 172.30.0.0/24 and tcp' &
capture_pid=$!
trap 'kill -INT "$capture_pid" 2>/dev/null || true' EXIT
sleep 1
python /generate.py
kill -INT "$capture_pid"
wait "$capture_pid" || true
