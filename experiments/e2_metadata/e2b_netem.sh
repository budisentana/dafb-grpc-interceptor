#!/usr/bin/env bash
# E2b network condition: limit gRPC traffic on loopback (TCP port 50060, both
# directions, IPv4 and IPv6) to a fixed rate with netem; all other loopback
# traffic is untouched. No delay is added, so the cost measured is serialization.
#   sudo ./e2b_netem.sh on [rate]   (default rate 100mbit)
#   sudo ./e2b_netem.sh off         (restore the default lo qdisc)
#   ./e2b_netem.sh status
set -euo pipefail
mode="${1:-status}"; rate="${2:-100mbit}"; port=50060
case "$mode" in
  on)
    tc qdisc add dev lo root handle 1: prio bands 3 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
    tc qdisc add dev lo parent 1:3 handle 30: netem rate "$rate"
    tc filter add dev lo parent 1: protocol ip   prio 1 u32 match ip  dport $port 0xffff flowid 1:3
    tc filter add dev lo parent 1: protocol ip   prio 1 u32 match ip  sport $port 0xffff flowid 1:3
    tc filter add dev lo parent 1: protocol ipv6 prio 2 u32 match ip6 dport $port 0xffff flowid 1:3
    tc filter add dev lo parent 1: protocol ipv6 prio 2 u32 match ip6 sport $port 0xffff flowid 1:3
    tc qdisc show dev lo ;;
  off) tc qdisc del dev lo root && tc qdisc show dev lo ;;
  status) tc -s qdisc show dev lo; tc filter show dev lo ;;
  *) echo "usage: $0 on [rate] | off | status"; exit 1 ;;
esac
