#!/usr/bin/env bash
# Link profiles for E6/E7: tc netem on loopback, applied only to one TCP port (both directions,
# IPv4 and IPv6), as in E2b/E5. Delay is one-way per direction (5ms each way = 10 ms RTT).
#   sudo bash experiments/common/netem_profile.sh on <profile> <port>
#   sudo bash experiments/common/netem_profile.sh off
#   bash experiments/common/netem_profile.sh status
# Profiles:
#   L1     1 Gbit/s,   no delay, no loss    (data centre, crossover model)
#   L2     100 Mbit/s, 5 ms,     no loss    (regional / edge-to-cloud)
#   L3     100 Mbit/s, 5 ms,     0.5% loss  (lossy regional link)
#   L4     20 Mbit/s,  20 ms,    no loss    (cross-region / mobile backhaul)
#   N100   100 Mbit/s, no delay, no loss    (E2b/E4/E5 condition; E7)
set -euo pipefail
mode="${1:-status}"
case "$mode" in
  on)
    profile="${2:?profile}"; port="${3:?port}"
    case "$profile" in
      L1)   args="rate 1gbit" ;;
      L2)   args="rate 100mbit delay 5ms" ;;
      L3)   args="rate 100mbit delay 5ms loss 0.5%" ;;
      L4)   args="rate 20mbit delay 20ms" ;;
      N100) args="rate 100mbit" ;;
      *) echo "unknown profile $profile"; exit 1 ;;
    esac
    tc qdisc del dev lo root 2>/dev/null || true
    tc qdisc add dev lo root handle 1: prio bands 3 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
    # shellcheck disable=SC2086
    tc qdisc add dev lo parent 1:3 handle 30: netem limit 10000 $args
    tc filter add dev lo parent 1: protocol ip   prio 1 u32 match ip  dport "$port" 0xffff flowid 1:3
    tc filter add dev lo parent 1: protocol ip   prio 1 u32 match ip  sport "$port" 0xffff flowid 1:3
    tc filter add dev lo parent 1: protocol ipv6 prio 2 u32 match ip6 dport "$port" 0xffff flowid 1:3
    tc filter add dev lo parent 1: protocol ipv6 prio 2 u32 match ip6 sport "$port" 0xffff flowid 1:3
    tc qdisc show dev lo ;;
  off) tc qdisc del dev lo root 2>/dev/null || true; tc qdisc show dev lo ;;
  status) tc -s qdisc show dev lo; tc filter show dev lo ;;
  *) echo "usage: $0 on <L1|L2|L3|L4|N100> <port> | off | status"; exit 1 ;;
esac
