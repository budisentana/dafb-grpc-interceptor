#!/usr/bin/env bash
# DAFB: fix the CPU frequency for benchmarking, or restore the defaults.
#   sudo bash experiments/scripts/cpu_setup.sh          -> governor=performance, turbo off
#   sudo bash experiments/scripts/cpu_setup.sh restore  -> governor=powersave, turbo on
set -euo pipefail
mode="${1:-fix}"
if [[ $EUID -ne 0 ]]; then echo "Run with sudo."; exit 1; fi

if [[ "$mode" == "restore" ]]; then gov=powersave; no_turbo=0; else gov=performance; no_turbo=1; fi

for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo "$gov" > "$f"; done
if [[ -w /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
  echo "$no_turbo" > /sys/devices/system/cpu/intel_pstate/no_turbo
fi

echo "governor: $(sort -u /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | tr '\n' ' ')"
echo "no_turbo: $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo 'not available')"