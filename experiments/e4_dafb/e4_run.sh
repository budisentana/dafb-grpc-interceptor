#!/usr/bin/env bash
# E4: 5 runs on one link, then the analysis. Run from the repo root, venv active.
#
#   loopback:
#     sudo bash experiments/common/cpu_setup.sh
#     bash experiments/e4_dafb/e4_run.sh loopback
#
#   100 Mbit/s netem link (E2b condition, on the E4 port 50080):
#     sudo bash experiments/e2_metadata/e2b_netem.sh on 100mbit 50080
#     bash experiments/e4_dafb/e4_run.sh netem100
#     sudo bash experiments/e2_metadata/e2b_netem.sh off
#
#     sudo bash experiments/common/cpu_setup.sh restore
#
# e4_benchmark.py refuses to start if the tc state does not match the link.
set -euo pipefail
link="${1:?usage: e4_run.sh loopback|netem100}"
E=experiments/e4_dafb; R=$E/results
mkdir -p "$R"
if [ "$link" = netem100 ]; then
  { echo "E4 network condition"; date -Is; uname -r; tc qdisc show dev lo; tc filter show dev lo; } > "$R/e4_netem_setup.txt"
fi
for i in 1 2 3 4 5; do
  echo "== $link run $i"; [ "$i" -gt 1 ] && sleep 60
  python "$E/e4_benchmark.py" --link "$link" 2>&1 | tail -3
done
if [ "$link" = netem100 ]; then
  { echo "--- counters after 5 runs"; tc -s qdisc show dev lo; } >> "$R/e4_netem_setup.txt"
fi
python "$E/e4_analyze.py" > /dev/null && echo "Analysis written to $R/e4_report.txt"
