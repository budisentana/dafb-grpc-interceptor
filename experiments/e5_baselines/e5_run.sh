#!/usr/bin/env bash
# E5: 5 runs for one transport on one link, then the analysis (over all E5 data so far).
# Run from the repo root, venv active, CPU frequency fixed (experiments/common/cpu_setup.sh):
#   bash experiments/e5_baselines/e5_run.sh plaintext [loopback]
#   bash experiments/e5_baselines/e5_run.sh tls [loopback]
# netem (optional): sudo bash experiments/e2_metadata/e2b_netem.sh on 100mbit 50100, then link netem100.
set -euo pipefail
transport="${1:?usage: e5_run.sh plaintext|tls [loopback|netem100]}"; link="${2:-loopback}"
E=experiments/e5_baselines; R=$E/results
mkdir -p "$R"
if [ "$link" = netem100 ]; then
  { echo "E5 network condition ($transport)"; date -Is; tc qdisc show dev lo; tc filter show dev lo; } >> "$R/e5_netem_setup.txt"
fi
for i in 1 2 3 4 5; do
  echo "== $transport/$link run $i"; [ "$i" -gt 1 ] && sleep 60
  python "$E/e5_benchmark.py" --transport "$transport" --link "$link" 2>&1 | tail -3
done
if [ "$link" = netem100 ]; then
  { echo "--- counters after 5 runs"; tc -s qdisc show dev lo; } >> "$R/e5_netem_setup.txt"
fi
python "$E/e5_analyze.py" > /dev/null && echo "Analysis written to $R/e5_report.txt"
