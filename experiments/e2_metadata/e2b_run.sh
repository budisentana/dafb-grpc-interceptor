#!/usr/bin/env bash
# E2b: E2 repeated over the netem link. Run from the repo root, venv active:
#   sudo bash experiments/common/cpu_setup.sh
#   sudo bash experiments/e2_metadata/e2b_netem.sh on
#   bash experiments/e2_metadata/e2b_run.sh
#   sudo bash experiments/e2_metadata/e2b_netem.sh off
#   sudo bash experiments/common/cpu_setup.sh restore
# Writes results/e2b_* files only; the E2 (loopback) files are never touched.
set -euo pipefail
E=experiments/e2_metadata; R=$E/results
tc qdisc show dev lo | grep -q netem || { echo "netem rule not active: run e2b_netem.sh on first"; exit 1; }
{ echo "E2b network condition"; date -Is; uname -r; tc qdisc show dev lo; tc filter show dev lo; } > $R/e2b_netem_setup.txt
for i in 1 2 3 4 5; do
  echo "== run $i"; [ $i -gt 1 ] && sleep 60
  python -c "import sys; sys.path.insert(0,'$E'); import e2_benchmark as b; b.BYTES_FILE=b.RESULTS_DIR/'e2b_bytes.csv'; b.LATENCY_FILE=b.RESULTS_DIR/'e2b_latency.csv'; b.ENV_FILE=b.RESULTS_DIR/'e2b_run_environment.csv'; b.main()" 2>&1 | tail -4 | head -2
done
{ echo "--- counters after 5 runs"; tc -s qdisc show dev lo; } >> $R/e2b_netem_setup.txt
# e2_analyze.py has fixed file names, so run it on copies and save the outputs as e2b_*
grep -q "^RESULTS" $E/e2_analyze.py || { echo "RESULTS not top-level in e2_analyze.py, stopping"; exit 1; }
T=$(mktemp -d); cp $R/e2b_bytes.csv $T/e2_bytes.csv; cp $R/e2b_latency.csv $T/e2_latency.csv
python -c "import sys; sys.path.insert(0,'$E'); import e2_analyze as a; from pathlib import Path; a.RESULTS=Path('$T'); a.main()" > /dev/null
for f in bytes_summary.csv latency_summary.csv report.txt; do cp $T/e2_$f $R/e2b_$f; done
python $E/e2b_compare.py
