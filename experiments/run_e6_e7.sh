#!/usr/bin/env bash
# E6 + E7, all steps that need root in one script. Run from your own account:
#   sudo bash experiments/run_e6_e7.sh            # E6 and E7 (about 2.5 hours)
#   sudo bash experiments/run_e6_e7.sh e6         # only E6 (about 45 minutes)
#   sudo bash experiments/run_e6_e7.sh e7         # only E7 (about 1.7 hours)
# Root is used only for the CPU governor and tc/netem; every benchmark runs as $SUDO_USER, so all
# result files belong to you. Runs are interleaved: run 1 over all links (shuffled), then run 2, ...
# netem is removed on exit (also on error or Ctrl-C). The CPU stays fixed afterwards; restore with
#   sudo bash experiments/common/cpu_setup.sh restore
# Progress: experiments/run_e6_e7.log
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo bash $0 ${1:-}"; exit 1; }
U="${SUDO_USER:?run with sudo from your own account}"
what="${1:-all}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
as_user() { sudo -u "$U" -H "$@"; }
COMMON_GIT="$(as_user git -C "$REPO" rev-parse --path-format=absolute --git-common-dir)"
PY="${PY:-$(dirname "$COMMON_GIT")/venv/bin/python}"
[[ -x "$PY" ]] || { echo "python not found: $PY (set PY=/path/to/venv/bin/python)"; exit 1; }

LOG="$REPO/experiments/run_e6_e7.log"
as_user touch "$LOG"
exec > >(as_user tee -a "$LOG") 2>&1
NETEM="bash $REPO/experiments/common/netem_profile.sh"
E6R=experiments/e6_network/results
E7R=experiments/e7_load/results
as_user mkdir -p "$E6R" "$E7R"
trap '$NETEM off >/dev/null 2>&1 || true; echo "netem removed"' EXIT
log_tc() { { echo "== $1 $(date -Is)"; tc -s qdisc show dev lo; tc filter show dev lo; } | as_user tee -a "$2" >/dev/null; }

echo "=== DAFB E6/E7 start $(date -Is), repo $REPO, python $PY, what=$what"
bash experiments/common/cpu_setup.sh
$NETEM off >/dev/null

if [[ "$what" == all || "$what" == e6 ]]; then
  for run in 1 2 3 4 5; do
    for p in $(printf "L1\nL2\nL3\nL4\n" | shuf); do
      echo "--- E6 run $run, link $p, $(date -Is)"
      $NETEM on "$p" 50110 >/dev/null
      log_tc "E6 run $run $p before" "$E6R/e6_netem_setup.txt"
      as_user "$PY" experiments/e6_network/e6_benchmark.py --link "$p" | tail -1
      log_tc "E6 run $run $p after" "$E6R/e6_netem_setup.txt"
      $NETEM off >/dev/null
      sleep 20
    done
  done
  as_user "$PY" experiments/e6_network/e6_analyze.py >/dev/null && echo "E6 analysis: $E6R/e6_report.txt"
fi

if [[ "$what" == all || "$what" == e7 ]]; then
  for run in 1 2 3 4 5; do
    for link in $(printf "loopback\nN100\n" | shuf); do
      echo "--- E7 run $run, link $link, $(date -Is)"
      if [[ "$link" == N100 ]]; then
        $NETEM on N100 50120 >/dev/null
        log_tc "E7 run $run N100 before" "$E7R/e7_netem_setup.txt"
      fi
      as_user "$PY" experiments/e7_load/e7_benchmark.py --link "$link" | tail -1
      if [[ "$link" == N100 ]]; then
        log_tc "E7 run $run N100 after" "$E7R/e7_netem_setup.txt"
        $NETEM off >/dev/null
      fi
      sleep 20
    done
    echo "--- E7 store scaling, run $run"
    as_user "$PY" experiments/e7_load/e7_store_scaling.py | tail -4
  done
  as_user "$PY" experiments/e7_load/e7_analyze.py >/dev/null && echo "E7 analysis: $E7R/e7_report.txt"
fi

echo "=== DAFB E6/E7 ALL DONE $(date -Is) (CPU still fixed; restore: sudo bash experiments/common/cpu_setup.sh restore)"
