"""
DAFB E3: analysis of e3_latency.csv.

Per scenario/mode, pooled over runs:
  median, p95, p99 end-to-end latency; median client signing time and server
  verification time; mean of run medians with 95% CI (t distribution);
  extra latency vs `none` and vs the same scheme's `send_only`.
Also checks run-to-run spread and failed calls.

Usage:
  python experiments/e3_combined/e3_analyze.py [path/to/e3_latency.csv]
Writes results/e3_latency_summary.csv and results/e3_report.txt.
"""

import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

E3_DIR = Path(__file__).resolve().parent
RESULTS_DIR = E3_DIR / "results"
DEFAULT_INPUT = RESULTS_DIR / "e3_latency.csv"
SUMMARY_FILE = RESULTS_DIR / "e3_latency_summary.csv"
REPORT_FILE = RESULTS_DIR / "e3_report.txt"

SCHEMES = ["none", "ES256", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
MODES = ["none", "send_only", "verify", "sign_verify"]
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}


def pct(sorted_values, p):
    if not sorted_values:
        return float("nan")
    k = (len(sorted_values) - 1) * p
    lo, hi = math.floor(k), math.ceil(k)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def ci95(values):
    if len(values) < 2:
        return float("nan"), float("nan")
    m = statistics.mean(values)
    h = T95.get(len(values) - 1, 1.96) * statistics.stdev(values) / math.sqrt(len(values))
    return m - h, m + h


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))

    ok = defaultdict(list)                      # (scheme, mode) -> rows
    per_run = defaultdict(lambda: defaultdict(list))
    failed = defaultdict(int)
    runs = []
    for r in rows:
        key = (r["scenario"], r["mode"])
        if r["run_id"] not in runs:
            runs.append(r["run_id"])
        if r["status"] != "success":
            failed[key] += 1
            continue
        ok[key].append(r)
        per_run[key][r["run_id"]].append(int(r["latency_ns"]) / 1000)

    summary = []
    for scheme in SCHEMES:
        for mode in MODES:
            key = (scheme, mode)
            if key not in ok and key not in failed:
                continue
            lat = sorted(int(r["latency_ns"]) / 1000 for r in ok[key])
            sign = sorted(int(r["sign_ns"]) / 1000 for r in ok[key])
            ver = sorted(int(r["verify_ns"]) / 1000 for r in ok[key])
            run_medians = [statistics.median(v) for v in per_run[key].values()]
            lo, hi = ci95(run_medians)
            summary.append(dict(
                scenario=scheme, mode=mode, runs=len(run_medians), calls=len(lat), failed=failed[key],
                header_value_bytes=ok[key][0]["header_value_bytes"] if ok[key] else "",
                signature_bytes=ok[key][0]["signature_bytes"] if ok[key] else "",
                median_us=round(pct(lat, 0.5), 1), p95_us=round(pct(lat, 0.95), 1), p99_us=round(pct(lat, 0.99), 1),
                sign_median_us=round(pct(sign, 0.5), 1), verify_median_us=round(pct(ver, 0.5), 1),
                run_median_mean_us=round(statistics.mean(run_medians), 1) if run_medians else "",
                ci95_low_us=round(lo, 1), ci95_high_us=round(hi, 1),
                run_medians_us=" ".join(f"{m:.1f}" for m in run_medians),
            ))

    by_key = {(s["scenario"], s["mode"]): s for s in summary}
    base = by_key.get(("none", "none"), {}).get("median_us")
    for s in summary:
        s["extra_vs_none_us"] = round(s["median_us"] - base, 1) if base else ""
        so = by_key.get((s["scenario"], "send_only"), {}).get("median_us")
        s["extra_vs_send_only_us"] = round(s["median_us"] - so, 1) if so and s["mode"] != "send_only" else ""

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with SUMMARY_FILE.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0]))
        w.writeheader()
        w.writerows(summary)

    lines = [f"E3 results, {len(runs)} run(s), input: {path}", "",
             "Latency per call (microseconds, pooled over runs)",
             f"{'Scheme':<10} {'Mode':<11} {'Sig B':>6} {'Median':>8} {'p95':>8} {'p99':>8} "
             f"{'Sign':>7} {'Verify':>7} {'+none':>7} {'+send':>7}  Run-median mean [95% CI]"]
    for s in summary:
        lines.append(f"{s['scenario']:<10} {s['mode']:<11} {s['signature_bytes'] or 0:>6} {s['median_us']:>8.1f} "
                     f"{s['p95_us']:>8.1f} {s['p99_us']:>8.1f} {s['sign_median_us']:>7.1f} {s['verify_median_us']:>7.1f} "
                     f"{s['extra_vs_none_us'] if s['extra_vs_none_us'] != '' else '-':>7} "
                     f"{s['extra_vs_send_only_us'] if s['extra_vs_send_only_us'] != '' else '-':>7}  "
                     f"{s['run_median_mean_us']} [{s['ci95_low_us']}, {s['ci95_high_us']}]")

    lines += ["", "Run check (run median more than 10% from the median of run medians)"]
    warnings = 0
    for s in summary:
        meds = [float(x) for x in s["run_medians_us"].split()]
        if len(meds) < 2:
            continue
        mid = statistics.median(meds)
        for i, m in enumerate(meds, 1):
            if abs(m - mid) / mid > 0.10:
                warnings += 1
                lines.append(f"  {s['scenario']}/{s['mode']}: run {i} median {m:.1f} us ({(m - mid) / mid:+.0%})")
    if warnings == 0:
        lines.append("  none")
    lines += ["", f"Measured calls: {sum(s['calls'] for s in summary)}, failed: {sum(failed.values())}"]

    text = "\n".join(lines)
    REPORT_FILE.write_text(text + "\n")
    print(text)
    print(f"\nWritten: {SUMMARY_FILE}\n         {REPORT_FILE}")


if __name__ == "__main__":
    main()
