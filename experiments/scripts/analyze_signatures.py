"""
DAFB: summarize E1 / E1b timing data (same statistics as the paper).

For each algorithm and operation: median, mean, p95, p99 over all successful
measurements, and the mean of the per-run means with a 95% confidence interval
(t distribution, runs - 1 degrees of freedom). Flags any run whose mean is more
than 10% away from the median run.

Usage (from the project folder):
  python experiments/scripts/analyze_signatures.py                       # E1b data
  python experiments/scripts/analyze_signatures.py experiments/results/e1_crypto_benchmark.csv

Writes <name>_summary.csv and <name>_report.txt next to the input file.
"""

import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_FILE = PROJECT_DIR / "experiments" / "results" / "e1b_signature_benchmark.csv"

T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}
ALG_ORDER = ["ECDSA-P256", "Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
OPS = [("keygen", "Key generation"), ("sign", "Signing"), ("verify", "Verification")]


def percentile(sorted_values, q):
    """Linear interpolation, same as pandas/numpy default."""
    k = (len(sorted_values) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def main(path):
    values = defaultdict(list)       # (alg, op) -> [us]
    per_run = defaultdict(list)      # (alg, op, run_id) -> [us]
    run_time = {}                    # run_id -> timestamp (for run numbering)
    failed = defaultdict(int)

    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["algorithm"], row["operation"])
            run_time.setdefault(row["run_id"], row["timestamp_utc"])
            if row["status"] != "success":
                failed[key] += 1
                continue
            us = int(row["duration_ns"]) / 1000
            values[key].append(us)
            per_run[key + (row["run_id"],)].append(us)

    run_number = {r: i + 1 for i, r in enumerate(sorted(run_time, key=run_time.get))}
    lines, summary = [], []
    out = lines.append

    algorithms = [a for a in ALG_ORDER if any(k[0] == a for k in values)]
    algorithms += sorted({k[0] for k in values} - set(algorithms))

    out(f"Input: {path}")
    out(f"Runs: {len(run_number)}")
    warnings = []
    stats = {}
    for alg in algorithms:
        for op, _ in OPS:
            v = sorted(values.get((alg, op), []))
            if not v:
                continue
            runs = sorted((k[2] for k in per_run if k[:2] == (alg, op)), key=run_number.get)
            means = [statistics.fmean(per_run[(alg, op, r)]) for r in runs]
            m = statistics.fmean(means)
            half = (T975.get(len(means) - 1, 1.96) * statistics.stdev(means) / math.sqrt(len(means))
                    if len(means) > 1 else float("nan"))
            mid = statistics.median(means)
            for r, x in zip(runs, means):
                if abs(x / mid - 1) > 0.10:
                    warnings.append(f"{alg} {op}: run {run_number[r]} mean {x:.1f} us "
                                    f"({100 * (x / mid - 1):+.0f}% vs median run)")
            s = dict(algorithm=alg, operation=op, n=len(v), failed=failed[(alg, op)],
                     median_us=statistics.median(v), mean_us=statistics.fmean(v),
                     p95_us=percentile(v, 0.95), p99_us=percentile(v, 0.99),
                     mean_of_run_means_us=m, ci95_low_us=m - half, ci95_high_us=m + half,
                     run_means_us=" ".join(f"{x:.1f}" for x in means))
            stats[(alg, op)] = s
            summary.append(s)

    for alg in algorithms:
        if not any((alg, op) in stats for op, _ in OPS):
            continue
        out("")
        out(f"{alg} (microseconds)")
        out(f"{'Operation':<16}{'Median':>9}{'Mean':>9}{'p95':>9}{'p99':>9}   Mean of run means (95% CI)")
        for op, name in OPS:
            s = stats.get((alg, op))
            if s:
                out(f"{name:<16}{s['median_us']:>9.1f}{s['mean_us']:>9.1f}{s['p95_us']:>9.1f}{s['p99_us']:>9.1f}"
                    f"   {s['mean_of_run_means_us']:.1f} [{s['ci95_low_us']:.1f}, {s['ci95_high_us']:.1f}]")

    if len(algorithms) > 1:
        out("")
        out("Comparison (Table 7 of the paper), microseconds")
        out(f"{'Scheme':<12}{'Keygen med':>12}{'Sign med':>10}{'Verify med':>12}{'Sign p99':>10}")
        for alg in algorithms:
            if (alg, "sign") in stats:
                out(f"{alg:<12}{stats[(alg, 'keygen')]['median_us']:>12.1f}{stats[(alg, 'sign')]['median_us']:>10.1f}"
                    f"{stats[(alg, 'verify')]['median_us']:>12.1f}{stats[(alg, 'sign')]['p99_us']:>10.1f}")

    out("")
    out(f"Measurements: {sum(s['n'] for s in summary)}, failed: {sum(failed.values())}")
    out("Run check: " + ("every run within 10% of the median run" if not warnings else f"{len(warnings)} warning(s)"))
    for w in warnings:
        out("  " + w)

    path = Path(path)
    summary_file = path.with_name(path.stem + "_summary.csv")
    report_file = path.with_name(path.stem + "_report.txt")
    with summary_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary[0]))
        writer.writeheader()
        for s in summary:
            writer.writerow({k: round(v, 1) if isinstance(v, float) else v for k, v in s.items()})
    report_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))
    print(f"\nSummary CSV: {summary_file}")
    print(f"Report text: {report_file}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FILE)