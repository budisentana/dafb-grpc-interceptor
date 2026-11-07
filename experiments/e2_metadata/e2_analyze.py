"""
DAFB E2: summarize the byte and latency results.

Bytes:   per scenario, HEADERS bytes on the first call of a fresh connection
         and on later calls (median of calls 2-10), checked across runs.
Latency: median, mean, p95, p99, mean of run means with 95% CI, and the
         sequential call rate (1 / mean latency).

Usage (from the project folder):
  python experiments/e2_metadata/e2_analyze.py

Writes e2_bytes_summary.csv, e2_latency_summary.csv and e2_report.txt
in experiments/e2_metadata/results/.
"""

import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"
T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}
PART_A = ["none", "ES256", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
HPACK_TABLE = 4096


def percentile(v, q):
    k = (len(v) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        for r in rows:
            w.writerow({k: round(x, 1) if isinstance(x, float) else x for k, x in r.items()})


def main():
    # ---------------- bytes
    calls = defaultdict(lambda: defaultdict(dict))     # scenario -> run -> call -> header bytes
    meta = {}
    byte_fail = 0
    with (RESULTS / "e2_bytes.csv").open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            calls[r["scenario"]][r["run_id"]][int(r["call"])] = int(r["header_bytes"])
            meta[r["scenario"]] = (r["part"], int(r["header_value_bytes"]), int(r["hpack_entry_bytes"]))
            byte_fail += r["status"] != "success"

    byte_rows = {}
    for sc, runs in calls.items():
        first = [c[1] for c in runs.values()]
        later = [statistics.median([c[i] for i in c if i > 1]) for c in runs.values()]
        part, value, entry = meta[sc]
        byte_rows[sc] = dict(part=part, scenario=sc, header_value_bytes=value, hpack_entry_bytes=entry,
                             fits_table="yes" if 0 < entry <= HPACK_TABLE else ("-" if entry == 0 else "no"),
                             first_call_bytes=statistics.median(first), later_call_bytes=statistics.median(later),
                             first_min=min(first), first_max=max(first),
                             later_min=min(later), later_max=max(later), runs=len(runs))
    base_later = byte_rows.get("none", {}).get("later_call_bytes", 0)
    for r in byte_rows.values():
        r["overhead_vs_none_bytes"] = r["later_call_bytes"] - base_later

    # ---------------- latency
    lat = defaultdict(list)
    per_run = defaultdict(lambda: defaultdict(list))
    lat_fail = defaultdict(int)
    with (RESULTS / "e2_latency.csv").open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["status"] != "success":
                lat_fail[r["scenario"]] += 1
                continue
            us = int(r["latency_ns"]) / 1000
            lat[r["scenario"]].append(us)
            per_run[r["scenario"]][r["run_id"]].append(us)

    lat_rows = {}
    for sc, v in lat.items():
        v.sort()
        means = [statistics.fmean(x) for x in per_run[sc].values()]
        m = statistics.fmean(means)
        half = T975.get(len(means) - 1, 1.96) * statistics.stdev(means) / math.sqrt(len(means)) if len(means) > 1 else float("nan")
        lat_rows[sc] = dict(scenario=sc, n=len(v), failed=lat_fail[sc], median_us=statistics.median(v),
                            mean_us=statistics.fmean(v), p95_us=percentile(v, 0.95), p99_us=percentile(v, 0.99),
                            mean_of_run_means_us=m, ci95_low_us=m - half, ci95_high_us=m + half,
                            calls_per_s=1e6 / statistics.fmean(v))

    def order(sc):
        return (0, PART_A.index(sc)) if sc in PART_A else (1, byte_rows[sc]["header_value_bytes"])

    scs = sorted(byte_rows, key=order)
    write_csv(RESULTS / "e2_bytes_summary.csv", [byte_rows[s] for s in scs])
    write_csv(RESULTS / "e2_latency_summary.csv", [lat_rows[s] for s in scs if s in lat_rows])

    out = []
    runs = max(r["runs"] for r in byte_rows.values())
    out.append(f"E2 results, {runs} run(s)")
    out.append("")
    out.append("Part A: bearer tokens in the authorization header (bytes per call, HEADERS frames)")
    out.append(f"{'Scenario':<10}{'Value':>7}{'Entry':>7}{'Fits':>6}{'Call 1':>8}{'Later':>7}{'Extra':>7}"
               f"{'Median us':>11}{'p99 us':>9}{'Calls/s':>9}")
    for s in scs:
        b = byte_rows[s]
        if b["part"] != "A":
            continue
        l = lat_rows.get(s, {})
        out.append(f"{s:<10}{b['header_value_bytes']:>7}{b['hpack_entry_bytes']:>7}{b['fits_table']:>6}"
                   f"{b['first_call_bytes']:>8.0f}{b['later_call_bytes']:>7.0f}{b['overhead_vs_none_bytes']:>7.0f}"
                   f"{l.get('median_us', float('nan')):>11.1f}{l.get('p99_us', float('nan')):>9.1f}{l.get('calls_per_s', float('nan')):>9.0f}")
    out.append("")
    out.append("Part B: synthetic token sweep")
    out.append(f"{'Value':>7}{'Entry':>7}{'Fits':>6}{'Call 1':>8}{'Later':>7}{'Median us':>11}")
    for s in scs:
        b = byte_rows[s]
        if b["part"] != "B":
            continue
        l = lat_rows.get(s, {})
        out.append(f"{b['header_value_bytes']:>7}{b['hpack_entry_bytes']:>7}{b['fits_table']:>6}"
                   f"{b['first_call_bytes']:>8.0f}{b['later_call_bytes']:>7.0f}{l.get('median_us', float('nan')):>11.1f}")
    out.append("")
    unstable = [s for s, b in byte_rows.items() if b["first_min"] != b["first_max"] or b["later_min"] != b["later_max"]]
    out.append("Byte check across runs: " + ("identical in every run" if not unstable else "differs for " + ", ".join(unstable)))
    out.append(f"Failed calls: bytes pass {byte_fail}, latency pass {sum(lat_fail.values())}")

    (RESULTS / "e2_report.txt").write_text("\n".join(out) + "\n", encoding="utf-8")
    print("\n".join(out))
    print(f"\nWritten: {RESULTS / 'e2_bytes_summary.csv'}, {RESULTS / 'e2_latency_summary.csv'}, {RESULTS / 'e2_report.txt'}")


if __name__ == "__main__":
    main()
