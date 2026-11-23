"""
DAFB E7 (paper E5): analysis of e7_scenarios.csv and e7_store_scaling.csv.

Per link / scheme / concurrency / arm, over runs (mean ± 95% t-interval, df = runs-1):
throughput (calls/s), p50 and p99 latency (per-run values from that run's calls), server CPU
per call, server and client CPUs used, handle-store / cache entries and size, server RSS.
Paired-run comparison of dafb_reference vs e3_verify (none) and vs token_cache: per run,
% change of throughput and of p99; mean ± 95% t-interval.
Store scaling: bytes per entry and lookup median per store and size, mean over runs.

Usage: python experiments/e7_load/e7_analyze.py [results_dir]
Writes e7_summary.csv and e7_report.txt.
"""

import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
import bench_common as bc  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"
LINKS = ["loopback", "N100"]
ARMS = ["e3_verify", "token_cache", "dafb_reference"]
METRICS = ["throughput_cps", "p50_us", "p99_us", "cpu_us_per_call", "server_cpu_util", "client_cpu_util",
           "server_rss_kb"]


def load(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def main():
    rdir = Path(sys.argv[1]) if len(sys.argv) > 1 else RESULTS_DIR
    rows = load(rdir / "e7_scenarios.csv")
    by = defaultdict(dict)                     # (link, scheme, conc, arm) -> run -> row
    for r in rows:
        by[(r["link"], r["scenario"], int(r["concurrency"]), r["arm"])][r["run_id"]] = r

    keys = sorted(by, key=lambda k: (LINKS.index(k[0]), k[1] != "ML-DSA-65", k[1], k[2], ARMS.index(k[3])))
    summary = []
    for key in keys:
        runs = by[key]
        link, scheme, conc, arm = key
        row = dict(link=link, scenario=scheme, concurrency=conc, arm=arm, runs=len(runs),
                   failed=sum(int(r["failed"]) for r in runs.values()))
        for m in METRICS:
            vals = [float(r[m]) for r in runs.values() if r[m] != ""]
            mean, h, _ = bc.mean_ci(vals)
            row[m], row[m + "_ci"] = round(mean, 1), round(h, 1)
        for m in ("handles", "cache_entries", "handle_store_bytes", "cache_store_bytes", "tcp_retrans_segs",
                  "netem_dropped", "handles_rejected"):
            vals = [int(r[m]) for r in runs.values() if r.get(m, "") != ""]
            row[m] = max(vals) if vals and m not in ("tcp_retrans_segs", "netem_dropped") else sum(vals)
        if arm == "dafb_reference":
            for other, tag in (("e3_verify", "none"), ("token_cache", "cache")):
                o = by.get((link, scheme, conc, other))
                if not o:
                    continue
                for m in ("throughput_cps", "p99_us"):
                    mine = {run: float(r[m]) for run, r in runs.items()}
                    theirs = {run: float(r[m]) for run, r in o.items()}
                    mean, h, _ = bc.paired(mine, theirs)
                    row[f"vs_{tag}_{m}_pct"], row[f"vs_{tag}_{m}_pct_ci"] = round(mean, 2), round(h, 2)
        summary.append(row)

    with (rdir / "e7_summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in summary for k in r)))
        w.writeheader()
        w.writerows(summary)

    s_rows = []
    try:
        s_rows = load(rdir / "e7_store_scaling.csv")
    except OSError:
        pass

    L = ["E7 (paper E5): concurrent load and the handle store", f"input: {rdir}",
         "Server: cores 2-3 (one physical core, 2 threads), 16 workers; clients: cores 0-1, closed loop,",
         "one TCP connection and one distinct token per client channel. Values: mean over runs ± 95% t-CI.",
         "Paired: per run, (DAFB - baseline) / baseline; mean ± 95% t-CI. CPUs = CPU-seconds per second."]
    for link in LINKS:
        rows_l = [r for r in summary if r["link"] == link]
        if not rows_l:
            continue
        L += ["", "=" * 118, f"Link: {link}{' (100 Mbit/s netem, no delay)' if link == 'N100' else ''}, "
              f"{rows_l[0]['runs']} run(s)", "=" * 118,
              f"{'Scheme':<9} {'C':>3} {'Arm':<15} {'calls/s':>16} {'p50 us':>16} {'p99 us':>17} "
              f"{'CPU us/call':>12} {'srv CPUs':>8} {'cli CPUs':>8} {'entries':>7} {'store B':>8} {'RSS MB':>7}"]
        for r in rows_l:
            entries = r["handles"] if r["arm"] == "dafb_reference" else r["cache_entries"]
            store = r["handle_store_bytes"] if r["arm"] == "dafb_reference" else r["cache_store_bytes"]
            L.append(f"{r['scenario']:<9} {r['concurrency']:>3} {r['arm']:<15} "
                     f"{r['throughput_cps']:>8.1f} ±{r['throughput_cps_ci']:>6.1f} {r['p50_us']:>8.1f} ±{r['p50_us_ci']:>6.1f} "
                     f"{r['p99_us']:>9.1f} ±{r['p99_us_ci']:>6.1f} {r['cpu_us_per_call']:>12.1f} "
                     f"{r['server_cpu_util']:>8.2f} {r['client_cpu_util']:>8.2f} {entries:>7} {store:>8} "
                     f"{r['server_rss_kb'] / 1024:>7.1f}")
        L += ["", "DAFB reference vs baselines (paired over runs; positive throughput / negative p99 = DAFB better)",
              f"{'Scheme':<9} {'C':>3} {'vs none: calls/s':>18} {'p99':>16}   {'vs cache: calls/s':>18} {'p99':>16}"]
        for r in rows_l:
            if r["arm"] != "dafb_reference" or "vs_none_throughput_cps_pct" not in r:
                continue
            c = [bc.fmt_ci(r.get(f"vs_{t}_{m}_pct", float("nan")), r.get(f"vs_{t}_{m}_pct_ci", 0), 1, "%")
                 for t in ("none", "cache") for m in ("throughput_cps", "p99_us")]
            L.append(f"{r['scenario']:<9} {r['concurrency']:>3} {c[0]:>18} {c[1]:>16}   {c[2]:>18} {c[3]:>16}")
        retr = sum(r["tcp_retrans_segs"] for r in rows_l)
        drops = sum(r["netem_dropped"] for r in rows_l)
        rej = sum(int(r["handles_rejected"] or 0) for r in rows_l)
        L.append(f"TCP retransmits during windows: {retr}; netem drops: {drops}; rejected handles: {rej}; "
                 f"failed calls: {sum(r['failed'] for r in rows_l)}")

    if s_rows:
        agg = defaultdict(lambda: defaultdict(list))
        for r in s_rows:
            k = (r["store"], int(r["entries"]))
            for m in ("bytes_per_entry", "lookup_median_ns", "lookup_p99_ns", "timer_overhead_ns"):
                agg[k][m].append(float(r[m]))
        n_runs = len({r["run_id"] for r in s_rows})
        L += ["", "=" * 118, f"Handle-store scaling (in-process, {n_runs} run(s); mean ± 95% t-CI over runs)", "=" * 118,
              f"{'Store':<13} {'entries':>8} {'bytes/entry':>18} {'lookup median ns':>20} {'lookup p99 ns':>16} {'timer ns':>9}"]
        for (store, n) in sorted(agg, key=lambda k: (k[1], k[0])):
            a = agg[(store, n)]
            b, bh, _ = bc.mean_ci(a["bytes_per_entry"])
            lm, lh, _ = bc.mean_ci(a["lookup_median_ns"])
            L.append(f"{store:<13} {n:>8} {b:>10.1f} ± {bh:>5.1f} {lm:>12.0f} ± {lh:>5.0f} "
                     f"{statistics.mean(a['lookup_p99_ns']):>16.0f} {statistics.mean(a['timer_overhead_ns']):>9.0f}")
        L += ["  token_cache lookup includes SHA-256 of the 4,730-byte ML-DSA-65 token; dafb_handles lookup is a",
              "  dict lookup by the 41-character handle. Memory is tracemalloc traced bytes / entries (claims dict included)."]

    text = "\n".join(L)
    (rdir / "e7_report.txt").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
