"""
DAFB E6 (paper E4): analysis.

Per link / scheme / arm (pooled over runs): median, p95, p99 latency, runs, calls,
TCP retransmits and netem drops during the measured calls, registration (first
DAFB call) median. Paired-run comparison of dafb_reference vs e3_verify (none)
and vs token_cache: per run, % change of the run median (and of the run p99),
and absolute difference of run medians in us; mean ± 95% t-interval (df = runs-1).

Crossover check on L1 (R = 1 Gbit/s): predicted cache - DAFB difference
    dt = 8 * dB / R - delta
with dB = HEADERS bytes per later call, cache - DAFB (E6 byte pass, client->server),
delta = DAFB - cache median on loopback from E5 (plaintext, loopback), next to the
measured cache - DAFB difference of medians (paired mean ± CI).

Usage: python experiments/e6_network/e6_analyze.py [results_dir]
Writes e6_summary.csv and e6_report.txt.
"""

import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
import bench_common as bc  # noqa: E402

E6_DIR = Path(__file__).resolve().parent
RESULTS_DIR = E6_DIR / "results"
E5_SUMMARY = E6_DIR.parent / "e5_baselines" / "results" / "e5_latency_summary.csv"
LINKS = ["loopback", "L1", "L2", "L3", "L4"]
LINK_TEXT = {"loopback": "loopback (no netem)", "L1": "1 Gbit/s, no delay", "L2": "100 Mbit/s, 5 ms one-way",
             "L3": "100 Mbit/s, 5 ms one-way, 0.5% loss", "L4": "20 Mbit/s, 20 ms one-way"}
RATE_BPS = {"L1": 1e9, "L2": 1e8, "L3": 1e8, "L4": 2e7}
SCHEMES = ["ES256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
ARMS = ["e3_verify", "token_cache", "dafb_reference"]


def load(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def e5_delta():
    """delta = DAFB reference - token cache median on plaintext loopback (E5), per scheme."""
    try:
        rows = load(E5_SUMMARY)
    except OSError:
        return {}
    med = {(r["scenario"], r["arm"]): float(r["median_us"]) for r in rows
           if r["transport"] == "plaintext" and r["link"] == "loopback"}
    return {s: med[(s, "dafb_reference")] - med[(s, "token_cache")] for s in SCHEMES
            if (s, "dafb_reference") in med and (s, "token_cache") in med}


def main():
    rdir = Path(sys.argv[1]) if len(sys.argv) > 1 else RESULTS_DIR
    lat_rows, byte_rows, scen_rows = (load(rdir / f) for f in ("e6_latency.csv", "e6_bytes.csv", "e6_scenarios.csv"))

    calls = defaultdict(list)
    per_run = defaultdict(lambda: defaultdict(list))
    failed = defaultdict(int)
    for r in lat_rows:
        key = (r["link"], r["scenario"], r["arm"])
        if r["status"] != "success":
            failed[key] += 1
            continue
        us = int(r["latency_ns"]) / 1000
        calls[key].append(us)
        per_run[key][r["run_id"]].append(us)
    run_med = {k: {run: statistics.median(v) for run, v in d.items()} for k, d in per_run.items()}
    run_p99 = {k: {run: bc.pct(sorted(v), .99) for run, v in d.items()} for k, d in per_run.items()}

    scen = defaultdict(lambda: defaultdict(list))
    for r in scen_rows:
        key = (r["link"], r["scenario"], r["arm"])
        for f in ("tcp_retrans_segs", "netem_dropped", "netem_sent_pkts", "measured", "warmup"):
            scen[key][f].append(int(r[f]))
        scen[key]["first_us"].append(int(r["first_call_latency_ns"]) / 1000)
    hb = defaultdict(list)
    for r in byte_rows:
        if r["call"] != "1":
            hb[(r["link"], r["scenario"], r["arm"])].append(int(r["c2s_header_bytes"]))

    links = [l for l in LINKS if any(k[0] == l for k in calls)]
    summary = []
    for link in links:
        for s in SCHEMES:
            for arm in ARMS:
                key = (link, s, arm)
                if key not in calls:
                    continue
                v = sorted(calls[key])
                sc = scen[key]
                row = dict(link=link, scenario=s, arm=arm, runs=len(run_med[key]), calls=len(v), failed=failed[key],
                           warmup=sc["warmup"][0], measured=sc["measured"][0],
                           median_us=round(bc.pct(v, .5), 1), p95_us=round(bc.pct(v, .95), 1),
                           p99_us=round(bc.pct(v, .99), 1),
                           run_medians_us=" ".join(f"{m:.1f}" for m in run_med[key].values()),
                           headers_c2s_later_B=statistics.median(hb[key]) if hb[key] else "",
                           tcp_retrans_segs=sum(sc["tcp_retrans_segs"]), netem_dropped=sum(sc["netem_dropped"]),
                           netem_sent_pkts=sum(sc["netem_sent_pkts"]),
                           first_call_median_us=round(statistics.median(sc["first_us"]), 1))
                if arm == "dafb_reference":
                    for other, tag in (("e3_verify", "none"), ("token_cache", "cache")):
                        o = (link, s, other)
                        if o not in run_med:
                            continue
                        m, h, n = bc.paired(run_med[key], run_med[o])
                        row[f"vs_{tag}_median_pct"], row[f"vs_{tag}_median_pct_ci"] = round(m, 2), round(h, 2)
                        m, h, n = bc.paired(run_med[key], run_med[o], relative=False)
                        row[f"vs_{tag}_median_us"], row[f"vs_{tag}_median_us_ci"] = round(m, 1), round(h, 1)
                        m, h, n = bc.paired(run_p99[key], run_p99[o])
                        row[f"vs_{tag}_p99_pct"], row[f"vs_{tag}_p99_pct_ci"] = round(m, 2), round(h, 2)
                summary.append(row)

    with (rdir / "e6_summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in summary for k in r)))
        w.writeheader()
        w.writerows(summary)

    by = {(r["link"], r["scenario"], r["arm"]): r for r in summary}
    L = ["E6 (paper E4): realistic links and the crossover", f"input: {rdir}",
         "Paired-run comparisons: per run, (DAFB - baseline) / baseline of the run medians (or run p99);",
         "mean ± 95% t-interval over runs (df = runs - 1). Negative = DAFB faster."]
    for link in links:
        any_row = next(r for r in summary if r["link"] == link)
        L += ["", "=" * 108,
              f"Link {link}: {LINK_TEXT[link]}; {any_row['runs']} run(s), {any_row['warmup']} warm-up + "
              f"{any_row['measured']} measured calls per scenario", "=" * 108,
              f"{'Scheme':<10} {'Arm':<15} {'Median':>9} {'p95':>9} {'p99':>9} {'HEADERS':>8} {'retrans':>8} "
              f"{'drops':>6} {'1st call':>9}"]
        for s in SCHEMES:
            for arm in ARMS:
                r = by.get((link, s, arm))
                if r:
                    first = f"{r['first_call_median_us']:.1f}" if arm == "dafb_reference" else ""
                    L.append(f"{s:<10} {arm:<15} {r['median_us']:>9.1f} {r['p95_us']:>9.1f} {r['p99_us']:>9.1f} "
                             f"{r['headers_c2s_later_B']:>8} {r['tcp_retrans_segs']:>8} {r['netem_dropped']:>6} "
                             f"{first:>9}")
        L += ["", "DAFB reference vs baselines (paired over runs)",
              f"{'Scheme':<10} {'vs none: median %':>20} {'median us':>17} {'p99 %':>16}   "
              f"{'vs cache: median %':>19} {'median us':>17} {'p99 %':>16}"]
        for s in SCHEMES:
            r = by.get((link, s, "dafb_reference"))
            if not r or "vs_none_median_pct" not in r:
                continue
            cells = []
            for tag in ("none", "cache"):
                cells += [bc.fmt_ci(r.get(f"vs_{tag}_median_pct", float("nan")), r.get(f"vs_{tag}_median_pct_ci", 0), 1, "%"),
                          bc.fmt_ci(r.get(f"vs_{tag}_median_us", float("nan")), r.get(f"vs_{tag}_median_us_ci", 0), 1),
                          bc.fmt_ci(r.get(f"vs_{tag}_p99_pct", float("nan")), r.get(f"vs_{tag}_p99_pct_ci", 0), 1, "%")]
            L.append(f"{s:<10} {cells[0]:>20} {cells[1]:>17} {cells[2]:>16}   {cells[3]:>19} {cells[4]:>17} {cells[5]:>16}")

    if "L1" in links:
        delta = e5_delta()
        L += ["", "Crossover check on L1: dt = 8*dB/R - delta (cache - DAFB; positive = DAFB faster)",
              f"  R = 1 Gbit/s; dB = HEADERS cache - DAFB (E6 byte pass); delta = DAFB - cache on loopback (E5, {E5_SUMMARY.name})",
              f"{'Scheme':<10} {'dB (B)':>7} {'8dB/R (us)':>11} {'delta (us)':>11} {'predicted':>10} {'measured (paired)':>20}"]
        for s in SCHEMES:
            d, c = by.get(("L1", s, "dafb_reference")), by.get(("L1", s, "token_cache"))
            if not d or not c or s not in delta:
                continue
            dB = c["headers_c2s_later_B"] - d["headers_c2s_later_B"]
            ser = 8 * dB / RATE_BPS["L1"] * 1e6
            pred = ser - delta[s]
            m, h = -d["vs_cache_median_us"], d["vs_cache_median_us_ci"]
            L.append(f"{s:<10} {dB:>7g} {ser:>11.1f} {delta[s]:>11.1f} {pred:>10.1f} {bc.fmt_ci(m, h, 1):>20}")
        L.append("  Serialization only counts client->server HEADERS bytes at the link rate (no TCP/IP framing).")

    total_failed = sum(failed.values())
    L += ["", f"Measured calls: {len(lat_rows)}, failed: {total_failed}"]
    text = "\n".join(L)
    (rdir / "e6_report.txt").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
