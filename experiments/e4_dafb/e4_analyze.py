"""
DAFB E4: analysis of e4_latency.csv, e4_bytes.csv and e4_scenarios.csv.

Per link / scheme / arm, pooled over runs:
  latency  median, p95, p99, median server verification time, mean of run
           medians with 95% CI (t distribution), difference vs e3_verify
           (same scheme) and vs none
  bytes    HEADERS bytes (E2 relay method, incl. 9-byte frame headers) of the
           first call on a fresh connection and of later calls (calls 2-10),
           client->server and server->client

Break-even, per link / scheme / DAFB policy that registers (reference; adaptive
when the token is over the HPACK budget):

  k* = number of reference calls needed AFTER the registration call so that
       registration + k reference calls cost no more than k+1 calls of the
       no-mitigation baseline (e3_verify):
         R + k*F <= (k+1)*B   ->   k* = max(0, ceil((R - B) / (B - F)))
       R = registration cost (dafb_register arm: every call registers),
       F = steady reference-call cost (the policy's own arm),
       B = baseline call cost (e3_verify). If F >= B there is no break-even.
  Computed for median latency (pooled, plus the range over per-run medians),
  for client->server HEADERS bytes of later calls (warm connection), and for
  HEADERS bytes in both directions (the registration response carries the handle).

Usage:
  python experiments/e4_dafb/e4_analyze.py [results_dir]
Writes e4_latency_summary.csv, e4_bytes_summary.csv, e4_breakeven.csv, e4_report.txt.
"""

import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "results"
SCHEMES = ["none", "ES256", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
ARMS = ["none", "e3_verify", "dafb_inline", "dafb_adaptive", "dafb_reference", "dafb_register"]
LINKS = ["loopback", "netem100"]
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


def breakeven(reg, ref, base):
    """(k*, exact ratio) or (None, None) when the reference path is not cheaper than the baseline."""
    if base - ref <= 0:
        return None, None
    ratio = (reg - base) / (base - ref)
    return max(0, math.ceil(ratio - 1e-9)), ratio


def load(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def fmt(v, nd=1):
    if v is None or v == "":
        return "-"
    return f"{v:.{nd}f}" if isinstance(v, float) else str(v)


def main():
    rdir = Path(sys.argv[1]) if len(sys.argv) > 1 else RESULTS_DIR
    lat_rows = load(rdir / "e4_latency.csv")
    byte_rows = load(rdir / "e4_bytes.csv")
    scen_rows = load(rdir / "e4_scenarios.csv")

    # ---------------- latency ----------------
    ok = defaultdict(list)
    per_run = defaultdict(lambda: defaultdict(list))
    failed = defaultdict(int)
    runs = defaultdict(set)
    for r in lat_rows:
        key = (r["link"], r["scenario"], r["arm"])
        runs[r["link"]].add(r["run_id"])
        if r["status"] != "success":
            failed[key] += 1
            continue
        us = int(r["latency_ns"]) / 1000
        ok[key].append((us, int(r["verify_ns"]) / 1000))
        per_run[key][r["run_id"]].append(us)

    lat_summary = {}
    for link in LINKS:
        for scheme in SCHEMES:
            for arm in ARMS:
                key = (link, scheme, arm)
                if key not in ok and key not in failed:
                    continue
                lat = sorted(v[0] for v in ok[key])
                ver = sorted(v[1] for v in ok[key])
                run_medians = {run: statistics.median(v) for run, v in per_run[key].items()}
                lo, hi = ci95(list(run_medians.values()))
                lat_summary[key] = dict(
                    link=link, scenario=scheme, arm=arm, runs=len(run_medians), calls=len(lat), failed=failed[key],
                    median_us=round(pct(lat, 0.5), 1), p95_us=round(pct(lat, 0.95), 1),
                    p99_us=round(pct(lat, 0.99), 1), verify_median_us=round(pct(ver, 0.5), 1),
                    run_median_mean_us=round(statistics.mean(run_medians.values()), 1) if run_medians else "",
                    ci95_low_us=round(lo, 1), ci95_high_us=round(hi, 1),
                    run_medians_us=" ".join(f"{m:.1f}" for m in run_medians.values()),
                    _run_medians=run_medians)
    for (link, scheme, arm), s in lat_summary.items():
        base = lat_summary.get((link, scheme, "e3_verify"))
        none = lat_summary.get((link, "none", "none"))
        s["vs_e3_verify_us"] = round(s["median_us"] - base["median_us"], 1) if base and arm != "e3_verify" else ""
        s["vs_e3_verify_pct"] = (round(100 * (s["median_us"] - base["median_us"]) / base["median_us"], 1)
                                 if base and arm != "e3_verify" else "")
        s["vs_none_us"] = round(s["median_us"] - none["median_us"], 1) if none else ""

    # ---------------- bytes ----------------
    calls = defaultdict(lambda: defaultdict(list))     # key -> field -> values
    byte_status = defaultdict(int)
    for r in byte_rows:
        key = (r["link"], r["scenario"], r["arm"])
        byte_status[key] += r["status"] != "success"
        phase = "first" if r["call"] == "1" else "later"
        for d in ("c2s", "s2c"):
            calls[key][f"{d}_{phase}"].append(int(r[f"{d}_header_bytes"]))
        calls[key]["modes_" + phase].append(r["dafb_mode"])

    byte_summary = {}
    for link in LINKS:
        for scheme in SCHEMES:
            for arm in ARMS:
                key = (link, scheme, arm)
                if key not in calls:
                    continue
                c = calls[key]
                s = dict(link=link, scenario=scheme, arm=arm, runs=len(c["c2s_first"]), failed=byte_status[key],
                         first_call_mode="/".join(sorted(set(c["modes_first"]))),
                         later_call_mode="/".join(sorted(set(c["modes_later"]))))
                for d in ("c2s", "s2c"):
                    for phase in ("first", "later"):
                        v = c[f"{d}_{phase}"]
                        s[f"{d}_{phase}_median"] = statistics.median(v)
                        s[f"{d}_{phase}_min"] = min(v)
                        s[f"{d}_{phase}_max"] = max(v)
                byte_summary[key] = s
    for (link, scheme, arm), s in byte_summary.items():
        base = byte_summary.get((link, scheme, "e3_verify"))
        s["c2s_later_vs_e3_verify"] = s["c2s_later_median"] - base["c2s_later_median"] if base else ""

    # ---------------- break-even ----------------
    be_rows = []
    for link in LINKS:
        for scheme in SCHEMES[1:]:
            for policy in ("dafb_adaptive", "dafb_reference"):
                pol_l = lat_summary.get((link, scheme, policy))
                reg_l = lat_summary.get((link, scheme, "dafb_register"))
                base_l = lat_summary.get((link, scheme, "e3_verify"))
                pol_b = byte_summary.get((link, scheme, policy))
                reg_b = byte_summary.get((link, scheme, "dafb_register"))
                base_b = byte_summary.get((link, scheme, "e3_verify"))
                if not (pol_l and reg_l and base_l and pol_b and reg_b and base_b):
                    continue
                if "reference" not in pol_b["later_call_mode"]:
                    be_rows.append(dict(link=link, scenario=scheme, policy=policy,
                                        note=f"no registration (policy sends the token {pol_b['later_call_mode']})"))
                    continue
                R, F, B = reg_l["median_us"], pol_l["median_us"], base_l["median_us"]
                k_lat, ratio_lat = breakeven(R, F, B)
                per_run_k = []
                for run, b in base_l["_run_medians"].items():
                    r_, f_ = reg_l["_run_medians"].get(run), pol_l["_run_medians"].get(run)
                    if r_ is not None and f_ is not None:
                        per_run_k.append(breakeven(r_, f_, b)[0])
                k_c2s, ratio_c2s = breakeven(reg_b["c2s_later_median"], pol_b["c2s_later_median"],
                                             base_b["c2s_later_median"])
                both = lambda s: s["c2s_later_median"] + s["s2c_later_median"]
                k_both, ratio_both = breakeven(both(reg_b), both(pol_b), both(base_b))
                be_rows.append(dict(
                    link=link, scenario=scheme, policy=policy,
                    register_us=R, reference_us=F, e3_verify_us=B,
                    k_latency=fmt(k_lat), k_latency_exact=fmt(ratio_lat, 2),
                    k_latency_per_run=" ".join(fmt(k) for k in per_run_k),
                    register_c2s_B=reg_b["c2s_later_median"], reference_c2s_B=pol_b["c2s_later_median"],
                    e3_verify_c2s_B=base_b["c2s_later_median"],
                    k_bytes_c2s=fmt(k_c2s), k_bytes_c2s_exact=fmt(ratio_c2s, 3),
                    register_both_B=both(reg_b), reference_both_B=both(pol_b), e3_verify_both_B=both(base_b),
                    k_bytes_both=fmt(k_both), k_bytes_both_exact=fmt(ratio_both, 3), note=""))

    # ---------------- write ----------------
    lat_out = [{k: v for k, v in s.items() if not k.startswith("_")} for s in lat_summary.values()]
    for name, rows in (("e4_latency_summary.csv", lat_out), ("e4_bytes_summary.csv", list(byte_summary.values())),
                       ("e4_breakeven.csv", be_rows)):
        if not rows:
            continue
        fields = list(dict.fromkeys(k for r in rows for k in r))
        with (rdir / name).open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)

    lines = [f"E4 results (DAFB vs no mitigation), input: {rdir}"]
    for link in LINKS:
        if not runs[link]:
            continue
        lines += ["", "=" * 100, f"Link: {link}, {len(runs[link])} run(s)", "=" * 100, "",
                  "Latency per call (us, pooled over runs); diff vs e3_verify of the same scheme",
                  f"{'Scheme':<10} {'Arm':<15} {'Median':>8} {'p95':>8} {'p99':>8} {'Verify':>7} "
                  f"{'vs e3':>8} {'vs e3 %':>8}  Run-median mean [95% CI]"]
        for (l, scheme, arm), s in lat_summary.items():
            if l != link:
                continue
            lines.append(f"{scheme:<10} {arm:<15} {s['median_us']:>8.1f} {s['p95_us']:>8.1f} {s['p99_us']:>8.1f} "
                         f"{s['verify_median_us']:>7.1f} {fmt(s['vs_e3_verify_us']):>8} {fmt(s['vs_e3_verify_pct']):>8}  "
                         f"{s['run_median_mean_us']} [{s['ci95_low_us']}, {s['ci95_high_us']}]")
        lines += ["", "HEADERS bytes per call (E2 relay method; median over runs, [min-max] for later calls)",
                  f"{'Scheme':<10} {'Arm':<15} {'c2s 1st':>8} {'c2s later':>18} {'vs e3':>7} "
                  f"{'s2c 1st':>8} {'s2c later':>9}  modes (1st / later)"]
        for (l, scheme, arm), s in byte_summary.items():
            if l != link:
                continue
            later = f"{s['c2s_later_median']:g} [{s['c2s_later_min']}-{s['c2s_later_max']}]"
            lines.append(f"{scheme:<10} {arm:<15} {s['c2s_first_median']:>8g} {later:>18} "
                         f"{fmt(s['c2s_later_vs_e3_verify']):>7} {s['s2c_first_median']:>8g} "
                         f"{s['s2c_later_median']:>9g}  {s['first_call_mode']} / {s['later_call_mode']}")
        lines += ["", "Break-even: reference calls needed after the registration call (k*)",
                  f"{'Scheme':<10} {'Policy':<15} {'Reg us':>8} {'Ref us':>8} {'Base us':>8} {'k lat':>6} "
                  f"{'exact':>7} {'per run':>14} {'k c2s B':>8} {'k both B':>9}"]
        for b in be_rows:
            if b["link"] != link:
                continue
            if b["note"]:
                lines.append(f"{b['scenario']:<10} {b['policy']:<15} {b['note']}")
                continue
            lines.append(f"{b['scenario']:<10} {b['policy']:<15} {b['register_us']:>8.1f} {b['reference_us']:>8.1f} "
                         f"{b['e3_verify_us']:>8.1f} {b['k_latency']:>6} {b['k_latency_exact']:>7} "
                         f"{b['k_latency_per_run']:>14} {b['k_bytes_c2s']:>8} {b['k_bytes_both']:>9}")

    lines += ["", "Checks"]
    problems = 0
    for s in lat_summary.values():
        meds = list(s["_run_medians"].values())
        if len(meds) >= 2:
            mid = statistics.median(meds)
            for i, m in enumerate(meds, 1):
                if abs(m - mid) / mid > 0.10:
                    problems += 1
                    lines.append(f"  spread: {s['link']} {s['scenario']}/{s['arm']} run {i} median {m:.1f} us "
                                 f"({(m - mid) / mid:+.0%} vs median of run medians)")
    for r in scen_rows:
        arm = r["arm"]
        if r["measured_handle_rejected"] not in ("", "0") or r["measured_no_handle_issued"] not in ("", "0"):
            problems += 1
            lines.append(f"  handle problem: {r['link']} {r['scenario']}/{arm} run {r['run_id'][:8]}")
        if arm != "dafb_register" and int(r["measured_register"] or 0):
            problems += 1
            lines.append(f"  unexpected registration in measured calls: {r['link']} {r['scenario']}/{arm}")
    for s in byte_summary.values():
        if s["failed"]:
            problems += 1
            lines.append(f"  byte pass failures: {s['link']} {s['scenario']}/{s['arm']}: {s['failed']}")
    if not problems:
        lines.append("  none (run medians within 10%, no rejected handles, no failures)")
    total_failed = sum(failed.values())
    lines.append(f"Measured calls: {sum(len(v) for v in ok.values()) + total_failed}, failed: {total_failed}")

    text = "\n".join(lines)
    (rdir / "e4_report.txt").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
