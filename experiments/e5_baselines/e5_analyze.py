"""
DAFB E5: analysis of e5_latency.csv, e5_bytes.csv and e5_scenarios.csv.

Per transport / link / scheme / arm, pooled over runs: median, p95, p99,
median verification time, mean of run medians with 95% CI. Bytes per call from
the byte pass: plaintext = HEADERS bytes (E2 relay method), TLS = TCP payload
bytes (frames are encrypted); first call and later calls (2-10), both directions.

DAFB (adaptive, reference) vs each baseline, per transport / link / scheme:
  baseline 1  e3_verify    no mitigation
  baseline 2  hpack_64k    64 KiB HPACK tables (indexing check: later-call bytes vs token size)
  baseline 3  token_cache  verified-token cache (first call = token_cache_miss)

  difference in median latency and in later-call bytes (c2s, and both directions)
  break-even k*: smallest k >= 0 with  R + k*F <= M + k*B
      DAFB:      R = registration (dafb_register), F = reference call (policy arm)
      baseline:  M = its first call to the server for this token, B = its steady call
                 (M = B for baselines 1 and 2; M = token_cache_miss for baseline 3)
      k* = max(0, ceil((R - M) / (B - F))) when F < B; "never" when F >= B.
  For adaptive policies that keep the token inline (ES256, EdDSA) there is no
  registration: R = F = the inline call.

Usage: python experiments/e5_baselines/e5_analyze.py [results_dir]
Writes e5_latency_summary.csv, e5_bytes_summary.csv, e5_comparison.csv, e5_report.txt.
"""

import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "results"
SCHEMES = ["none", "ES256", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
ARMS = ["none", "e3_verify", "hpack_64k", "token_cache", "token_cache_miss",
        "dafb_adaptive", "dafb_reference", "dafb_register"]
BASELINES = [("1 no mitigation", "e3_verify", "e3_verify"), ("2 HPACK 64 KiB", "hpack_64k", "hpack_64k"),
             ("3 token cache", "token_cache", "token_cache_miss")]
POLICIES = ["dafb_adaptive", "dafb_reference"]
INDEXED_FIELD_BYTES = 1          # RFC 7541 6.1: indexed field, 7-bit prefix -> 1 byte up to index 126
BASELINE_2_ANALYTIC = "2a indexed*"
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}


def pct(v, p):
    if not v:
        return float("nan")
    k = (len(v) - 1) * p
    lo, hi = math.floor(k), math.ceil(k)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def ci95(values):
    if len(values) < 2:
        return float("nan"), float("nan")
    m = statistics.mean(values)
    h = T95.get(len(values) - 1, 1.96) * statistics.stdev(values) / math.sqrt(len(values))
    return m - h, m + h


def breakeven(R, F, M, B):
    """k* (int) or None (never), and the exact ratio."""
    if F >= B:
        return None, None
    ratio = (R - M) / (B - F)
    return max(0, math.ceil(ratio - 1e-9)), ratio


def fmt(v, nd=1):
    if v is None or v == "":
        return "never" if v is None else "-"
    return f"{v:.{nd}f}" if isinstance(v, float) else str(v)


def load(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def main():
    rdir = Path(sys.argv[1]) if len(sys.argv) > 1 else RESULTS_DIR
    lat_rows, byte_rows, scen_rows = (load(rdir / f) for f in ("e5_latency.csv", "e5_bytes.csv", "e5_scenarios.csv"))
    conditions = list(dict.fromkeys((r["transport"], r["link"]) for r in lat_rows))

    # ---------------- latency ----------------
    ok, failed = defaultdict(list), defaultdict(int)
    per_run = defaultdict(lambda: defaultdict(list))
    runs = defaultdict(set)
    for r in lat_rows:
        key = (r["transport"], r["link"], r["scenario"], r["arm"])
        runs[key[:2]].add(r["run_id"])
        if r["status"] != "success":
            failed[key] += 1
            continue
        us = int(r["latency_ns"]) / 1000
        ok[key].append((us, int(r["verify_ns"]) / 1000))
        per_run[key][r["run_id"]].append(us)
    lat = {}
    for key in sorted(set(ok) | set(failed), key=lambda k: (conditions.index(k[:2]), SCHEMES.index(k[2]), ARMS.index(k[3]))):
        v = sorted(x[0] for x in ok[key])
        ver = sorted(x[1] for x in ok[key])
        meds = [statistics.median(x) for x in per_run[key].values()]
        lo, hi = ci95(meds)
        lat[key] = dict(transport=key[0], link=key[1], scenario=key[2], arm=key[3], runs=len(meds), calls=len(v),
                        failed=failed[key], median_us=round(pct(v, .5), 1), p95_us=round(pct(v, .95), 1),
                        p99_us=round(pct(v, .99), 1), verify_median_us=round(pct(ver, .5), 1),
                        verified_share=round(sum(1 for x in ver if x > 0) / len(ver), 3) if ver else "",
                        run_median_mean_us=round(statistics.mean(meds), 1) if meds else "",
                        ci95_low_us=round(lo, 1), ci95_high_us=round(hi, 1),
                        run_medians_us=" ".join(f"{m:.1f}" for m in meds))

    # ---------------- bytes ----------------
    vals = defaultdict(lambda: defaultdict(list))
    for r in byte_rows:
        key = (r["transport"], r["link"], r["scenario"], r["arm"])
        phase = "first" if r["call"] == "1" else "later"
        tls = r["transport"] == "tls"
        for d in ("c2s", "s2c"):
            vals[key][f"{d}_{phase}"].append(int(r[f"{d}_bytes"] if tls else r[f"{d}_header_bytes"]))
        vals[key]["mode_" + phase].append(r["dafb_mode"])
        vals[key]["failed"].append(r["status"] != "success")
        vals[key]["value"].append(int(r["header_value_bytes"]))
    byt = {}
    for key in sorted(vals, key=lambda k: (conditions.index(k[:2]), SCHEMES.index(k[2]), ARMS.index(k[3]))):
        v = vals[key]
        s = dict(transport=key[0], link=key[1], scenario=key[2], arm=key[3],
                 unit="TCP payload" if key[0] == "tls" else "HEADERS", failed=sum(v["failed"]),
                 first_mode="/".join(sorted(set(v["mode_first"]))), later_mode="/".join(sorted(set(v["mode_later"]))))
        for f in ("c2s_first", "c2s_later", "s2c_first", "s2c_later"):
            s[f + "_median"] = statistics.median(v[f])
            s[f + "_min"], s[f + "_max"] = min(v[f]), max(v[f])
        s["token_bytes"] = v["value"][0]
        byt[key] = s

    # ---------------- comparison ----------------
    comp = []
    for (transport, link) in conditions:
        for scheme in SCHEMES[1:]:
            k = lambda arm: (transport, link, scheme, arm)
            if not all(k(a) in lat and k(a) in byt for a in ARMS[1:]):
                continue
            both = lambda a: byt[k(a)]["c2s_later_median"] + byt[k(a)]["s2c_later_median"]
            for policy in POLICIES:
                registers = "reference" in byt[k(policy)]["later_mode"]
                reg = "dafb_register" if registers else policy
                for label, steady, first in BASELINES:
                    R, F = lat[k(reg)]["median_us"], lat[k(policy)]["median_us"]
                    M, B = lat[k(first)]["median_us"], lat[k(steady)]["median_us"]
                    k_lat, x_lat = breakeven(R, F, M, B)
                    Rb, Fb = byt[k(reg)]["c2s_later_median"], byt[k(policy)]["c2s_later_median"]
                    Mb, Bb = byt[k(first)]["c2s_later_median"], byt[k(steady)]["c2s_later_median"]
                    k_b, _ = breakeven(Rb, Fb, Mb, Bb)
                    k_bb, _ = breakeven(both(reg), both(policy), both(first), both(steady))
                    comp.append(dict(
                        transport=transport, link=link, scenario=scheme, policy=policy, dafb_registers=int(registers),
                        baseline=label, dafb_us=F, baseline_us=B, diff_us=round(F - B, 1),
                        diff_pct=round(100 * (F - B) / B, 1), dafb_register_us=R, baseline_first_us=M,
                        k_latency=fmt(k_lat), k_latency_exact=fmt(x_lat, 2),
                        unit=byt[k(policy)]["unit"], dafb_c2s_B=Fb, baseline_c2s_B=Bb, diff_c2s_B=Fb - Bb,
                        dafb_beats_on_bytes="yes" if Fb < Bb else "NO", k_bytes_c2s=fmt(k_b),
                        dafb_both_B=both(policy), baseline_both_B=both(steady), k_bytes_both=fmt(k_bb)))
                # Baseline 2 analytic bound (not achievable in grpcio): token indexed after the first call,
                # so a later call carries a 1-byte indexed field (dynamic-table index <= 126) instead of the
                # token; verification still runs on every call, so latency is taken as e3_verify.
                none_later = byt[(transport, link, "none", "none")]["c2s_later_median"]
                Bb = none_later + INDEXED_FIELD_BYTES
                Fb = byt[k(policy)]["c2s_later_median"]
                Rb = byt[k(reg)]["c2s_later_median"]
                Mb = byt[k("e3_verify")]["c2s_later_median"]        # first sighting: token sent literally
                k_b, _ = breakeven(Rb, Fb, Mb, Bb)
                F, B = lat[k(policy)]["median_us"], lat[k("e3_verify")]["median_us"]
                R = lat[k(reg)]["median_us"]
                k_lat, x_lat = breakeven(R, F, B, B)
                comp.append(dict(
                    transport=transport, link=link, scenario=scheme, policy=policy, dafb_registers=int(registers),
                    baseline=BASELINE_2_ANALYTIC, dafb_us=F, baseline_us=B, diff_us=round(F - B, 1),
                    diff_pct=round(100 * (F - B) / B, 1), dafb_register_us=R, baseline_first_us=B,
                    k_latency=fmt(k_lat), k_latency_exact=fmt(x_lat, 2), unit=byt[k(policy)]["unit"],
                    dafb_c2s_B=Fb, baseline_c2s_B=Bb, diff_c2s_B=Fb - Bb,
                    dafb_beats_on_bytes="yes" if Fb < Bb else "NO", k_bytes_c2s=fmt(k_b),
                    dafb_both_B="", baseline_both_B="", k_bytes_both="-"))

    # ---------------- write ----------------
    for name, rows in (("e5_latency_summary.csv", list(lat.values())), ("e5_bytes_summary.csv", list(byt.values())),
                       ("e5_comparison.csv", comp)):
        if rows:
            with (rdir / name).open("w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(x for r in rows for x in r)))
                w.writeheader()
                w.writerows(rows)

    L = [f"E5 results (DAFB vs fair baselines), input: {rdir}"]
    for cond in conditions:
        transport, link = cond
        unit = "TCP payload bytes (TLS)" if transport == "tls" else "HEADERS bytes (E2 relay method)"
        L += ["", "=" * 104, f"Transport: {transport}, link: {link}, {len(runs[cond])} run(s)", "=" * 104, "",
              "Latency per call (us, pooled over runs)",
              f"{'Scheme':<10} {'Arm':<17} {'Median':>8} {'p95':>8} {'p99':>8} {'Verify':>7} {'verified':>8}"
              f"  Run-median mean [95% CI]"]
        for key, s in lat.items():
            if key[:2] == cond:
                L.append(f"{s['scenario']:<10} {s['arm']:<17} {s['median_us']:>8.1f} {s['p95_us']:>8.1f} "
                         f"{s['p99_us']:>8.1f} {s['verify_median_us']:>7.1f} {s['verified_share']:>8}  "
                         f"{s['run_median_mean_us']} [{s['ci95_low_us']}, {s['ci95_high_us']}]")
        L += ["", f"{unit} per call (median over runs; later = calls 2-10 [min-max])",
              f"{'Scheme':<10} {'Arm':<17} {'token':>6} {'c2s 1st':>8} {'c2s later':>18} {'s2c 1st':>8} {'s2c later':>9}  modes"]
        for key, s in byt.items():
            if key[:2] == cond:
                later = f"{s['c2s_later_median']:g} [{s['c2s_later_min']}-{s['c2s_later_max']}]"
                L.append(f"{s['scenario']:<10} {s['arm']:<17} {s['token_bytes']:>6} {s['c2s_first_median']:>8g} "
                         f"{later:>18} {s['s2c_first_median']:>8g} {s['s2c_later_median']:>9g}  "
                         f"{s['first_mode']} / {s['later_mode']}")
        hp = [(sc, byt[(transport, link, sc, "hpack_64k")]) for sc in SCHEMES[1:]
              if (transport, link, sc, "hpack_64k") in byt]
        if hp:
            L += ["", "Baseline 2 indexing check: is the token absent from later calls with 64 KiB tables?"]
            for sc, s in hp:
                base = byt[(transport, link, sc, "e3_verify")]["c2s_later_median"]
                indexed = s["c2s_later_median"] < s["token_bytes"]
                L.append(f"  {sc:<10} later calls {s['c2s_later_median']:g} B vs no mitigation {base:g} B, "
                         f"token {s['token_bytes']} B -> token {'INDEXED' if indexed else 'NOT indexed (sent in full every call)'}")
            none_later = byt[(transport, link, "none", "none")]["c2s_later_median"]
            L += ["  grpcio sends all application metadata as 'literal header field without indexing' (0x00),",
                  "  so baseline 2 is not achievable in grpcio. RFC 7541 7.1.3 also lets encoders mark authorization",
                  "  never-indexed, as a sensitive header (compression side channels).",
                  f"  2a indexed* = analytic bound if the token were indexed: later calls {none_later:g} + "
                  f"{INDEXED_FIELD_BYTES} B (indexed field) = {none_later + INDEXED_FIELD_BYTES:g} B;",
                  "  verification still runs on every call, so its latency is taken as e3_verify."]
        L += ["", "DAFB vs baselines (steady state; k* = calls after the first call to break even, R+kF <= M+kB)",
              f"{'Scheme':<10} {'Policy':<15} {'Baseline':<16} {'DAFB us':>8} {'Base us':>8} {'diff %':>7} {'k lat':>6} "
              f"{'DAFB B':>7} {'Base B':>7} {'beats B':>7} {'k B':>5} {'k both':>6}"]
        for c in comp:
            if (c["transport"], c["link"]) == cond:
                L.append(f"{c['scenario']:<10} {c['policy']:<15} {c['baseline']:<16} {c['dafb_us']:>8.1f} "
                         f"{c['baseline_us']:>8.1f} {c['diff_pct']:>7.1f} {c['k_latency']:>6} {c['dafb_c2s_B']:>7g} "
                         f"{c['baseline_c2s_B']:>7g} {c['dafb_beats_on_bytes']:>7} {c['k_bytes_c2s']:>5} "
                         f"{c['k_bytes_both']:>6}")

    L += ["", "Checks"]
    problems = 0
    for s in lat.values():
        meds = [float(x) for x in s["run_medians_us"].split()]
        if len(meds) >= 2:
            mid = statistics.median(meds)
            for i, m in enumerate(meds, 1):
                if abs(m - mid) / mid > 0.10:
                    problems += 1
                    L.append(f"  spread: {s['transport']}/{s['link']} {s['scenario']}/{s['arm']} run {i} "
                             f"{m:.1f} us ({(m - mid) / mid:+.0%})")
    expect_verified = {"e3_verify": 1, "hpack_64k": 1, "token_cache_miss": 1, "dafb_register": 1, "token_cache": 0,
                       "dafb_reference": 0}
    for s in lat.values():
        want = expect_verified.get(s["arm"])
        if want is not None and s["verified_share"] != "" and s["verified_share"] != want:
            problems += 1
            L.append(f"  verification share {s['verified_share']} (expected {want}): "
                     f"{s['transport']}/{s['link']} {s['scenario']}/{s['arm']}")
    for r in scen_rows:
        if r["measured_handle_rejected"] not in ("", "0"):
            problems += 1
            L.append(f"  rejected handles: {r['transport']}/{r['link']} {r['scenario']}/{r['arm']}")
    nf = sum(failed.values()) + sum(s["failed"] for s in byt.values())
    if nf:
        problems += 1
        L.append(f"  failed calls: {nf}")
    if not problems:
        L.append("  none (run medians within 10%, verification as expected, no rejected handles, no failures)")
    L.append(f"Measured calls: {sum(len(v) for v in ok.values()) + sum(failed.values())}")

    text = "\n".join(L)
    (rdir / "e5_report.txt").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
