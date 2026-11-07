"""E2b vs E2: latency over a 100 Mbit/s netem link vs plain loopback.
Writes results/e2b_comparison.csv and prints a table plus a linear fit of the
sweep (Part B): latency increase vs header value size, against the
serialization prediction of 8 bits / 100 Mbit/s = 80 ns per byte."""
import csv, statistics as st
from collections import defaultdict
from pathlib import Path

R = Path(__file__).resolve().parent / "results"

def load(name):
    pooled, runs, size, part = defaultdict(list), defaultdict(lambda: defaultdict(list)), {}, {}
    with (R / name).open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["status"] != "success":
                continue
            s, v = r["scenario"], int(r["latency_ns"]) / 1000.0
            pooled[s].append(v); runs[s][r["run_id"]].append(v)
            size[s] = int(r["header_value_bytes"] or 0); part[s] = r["part"]
    return pooled, runs, size, part

def pct(x, q):
    x = sorted(x); return x[min(len(x) - 1, int(q * len(x)))]

def fit(pts):
    n = len(pts); mx = sum(x for x, _ in pts) / n; my = sum(y for _, y in pts) / n
    sxx = sum((x - mx) ** 2 for x, _ in pts); sxy = sum((x - mx) * (y - my) for x, y in pts)
    k = sxy / sxx; c = my - k * mx
    ss = sum((y - my) ** 2 for _, y in pts); sr = sum((y - (k * x + c)) ** 2 for x, y in pts)
    return k, c, 1 - sr / ss

a, _, size, part = load("e2_latency.csv")
b, b_runs, _, _ = load("e2b_latency.csv")
order = sorted(b, key=lambda s: (part[s], size[s], s))
rows = []
print(f"{'scenario':<10}{'bytes':>6}{'n':>6}{'E2 med':>9}{'E2b med':>9}{'delta':>8}{'E2b p95':>9}{'E2b p99':>9}  E2b run medians")
for s in order:
    ma, mb = st.median(a[s]), st.median(b[s])
    rm = [st.median(v) for v in b_runs[s].values()]
    row = dict(part=part[s], scenario=s, header_value_bytes=size[s], n_e2b=len(b[s]),
               e2_median_us=round(ma, 1), e2b_median_us=round(mb, 1), delta_us=round(mb - ma, 1),
               e2b_p95_us=round(pct(b[s], .95), 1), e2b_p99_us=round(pct(b[s], .99), 1),
               e2b_run_median_min_us=round(min(rm), 1), e2b_run_median_max_us=round(max(rm), 1))
    rows.append(row)
    print(f"{s:<10}{size[s]:>6}{len(b[s]):>6}{ma:>9.1f}{mb:>9.1f}{mb-ma:>8.1f}{row['e2b_p95_us']:>9.1f}{row['e2b_p99_us']:>9.1f}  {min(rm):.1f}-{max(rm):.1f}")
with (R / "e2b_comparison.csv").open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

sweep = [r for r in rows if r["part"] == "B"]
k, c, r2 = fit([(r["header_value_bytes"], r["delta_us"]) for r in sweep])
k2, c2, r22 = fit([(r["header_value_bytes"], r["e2b_median_us"]) for r in sweep])
print(f"\nSweep fit, delta vs bytes:      {k*1000:.1f} ns/byte, intercept {c:.1f} us, R^2 {r2:.4f}  (predicted 80 ns/byte)")
print(f"Sweep fit, E2b median vs bytes: {k2*1000:.1f} ns/byte, intercept {c2:.1f} us, R^2 {r22:.4f}")
d = {r["scenario"]: r for r in rows}
if "ES256" in d and "ML-DSA-65" in d:
    e, m = d["ES256"], d["ML-DSA-65"]
    print(f"ML-DSA-65 vs ES256 at 100 Mbit/s: {m['e2b_median_us']} vs {e['e2b_median_us']} us "
          f"(+{m['e2b_median_us']-e['e2b_median_us']:.1f} us, +{100*(m['e2b_median_us']/e['e2b_median_us']-1):.1f}%)")
