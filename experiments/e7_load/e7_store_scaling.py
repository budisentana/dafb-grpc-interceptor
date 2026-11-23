"""
DAFB E7 (paper E5): handle-store scaling sub-test (in-process, no network).

For N = 10,000 and 100,000 distinct clients:
  dafb_handles   DAFBServerInterceptor.issue_handle() with a realistic claims dict per client
                 (json.loads of a distinct 200-byte claim set, as the verifier returns it);
                 lookup = lookup_handle(handle)
  token_cache    VerifiedTokenCache entries for distinct ML-DSA-65-sized tokens (4,730 B strings,
                 inserted with the same claims, verification bypassed); lookup = cache(token) on a
                 hit, which includes SHA-256 of the full token, as in a real cache
Memory per entry: tracemalloc traced-memory difference around the fill, divided by N.
Lookup time: 10,000 random existing entries, each timed with perf_counter_ns (timer overhead
included, reported separately), median and p99 in ns.

Pinned to core 3 (a server core). One launch = one run; appends to results/e7_store_scaling.csv.
"""

import argparse
import csv
import json
import os
import random
import secrets
import statistics
import sys
import time
import tracemalloc
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
for sub in ("", "experiments/common", "experiments/e2_metadata", "experiments/e4_dafb"):
    sys.path.insert(0, str(PROJECT_DIR / sub))

import bench_common as bc
import e4_benchmark as e4
from e7_benchmark import channel_claims
from interceptors.dafb_engine import DAFBServerInterceptor
from interceptors.token_cache import VerifiedTokenCache

RESULTS_DIR = Path(__file__).resolve().parent / "results"
SIZES = (10_000, 100_000)
LOOKUPS = 10_000
TOKEN_LEN = 4730            # ML-DSA-65 token in E4-E7


def claims_for(i):
    return json.loads(json.dumps(channel_claims(i), separators=(",", ":")))


def timer_overhead_ns():
    samples = []
    for _ in range(LOOKUPS):
        t0 = time.perf_counter_ns()
        samples.append(time.perf_counter_ns() - t0)
    return statistics.median(samples)


def measure(store, n, run_id, overhead):
    random.seed(n)
    if store == "dafb_handles":
        obj = DAFBServerInterceptor(max_handles=n + 1)
        tracemalloc.start()
        before = tracemalloc.get_traced_memory()[0]
        keys = [obj.issue_handle(claims_for(i))[0] for i in range(n)]
        used = tracemalloc.get_traced_memory()[0] - before
        tracemalloc.stop()
        key_bytes = 0                                       # handles are part of the store
        lookup = obj.lookup_handle
    else:
        obj = VerifiedTokenCache(lambda t: None, max_entries=n + 1)
        prefix = "Bearer "
        keys = [prefix + secrets.token_urlsafe(TOKEN_LEN)[:TOKEN_LEN - len(prefix)] for _ in range(n)]
        key_bytes = sum(sys.getsizeof(k) for k in keys)     # client tokens: not part of the store
        import hashlib
        expires = time.time() + 3600
        tracemalloc.start()
        before = tracemalloc.get_traced_memory()[0]
        for i, k in enumerate(keys):
            obj.entries[hashlib.sha256(k.encode()).digest()] = (claims_for(i), expires)
        used = tracemalloc.get_traced_memory()[0] - before
        tracemalloc.stop()
        lookup = obj
    sample = random.sample(keys, LOOKUPS)
    times, misses = [], 0
    for k in sample:
        t0 = time.perf_counter_ns()
        r = lookup(k)
        times.append(time.perf_counter_ns() - t0)
        misses += r is None
    times.sort()
    return dict(run_id=run_id, store=store, entries=n, traced_bytes=used,
                bytes_per_entry=round(used / n, 1), lookup_median_ns=statistics.median(times),
                lookup_p99_ns=bc.pct(times, .99), timer_overhead_ns=overhead, lookup_misses=misses,
                note="" if not key_bytes else "token strings held by the test, not counted")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--sizes", default=",".join(map(str, SIZES)))
    args = parser.parse_args()
    os.sched_setaffinity(0, {3})
    run_id = str(uuid.uuid4())
    overhead = timer_overhead_ns()
    rows = []
    for n in (int(x) for x in args.sizes.split(",")):
        for store in ("dafb_handles", "token_cache"):
            r = measure(store, n, run_id, overhead)
            r.update(timestamp_utc=datetime.now(timezone.utc).isoformat(), **bc.cpu_state())
            rows.append(r)
            print(f"{store:<13} N={n:>7}: {r['bytes_per_entry']:7.1f} B/entry, lookup median "
                  f"{r['lookup_median_ns']:6.0f} ns (timer {overhead:.0f} ns), p99 {r['lookup_p99_ns']:7.0f} ns, "
                  f"misses {r['lookup_misses']}", flush=True)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    e4.append_csv(args.results_dir / "e7_store_scaling.csv", rows, list(rows[0]))


if __name__ == "__main__":
    main()
