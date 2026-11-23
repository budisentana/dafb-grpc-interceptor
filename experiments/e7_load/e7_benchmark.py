"""
DAFB E7 (paper E5): concurrent load and the handle store.

Arms: e3_verify (no mitigation), token_cache (verified-token cache), dafb_reference.
Scenarios per run (shuffled): ML-DSA-65 at 1, 4, 16, 64 client channels, ES256 at 16 and 64,
each with every arm. Every channel is its own TCP connection with its own token (distinct
`sub`, same 200-byte claim size) and, for DAFB, its own handle.

Server: experiments/e7_load/e7_server.py, cores 2-3, 16 worker threads, restarted per scenario
(so CPU time and store size belong to one scenario). Clients: closed loop of unary calls in up
to 2 processes pinned to cores 0 and 1 (C/2 threads each; 1 process for C = 1); 5 s warm-up,
then a 20 s measurement window. Calls that start and finish inside the window are recorded.

Per scenario: completed calls -> throughput, p50/p99, server CPU time over the window
(/proc/<pid>/stat utime+stime) -> CPU us per call and CPUs used (server and client processes), handle-store / cache entries and size, RSS.

Link (--link): loopback, or N100 (100 Mbit/s netem, no delay, on port 50120).
One launch = one run on one link. Output (experiments/e7_load/results/):
  e7_calls_<run>.csv.gz   one row per measured call (scenario_id, thread, latency_ns, ok)
  e7_scenarios.csv        one row per scenario
  e7_run_environment.csv
"""

import argparse
import base64
import csv
import gzip
import json
import multiprocessing as mp
import os
import platform
import random
import signal
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
for sub in ("", "experiments/common", "experiments/e2_metadata", "experiments/e4_dafb", "experiments/e5_baselines"):
    sys.path.insert(0, str(PROJECT_DIR / sub))

import bench_common as bc
import e4_benchmark as e4

E7_DIR = PROJECT_DIR / "experiments" / "e7_load"
RESULTS_DIR = E7_DIR / "results"
SERVER_SCRIPT = E7_DIR / "e7_server.py"
EXPERIMENT_ID = "E7"
SERVER_PORT = 50120
SERVER_CORES = "2,3"
CLIENT_CORES = [0, 1]
WORKERS = 16
WARMUP_S = 5.0
WINDOW_S = 20.0
ARMS = ["e3_verify", "token_cache", "dafb_reference"]
PLAN = [("ML-DSA-65", c) for c in (1, 4, 16, 64)] + [("ES256", c) for c in (16, 64)]
CLK_TCK = os.sysconf("SC_CLK_TCK")


def channel_claims(i):
    """200-byte claim set with a distinct `sub` of the same length as E4's."""
    claims = e4.claim_set()
    claims["sub"] = f"e7_load_client_{i:04d}".ljust(len(claims["sub"]), "x")
    return claims


# --------------------------------------------------
# Client worker process
# --------------------------------------------------

def worker(core, port, arm, tokens, ready_q, go_q, result_q):
    os.sched_setaffinity(0, {core})
    import e5_benchmark as e5
    clients = [e5.Client(port, arm, iter(lambda t=t: t, None), None) for t in tokens]
    ready_q.put(core)
    t_start, t_warm_end, t_end = go_q.get()
    results = [None] * len(clients)

    def loop(idx, client):
        lat, ok = [], []
        while time.time() < t_start:
            time.sleep(0.001)
        while True:
            s = time.time()
            if s >= t_end:
                break
            r = client.call()
            e = time.time()
            if s >= t_warm_end and e <= t_end:
                lat.append(r["latency_ns"])
                ok.append(1 if r["status"] == "success" else 0)
        results[idx] = (lat, ok, dict(client.dafb.stats) if client.dafb else {})

    threads = [threading.Thread(target=loop, args=(i, c)) for i, c in enumerate(clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for c in clients:
        c.close()
    result_q.put((core, results))


def proc_cpu_s(pid):
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / CLK_TCK          # utime + stime (fields 14, 15)


def run_scenario(ctx, port, arm, tokens):
    """Returns (per-thread results, server cpu seconds over the window)."""
    n = len(tokens)
    procs_n = 1 if n == 1 else len(CLIENT_CORES)
    split = [tokens[i::procs_n] for i in range(procs_n)]
    ready_q, result_q = ctx.Queue(), ctx.Queue()
    go_qs = [ctx.Queue() for _ in range(procs_n)]
    procs = [ctx.Process(target=worker, args=(CLIENT_CORES[i], port, arm, split[i], ready_q, go_qs[i], result_q))
             for i in range(procs_n)]
    for p in procs:
        p.start()
    for _ in procs:
        ready_q.get(timeout=120)
    t_start = time.time() + 0.5
    times = (t_start, t_start + WARMUP_S, t_start + WARMUP_S + WINDOW_S)
    for q in go_qs:
        q.put(times)
    return procs, result_q, times


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():
    global WINDOW_S, WARMUP_S
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--link", choices=["loopback", "N100"], required=True)
    parser.add_argument("--window", type=float, default=WINDOW_S, help="override (smoke tests)")
    parser.add_argument("--warmup", type=float, default=WARMUP_S, help="override (smoke tests)")
    parser.add_argument("--only", help="smoke tests: e.g. ML-DSA-65:4")
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    args = parser.parse_args()
    WINDOW_S, WARMUP_S = args.window, args.warmup
    tc_line = bc.check_link(args.link, SERVER_PORT)

    import grpc
    from interceptors.jws_tokens import TokenSigner
    os.sched_setaffinity(0, set(CLIENT_CORES))
    out = args.results_dir
    out.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    tmpdir = tempfile.mkdtemp(prefix="e7_")
    ctx = mp.get_context("spawn")

    max_c = max(c for _, c in PLAN)
    signers = {s: TokenSigner(s) for s in {s for s, _ in PLAN}}
    tokens = {s: [signers[s].make_token(channel_claims(i)) for i in range(max_c)] for s in signers}
    keys_file = str(Path(tmpdir) / "keys.json")
    with open(keys_file, "w") as f:
        json.dump({s: base64.b64encode(sg.public_key).decode() for s, sg in signers.items()}, f)

    plan = [(s, c, a) for s, c in PLAN for a in ARMS]
    if args.only:
        s, c = args.only.split(":")
        plan = [p for p in plan if p[0] == s and p[1] == int(c)]
    random.shuffle(plan)
    print(f"DAFB E7: link {args.link} ({tc_line}); run {run_id}; {len(plan)} scenarios, "
          f"{WARMUP_S:g} s warm-up + {WINDOW_S:g} s window", flush=True)

    calls_path = out / f"e7_calls_{run_id[:8]}.csv.gz"
    scenario_rows = []
    with gzip.open(calls_path, "wt", newline="") as gz:
        cw = csv.writer(gz)
        cw.writerow(["run_id", "scenario_id", "thread", "latency_ns", "ok"])
        for sid, (scheme, conc, arm) in enumerate(plan, 1):
            stats_file = str(Path(tmpdir) / f"stats_{sid}.json")
            flags = ["--token-cache"] if arm == "token_cache" else []
            server = bc.start_server([SERVER_SCRIPT, "--port", SERVER_PORT, "--cores", SERVER_CORES,
                                      "--workers", WORKERS, "--keys", keys_file, "--stats-file", stats_file] + flags,
                                     "E7")
            try:
                procs, result_q, (t_start, t_warm_end, t_end) = run_scenario(ctx, SERVER_PORT, arm,
                                                                             tokens[scheme][:conc])
                time.sleep(max(0.0, t_warm_end - time.time()))
                cpu0, retr0, net0 = proc_cpu_s(server.pid), bc.tcp_retrans_segs(), bc.netem_counters()
                ccpu0 = sum(proc_cpu_s(p.pid) for p in procs)
                time.sleep(max(0.0, t_end - time.time()))
                cpu1, retr1, net1 = proc_cpu_s(server.pid), bc.tcp_retrans_segs(), bc.netem_counters()
                ccpu1 = sum(proc_cpu_s(p.pid) for p in procs)
                results = [result_q.get(timeout=120) for _ in procs]
                for p in procs:
                    p.join(timeout=30)
                os.kill(server.pid, signal.SIGUSR1)
                for _ in range(100):
                    if os.path.exists(stats_file):
                        break
                    time.sleep(0.05)
                state = json.load(open(stats_file))
            finally:
                bc.stop_server(server)

            lat_all, done, failed, thread_id, dafb = [], 0, 0, 0, {}
            for _, per_thread in sorted(results):
                for lat, ok, st in per_thread:
                    thread_id += 1
                    for x, o in zip(lat, ok):
                        cw.writerow([run_id, sid, thread_id, x, o])
                    lat_all += [x for x, o in zip(lat, ok) if o]
                    done += sum(ok)
                    failed += len(ok) - sum(ok)
                    for k, v in st.items():
                        dafb[k] = dafb.get(k, 0) + v
            lat_all.sort()
            cpu_s = cpu1 - cpu0
            row = dict(experiment_id=EXPERIMENT_ID, run_id=run_id, timestamp_utc=timestamp, link=args.link,
                       scenario_id=sid, scenario=scheme, arm=arm, concurrency=conc, window_s=WINDOW_S,
                       completed=done, failed=failed, throughput_cps=round(done / WINDOW_S, 1),
                       p50_us=round(bc.pct(lat_all, .5) / 1000, 1), p99_us=round(bc.pct(lat_all, .99) / 1000, 1),
                       server_cpu_s=round(cpu_s, 3), cpu_us_per_call=round(cpu_s * 1e6 / done, 1) if done else "",
                       server_cpu_util=round(cpu_s / WINDOW_S, 2), client_cpu_s=round(ccpu1 - ccpu0, 3),
                       client_cpu_util=round((ccpu1 - ccpu0) / WINDOW_S, 2),
                       handles=state["handles"], handle_store_bytes=state["handle_store_bytes"],
                       cache_entries=state["cache_entries"], cache_store_bytes=state["cache_store_bytes"],
                       server_rss_kb=state["rss_kb"], verifier_calls=state["verifier_calls"],
                       client_registers=dafb.get("register", ""), client_references=dafb.get("reference", ""),
                       handles_rejected=dafb.get("handle_rejected", ""), tcp_retrans_segs=retr1 - retr0,
                       netem_dropped=net1[2] - net0[2])
            scenario_rows.append(row)
            print(f"[{sid:2d}/{len(plan)}] {scheme:<9} C={conc:<3} {arm:<15} {row['throughput_cps']:8.1f} calls/s "
                  f"p50 {row['p50_us']:8.1f} p99 {row['p99_us']:9.1f} us | {row['cpu_us_per_call']} us CPU/call (server {row['server_cpu_util']} / client {row['client_cpu_util']} CPUs) | "
                  f"handles {row['handles']}, cache {row['cache_entries']} | failed {failed}", flush=True)

    e4.append_csv(out / "e7_scenarios.csv", scenario_rows, list(scenario_rows[0]))
    try:
        import oqs
        oqs_version = oqs.oqs_python_version()
    except Exception:
        oqs_version = ""
    env = dict(run_id=run_id, timestamp_utc=timestamp, link=args.link, netem=tc_line, warmup_s=WARMUP_S,
               window_s=WINDOW_S, server_cores=SERVER_CORES, server_workers=WORKERS,
               client_cores=" ".join(map(str, CLIENT_CORES)), calls_file=calls_path.name,
               scenario_order=" > ".join(f"{s}/C{c}/{a}" for s, c, a in plan), **bc.cpu_state(),
               python=platform.python_version(), grpcio=grpc.__version__, liboqs_python=oqs_version,
               claim_exp=e4.CLAIM_EXP)
    e4.append_csv(out / "e7_run_environment.csv", [env], list(env))
    print(f"Scenarios: {len(scenario_rows)}, failed calls: {sum(r['failed'] for r in scenario_rows)}; "
          f"governor {env['cpu_governor']}, no_turbo {env['intel_no_turbo']}", flush=True)


if __name__ == "__main__":
    main()
