"""
DAFB E6 (paper E4): realistic links and the crossover.

Arms (plaintext, same implementation as E5):
  e3_verify       no mitigation (plain server)
  token_cache     verified-token cache (server --token-cache)
  dafb_reference  DAFB, policy reference (plain server); the registration is the
                  first call of each connection and is logged in e6_scenarios.csv
Schemes: ES256, ML-DSA-44, ML-DSA-65, ML-DSA-87 (E4/E5 tokens, 200-byte claims, exp 2028).

Links (--link): L1 1 Gbit/s | L2 100 Mbit/s + 5 ms one-way | L3 L2 + 0.5% loss |
L4 20 Mbit/s + 20 ms one-way (netem on port 50110, experiments/common/netem_profile.sh),
or loopback (no netem, smoke tests). The tc state is checked against the link.

Per scenario (fresh connection each pass, shuffled order, server group order shuffled):
  1. byte pass: 10 calls through the E2 relay, HEADERS bytes per call (both directions)
  2. latency pass: warm-up + measured calls, direct. L1/loopback: 50 + 500;
     L2-L4: 20 + 300 (RTT-bound links, to keep the runtime sane).
     Before/after the measured calls: system TCP RetransSegs and netem sent/dropped.
Client on core 2, server on core 3 (as E1-E5).

One launch = one run on one link. Output (experiments/e6_network/results/):
  e6_latency.csv (one row per measured call), e6_bytes.csv, e6_scenarios.csv, e6_run_environment.csv
"""

import argparse
import base64
import json
import os
import platform
import random
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
for sub in ("", "experiments/common", "experiments/e2_metadata", "experiments/e4_dafb", "experiments/e5_baselines"):
    sys.path.insert(0, str(PROJECT_DIR / sub))

import bench_common as bc
import e4_benchmark as e4
import e5_benchmark as e5
from interceptors.jws_tokens import TokenSigner

E6_DIR = PROJECT_DIR / "experiments" / "e6_network"
RESULTS_DIR = E6_DIR / "results"
SERVER_SCRIPT = PROJECT_DIR / "experiments" / "e5_baselines" / "e5_server.py"
EXPERIMENT_ID = "E6"
SERVER_PORT = 50110
RELAY_PORT = 50111
CLIENT_CORE = 2
SERVER_CORE = 3
BYTE_PASS_CALLS = 10
SCHEMES = ["ES256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
LINKS = ["loopback", "L1", "L2", "L3", "L4"]
CALLS = {"loopback": (50, 500), "L1": (50, 500), "L2": (20, 300), "L3": (20, 300), "L4": (20, 300)}
GROUPS = {"plain": ([], ["e3_verify", "dafb_reference"]), "cache": (["--token-cache"], ["token_cache"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--link", choices=LINKS, required=True)
    parser.add_argument("--warmup", type=int, help="override (smoke tests)")
    parser.add_argument("--measured", type=int, help="override (smoke tests)")
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    args = parser.parse_args()
    tc_line = bc.check_link(args.link, SERVER_PORT)
    warmup, measured = CALLS[args.link]
    warmup, measured = args.warmup or warmup, args.measured or measured

    import grpc
    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {CLIENT_CORE})
    out = args.results_dir
    run_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    tmpdir = tempfile.mkdtemp(prefix="e6_")

    signers = {s: TokenSigner(s) for s in SCHEMES}
    tokens = {s: signers[s].make_token(e4.claim_set()) for s in SCHEMES}
    keys_file = str(Path(tmpdir) / "keys.json")
    with open(keys_file, "w") as f:
        json.dump({s: base64.b64encode(sg.public_key).decode() for s, sg in signers.items()}, f)

    group_order = list(GROUPS)
    random.shuffle(group_order)
    plan = []
    for g in group_order:
        scen = [(s, a) for s in SCHEMES for a in GROUPS[g][1]]
        random.shuffle(scen)
        plan += [(g, s, a) for s, a in scen]

    print(f"DAFB E6: link {args.link} ({tc_line}); run {run_id}; {len(plan)} scenarios, "
          f"{warmup} warm-up + {measured} measured", flush=True)

    byte_rows, latency_rows, scenario_rows = [], [], []
    relay = e5.Relay(RELAY_PORT, SERVER_PORT, False)
    server, current = None, None
    try:
        for n, (group, scheme, arm) in enumerate(plan, 1):
            if group != current:
                if server:
                    bc.stop_server(server)
                server = bc.start_server([SERVER_SCRIPT, "--port", SERVER_PORT, "--core", SERVER_CORE,
                                          "--keys", keys_file] + GROUPS[group][0], "E6")
                current = group
            token = tokens[scheme]
            fixed = lambda: iter(lambda: token, None)
            common = dict(experiment_id=EXPERIMENT_ID, run_id=run_id, timestamp_utc=timestamp, link=args.link,
                          scenario=scheme, arm=arm, header_value_bytes=len(token))

            relay.reset()
            client = e5.Client(RELAY_PORT, arm, fixed(), None)
            prev = relay.snapshot()
            for i in range(1, BYTE_PASS_CALLS + 1):
                r = client.call()
                time.sleep(0.005 if args.link in ("loopback", "L1") else 0.06)
                now = relay.snapshot()
                d = [a - b for a, b in zip(now, prev)]
                byte_rows.append(dict(common, call=i, dafb_mode=r["dafb_mode"], c2s_header_bytes=d[0],
                                      c2s_bytes=d[3], s2c_header_bytes=d[4], s2c_bytes=d[7], status=r["status"]))
                prev = now
            client.close()

            client = e5.Client(SERVER_PORT, arm, fixed(), None)
            first = client.call()
            warm_fail = first["status"] != "success"
            for _ in range(warmup - 1):
                warm_fail += client.call()["status"] != "success"
            retr0, net0 = bc.tcp_retrans_segs(), bc.netem_counters()
            failed, lat = 0, []
            for i in range(1, measured + 1):
                r = client.call()
                failed += r["status"] != "success"
                lat.append(r["latency_ns"])
                latency_rows.append(dict(common, iteration=i, latency_ns=r["latency_ns"], verify_ns=r["verify_ns"],
                                         dafb_mode=r["dafb_mode"], status=r["status"], grpc_status=r["grpc_status"]))
            retr1, net1 = bc.tcp_retrans_segs(), bc.netem_counters()
            client.close()
            scenario_rows.append(dict(
                common, warmup=warmup, measured=measured,
                first_call_latency_ns=first["latency_ns"], first_call_mode=first["dafb_mode"],
                first_call_verify_ns=first["verify_ns"], warmup_failed=warm_fail, measured_failed=failed,
                tcp_retrans_segs=retr1 - retr0, netem_sent_bytes=net1[0] - net0[0],
                netem_sent_pkts=net1[1] - net0[1], netem_dropped=net1[2] - net0[2]))
            lat.sort()
            print(f"[{n:2d}/{len(plan)}] {scheme:<10} {arm:<15} median {lat[len(lat) // 2] / 1000:8.1f} us "
                  f"p99 {lat[int(len(lat) * .99)] / 1000:8.1f} us | retrans {retr1 - retr0}, "
                  f"netem drop {net1[2] - net0[2]} | failed {failed}", flush=True)
    finally:
        relay.close()
        if server:
            bc.stop_server(server)

    e4.append_csv(out / "e6_latency.csv", latency_rows, list(latency_rows[0]))
    e4.append_csv(out / "e6_bytes.csv", byte_rows, list(byte_rows[0]))
    e4.append_csv(out / "e6_scenarios.csv", scenario_rows, list(scenario_rows[0]))
    try:
        import oqs
        oqs_version = oqs.oqs_python_version()
    except Exception:
        oqs_version = ""
    env = dict(run_id=run_id, timestamp_utc=timestamp, link=args.link, netem=tc_line, warmup=warmup,
               measured=measured, scenario_order=" > ".join(f"{g}:{s}/{a}" for g, s, a in plan),
               client_core=CLIENT_CORE, server_core=SERVER_CORE, **bc.cpu_state(),
               python=platform.python_version(), grpcio=grpc.__version__, liboqs_python=oqs_version,
               claim_exp=e4.CLAIM_EXP, token_bytes="; ".join(f"{s}={len(tokens[s])}" for s in SCHEMES))
    e4.append_csv(out / "e6_run_environment.csv", [env], list(env))
    print(f"Measured calls: {len(latency_rows)}, failed: {sum(r['status'] != 'success' for r in latency_rows)}; "
          f"governor {env['cpu_governor']}, no_turbo {env['intel_no_turbo']}", flush=True)


if __name__ == "__main__":
    main()
