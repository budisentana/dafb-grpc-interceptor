"""
DAFB E4: DAFB vs no mitigation.

Schemes: ES256, EdDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87 (JWS tokens in the
`authorization` header, same format and 200-byte claim set size as E2/E3, but
with a future `exp`; the E2/E3 claim set expired on 1 Jan 2026), plus `none`.

Arms (all against the same E4 server, same TokenVerifier with exp check):
  e3_verify       plain bearer token, verified on every call (no mitigation; E3 verify path)
  dafb_inline     DAFB client, policy inline    (token + x-dafb-mode: inline, verified every call)
  dafb_adaptive   DAFB client, policy adaptive  (reference path only above the HPACK budget)
  dafb_reference  DAFB client, policy reference (register once, then handle only)
  dafb_register   DAFB client, policy reference, handle forgotten before every call,
                  so every call is a registration: the registration cost for the break-even

For every scenario, each on a fresh TCP connection (empty HPACK table) and,
for DAFB, a fresh client interceptor (empty handle cache):
  1. byte pass:    10 calls through a local relay that parses the HTTP/2 frames
                   (E2 method) and records HEADERS bytes per call, client->server
                   and server->client
  2. latency pass: 50 warm-up + 500 measured calls, direct (no relay). The first
                   warm-up call (the registration for DAFB reference) is saved
                   separately as the cold first call.

Link (--link): loopback, or netem100 (E2b condition: 100 Mbit/s netem on the
E4 port, set with `sudo bash experiments/e2_metadata/e2b_netem.sh on 100mbit 50080`).
The script checks that the tc state matches the chosen link before it starts.

One launch = one run; run it 5 times per link, then e4_analyze.py.

Output (experiments/e4_dafb/results/), every row tagged with the link:
  e4_bytes.csv             one row per byte-pass call
  e4_latency.csv           one row per measured call
  e4_scenarios.csv         one row per scenario: cold first call, failures, DAFB mode counts
  e4_run_environment.csv   CPU settings, versions, token sizes, tc state per run
"""

import argparse
import base64
import csv
import glob
import json
import os
import platform
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIR))
sys.path.insert(0, str(PROJECT_DIR / "experiments" / "e2_metadata"))

from e2_benchmark import FrameCounter          # E2 relay frame parser (unchanged)
from interceptors.dafb_engine import DAFBClientInterceptor, DAFBSecurityContext
from interceptors.jws_tokens import SCHEMES, TokenSigner

E4_DIR = PROJECT_DIR / "experiments" / "e4_dafb"
RESULTS_DIR = E4_DIR / "results"
BYTES_FILE = RESULTS_DIR / "e4_bytes.csv"
LATENCY_FILE = RESULTS_DIR / "e4_latency.csv"
SCENARIO_FILE = RESULTS_DIR / "e4_scenarios.csv"
ENV_FILE = RESULTS_DIR / "e4_run_environment.csv"
SERVER_SCRIPT = E4_DIR / "e4_server.py"

EXPERIMENT_ID = "E4"
SERVER_PORT = 50080
RELAY_PORT = 50081
CLIENT_CORE = 2
SERVER_CORE = 3

BYTE_PASS_CALLS = 10
WARMUP_REQUESTS = 50
MEASURED_REQUESTS = 500

HEADER_NAME = "authorization"
ARMS = ["e3_verify", "dafb_inline", "dafb_adaptive", "dafb_reference", "dafb_register"]
LINKS = ["loopback", "netem100"]

# 200-byte claim set. Same fields and lengths as E2/E3 except exp: 1 Jan 2028 00:00 UTC.
CLAIM_IAT = 1767225600
CLAIM_EXP = 1830297600
CLAIM_SIZE = 200


def claim_set(jti_seed=0, size=CLAIM_SIZE):
    claims = {"sub": "mldsa65_experiment_client", "role": "research_experimenter",
              "iss": "dafb-e4", "aud": "dafb-grpc", "iat": CLAIM_IAT, "exp": CLAIM_EXP, "jti": ""}
    pad = size - len(json.dumps(claims, separators=(",", ":")).encode())
    claims["jti"] = f"{jti_seed:0{pad}d}"[-pad:]
    assert len(json.dumps(claims, separators=(",", ":")).encode()) == size
    return claims


# --------------------------------------------------
# Link check (tc state must match --link)
# --------------------------------------------------

def tc_state():
    out = []
    for cmd in (["tc", "qdisc", "show", "dev", "lo"], ["tc", "filter", "show", "dev", "lo"]):
        try:
            out.append(subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip())
        except (OSError, subprocess.SubprocessError) as exc:
            out.append(f"{' '.join(cmd)} failed: {exc}")
    return out


def check_link(link):
    qdisc, filters = tc_state()
    port_hex = f"{SERVER_PORT:04x}"
    netem_on = "netem" in qdisc
    if link == "loopback" and netem_on:
        sys.exit("netem is active on lo; turn it off for --link loopback "
                 "(sudo bash experiments/e2_metadata/e2b_netem.sh off)")
    if link == "netem100":
        if not netem_on or "rate 100Mbit" not in qdisc or port_hex not in filters:
            sys.exit(f"--link netem100 needs 100 Mbit/s netem on port {SERVER_PORT}: "
                     f"sudo bash experiments/e2_metadata/e2b_netem.sh on 100mbit {SERVER_PORT}")
    return qdisc + " || " + filters.replace("\n", " ")


# --------------------------------------------------
# Relay (E2 method, both directions counted)
# --------------------------------------------------

class Relay:
    """127.0.0.1:listen_port -> 127.0.0.1:target_port; HTTP/2 frames counted in both directions."""

    def __init__(self, listen_port, target_port):
        self.target_port = target_port
        self.reset()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", listen_port))
        self.sock.listen(8)
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()

    def reset(self):
        self.c2s = FrameCounter()
        self.s2c = FrameCounter()
        self.s2c.preface_done = True          # the server sends no connection preface

    def snapshot(self):
        return self.c2s.snapshot() + self.s2c.snapshot()

    def _accept(self):
        while self.running:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            upstream = socket.create_connection(("127.0.0.1", self.target_port))
            for s in (client, upstream):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c2s, s2c = self.c2s, self.s2c
            threading.Thread(target=self._pump, args=(client, upstream, c2s), daemon=True).start()
            threading.Thread(target=self._pump, args=(upstream, client, s2c), daemon=True).start()

    @staticmethod
    def _pump(src, dst, counter):
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                counter.feed(chunk)
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self):
        self.running = False
        self.sock.close()


# --------------------------------------------------
# gRPC
# --------------------------------------------------

def start_server(keys_file):
    cmd = [sys.executable, str(SERVER_SCRIPT), "--port", str(SERVER_PORT), "--core", str(SERVER_CORE),
           "--keys", keys_file]
    server = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    seen = []
    for _ in range(20):
        line = server.stdout.readline()
        if not line:
            break
        seen.append(line.strip())
        if "ready" in line:
            print(line.strip(), flush=True)
            return server
    server.kill()
    raise RuntimeError("E4 server did not start: " + " | ".join(seen))


def stop_server(server):
    server.terminate()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()


class Client:
    """One arm on one fresh connection. `call()` returns timings and the DAFB mode used."""

    def __init__(self, port, arm, token):
        import grpc
        from protobufs import security_service_pb2 as pb2
        from protobufs import security_service_pb2_grpc as pb2_grpc
        self.grpc = grpc
        self.arm = arm
        self.metadata = [] if token is None else [(HEADER_NAME, token)]
        # Local subchannel pool: new TCP connection, empty HPACK table.
        self.channel = grpc.insecure_channel(f"127.0.0.1:{port}", options=[("grpc.use_local_subchannel_pool", 1)])
        grpc.channel_ready_future(self.channel).result(timeout=10)
        self.dafb = None
        channel = self.channel
        if arm.startswith("dafb_"):
            policy = {"dafb_inline": "inline", "dafb_adaptive": "adaptive"}.get(arm, "reference")
            self.dafb = DAFBClientInterceptor(metadata_auth_key=HEADER_NAME, policy=policy)
            channel = grpc.intercept_channel(self.channel, self.dafb)
        self.stub = pb2_grpc.CredentialBrokerStub(channel)
        self.request = pb2.RegistrationRequest(raw_token="e4")

    def call(self):
        if self.arm == "dafb_register":
            self.dafb.forget()                          # outside the timed region
        before = dict(self.dafb.stats) if self.dafb else None
        start = time.perf_counter_ns()
        try:
            _, call_obj = self.stub.RegisterCredential.with_call(self.request, metadata=self.metadata, timeout=10.0)
            latency = time.perf_counter_ns() - start
            verify_ns = next((int(v) for k, v in call_obj.trailing_metadata() or () if k == "x-verify-ns"), 0)
            result = dict(latency_ns=latency, verify_ns=verify_ns, status="success", grpc_status="OK", error="")
        except self.grpc.RpcError as exc:
            latency = time.perf_counter_ns() - start
            result = dict(latency_ns=latency, verify_ns=0, status="error", grpc_status=str(exc.code()),
                          error=str(exc.details())[:200])
        result["dafb_mode"] = self._mode(before)
        return result

    def _mode(self, before):
        if self.dafb is None:
            return "bearer" if self.metadata else "none"
        changed = [k for k, v in self.dafb.stats.items() if v != before[k]]
        # a rejected handle followed by a re-registration shows as "handle_rejected+register"
        order = ["inline", "reference", "handle_rejected", "register", "no_handle_issued"]
        return "+".join(k for k in order if k in changed)

    def close(self):
        self.channel.close()


# --------------------------------------------------
# Output helpers
# --------------------------------------------------

def append_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        writer.writerows(rows)


def read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--link", choices=LINKS, required=True)
    parser.add_argument("--measured", type=int, default=MEASURED_REQUESTS, help="for smoke tests only")
    parser.add_argument("--warmup", type=int, default=WARMUP_REQUESTS, help="for smoke tests only")
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR, help="for smoke tests only")
    args = parser.parse_args()
    tc_text = check_link(args.link)

    import grpc
    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {CLIENT_CORE})

    out = args.results_dir
    files = {name: out / path.name for name, path in
             dict(bytes=BYTES_FILE, latency=LATENCY_FILE, scenarios=SCENARIO_FILE, env=ENV_FILE).items()}

    run_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    signers = {s: TokenSigner(s) for s in SCHEMES}
    tokens = {s: signers[s].make_token(claim_set()) for s in SCHEMES}

    keys_fd, keys_file = tempfile.mkstemp(prefix="e4_pubkeys_", suffix=".json")
    with os.fdopen(keys_fd, "w") as f:
        json.dump({s: base64.b64encode(sg.public_key).decode() for s, sg in signers.items()}, f)

    order = [("none", "none")] + [(s, a) for s in SCHEMES for a in ARMS]
    random.shuffle(order)

    print("=" * 66)
    print(f"DAFB E4: DAFB vs no mitigation, link: {args.link}")
    print("=" * 66)
    print(f"Run ID: {run_id}")
    print(f"Scenarios: {len(order)}, shuffled; byte pass {BYTE_PASS_CALLS} calls, "
          f"{args.warmup} warm-up + {args.measured} measured")
    for s in SCHEMES:
        entry = DAFBSecurityContext.calculate_wire_size(HEADER_NAME, tokens[s])
        print(f"  {s:<10} token {len(tokens[s]):5d} B, HPACK entry {entry:5d} B, "
              f"adaptive -> {'reference' if DAFBSecurityContext.exceeds_hpack_budget(HEADER_NAME, tokens[s]) else 'inline'}")

    byte_rows, latency_rows, scenario_rows = [], [], []
    server = start_server(keys_file)
    relay = Relay(RELAY_PORT, SERVER_PORT)
    try:
        for n, (scheme, arm) in enumerate(order, 1):
            token = tokens.get(scheme)
            value_len = 0 if token is None else len(token.encode())
            common = dict(experiment_id=EXPERIMENT_ID, run_id=run_id, timestamp_utc=timestamp, link=args.link,
                          scenario=scheme, arm=arm, header_value_bytes=value_len,
                          hpack_entry_bytes=0 if token is None else len(HEADER_NAME) + value_len + 32)

            # 1. byte pass through the relay
            relay.reset()
            client = Client(RELAY_PORT, arm, token)
            prev = relay.snapshot()
            for i in range(1, BYTE_PASS_CALLS + 1):
                r = client.call()
                time.sleep(0.005)                       # let the relay forward the response frames
                now = relay.snapshot()
                d = [a - b for a, b in zip(now, prev)]
                byte_rows.append(dict(common, call=i, dafb_mode=r["dafb_mode"],
                                      c2s_header_bytes=d[0], c2s_header_frames=d[1], c2s_data_bytes=d[2],
                                      c2s_bytes=d[3], s2c_header_bytes=d[4], s2c_header_frames=d[5],
                                      s2c_data_bytes=d[6], s2c_bytes=d[7],
                                      status=r["status"], grpc_status=r["grpc_status"]))
                prev = now
            client.close()

            # 2. latency pass, direct
            client = Client(SERVER_PORT, arm, token)
            first = client.call()
            warm_fail = first["status"] != "success"
            for _ in range(args.warmup - 1):
                warm_fail += client.call()["status"] != "success"
            stats_before = dict(client.dafb.stats) if client.dafb else {}
            failed, lat = 0, []
            for i in range(1, args.measured + 1):
                r = client.call()
                failed += r["status"] != "success"
                lat.append(r["latency_ns"])
                latency_rows.append(dict(common, iteration=i, **r))
            counts = {k: v - stats_before.get(k, 0) for k, v in client.dafb.stats.items()} if client.dafb else {}
            client.close()

            scenario_rows.append(dict(
                common, first_call_latency_ns=first["latency_ns"], first_call_verify_ns=first["verify_ns"],
                first_call_mode=first["dafb_mode"], first_call_status=first["status"],
                warmup_failed=warm_fail, measured_failed=failed,
                measured_inline=counts.get("inline", ""), measured_register=counts.get("register", ""),
                measured_reference=counts.get("reference", ""),
                measured_handle_rejected=counts.get("handle_rejected", ""),
                measured_no_handle_issued=counts.get("no_handle_issued", "")))

            lat.sort()
            hb = [b["c2s_header_bytes"] for b in byte_rows[-BYTE_PASS_CALLS:]]
            print(f"[{n:2d}/{len(order)}] {scheme:<10} {arm:<15} median {lat[len(lat) // 2] / 1000:7.1f} us | "
                  f"HEADERS call1 {hb[0]:5d} B, call10 {hb[-1]:5d} B | failed {failed}, warm-up failed {warm_fail}",
                  flush=True)
    finally:
        relay.close()
        stop_server(server)
        try:
            os.unlink(keys_file)
        except OSError:
            pass

    append_csv(files["bytes"], byte_rows, list(byte_rows[0]))
    append_csv(files["latency"], latency_rows, list(latency_rows[0]))
    append_csv(files["scenarios"], scenario_rows, list(scenario_rows[0]))

    governors = sorted({read(p) for p in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")} - {""})
    try:
        import oqs
        oqs_version = oqs.oqs_python_version()
    except Exception:
        oqs_version = ""
    env = dict(run_id=run_id, timestamp_utc=timestamp, link=args.link,
               warmup=args.warmup, measured=args.measured,
               scenario_order=" > ".join(f"{s}/{a}" for s, a in order),
               cpu_governor="/".join(governors),
               intel_no_turbo=read("/sys/devices/system/cpu/intel_pstate/no_turbo"),
               client_core=CLIENT_CORE, server_core=SERVER_CORE,
               python=platform.python_version(), grpcio=grpc.__version__, liboqs_python=oqs_version,
               claim_exp=CLAIM_EXP, token_bytes="; ".join(f"{s}={len(tokens[s])}" for s in SCHEMES),
               tc_state=tc_text)
    append_csv(files["env"], [env], list(env))

    total_failed = sum(r["status"] != "success" for r in latency_rows)
    rejected = sum(int(r["measured_handle_rejected"] or 0) for r in scenario_rows)
    print("=" * 66)
    print(f"Measured calls: {len(latency_rows)}, failed: {total_failed}, handles rejected: {rejected}")
    print(f"CPU governor: {env['cpu_governor']}, no_turbo: {env['intel_no_turbo']}")
    print(f"Results appended to: {out}")


if __name__ == "__main__":
    main()
