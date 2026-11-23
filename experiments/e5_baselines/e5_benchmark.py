"""
DAFB E5: DAFB vs fair baselines.

Schemes ES256, EdDSA, ML-DSA-44/65/87 (+ none), same tokens as E4 (200-byte
claim set, exp 1 Jan 2028), same TokenVerifier with exp check everywhere.

Arms, grouped by the server configuration they need (one server process per
group; group order and scenario order shuffled per run):

  plain server
    none              no token
    e3_verify         baseline 1, no mitigation: bearer token, verified every call
    dafb_adaptive     DAFB, policy adaptive
    dafb_reference    DAFB, policy reference
    dafb_register     DAFB, every call registers (registration cost, as in E4)
  server --hpack-table 65536
    hpack_64k         baseline 2: bearer token; client encoder and server decoder
                      HPACK tables set to 64 KiB (grpc.http2.hpack_table_size.*)
  server --token-cache
    token_cache       baseline 3: bearer token, server skips verification on a cache hit
    token_cache_miss  baseline 3, every call a fresh token (always a miss):
                      the miss cost for the break-even

Transport (--transport): plaintext, or tls (every arm over TLS, self-signed
P-256 certificate generated per run). Link (--link): loopback or netem100
(netem on the E5 port 50100, checked against the tc state).

Per scenario, fresh connection (and fresh DAFB handle cache):
  1. byte pass, 10 calls through a relay. Plaintext: HTTP/2 frames parsed (E2
     method), HEADERS bytes per call in both directions. TLS: frames are
     encrypted, so only TCP payload bytes per call are counted (both directions).
  2. latency pass: 50 warm-up + 500 measured calls, direct.

One launch = one run; 5 runs per transport/link, then e5_analyze.py.
Output (experiments/e5_baselines/results/): e5_bytes.csv, e5_latency.csv,
e5_scenarios.csv, e5_run_environment.csv (rows tagged with transport and link).
"""

import argparse
import base64
import datetime as dt
import glob
import ipaddress
import json
import os
import platform
import random
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
sys.path.insert(0, str(PROJECT_DIR / "experiments" / "e4_dafb"))
sys.path.insert(0, str(PROJECT_DIR / "experiments" / "e2_metadata"))

import e4_benchmark as e4                       # claim set, relay, csv helpers (E4, unchanged)
from interceptors.dafb_engine import DAFBClientInterceptor
from interceptors.jws_tokens import SCHEMES, TokenSigner

E5_DIR = PROJECT_DIR / "experiments" / "e5_baselines"
RESULTS_DIR = E5_DIR / "results"
SERVER_SCRIPT = E5_DIR / "e5_server.py"

EXPERIMENT_ID = "E5"
SERVER_PORT = 50100
RELAY_PORT = 50101
CLIENT_CORE = 2
SERVER_CORE = 3
BYTE_PASS_CALLS = 10
WARMUP_REQUESTS = 50
MEASURED_REQUESTS = 500
HPACK_TABLE = 65536
HEADER_NAME = e4.HEADER_NAME
TLS_NAME = "localhost"

GROUPS = {
    "plain": dict(flags=[], arms=["e3_verify", "dafb_adaptive", "dafb_reference", "dafb_register"]),
    "hpack64k": dict(flags=["--hpack-table", str(HPACK_TABLE)], arms=["hpack_64k"]),
    "cache": dict(flags=["--token-cache"], arms=["token_cache", "token_cache_miss"]),
}
DAFB_POLICY = {"dafb_adaptive": "adaptive", "dafb_reference": "reference", "dafb_register": "reference"}


# --------------------------------------------------
# TLS material and link check
# --------------------------------------------------

def make_cert(directory):
    """Self-signed P-256 certificate for localhost / 127.0.0.1. Returns (cert_path, key_path, cert_pem)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TLS_NAME)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(TLS_NAME),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path, key_path = Path(directory) / "e5_cert.pem", Path(directory) / "e5_key.pem"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return str(cert_path), str(key_path), cert_pem


def check_link(link):
    qdisc, filters = e4.tc_state()
    netem_on = "netem" in qdisc
    if link == "loopback" and netem_on:
        sys.exit("netem is active on lo; turn it off for --link loopback")
    if link == "netem100" and (not netem_on or "rate 100Mbit" not in qdisc or f"{SERVER_PORT:04x}" not in filters):
        sys.exit(f"--link netem100 needs: sudo bash experiments/e2_metadata/e2b_netem.sh on 100mbit {SERVER_PORT}")
    return qdisc + " || " + filters.replace("\n", " ")


class RawCounter:
    """Byte counter for TLS traffic (frames cannot be parsed). Same snapshot shape as FrameCounter."""

    def __init__(self):
        self.lock = threading.Lock()
        self.total_bytes = 0
        self.preface_done = True

    def feed(self, chunk):
        with self.lock:
            self.total_bytes += len(chunk)

    def snapshot(self):
        with self.lock:
            return 0, 0, 0, self.total_bytes


class Relay(e4.Relay):
    def __init__(self, listen_port, target_port, tls):
        self.tls = tls
        super().__init__(listen_port, target_port)

    def reset(self):
        if getattr(self, "tls", False):
            self.c2s, self.s2c = RawCounter(), RawCounter()
        else:
            super().reset()


# --------------------------------------------------
# Server and client
# --------------------------------------------------

def start_server(keys_file, flags, tls_files):
    cmd = [sys.executable, str(SERVER_SCRIPT), "--port", str(SERVER_PORT), "--core", str(SERVER_CORE),
           "--keys", keys_file] + flags
    if tls_files:
        cmd += ["--tls", *tls_files]
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
    raise RuntimeError("E5 server did not start: " + " | ".join(seen))


class Client(e4.Client):
    """E4 client with TLS, HPACK options and a token source (fixed token, or a fresh token per call)."""

    def __init__(self, port, arm, tokens, cert_pem):
        import grpc
        from protobufs import security_service_pb2 as pb2
        from protobufs import security_service_pb2_grpc as pb2_grpc
        self.grpc = grpc
        self.arm = arm
        self.tokens = tokens                           # iterator of token strings, or None
        self.metadata = [] if tokens is None else [(HEADER_NAME, "")]
        options = [("grpc.use_local_subchannel_pool", 1)]
        if arm == "hpack_64k":
            options.append(("grpc.http2.hpack_table_size.encoder", HPACK_TABLE))
        target = f"127.0.0.1:{port}"
        if cert_pem:
            options.append(("grpc.ssl_target_name_override", TLS_NAME))
            self.channel = grpc.secure_channel(target, grpc.ssl_channel_credentials(root_certificates=cert_pem),
                                               options=options)
        else:
            self.channel = grpc.insecure_channel(target, options=options)
        grpc.channel_ready_future(self.channel).result(timeout=10)
        self.dafb = None
        channel = self.channel
        if arm in DAFB_POLICY:
            self.dafb = DAFBClientInterceptor(metadata_auth_key=HEADER_NAME, policy=DAFB_POLICY[arm])
            channel = grpc.intercept_channel(self.channel, self.dafb)
        self.stub = pb2_grpc.CredentialBrokerStub(channel)
        self.request = pb2.RegistrationRequest(raw_token="e5")

    def call(self):
        if self.tokens is not None:
            self.metadata = [(HEADER_NAME, next(self.tokens))]   # outside the timed region
        return super().call()


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--transport", choices=["plaintext", "tls"], required=True)
    parser.add_argument("--link", choices=e4.LINKS, default="loopback")
    parser.add_argument("--measured", type=int, default=MEASURED_REQUESTS, help="for smoke tests only")
    parser.add_argument("--warmup", type=int, default=WARMUP_REQUESTS, help="for smoke tests only")
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR, help="for smoke tests only")
    args = parser.parse_args()
    tc_text = check_link(args.link)

    import grpc
    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {CLIENT_CORE})

    out = args.results_dir
    run_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    tmpdir = tempfile.mkdtemp(prefix="e5_")
    tls = args.transport == "tls"
    tls_files, cert_pem = None, None
    if tls:
        cert_path, key_path, cert_pem = make_cert(tmpdir)
        tls_files = (cert_path, key_path)

    signers = {s: TokenSigner(s) for s in SCHEMES}
    tokens = {s: signers[s].make_token(e4.claim_set()) for s in SCHEMES}
    # token_cache_miss: distinct tokens (jti differs, same length), never reused in the run
    per_scenario = BYTE_PASS_CALLS + args.warmup + args.measured
    fresh = {s: iter([signers[s].make_token(e4.claim_set(jti_seed=i + 1)) for i in range(per_scenario)])
             for s in SCHEMES}
    keys_file = str(Path(tmpdir) / "e5_pubkeys.json")
    with open(keys_file, "w") as f:
        json.dump({s: base64.b64encode(sg.public_key).decode() for s, sg in signers.items()}, f)

    group_order = list(GROUPS)
    random.shuffle(group_order)
    plan = []
    for g in group_order:
        scen = [(s, a) for s in SCHEMES for a in GROUPS[g]["arms"]] + ([("none", "none")] if g == "plain" else [])
        random.shuffle(scen)
        plan += [(g, s, a) for s, a in scen]

    print("=" * 70)
    print(f"DAFB E5: DAFB vs fair baselines, transport: {args.transport}, link: {args.link}")
    print("=" * 70)
    print(f"Run ID: {run_id}; {len(plan)} scenarios; byte pass {BYTE_PASS_CALLS}, "
          f"{args.warmup} warm-up + {args.measured} measured")

    byte_rows, latency_rows, scenario_rows = [], [], []
    server, current = None, None
    relay = Relay(RELAY_PORT, SERVER_PORT, tls)
    try:
        for n, (group, scheme, arm) in enumerate(plan, 1):
            if group != current:
                if server:
                    e4.stop_server(server)
                server = start_server(keys_file, GROUPS[group]["flags"], tls_files)
                current = group

            def source():
                if scheme == "none":
                    return None
                if arm == "token_cache_miss":
                    return fresh[scheme]
                return iter(lambda: tokens[scheme], None)      # endless fixed token

            token = tokens.get(scheme)
            value_len = 0 if token is None else len(token.encode())
            common = dict(experiment_id=EXPERIMENT_ID, run_id=run_id, timestamp_utc=timestamp,
                          transport=args.transport, link=args.link, server_group=group,
                          scenario=scheme, arm=arm, header_value_bytes=value_len)

            # 1. byte pass
            relay.reset()
            client = Client(RELAY_PORT, arm, source(), cert_pem)
            prev = relay.snapshot()
            for i in range(1, BYTE_PASS_CALLS + 1):
                r = client.call()
                time.sleep(0.005)
                now = relay.snapshot()
                d = [a - b for a, b in zip(now, prev)]
                byte_rows.append(dict(common, call=i, dafb_mode=r["dafb_mode"],
                                      c2s_header_bytes="" if tls else d[0], c2s_bytes=d[3],
                                      s2c_header_bytes="" if tls else d[4], s2c_bytes=d[7],
                                      status=r["status"], grpc_status=r["grpc_status"]))
                prev = now
            client.close()

            # 2. latency pass
            client = Client(SERVER_PORT, arm, source(), cert_pem)
            first = client.call()
            warm_fail = first["status"] != "success"
            for _ in range(args.warmup - 1):
                warm_fail += client.call()["status"] != "success"
            stats_before = dict(client.dafb.stats) if client.dafb else {}
            failed, lat, verified = 0, [], 0
            for i in range(1, args.measured + 1):
                r = client.call()
                failed += r["status"] != "success"
                verified += r["verify_ns"] > 0
                lat.append(r["latency_ns"])
                latency_rows.append(dict(common, iteration=i, **r))
            counts = {k: v - stats_before.get(k, 0) for k, v in client.dafb.stats.items()} if client.dafb else {}
            client.close()

            scenario_rows.append(dict(
                common, first_call_latency_ns=first["latency_ns"], first_call_mode=first["dafb_mode"],
                warmup_failed=warm_fail, measured_failed=failed, measured_verified=verified,
                measured_register=counts.get("register", ""), measured_reference=counts.get("reference", ""),
                measured_handle_rejected=counts.get("handle_rejected", "")))

            lat.sort()
            b = byte_rows[-BYTE_PASS_CALLS:]
            col = "c2s_bytes" if tls else "c2s_header_bytes"
            print(f"[{n:2d}/{len(plan)}] {scheme:<10} {arm:<17} median {lat[len(lat) // 2] / 1000:7.1f} us | "
                  f"{'c2s' if tls else 'HEADERS'} call1 {b[0][col]:5d} B, call10 {b[-1][col]:5d} B | "
                  f"verified {verified}/{args.measured}, failed {failed}", flush=True)
    finally:
        relay.close()
        if server:
            e4.stop_server(server)

    e4.append_csv(out / "e5_bytes.csv", byte_rows, list(byte_rows[0]))
    e4.append_csv(out / "e5_latency.csv", latency_rows, list(latency_rows[0]))
    e4.append_csv(out / "e5_scenarios.csv", scenario_rows, list(scenario_rows[0]))

    governors = sorted({e4.read(p) for p in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")} - {""})
    try:
        import oqs
        oqs_version = oqs.oqs_python_version()
    except Exception:
        oqs_version = ""
    env = dict(run_id=run_id, timestamp_utc=timestamp, transport=args.transport, link=args.link,
               warmup=args.warmup, measured=args.measured, hpack_table=HPACK_TABLE,
               scenario_order=" > ".join(f"{g}:{s}/{a}" for g, s, a in plan),
               cpu_governor="/".join(governors),
               intel_no_turbo=e4.read("/sys/devices/system/cpu/intel_pstate/no_turbo"),
               client_core=CLIENT_CORE, server_core=SERVER_CORE, python=platform.python_version(),
               grpcio=grpc.__version__, liboqs_python=oqs_version, claim_exp=e4.CLAIM_EXP,
               token_bytes="; ".join(f"{s}={len(tokens[s])}" for s in SCHEMES), tc_state=tc_text)
    e4.append_csv(out / "e5_run_environment.csv", [env], list(env))

    total_failed = sum(r["status"] != "success" for r in latency_rows)
    print("=" * 70)
    print(f"Measured calls: {len(latency_rows)}, failed: {total_failed}")
    print(f"CPU governor: {env['cpu_governor']}, no_turbo: {env['intel_no_turbo']}")
    print(f"Results appended to: {out}")


if __name__ == "__main__":
    main()
