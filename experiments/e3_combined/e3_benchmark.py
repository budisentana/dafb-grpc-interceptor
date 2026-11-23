"""
DAFB E3: combined cryptographic and gRPC cost of bearer-token authentication.

E1/E1b measured signing and verification alone; E2 measured the token on the
wire with no verification. E3 puts both into the same gRPC call, as a real
deployment does, and serves as the baseline that the DAFB reference path
(E4-E5) will be compared against.

Schemes: ES256, EdDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87 (same 200-byte claim
set and token format as E2), plus `none` (no token).

Modes:
  send_only    token sent on every call, server does not verify   (= E2 path)
  verify       one token reused, server verifies it on every call (bearer JWT)
  sign_verify  client signs a fresh token for every call, server verifies it
               (per-request signing)

For every scenario, on a fresh TCP connection: 50 warm-up + 500 measured
calls. The server returns its verification time in trailing metadata
(x-verify-ns) so latency can be split into verification and the rest.
Scenario order is shuffled; the server is restarted between the
non-verifying and the verifying group.

One launch = one run (as in E1b/E2); run it 5 times, then e3_analyze.py.

Output (experiments/e3_combined/results/):
  e3_latency.csv           one row per measured call
  e3_run_environment.csv   CPU settings, versions and token sizes per run
"""

import base64
import csv
import glob
import json
import os
import platform
import random
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIR))

E3_DIR = PROJECT_DIR / "experiments" / "e3_combined"
RESULTS_DIR = E3_DIR / "results"
LATENCY_FILE = RESULTS_DIR / "e3_latency.csv"
ENV_FILE = RESULTS_DIR / "e3_run_environment.csv"
SERVER_SCRIPT = E3_DIR / "e3_server.py"

EXPERIMENT_ID = "E3"
SERVER_PORT = 50070
CLIENT_CORE = 2
SERVER_CORE = 3

WARMUP_REQUESTS = 50
MEASURED_REQUESTS = 500

HEADER_NAME = "authorization"
SCHEMES = ["ES256", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
MODES = ["send_only", "verify", "sign_verify"]


# --------------------------------------------------
# Keys, signing and tokens
# --------------------------------------------------

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class Signer:
    """One key pair per scheme per run; the signing object is kept open."""

    def __init__(self, scheme):
        self.scheme = scheme
        if scheme == "ES256":
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
            key = ec.generate_private_key(ec.SECP256R1())
            self.public_key = key.public_key().public_bytes(serialization.Encoding.X962,
                                                            serialization.PublicFormat.UncompressedPoint)

            def sign(message):
                r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
                return r.to_bytes(32, "big") + s.to_bytes(32, "big")   # JWS raw r||s
            self.source = "cryptography"
        elif scheme == "EdDSA":
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
            key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = key.public_key().public_bytes(serialization.Encoding.Raw,
                                                            serialization.PublicFormat.Raw)
            sign = key.sign
            self.source = "cryptography"
        else:
            import oqs
            self._oqs = oqs.Signature(scheme)
            self.public_key = self._oqs.generate_keypair()
            sign = self._oqs.sign
            self.source = "liboqs"
        self.sign = sign
        self.header_b64 = b64url(json.dumps({"alg": scheme, "typ": "JWT"}, separators=(",", ":")).encode())


def claim_set(jti_seed, size=200):
    """JSON claim set of exactly `size` bytes; jti changes per token (same length)."""
    claims = {
        "sub": "mldsa65_experiment_client", "role": "research_experimenter",
        "iss": "dafb-e3", "aud": "dafb-grpc", "iat": 1767225600, "exp": 1767229200, "jti": "",
    }
    base = len(json.dumps(claims, separators=(",", ":")).encode())
    pad = size - base
    claims["jti"] = f"{jti_seed:0{pad}d}"[-pad:]
    data = json.dumps(claims, separators=(",", ":")).encode()
    assert len(data) == size, len(data)
    return data


def make_token(signer, jti_seed):
    signing_input = f"{signer.header_b64}.{b64url(claim_set(jti_seed))}"
    signature = signer.sign(signing_input.encode("ascii"))
    return f"Bearer {signing_input}.{b64url(signature)}", len(signature)


# --------------------------------------------------
# gRPC
# --------------------------------------------------

def start_server(keys_file, verify):
    cmd = [sys.executable, str(SERVER_SCRIPT), "--port", str(SERVER_PORT), "--core", str(SERVER_CORE),
           "--keys", keys_file]
    if verify:
        cmd.append("--verify")
    server = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # liboqs may print notices first (e.g. "faulthandler is disabled"); wait for the ready line.
    seen = []
    for _ in range(20):
        line = server.stdout.readline()
        if not line:
            break
        line = line.strip()
        seen.append(line)
        if "ready" in line:
            print(line, flush=True)
            return server
    server.kill()
    raise RuntimeError("E3 server did not start: " + " | ".join(seen))


def stop_server(server):
    server.terminate()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()


def new_channel():
    import grpc
    # Local subchannel pool forces a new TCP connection per scenario (empty HPACK table).
    channel = grpc.insecure_channel(f"127.0.0.1:{SERVER_PORT}", options=[("grpc.use_local_subchannel_pool", 1)])
    grpc.channel_ready_future(channel).result(timeout=10)
    return channel


def trailer(call_obj, key):
    for k, v in call_obj.trailing_metadata() or ():
        if k == key:
            return int(v)
    return 0


def one_call(stub, request, signer, mode, fixed_token, seq):
    """Returns a dict with the timings of one call."""
    import grpc
    start = time.perf_counter_ns()
    sign_ns = 0
    if signer is None:
        metadata = []
    elif mode == "sign_verify":
        s0 = time.perf_counter_ns()
        token, _ = make_token(signer, seq)
        sign_ns = time.perf_counter_ns() - s0
        metadata = [(HEADER_NAME, token)]
    else:
        metadata = [(HEADER_NAME, fixed_token)]
    try:
        _, call_obj = stub.RegisterCredential.with_call(request, metadata=metadata, timeout=10.0)
        latency = time.perf_counter_ns() - start
        return dict(latency_ns=latency, sign_ns=sign_ns, verify_ns=trailer(call_obj, "x-verify-ns"),
                    handler_ns=trailer(call_obj, "x-handler-ns"), status="success", grpc_status="OK", error="")
    except grpc.RpcError as exc:
        latency = time.perf_counter_ns() - start
        return dict(latency_ns=latency, sign_ns=sign_ns, verify_ns=0, handler_ns=0,
                    status="error", grpc_status=str(exc.code()), error=str(exc.details())[:200])


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
    import grpc
    from protobufs import security_service_pb2 as pb2
    from protobufs import security_service_pb2_grpc as pb2_grpc

    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {CLIENT_CORE})

    run_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    request = pb2.RegistrationRequest(raw_token="e3")

    signers = {s: Signer(s) for s in SCHEMES}
    fixed_tokens, sig_sizes = {}, {}
    for s, signer in signers.items():
        fixed_tokens[s], sig_sizes[s] = make_token(signer, 0)

    keys_fd, keys_file = tempfile.mkstemp(prefix="e3_pubkeys_", suffix=".json")
    with os.fdopen(keys_fd, "w") as f:
        json.dump({s: base64.b64encode(sg.public_key).decode() for s, sg in signers.items()}, f)

    # Groups: non-verifying server (none + send_only), verifying server (verify + sign_verify)
    groups = {
        False: [("none", "none")] + [(s, "send_only") for s in SCHEMES],
        True: [(s, m) for s in SCHEMES for m in ("verify", "sign_verify")],
    }
    group_order = [False, True]
    random.shuffle(group_order)
    for g in groups.values():
        random.shuffle(g)
    order = [(v, sc) for v in group_order for sc in groups[v]]

    print("=" * 60)
    print("DAFB E3: combined crypto + gRPC cost of bearer-token authentication")
    print("=" * 60)
    print(f"Run ID: {run_id}")
    print(f"Scenarios: {len(order)}, shuffled; {WARMUP_REQUESTS} warm-up + {MEASURED_REQUESTS} measured each")

    rows = []
    server = None
    current_verify = None
    try:
        for n, (verify, (scheme, mode)) in enumerate(order, 1):
            if verify != current_verify:
                if server:
                    stop_server(server)
                server = start_server(keys_file, verify)
                current_verify = verify

            signer = None if scheme == "none" else signers[scheme]
            token = fixed_tokens.get(scheme)
            value_len = 0 if token is None else len(token.encode())
            common = dict(experiment_id=EXPERIMENT_ID, run_id=run_id, timestamp_utc=timestamp,
                          scenario=scheme, mode=mode, server_verifies=int(verify),
                          header_value_bytes=value_len, signature_bytes=sig_sizes.get(scheme, 0))

            channel = new_channel()
            stub = pb2_grpc.CredentialBrokerStub(channel)
            seq = 0
            warm_fail = 0
            for _ in range(WARMUP_REQUESTS):
                seq += 1
                warm_fail += one_call(stub, request, signer, mode, token, seq)["status"] != "success"
            failed = 0
            lat = []
            for i in range(1, MEASURED_REQUESTS + 1):
                seq += 1
                r = one_call(stub, request, signer, mode, token, seq)
                failed += r["status"] != "success"
                lat.append(r["latency_ns"])
                rows.append(dict(common, iteration=i, **r))
            channel.close()

            lat.sort()
            print(f"[{n:2d}/{len(order)}] {scheme:<10} {mode:<11} median {lat[len(lat) // 2] / 1000:7.1f} us | "
                  f"failed: {failed}, warm-up failed: {warm_fail}", flush=True)
    finally:
        if server:
            stop_server(server)
        try:
            os.unlink(keys_file)
        except OSError:
            pass

    append_csv(LATENCY_FILE, rows, list(rows[0]))

    governors = sorted({read(p) for p in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")} - {""})
    try:
        import oqs
        oqs_version = oqs.oqs_python_version()
    except Exception:
        oqs_version = ""
    env = dict(run_id=run_id, timestamp_utc=timestamp,
               scenario_order=" > ".join(f"{s}/{m}" for _, (s, m) in order),
               cpu_governor="/".join(governors),
               intel_no_turbo=read("/sys/devices/system/cpu/intel_pstate/no_turbo"),
               client_core=CLIENT_CORE, server_core=SERVER_CORE,
               python=platform.python_version(), grpcio=grpc.__version__, liboqs_python=oqs_version,
               token_sizes="; ".join(f"{s}={len(fixed_tokens[s])}/{sig_sizes[s]}/{signers[s].source}"
                                     for s in SCHEMES))
    append_csv(ENV_FILE, [env], list(env))

    total_failed = sum(r["status"] != "success" for r in rows)
    print("=" * 60)
    print(f"Calls: {len(rows)}, failed: {total_failed}")
    print(f"CPU governor: {env['cpu_governor']}, no_turbo: {env['intel_no_turbo']}")
    print(f"Results appended to: {RESULTS_DIR}")
    print("E3 run completed. Run 5 times in total, then run e3_analyze.py.")


if __name__ == "__main__":
    main()
