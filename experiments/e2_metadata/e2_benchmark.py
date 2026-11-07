"""
DAFB E2: cost of post-quantum bearer tokens in gRPC metadata.

Part A: real bearer tokens in the standard `authorization` header
        (none, ES256, EdDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87),
        each with the same 200-byte claim set (Table 4 of the Lontar paper).
Part B: synthetic tokens (base64url characters, like real tokens) from
        1,000 to 6,000 bytes, to locate where HPACK stops storing the header.

For every scenario, in a fresh TCP connection each time:
  1. byte pass:    10 calls through a local relay that reads the HTTP/2
                   frames and records the HEADERS bytes of every call
  2. latency pass: 50 warm-up + 500 measured calls, direct (no relay)

One launch = one run (as in E1/E1b); run it 5 times.
The E2 server (e2_server.py) is started and stopped automatically.

Output (experiments/e2_metadata/results/):
  e2_bytes.csv             one row per call of the byte pass
  e2_latency.csv           one row per measured call
  e2_run_environment.csv   CPU settings, versions and token sizes per run
"""

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
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIR))

E2_DIR = PROJECT_DIR / "experiments" / "e2_metadata"
RESULTS_DIR = E2_DIR / "results"
BYTES_FILE = RESULTS_DIR / "e2_bytes.csv"
LATENCY_FILE = RESULTS_DIR / "e2_latency.csv"
ENV_FILE = RESULTS_DIR / "e2_run_environment.csv"
SERVER_SCRIPT = Path(__file__).resolve().parent / "e2_server.py"

EXPERIMENT_ID = "E2"
SERVER_PORT = 50060
RELAY_PORT = 50061
CLIENT_CORE = 2
SERVER_CORE = 3

BYTE_PASS_CALLS = 10
WARMUP_REQUESTS = 50
MEASURED_REQUESTS = 500

HEADER_NAME = "authorization"
HPACK_TABLE = 4096
SWEEP_SIZES = list(range(1000, 6001, 250)) + [4051, 4052]   # header value lengths
TOKEN_SCHEMES = ["ES256", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


# --------------------------------------------------
# Tokens
# --------------------------------------------------

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def claim_set(size=200):
    """Fixed JSON claim set of exactly `size` bytes."""
    claims = {
        "sub": "mldsa65_experiment_client", "role": "research_experimenter",
        "iss": "dafb-e2", "aud": "dafb-grpc", "iat": 1767225600, "exp": 1767229200, "jti": "",
    }
    base = len(json.dumps(claims, separators=(",", ":")).encode())
    claims["jti"] = "x" * (size - base)
    data = json.dumps(claims, separators=(",", ":")).encode()
    assert len(data) == size, len(data)
    return data


def sign(scheme, message):
    """Return (signature bytes, how it was produced)."""
    if scheme == "ES256":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        der = ec.generate_private_key(ec.SECP256R1()).sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big"), "cryptography"   # JWS raw r||s
    if scheme == "EdDSA":
        from cryptography.hazmat.primitives.asymmetric import ed25519
        return ed25519.Ed25519PrivateKey.generate().sign(message), "cryptography"
    import oqs
    with oqs.Signature(scheme) as signer:
        signer.generate_keypair()
        return signer.sign(message), "liboqs"


def bearer_token(scheme):
    header = json.dumps({"alg": scheme, "typ": "JWT"}, separators=(",", ":")).encode()
    signing_input = f"{b64url(header)}.{b64url(claim_set())}"
    signature, source = sign(scheme, signing_input.encode())
    return f"Bearer {signing_input}.{b64url(signature)}", len(signature), source


def synthetic_value(length):
    """Header value of exactly `length` characters: 'Bearer ' + base64url text."""
    rng = random.Random(length)
    return "Bearer " + "".join(rng.choice(B64_ALPHABET) for _ in range(length - 7))


def scenarios():
    items = [dict(part="A", scenario="none", value=None, signature_bytes=0, source="")]
    for scheme in TOKEN_SCHEMES:
        value, sig_len, source = bearer_token(scheme)
        items.append(dict(part="A", scenario=scheme, value=value, signature_bytes=sig_len, source=source))
    for size in sorted(set(SWEEP_SIZES)):
        items.append(dict(part="B", scenario=f"S{size}", value=synthetic_value(size), signature_bytes=0, source="synthetic"))
    return items


# --------------------------------------------------
# HTTP/2 byte-counting relay (client -> server direction is parsed)
# --------------------------------------------------

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HEADERS, CONTINUATION, DATA = 0x1, 0x9, 0x0


class FrameCounter:
    """Parses an HTTP/2 client byte stream and counts bytes by frame type."""

    def __init__(self):
        self.buffer = b""
        self.preface_done = False
        self.lock = threading.Lock()
        self.header_bytes = 0       # HEADERS + CONTINUATION, incl. 9-byte frame headers
        self.header_frames = 0
        self.data_bytes = 0         # DATA, incl. frame headers
        self.total_bytes = 0        # everything client -> server

    def feed(self, chunk):
        with self.lock:
            self.total_bytes += len(chunk)
            self.buffer += chunk
            if not self.preface_done:
                if len(self.buffer) < len(PREFACE):
                    return
                self.buffer = self.buffer[len(PREFACE):]
                self.preface_done = True
            while len(self.buffer) >= 9:
                length = int.from_bytes(self.buffer[0:3], "big")
                if len(self.buffer) < 9 + length:
                    break
                frame_type = self.buffer[3]
                if frame_type in (HEADERS, CONTINUATION):
                    self.header_bytes += 9 + length
                    self.header_frames += 1
                elif frame_type == DATA:
                    self.data_bytes += 9 + length
                self.buffer = self.buffer[9 + length:]

    def snapshot(self):
        with self.lock:
            return self.header_bytes, self.header_frames, self.data_bytes, self.total_bytes


class Relay:
    """Local TCP relay: 127.0.0.1:listen_port -> 127.0.0.1:target_port."""

    def __init__(self, listen_port, target_port):
        self.target_port = target_port
        self.counter = FrameCounter()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", listen_port))
        self.sock.listen(8)
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()

    def reset(self):
        self.counter = FrameCounter()

    def _accept(self):
        while self.running:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            upstream = socket.create_connection(("127.0.0.1", self.target_port))
            for s in (client, upstream):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            counter = self.counter
            threading.Thread(target=self._pump, args=(client, upstream, counter), daemon=True).start()
            threading.Thread(target=self._pump, args=(upstream, client, None), daemon=True).start()

    @staticmethod
    def _pump(src, dst, counter):
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                if counter is not None:
                    counter.feed(chunk)       # counted before it is forwarded
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
# gRPC calls
# --------------------------------------------------

def new_channel(port):
    import grpc
    # Local subchannel pool forces a new TCP connection, so every scenario
    # starts with an empty HPACK table.
    channel = grpc.insecure_channel(f"127.0.0.1:{port}", options=[("grpc.use_local_subchannel_pool", 1)])
    grpc.channel_ready_future(channel).result(timeout=10)
    return channel


def call(stub, request, metadata):
    import grpc
    start = time.perf_counter_ns()
    try:
        stub.RegisterCredential(request, metadata=metadata, timeout=10.0)
        return time.perf_counter_ns() - start, "success", "OK", ""
    except grpc.RpcError as exc:
        return time.perf_counter_ns() - start, "error", str(exc.code()), str(exc.details())[:200]


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
    items = scenarios()
    order = items[:]
    random.shuffle(order)
    request = pb2.RegistrationRequest(raw_token="e2")

    print("=" * 60)
    print("DAFB E2: post-quantum bearer tokens in gRPC metadata")
    print("=" * 60)
    print(f"Run ID: {run_id}")
    print(f"Scenarios: {len(items)} (Part A: 6 tokens, Part B: {len(items) - 6} sizes), shuffled")

    server = subprocess.Popen([sys.executable, str(SERVER_SCRIPT), "--port", str(SERVER_PORT), "--core", str(SERVER_CORE)],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    relay = None
    byte_rows, latency_rows = [], []
    try:
        line = server.stdout.readline().strip()
        print(line)
        if "ready" not in line:
            raise RuntimeError(f"E2 server did not start: {line}")
        relay = Relay(RELAY_PORT, SERVER_PORT)

        for n, item in enumerate(order, 1):
            value = item["value"]
            metadata = [] if value is None else [(HEADER_NAME, value)]
            value_len = 0 if value is None else len(value.encode())
            entry = 0 if value is None else len(HEADER_NAME) + value_len + 32
            common = dict(experiment_id=EXPERIMENT_ID, run_id=run_id, timestamp_utc=timestamp,
                          part=item["part"], scenario=item["scenario"],
                          header_value_bytes=value_len, hpack_entry_bytes=entry)

            # 1. byte pass through the relay, fresh connection
            relay.reset()
            channel = new_channel(RELAY_PORT)
            stub = pb2_grpc.CredentialBrokerStub(channel)
            prev = relay.counter.snapshot()
            for i in range(1, BYTE_PASS_CALLS + 1):
                _, status, code, _ = call(stub, request, metadata)
                now = relay.counter.snapshot()
                byte_rows.append(dict(common, call=i,
                                      header_bytes=now[0] - prev[0], header_frames=now[1] - prev[1],
                                      data_bytes=now[2] - prev[2], c2s_bytes=now[3] - prev[3],
                                      status=status, grpc_status=code))
                prev = now
            channel.close()

            # 2. latency pass, direct, fresh connection
            channel = new_channel(SERVER_PORT)
            stub = pb2_grpc.CredentialBrokerStub(channel)
            warm_fail = sum(call(stub, request, metadata)[1] != "success" for _ in range(WARMUP_REQUESTS))
            failed = 0
            for i in range(1, MEASURED_REQUESTS + 1):
                ns, status, code, err = call(stub, request, metadata)
                failed += status != "success"
                latency_rows.append(dict(common, iteration=i, latency_ns=ns,
                                         status=status, grpc_status=code, error=err))
            channel.close()

            first = byte_rows[-BYTE_PASS_CALLS]["header_bytes"]
            later = byte_rows[-1]["header_bytes"]
            print(f"[{n:2d}/{len(order)}] {item['scenario']:<10} value {value_len:>5} B | "
                  f"headers call 1: {first:>5} B, call {BYTE_PASS_CALLS}: {later:>5} B | "
                  f"failed: {failed}, warm-up failed: {warm_fail}", flush=True)
    finally:
        if relay:
            relay.close()
        server.terminate()
        server.wait(timeout=10)

    append_csv(BYTES_FILE, byte_rows, list(byte_rows[0]))
    append_csv(LATENCY_FILE, latency_rows, list(latency_rows[0]))

    governors = sorted({read(p) for p in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")} - {""})
    try:
        import oqs
        oqs_version = oqs.oqs_python_version()
    except Exception:
        oqs_version = ""
    env = dict(run_id=run_id, timestamp_utc=timestamp,
               scenario_order=" > ".join(i["scenario"] for i in order),
               cpu_governor="/".join(governors),
               intel_no_turbo=read("/sys/devices/system/cpu/intel_pstate/no_turbo"),
               client_core=CLIENT_CORE, server_core=SERVER_CORE,
               python=platform.python_version(), grpcio=grpc.__version__, liboqs_python=oqs_version,
               token_sizes="; ".join(f"{i['scenario']}={len(i['value'] or '')}/{i['signature_bytes']}/{i['source']}"
                                     for i in items if i["part"] == "A"))
    append_csv(ENV_FILE, [env], list(env))

    total_failed = sum(r["status"] != "success" for r in latency_rows + byte_rows)
    print("=" * 60)
    print(f"Calls: {len(latency_rows) + len(byte_rows)}, failed: {total_failed}")
    print(f"CPU governor: {env['cpu_governor']}, no_turbo: {env['intel_no_turbo']}")
    print(f"Results appended to: {RESULTS_DIR}")
    print("E2 run completed. Run 5 times in total, then run e2_analyze.py.")


if __name__ == "__main__":
    main()
