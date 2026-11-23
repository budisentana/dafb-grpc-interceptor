"""
DAFB E7 (paper E5): server for the concurrent-load test.

E5 server (DAFBServerInterceptor + TokenVerifier with exp check, optional
VerifiedTokenCache), with a 16-worker thread pool, pinned to several cores.
On SIGUSR1 it writes its state to --stats-file (JSON): DAFB handle-store and
token-cache entries, their approximate size in bytes (sys.getsizeof over each
entry, its claims dict and items; objects shared between entries are counted
once per entry, so this is an upper bound), process RSS, verifier and
interceptor counters.

Started by e7_benchmark.py.
"""

import argparse
import base64
import json
import os
import signal
import sys
import time
from concurrent import futures
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIR))
sys.path.insert(0, str(PROJECT_DIR / "experiments" / "e4_dafb"))

import grpc

from e4_server import HEADER_NAME, Broker, TimedVerifier
from interceptors.dafb_engine import DAFBServerInterceptor
from interceptors.jws_tokens import TokenVerifier
from interceptors.token_cache import VerifiedTokenCache
from protobufs import security_service_pb2_grpc as pb2_grpc


def store_bytes(entries):
    """Approximate bytes of a {key: (claims, expiry)} store (see module docstring)."""
    total = sys.getsizeof(entries)
    for key, (claims, expires) in list(entries.items()):
        total += sys.getsizeof(key) + sys.getsizeof((claims, expires)) + sys.getsizeof(expires)
        total += sys.getsizeof(claims) + sum(sys.getsizeof(k) + sys.getsizeof(v) for k, v in claims.items())
    return total


def rss_kb():
    for line in open("/proc/self/status"):
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=50120)
    parser.add_argument("--cores", default="2,3")
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--keys", required=True)
    parser.add_argument("--token-cache", action="store_true")
    parser.add_argument("--stats-file", required=True)
    args = parser.parse_args()

    os.sched_setaffinity(0, {int(c) for c in args.cores.split(",")})
    with open(args.keys) as f:
        public_keys = {k: base64.b64decode(v) for k, v in json.load(f).items()}
    base_verifier = TokenVerifier(public_keys, check_exp=True)
    timed = TimedVerifier(base_verifier)
    cache = VerifiedTokenCache(timed) if args.token_cache else None
    interceptor = DAFBServerInterceptor(metadata_auth_key=HEADER_NAME, token_verifier=cache or timed,
                                        require_auth=False)

    def dump(signum, frame):
        state = dict(handles=len(interceptor.validation_cache),
                     handle_store_bytes=store_bytes(interceptor.validation_cache),
                     cache_entries=len(cache.entries) if cache else 0,
                     cache_store_bytes=store_bytes(cache.entries) if cache else 0,
                     cache_stats=cache.stats if cache else {}, interceptor_stats=interceptor.stats,
                     verifier_calls=base_verifier.calls, rss_kb=rss_kb())
        tmp = args.stats_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, args.stats_file)

    signal.signal(signal.SIGUSR1, dump)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=args.workers), interceptors=[interceptor])
    pb2_grpc.add_CredentialBrokerServicer_to_server(Broker(timed), server)
    server.add_insecure_port(f"127.0.0.1:{args.port}")
    server.start()
    print(f"E7 server ready on 127.0.0.1:{args.port} (cores {args.cores}, workers {args.workers}, "
          f"token_cache={args.token_cache})", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    main()
