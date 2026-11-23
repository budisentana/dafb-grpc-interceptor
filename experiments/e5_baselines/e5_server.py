"""
DAFB E5: gRPC server for DAFB vs fair baselines.

Same as the E4 server (DAFBServerInterceptor, metadata key `authorization`,
TokenVerifier with exp check, verify time in trailing `x-verify-ns`), plus:

  --token-cache      verifier wrapped by interceptors.token_cache.VerifiedTokenCache
                     (baseline 3: full token sent, verification skipped on a hit)
  --hpack-table N    server option grpc.http2.hpack_table_size.decoder = N
                     (baseline 2: larger HPACK dynamic table advertised to the client)
  --tls CERT KEY     serve over TLS instead of plaintext

Started automatically by e5_benchmark.py.
"""

import argparse
import base64
import json
import os
import sys
import time
from concurrent import futures
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIR))
sys.path.insert(0, str(PROJECT_DIR / "experiments" / "e4_dafb"))

import grpc

from e4_server import HEADER_NAME, Broker, TimedVerifier   # same service and timing as E4
from interceptors.dafb_engine import DAFBServerInterceptor
from interceptors.jws_tokens import TokenVerifier
from interceptors.token_cache import VerifiedTokenCache
from protobufs import security_service_pb2_grpc as pb2_grpc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=50100)
    parser.add_argument("--core", type=int, default=None)
    parser.add_argument("--keys", required=True, help="JSON file {scheme: base64 public key}")
    parser.add_argument("--token-cache", action="store_true")
    parser.add_argument("--hpack-table", type=int, default=0)
    parser.add_argument("--tls", nargs=2, metavar=("CERT", "KEY"))
    args = parser.parse_args()

    if args.core is not None and hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {args.core})

    with open(args.keys) as f:
        public_keys = {k: base64.b64decode(v) for k, v in json.load(f).items()}
    timed = TimedVerifier(TokenVerifier(public_keys, check_exp=True))
    verifier = VerifiedTokenCache(timed) if args.token_cache else timed   # a hit leaves x-verify-ns at 0
    interceptor = DAFBServerInterceptor(metadata_auth_key=HEADER_NAME, token_verifier=verifier, require_auth=False)

    options = [("grpc.http2.hpack_table_size.decoder", args.hpack_table)] if args.hpack_table else []
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4), interceptors=[interceptor], options=options)
    pb2_grpc.add_CredentialBrokerServicer_to_server(Broker(timed), server)
    address = f"127.0.0.1:{args.port}"
    if args.tls:
        with open(args.tls[0], "rb") as c, open(args.tls[1], "rb") as k:
            creds = grpc.ssl_server_credentials([(k.read(), c.read())])
        server.add_secure_port(address, creds)
    else:
        server.add_insecure_port(address)
    server.start()
    print(f"E5 server ready on {address} (token_cache={args.token_cache}, hpack_table={args.hpack_table}, "
          f"tls={bool(args.tls)})", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    main()
