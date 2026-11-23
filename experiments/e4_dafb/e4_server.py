"""
DAFB E4: gRPC server for DAFB vs no mitigation.

One server serves every E4 arm, so the baseline and DAFB share the same
process, verifier and interceptor:

  DAFBServerInterceptor (metadata key `authorization`, as in E2/E3)
    no x-dafb-mode + token   -> token verified on every call   (E3 verify path)
    x-dafb-mode: inline      -> token verified on every call
    x-dafb-mode: register    -> token verified, handle issued
    x-dafb-mode: reference   -> handle looked up, no verification

Verification uses interceptors.jws_tokens.TokenVerifier with the exp check on.
The signature-check time of the current call is returned in the trailing
metadata as `x-verify-ns` (0 when no signature was checked, e.g. reference).

Started automatically by e4_benchmark.py; by hand:
  python experiments/e4_dafb/e4_server.py --keys /tmp/keys.json --port 50080 --core 3
"""

import argparse
import base64
import json
import os
import sys
import threading
import time
from concurrent import futures
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIR))

import grpc

from interceptors.dafb_engine import DAFBServerInterceptor
from interceptors.jws_tokens import TokenVerifier
from protobufs import security_service_pb2 as pb2
from protobufs import security_service_pb2_grpc as pb2_grpc

HEADER_NAME = "authorization"


class TimedVerifier:
    """TokenVerifier wrapper that leaves the signature-check time in a thread-local slot.

    The DAFB interceptor runs authentication and the service method on the same
    thread, so the service reads (and clears) the slot of its own call.
    """

    def __init__(self, verifier):
        self.verifier = verifier
        self.local = threading.local()

    def __call__(self, token):
        claims = self.verifier(token)
        self.local.verify_ns = self.verifier.last_verify_ns
        return claims

    def take(self):
        ns = getattr(self.local, "verify_ns", 0)
        self.local.verify_ns = 0
        return ns


class Broker(pb2_grpc.CredentialBrokerServicer):
    def __init__(self, timed):
        self.timed = timed

    def RegisterCredential(self, request, context):
        context.set_trailing_metadata((("x-verify-ns", str(self.timed.take())),))
        return pb2.RegistrationResponse(opaque_handle="ok", expires_at=0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=50080)
    parser.add_argument("--core", type=int, default=None)
    parser.add_argument("--keys", required=True, help="JSON file {scheme: base64 public key}")
    args = parser.parse_args()

    if args.core is not None and hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {args.core})

    with open(args.keys) as f:
        public_keys = {k: base64.b64decode(v) for k, v in json.load(f).items()}
    timed = TimedVerifier(TokenVerifier(public_keys, check_exp=True))
    interceptor = DAFBServerInterceptor(metadata_auth_key=HEADER_NAME, token_verifier=timed, require_auth=False)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4), interceptors=[interceptor])
    pb2_grpc.add_CredentialBrokerServicer_to_server(Broker(timed), server)
    server.add_insecure_port(f"127.0.0.1:{args.port}")
    server.start()
    print(f"E4 server ready on 127.0.0.1:{args.port}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    main()
