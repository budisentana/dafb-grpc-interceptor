"""
DAFB E2: minimal gRPC server for the metadata benchmark.

No DAFB interceptor and no signature verification: the server only answers,
so the benchmark measures transport cost, not computation (that is E1/E1b).
Uses the existing CredentialBroker proto, so nothing needs regenerating.
gRPC limits are left at their defaults, as in a typical deployment.

Started automatically by e2_benchmark.py; can also be run by hand:
  python experiments/e2_metadata/e2_server.py --port 50060 --core 3
"""

import argparse
import os
import sys
import time
from concurrent import futures
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIR))

import grpc

from protobufs import security_service_pb2 as pb2
from protobufs import security_service_pb2_grpc as pb2_grpc


class EchoBroker(pb2_grpc.CredentialBrokerServicer):
    def RegisterCredential(self, request, context):
        return pb2.RegistrationResponse(opaque_handle="ok", expires_at=0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=50060)
    parser.add_argument("--core", type=int, default=None)
    args = parser.parse_args()

    if args.core is not None and hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {args.core})

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pb2_grpc.add_CredentialBrokerServicer_to_server(EchoBroker(), server)
    server.add_insecure_port(f"127.0.0.1:{args.port}")
    server.start()
    print(f"E2 server ready on 127.0.0.1:{args.port}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    main()
