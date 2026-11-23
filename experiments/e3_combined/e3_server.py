"""
DAFB E3: gRPC server that verifies the bearer token on every call.

Same echo service as E2, plus real signature verification of the token in the
`authorization` header (JWS compact form: header.claims.signature). The
verification time is measured inside the server and returned in the trailing
metadata as `x-verify-ns`, so the client can split the end-to-end latency
into verification and everything else.

  --verify     verify every token (E3 modes `verify` and `sign_verify`)
  (no flag)    accept the token without verifying it (E3 mode `send_only`)

Verifier objects are created once at start-up and reused, as a real server
would; E1b instead created a fresh liboqs object per operation.

Started automatically by e3_benchmark.py; can also be run by hand:
  python experiments/e3_combined/e3_server.py --keys /tmp/keys.json --verify --port 50070 --core 3
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

import grpc

from protobufs import security_service_pb2 as pb2
from protobufs import security_service_pb2_grpc as pb2_grpc

HEADER_NAME = "authorization"


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_verifiers(public_keys):
    """public_keys: {scheme: raw public key bytes}. Returns {scheme: fn(message, signature) -> bool}."""
    verifiers = {}
    for scheme, pub in public_keys.items():
        if scheme == "ES256":
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)

            def verify(message, sig, key=key):
                if len(sig) != 64:
                    return False
                der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
                try:
                    key.verify(der, message, ec.ECDSA(hashes.SHA256()))
                    return True
                except InvalidSignature:
                    return False
        elif scheme == "EdDSA":
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric import ed25519
            key = ed25519.Ed25519PublicKey.from_public_bytes(pub)

            def verify(message, sig, key=key):
                try:
                    key.verify(sig, message)
                    return True
                except InvalidSignature:
                    return False
        else:
            import oqs
            verifier = oqs.Signature(scheme)   # kept open for the life of the server

            def verify(message, sig, verifier=verifier, pub=pub):
                return verifier.verify(message, sig, pub)
        verifiers[scheme] = verify
    return verifiers


def check_token(value, verifiers):
    """Parse 'Bearer h.c.s', verify the signature. Returns (ok, scheme, verify_ns)."""
    if not value.startswith("Bearer "):
        return False, "", 0
    try:
        header_b64, claims_b64, sig_b64 = value[7:].split(".")
        scheme = json.loads(b64url_decode(header_b64))["alg"]
        signature = b64url_decode(sig_b64)
    except Exception:
        return False, "", 0
    verify = verifiers.get(scheme)
    if verify is None:
        return False, scheme, 0
    message = f"{header_b64}.{claims_b64}".encode("ascii")
    start = time.perf_counter_ns()
    ok = verify(message, signature)
    return ok, scheme, time.perf_counter_ns() - start


class Broker(pb2_grpc.CredentialBrokerServicer):
    def __init__(self, verifiers, do_verify):
        self.verifiers = verifiers
        self.do_verify = do_verify

    def RegisterCredential(self, request, context):
        handler_start = time.perf_counter_ns()
        verify_ns = 0
        if self.do_verify:
            value = next((v for k, v in context.invocation_metadata() if k == HEADER_NAME), None)
            if value is not None:
                ok, _, verify_ns = check_token(value, self.verifiers)
                if not ok:
                    context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid token")
        handler_ns = time.perf_counter_ns() - handler_start
        context.set_trailing_metadata((("x-verify-ns", str(verify_ns)), ("x-handler-ns", str(handler_ns))))
        return pb2.RegistrationResponse(opaque_handle="ok", expires_at=0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=50070)
    parser.add_argument("--core", type=int, default=None)
    parser.add_argument("--keys", required=True, help="JSON file {scheme: base64 public key}")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    if args.core is not None and hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {args.core})

    with open(args.keys) as f:
        public_keys = {k: base64.b64decode(v) for k, v in json.load(f).items()}
    verifiers = make_verifiers(public_keys)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pb2_grpc.add_CredentialBrokerServicer_to_server(Broker(verifiers, args.verify), server)
    server.add_insecure_port(f"127.0.0.1:{args.port}")
    server.start()
    print(f"E3 server ready on 127.0.0.1:{args.port} (verify={args.verify})", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    main()
