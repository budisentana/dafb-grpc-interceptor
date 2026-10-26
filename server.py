import time
from concurrent import futures
from pathlib import Path

import grpc

from protobufs import security_service_pb2 as pb2
from protobufs import security_service_pb2_grpc as pb2_grpc
from interceptors.dafb_engine import DAFBServerInterceptor
from interceptors.mldsa_credentials import verify_credential


PUBLIC_KEY_FILE = Path(__file__).resolve().parent / "keys" / "mldsa65_public.key"


class CredentialBrokerServicer(pb2_grpc.CredentialBrokerServicer):
    def __init__(self, interceptor_instance):
        self.interceptor = interceptor_instance

        if not PUBLIC_KEY_FILE.is_file():
            raise FileNotFoundError(
                f"Trusted ML-DSA-65 public key not found: {PUBLIC_KEY_FILE}"
            )

        self.public_key = PUBLIC_KEY_FILE.read_bytes()

        if len(self.public_key) != 1952:
            raise ValueError(
                f"Unexpected ML-DSA-65 public key size: {len(self.public_key)}"
            )

    def RegisterCredential(self, request, context):
        # Reject requests that do not contain the signed credential.
        if not request.credential_payload or not request.signature:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "Credential payload and signature are required.",
            )

        # Verify the signature against the server's configured public key.
        try:
            valid = verify_credential(
                request.credential_payload,
                request.signature,
                self.public_key,
            )
        except Exception:
            context.abort(
                grpc.StatusCode.INTERNAL,
                "Credential verification failed internally.",
            )

        if not valid:
            context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                "Invalid ML-DSA-65 credential signature.",
            )

        # Only a successfully verified credential can receive a handle.
        import secrets

        opaque_handle = f"dafb_ref_{secrets.token_hex(16)}"

        simulated_claims = {
            "sub": "mldsa65_experiment_client",
            "role": "research_experimenter",
        }

        self.interceptor.register_incoming_handle(
            opaque_handle,
            simulated_claims,
        )

        return pb2.RegistrationResponse(
            opaque_handle=opaque_handle,
            expires_at=int(time.time()) + 3600,
        )


def serve():
    server_interceptor = DAFBServerInterceptor()

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        interceptors=(server_interceptor,),
        options=[
            ("grpc.max_metadata_size", 32768),
            ("grpc.http2.max_frame_size", 16384),
        ],
    )

    servicer = CredentialBrokerServicer(server_interceptor)

    pb2_grpc.add_CredentialBrokerServicer_to_server(
        servicer,
        server,
    )

    server.add_insecure_port("[::]:50051")

    print(
        "DAFB gRPC server with ML-DSA-65 credential verification "
        "initialized on port 50051."
    )

    try:
        server.start()
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    serve()