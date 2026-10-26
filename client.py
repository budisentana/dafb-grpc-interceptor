import sys
from pathlib import Path

import grpc

from protobufs import security_service_pb2 as pb2
from protobufs import security_service_pb2_grpc as pb2_grpc
from interceptors.dafb_engine import DAFBClientInterceptor
from interceptors.mldsa_credentials import sign_credential


PROJECT_DIR = Path(__file__).resolve().parent
SECRET_KEY_FILE = PROJECT_DIR / "keys" / "mldsa65_secret.key"


def run_experiment(simulate_pq_overhead: bool):
    target = "localhost:50051"

    if not SECRET_KEY_FILE.is_file():
        raise FileNotFoundError(
            f"ML-DSA-65 secret key not found: {SECRET_KEY_FILE}"
        )

    secret_key = SECRET_KEY_FILE.read_bytes()

    # Construct the credential payload.
    credential_payload = (
        b'{"sub":"mldsa65_experiment_client",'
        b'"role":"research_experimenter"}'
    )

    # Sign the exact bytes that will be sent to the server.
    signature = sign_credential(credential_payload, secret_key)

    print(f"Credential payload size: {len(credential_payload)} bytes")
    print(f"ML-DSA-65 signature size: {len(signature)} bytes")

    client_interceptor = DAFBClientInterceptor(
        target_endpoint=target
    )

    raw_channel = grpc.insecure_channel(
        target,
        options=[
            ("grpc.max_metadata_size", 32768),
            ("grpc.http2.max_frame_size", 16384),
        ],
    )

    channel = grpc.intercept_channel(
        raw_channel,
        client_interceptor,
    )

    stub = pb2_grpc.CredentialBrokerStub(channel)

    # Keep the two existing experimental scenarios.
    if simulate_pq_overhead:
        token_payload = "X" * 5120
        print(
            "Scenario: 5 KB synthetic metadata token "
            "with an actual ML-DSA-65 credential signature."
        )
    else:
        token_payload = "X" * 256
        print(
            "Scenario: 256-byte synthetic metadata token "
            "with an actual ML-DSA-65 credential signature."
        )

    request = pb2.RegistrationRequest(
        raw_token="baseline_telemetry_probe",
        credential_payload=credential_payload,
        signature=signature,
    )

    metadata_packet = [("authorization-pq", token_payload)]

    try:
        response = stub.RegisterCredential(
            request,
            metadata=metadata_packet,
            timeout=5.0,
        )

        print("\n--- Telemetry Metrics ---")
        print("Status: Success")
        print(f"Assigned Opaque Pointer Handle: {response.opaque_handle}")
        print(f"Handle expiration timestamp: {response.expires_at}")

    except grpc.RpcError as exc:
        print(
            f"Execution fault: {exc.code()} - {exc.details()}",
            file=sys.stderr,
        )

    finally:
        channel.close()


if __name__ == "__main__":
    run_experiment(simulate_pq_overhead=True)