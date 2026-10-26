from pathlib import Path

import grpc

from protobufs import security_service_pb2 as pb2
from protobufs import security_service_pb2_grpc as pb2_grpc
from interceptors.mldsa_credentials import sign_credential


PROJECT_DIR = Path(__file__).resolve().parent
SECRET_KEY_FILE = PROJECT_DIR / "keys" / "mldsa65_secret.key"


def main():
    target = "localhost:50051"

    secret_key = SECRET_KEY_FILE.read_bytes()

    original_payload = (
        b'{"sub":"mldsa65_experiment_client",'
        b'"role":"research_experimenter"}'
    )

    # Sign the original payload.
    signature = sign_credential(original_payload, secret_key)

    # Deliberately alter the payload after signing.
    tampered_payload = (
        b'{"sub":"attacker",'
        b'"role":"research_experimenter"}'
    )

    channel = grpc.insecure_channel(target)
    stub = pb2_grpc.CredentialBrokerStub(channel)

    request = pb2.RegistrationRequest(
        raw_token="tampering_test",
        credential_payload=tampered_payload,
        signature=signature,
    )

    try:
        response = stub.RegisterCredential(request, timeout=5.0)

        print("FAIL: Server accepted the tampered credential.")
        print(f"Unexpected handle: {response.opaque_handle}")
        raise SystemExit(1)

    except grpc.RpcError as exc:
        if exc.code() == grpc.StatusCode.UNAUTHENTICATED:
            print("PASS: Server rejected the tampered credential.")
            print(f"gRPC status: {exc.code()}")
            print(f"Details: {exc.details()}")
        else:
            print("FAIL: Server returned an unexpected gRPC error.")
            print(f"Status: {exc.code()}")
            print(f"Details: {exc.details()}")
            raise SystemExit(1)

    finally:
        channel.close()


if __name__ == "__main__":
    main()