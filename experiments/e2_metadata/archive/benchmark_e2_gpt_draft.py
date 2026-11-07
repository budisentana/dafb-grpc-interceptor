
import csv
import random
import statistics
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import grpc

from protobufs import security_service_pb2 as pb2
from protobufs import security_service_pb2_grpc as pb2_grpc
from interceptors.mldsa_credentials import sign_credential


PROJECT_DIR = Path(__file__).resolve().parents[3]

SECRET_KEY_FILE = PROJECT_DIR / "keys" / "mldsa65_secret.key"
RESULT_FILE = (
    PROJECT_DIR
    / "experiments"
    / "e2_metadata_benchmark"
    / "results"
    / "e2a_rpc_observations.csv"
)

TARGET = "localhost:50051"
METADATA_KEY = "authorization-pq"

METADATA_SIZES = [256, 1024, 2048, 4096, 5120, 8192]

WARMUP_REQUESTS = 50
MEASURED_REQUESTS = 500
NUMBER_OF_RUNS = 5

CREDENTIAL_PAYLOAD = (
    b'{"sub":"mldsa65_experiment_client",'
    b'"role":"research_experimenter"}'
)


def create_csv_file():
    RESULT_FILE.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "run_id",
        "run_number",
        "timestamp_utc",
        "scenario",
        "scenario_order",
        "metadata_size_bytes",
        "credential_size_bytes",
        "signature_size_bytes",
        "iteration",
        "latency_ns",
        "status",
        "grpc_status",
        "error",
        "scenario_elapsed_ns",
        "requests_per_second",
    ]

    file_exists = RESULT_FILE.exists() and RESULT_FILE.stat().st_size > 0

    return fields, file_exists


def make_request(stub, request, metadata):
    return stub.RegisterCredential(
        request,
        metadata=metadata,
        timeout=10.0,
    )


def main():
    if not SECRET_KEY_FILE.is_file():
        raise FileNotFoundError(
            f"ML-DSA-65 secret key not found: {SECRET_KEY_FILE}"
        )

    print("Preparing ML-DSA-65 credential...")

    secret_key = SECRET_KEY_FILE.read_bytes()

    # Sign once, outside the RPC measurement.
    signature = sign_credential(CREDENTIAL_PAYLOAD, secret_key)

    request = pb2.RegistrationRequest(
        raw_token="e2_metadata_benchmark",
        credential_payload=CREDENTIAL_PAYLOAD,
        signature=signature,
    )

    print(f"Credential size: {len(CREDENTIAL_PAYLOAD)} bytes")
    print(f"Signature size: {len(signature)} bytes")

    fields, file_exists = create_csv_file()

    with grpc.insecure_channel(
        TARGET,
        options=[
            ("grpc.max_metadata_size", 32768),
        ],
    ) as channel:

        print(f"\nConnecting to gRPC server: {TARGET}")

        grpc.channel_ready_future(channel).result(timeout=10)

        stub = pb2_grpc.CredentialBrokerStub(channel)

        with open(
            RESULT_FILE,
            "a",
            newline="",
            encoding="utf-8",
        ) as csv_file:

            writer = csv.DictWriter(csv_file, fieldnames=fields)

            if not file_exists:
                writer.writeheader()
                csv_file.flush()

            for run_number in range(1, NUMBER_OF_RUNS + 1):

                run_id = str(uuid.uuid4())
                scenario_order = METADATA_SIZES.copy()
                random.shuffle(scenario_order)

                print("\n" + "=" * 55)
                print(f"RUN {run_number}/{NUMBER_OF_RUNS}")
                print(f"Run ID: {run_id}")
                print("=" * 55)

                for order, metadata_size in enumerate(
                    scenario_order,
                    start=1,
                ):

                    scenario = f"S{METADATA_SIZES.index(metadata_size) + 1}"

                    token = "X" * metadata_size
                    actual_metadata_size = len(token.encode("ascii"))

                    metadata = [
                        (METADATA_KEY, token)
                    ]

                    print(
                        f"\n{scenario}: "
                        f"{actual_metadata_size} bytes"
                    )

                    # Warm-up phase.
                    for _ in range(WARMUP_REQUESTS):
                        try:
                            make_request(stub, request, metadata)
                        except grpc.RpcError as exc:
                            raise RuntimeError(
                                f"Warm-up failed for {scenario}: "
                                f"{exc.code()} - {exc.details()}"
                            ) from exc

                    print("Warm-up completed.")

                    # Measurement phase.
                    latencies = []
                    successful = 0
                    failed = 0

                    scenario_start = time.perf_counter_ns()

                    for iteration in range(
                        1,
                        MEASURED_REQUESTS + 1,
                    ):

                        timestamp = datetime.now(
                            timezone.utc
                        ).isoformat()

                        start = time.perf_counter_ns()

                        try:
                            make_request(stub, request, metadata)

                            latency = time.perf_counter_ns() - start

                            status = "success"
                            grpc_status = "OK"
                            error_message = ""

                            successful += 1

                        except grpc.RpcError as exc:

                            latency = time.perf_counter_ns() - start

                            status = "error"
                            grpc_status = str(exc.code())
                            error_message = str(exc.details())

                            failed += 1

                        except Exception as exc:

                            latency = time.perf_counter_ns() - start

                            status = "error"
                            grpc_status = "CLIENT_ERROR"
                            error_message = str(exc)

                            failed += 1

                        latencies.append(latency)

                        writer.writerow({
                            "run_id": run_id,
                            "run_number": run_number,
                            "timestamp_utc": timestamp,
                            "scenario": scenario,
                            "scenario_order": order,
                            "metadata_size_bytes": actual_metadata_size,
                            "credential_size_bytes": len(CREDENTIAL_PAYLOAD),
                            "signature_size_bytes": len(signature),
                            "iteration": iteration,
                            "latency_ns": latency,
                            "status": status,
                            "grpc_status": grpc_status,
                            "error": error_message,
                            "scenario_elapsed_ns": "",
                            "requests_per_second": "",
                        })

                    scenario_elapsed = (
                        time.perf_counter_ns() - scenario_start
                    )

                    throughput = (
                        MEASURED_REQUESTS
                        / (scenario_elapsed / 1_000_000_000)
                    )

                    # Store scenario-level timing in the final observation.
                    writer.writerow({
                        "run_id": run_id,
                        "run_number": run_number,
                        "timestamp_utc": datetime.now(
                            timezone.utc
                        ).isoformat(),
                        "scenario": scenario,
                        "scenario_order": order,
                        "metadata_size_bytes": actual_metadata_size,
                        "credential_size_bytes": len(CREDENTIAL_PAYLOAD),
                        "signature_size_bytes": len(signature),
                        "iteration": "SUMMARY",
                        "latency_ns": "",
                        "status": "summary",
                        "grpc_status": "",
                        "error": "",
                        "scenario_elapsed_ns": scenario_elapsed,
                        "requests_per_second": throughput,
                    })

                    csv_file.flush()

                    if latencies:
                        latency_ms = [
                            value / 1_000_000
                            for value in latencies
                        ]

                        print(f"Successful: {successful}")
                        print(f"Failed: {failed}")
                        print(
                            f"Mean latency: "
                            f"{statistics.mean(latency_ms):.4f} ms"
                        )
                        print(
                            f"Median latency: "
                            f"{statistics.median(latency_ms):.4f} ms"
                        )
                        print(
                            f"Throughput: {throughput:.2f} requests/sec"
                        )

                print(f"\nRun {run_number} completed.")

    print("\n" + "=" * 55)
    print("E2-A BENCHMARK COMPLETED")
    print(f"Results: {RESULT_FILE}")
    print("=" * 55)


if __name__ == "__main__":
    main()
