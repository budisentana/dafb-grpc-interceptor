
import csv
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------
# Project configuration
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIR))

from interceptors.mldsa_credentials import (
    generate_keypair,
    sign_credential,
    verify_credential,
)

RESULT_FILE = (
    PROJECT_DIR
    / "experiments"
    / "results"
    / "e1_crypto_benchmark.csv"
)

ALGORITHM = "ML-DSA-65"

WARMUP_ITERATIONS = 10
MEASURED_ITERATIONS = 500

CREDENTIAL = (
    b'{"sub":"mldsa65_experiment_client",'
    b'"role":"research_experimenter"}'
)


# --------------------------------------------------
# Benchmark function
# --------------------------------------------------

def measure_operation(operation, function, run_id, timestamp):
    """Execute warm-up and measured iterations."""

    print(f"\nBenchmarking {operation}...")

    # Warm-up
    for iteration in range(1, WARMUP_ITERATIONS + 1):
        try:
            result = function()

            if operation == "verify" and result is not True:
                raise RuntimeError(
                    "Signature verification returned False"
                )

        except Exception as exc:
            raise RuntimeError(
                f"{operation} warm-up failed at iteration "
                f"{iteration}: {exc}"
            ) from exc

    observations = []

    # Actual measurements
    for iteration in range(1, MEASURED_ITERATIONS + 1):

        start = time.perf_counter_ns()
        status = "success"

        try:
            result = function()

            if operation == "verify" and result is not True:
                status = "error:verification_failed"

        except Exception as exc:
            status = f"error:{type(exc).__name__}"
            print(
                f"Iteration {iteration} failed "
                f"during {operation}: {exc}"
            )

        duration_ns = time.perf_counter_ns() - start

        observations.append({
            "experiment_id": "E1",
            "run_id": run_id,
            "timestamp_utc": timestamp,
            "algorithm": ALGORITHM,
            "operation": operation,
            "iteration": iteration,
            "duration_ns": duration_ns,
            "status": status,
        })

    return observations


# --------------------------------------------------
# Main benchmark
# --------------------------------------------------

def main():

    run_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    print("=" * 60)
    print("DAFB E1: ML-DSA-65 Cryptographic Benchmark")
    print("=" * 60)

    print(f"Run ID: {run_id}")
    print(f"Timestamp UTC: {timestamp}")
    print(f"Algorithm: {ALGORITHM}")
    print(f"Credential size: {len(CREDENTIAL)} bytes")
    print(f"Warm-up iterations: {WARMUP_ITERATIONS}")
    print(f"Measured iterations: {MEASURED_ITERATIONS}")

    # ----------------------------------------------
    # 1. Key generation
    # ----------------------------------------------

    keygen_results = measure_operation(
        "keygen",
        generate_keypair,
        run_id,
        timestamp,
    )

    # Generate one key pair outside signing and
    # verification timing.
    public_key, secret_key = generate_keypair()

    # ----------------------------------------------
    # 2. Signing preparation
    # ----------------------------------------------

    signature = sign_credential(
        CREDENTIAL,
        secret_key,
    )

    print("\nCryptographic object sizes:")
    print(f"Public key: {len(public_key)} bytes")
    print(f"Secret key: {len(secret_key)} bytes")
    print(f"Signature: {len(signature)} bytes")

    # ----------------------------------------------
    # 3. Signing
    # ----------------------------------------------

    signing_results = measure_operation(
        "sign",
        lambda: sign_credential(
            CREDENTIAL,
            secret_key,
        ),
        run_id,
        timestamp,
    )

    # ----------------------------------------------
    # 4. Verification
    # ----------------------------------------------

    verification_results = measure_operation(
        "verify",
        lambda: verify_credential(
            CREDENTIAL,
            signature,
            public_key,
        ),
        run_id,
        timestamp,
    )

    # ----------------------------------------------
    # 5. Combine observations
    # ----------------------------------------------

    all_results = (
        keygen_results
        + signing_results
        + verification_results
    )

    # ----------------------------------------------
    # 6. Save raw observations to CSV
    # ----------------------------------------------

    RESULT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "experiment_id",
        "run_id",
        "timestamp_utc",
        "algorithm",
        "operation",
        "iteration",
        "duration_ns",
        "status",
    ]

    file_exists = (
        RESULT_FILE.exists()
        and RESULT_FILE.stat().st_size > 0
    )

    with RESULT_FILE.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames,
        )

        if not file_exists:
            writer.writeheader()

        writer.writerows(all_results)

    print("\nRaw measurements saved:")
    print(RESULT_FILE)

    # ----------------------------------------------
    # 7. Statistical summary
    # ----------------------------------------------

    print("\n")
    print("=" * 60)
    print("E1 BENCHMARK SUMMARY")
    print("=" * 60)

    for operation in ("keygen", "sign", "verify"):

        successful = [
            row["duration_ns"]
            for row in all_results
            if row["operation"] == operation
            and row["status"] == "success"
        ]

        failed = [
            row
            for row in all_results
            if row["operation"] == operation
            and row["status"] != "success"
        ]

        print(f"\nOperation: {operation}")
        print(f"Successful observations: {len(successful)}")
        print(f"Failed observations: {len(failed)}")

        if not successful:
            print("No successful observations.")
            continue

        durations_ms = [
            value / 1_000_000
            for value in successful
        ]

        print(
            f"Mean: "
            f"{statistics.mean(durations_ms):.4f} ms"
        )

        print(
            f"Median: "
            f"{statistics.median(durations_ms):.4f} ms"
        )

        if len(durations_ms) > 1:
            print(
                f"Standard deviation: "
                f"{statistics.stdev(durations_ms):.4f} ms"
            )

        print(
            f"Minimum: "
            f"{min(durations_ms):.4f} ms"
        )

        print(
            f"Maximum: "
            f"{max(durations_ms):.4f} ms"
        )

    print("\nE1 benchmark completed.")
    print(f"Run ID: {run_id}")


if __name__ == "__main__":
    main()
