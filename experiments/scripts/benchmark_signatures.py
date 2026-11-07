"""
DAFB E1b: signature-scheme comparison benchmark.

Same protocol as E1 (benchmark_crypto.py), extended to five schemes:
ML-DSA-44, ML-DSA-65, ML-DSA-87 (liboqs-python) and
ECDSA P-256, Ed25519 (pyca/cryptography, OpenSSL backend).

As in E1:
  - one launch of this script = one run (new run_id); run it 5 times
  - 10 warm-up + 500 measured iterations per operation
  - keygen, then sign, then verify, for each scheme
  - every call creates its signer/verifier object from scratch
  - the same 66-byte credential is signed; verification checks the same
    signature every iteration
  - raw rows are appended to experiments/results/e1b_signature_benchmark.csv
    with the same columns as E1

New in E1b:
  - the order of the five schemes is shuffled in every run
  - CPU governor, turbo state and core affinity are recorded per run in
    experiments/results/e1b_run_environment.csv
"""

import csv
import glob
import os
import platform
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
RESULTS_DIR = PROJECT_DIR / "experiments" / "results"
RESULT_FILE = RESULTS_DIR / "e1b_signature_benchmark.csv"
ENV_FILE = RESULTS_DIR / "e1b_run_environment.csv"

EXPERIMENT_ID = "E1b"
WARMUP_ITERATIONS = 10
MEASURED_ITERATIONS = 500

# Same credential as E1 (66 bytes)
CREDENTIAL = (
    b'{"sub":"mldsa65_experiment_client",'
    b'"role":"research_experimenter"}'
)

SCHEMES = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ECDSA-P256", "Ed25519"]


# --------------------------------------------------
# ML-DSA (same calls as interceptors/mldsa_credentials.py)
# --------------------------------------------------

def mldsa_functions(algorithm):
    import oqs

    def generate_keypair():
        with oqs.Signature(algorithm) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
        return public_key, secret_key

    def sign(credential, secret_key):
        with oqs.Signature(algorithm, secret_key=secret_key) as signer:
            return signer.sign(credential)

    def verify(credential, signature, public_key):
        with oqs.Signature(algorithm) as verifier:
            return verifier.verify(credential, signature, public_key)

    return generate_keypair, sign, verify


# --------------------------------------------------
# Classical schemes (key objects rebuilt from bytes on every call,
# matching the per-call context creation of the ML-DSA functions)
# --------------------------------------------------

def ecdsa_functions():
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    def generate_keypair():
        key = ec.generate_private_key(ec.SECP256R1())
        secret_key = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_key = key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        return public_key, secret_key

    def sign(credential, secret_key):
        key = serialization.load_der_private_key(secret_key, password=None)
        return key.sign(credential, ec.ECDSA(hashes.SHA256()))

    def verify(credential, signature, public_key):
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), public_key
        )
        try:
            key.verify(signature, credential, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    return generate_keypair, sign, verify


def ed25519_functions():
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    def generate_keypair():
        key = ed25519.Ed25519PrivateKey.generate()
        secret_key = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_key = key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return public_key, secret_key

    def sign(credential, secret_key):
        return ed25519.Ed25519PrivateKey.from_private_bytes(secret_key).sign(credential)

    def verify(credential, signature, public_key):
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, credential)
            return True
        except InvalidSignature:
            return False

    return generate_keypair, sign, verify


def functions_for(scheme):
    if scheme.startswith("ML-DSA"):
        return mldsa_functions(scheme)
    if scheme == "ECDSA-P256":
        return ecdsa_functions()
    if scheme == "Ed25519":
        return ed25519_functions()
    raise ValueError(scheme)


# --------------------------------------------------
# Benchmark function (same logic as E1)
# --------------------------------------------------

def measure_operation(scheme, operation, function, run_id, timestamp):
    print(f"  {operation}...", flush=True)

    for iteration in range(1, WARMUP_ITERATIONS + 1):
        result = function()
        if operation == "verify" and result is not True:
            raise RuntimeError(f"{scheme} verify warm-up returned False")

    observations = []
    for iteration in range(1, MEASURED_ITERATIONS + 1):
        start = time.perf_counter_ns()
        status = "success"
        try:
            result = function()
            if operation == "verify" and result is not True:
                status = "error:verification_failed"
        except Exception as exc:
            status = f"error:{type(exc).__name__}"
            print(f"  iteration {iteration} failed during {operation}: {exc}")
        duration_ns = time.perf_counter_ns() - start

        observations.append({
            "experiment_id": EXPERIMENT_ID,
            "run_id": run_id,
            "timestamp_utc": timestamp,
            "algorithm": scheme,
            "operation": operation,
            "iteration": iteration,
            "duration_ns": duration_ns,
            "status": status,
        })
    return observations


# --------------------------------------------------
# Environment record
# --------------------------------------------------

def read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def environment(run_id, timestamp, order, sizes):
    governors = sorted({read(p) for p in glob.glob(
        "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")} - {""})
    try:
        import oqs
        oqs_version = getattr(oqs, "oqs_python_version", lambda: "")()
    except Exception:
        oqs_version = ""
    import cryptography
    return {
        "run_id": run_id,
        "timestamp_utc": timestamp,
        "scheme_order": " > ".join(order),
        "cpu_governor": "/".join(governors),
        "intel_no_turbo": read("/sys/devices/system/cpu/intel_pstate/no_turbo"),
        "cpu_affinity": " ".join(map(str, sorted(os.sched_getaffinity(0)))),
        "python": platform.python_version(),
        "liboqs_python": oqs_version,
        "cryptography": cryptography.__version__,
        "credential_bytes": len(CREDENTIAL),
        "sizes_pk_sk_sig": "; ".join(f"{s}={p}/{k}/{g}" for s, (p, k, g) in sizes.items()),
    }


def append_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        writer.writerows(rows)


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():
    run_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    order = SCHEMES[:]
    random.shuffle(order)

    print("=" * 60)
    print("DAFB E1b: signature-scheme comparison benchmark")
    print("=" * 60)
    print(f"Run ID: {run_id}")
    print(f"Timestamp UTC: {timestamp}")
    print(f"Credential size: {len(CREDENTIAL)} bytes")
    print(f"Scheme order: {' > '.join(order)}")

    all_results = []
    sizes = {}
    for scheme in order:
        print(f"\n{scheme}")
        generate_keypair, sign, verify = functions_for(scheme)

        all_results += measure_operation(scheme, "keygen", generate_keypair, run_id, timestamp)

        public_key, secret_key = generate_keypair()
        signature = sign(CREDENTIAL, secret_key)
        sizes[scheme] = (len(public_key), len(secret_key), len(signature))

        all_results += measure_operation(
            scheme, "sign", lambda: sign(CREDENTIAL, secret_key), run_id, timestamp)
        all_results += measure_operation(
            scheme, "verify", lambda: verify(CREDENTIAL, signature, public_key), run_id, timestamp)

    append_csv(RESULT_FILE, all_results, [
        "experiment_id", "run_id", "timestamp_utc", "algorithm",
        "operation", "iteration", "duration_ns", "status"])
    env = environment(run_id, timestamp, order, sizes)
    append_csv(ENV_FILE, [env], list(env))

    failed = sum(1 for r in all_results if r["status"] != "success")
    print("\n" + "=" * 60)
    print(f"Measurements: {len(all_results)}, failed: {failed}")
    print(f"CPU governor: {env['cpu_governor']}, no_turbo: {env['intel_no_turbo']}, cores: {env['cpu_affinity']}")
    print(f"Raw data appended to: {RESULT_FILE}")
    print(f"Run environment appended to: {ENV_FILE}")
    print("E1b run completed. Run the script 5 times in total, then run analyze_signatures.py.")


if __name__ == "__main__":
    main()