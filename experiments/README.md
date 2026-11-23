# DAFB experiments

Each experiment has its own folder with its scripts and a `results/` folder.
Run everything from the project folder with the venv active. All experiments
ran on the machine described in `common/environment.txt`.

| Folder | What it measures | Paper |
| --- | --- | --- |
| `e1_crypto/` | E1: ML-DSA-65 key generation, signing and verification time (default CPU settings) | Lontar Komputer (Paper 1) |
| `e1b_signatures/` | E1b: ML-DSA-44/65/87 vs ECDSA P-256 and Ed25519, fixed CPU frequency | Lontar Komputer (Paper 1) |
| `e2_metadata/` | E2: bytes on the wire and latency of bearer tokens in gRPC metadata | Paper 2 |
| `e3_combined/` | E3: signing + server-side verification + gRPC transport in the same call (baseline for E4-E5) | DAFB paper |
| `common/` | Shared: `cpu_setup.sh` (fix/restore CPU frequency) and the environment record | |

## Running

```bash
# fix the CPU frequency for benchmarks (restore afterwards with: restore)
sudo bash experiments/common/cpu_setup.sh

# E1b: run 5 times, then analyse
taskset -c 2 python experiments/e1b_signatures/benchmark_signatures.py
python experiments/e1b_signatures/analyze_signatures.py

# E2: run 5 times (the E2 server starts and stops automatically), then analyse
python experiments/e2_metadata/e2_benchmark.py
python experiments/e2_metadata/e2_analyze.py

# E1 analysis (data from 2 Nov 2026)
python experiments/e1b_signatures/analyze_signatures.py experiments/e1_crypto/results/e1_crypto_benchmark.csv

sudo bash experiments/common/cpu_setup.sh restore
```

`keys/` (ML-DSA secret key) is never committed.

## E3: combined crypto + gRPC cost

Same token format and 200-byte claim set as E2 (ES256, EdDSA, ML-DSA-44/65/87, plus `none`), but the
server now verifies the signature in the `authorization` header. Three modes per scheme:

- `send_only`: token sent, not verified (the E2 path, repeated as an in-run reference)
- `verify`: one token reused, verified by the server on every call (bearer JWT)
- `sign_verify`: a fresh token signed by the client for every call, verified by the server

The server returns its verification time in trailing metadata (`x-verify-ns`). 16 scenarios x
(50 warm-up + 500 measured) per run, fresh connection per scenario, shuffled order, client on core 2,
server on core 3. Verifier/signer objects are kept open for the whole run (E1b created one per operation).

```bash
sudo bash experiments/common/cpu_setup.sh
python experiments/e3_combined/e3_benchmark.py     # 5 times
python experiments/e3_combined/e3_analyze.py
sudo bash experiments/common/cpu_setup.sh restore
```

Output: `e3_combined/results/e3_latency.csv`, `e3_run_environment.csv`, `e3_latency_summary.csv`, `e3_report.txt`.

## E2b: E2 over a bandwidth-limited link (100 Mbit/s, tc netem)

E2 repeated with gRPC traffic (TCP port 50060) limited to 100 Mbit/s on loopback; no delay added. 5 runs, fixed CPU frequency, 84,150 calls, 0 failures, 0 netem drops (7 Nov 2026).

- Procedure: `e2_metadata/e2b_netem.sh` (on/off/status), `e2_metadata/e2b_run.sh` (5 runs, analysis, comparison)
- Comparison with E2: `e2_metadata/e2b_compare.py` -> `results/e2b_comparison.csv`
- Packet capture (S3000/S3500/S4000): `e2_metadata/e2b_capture.sh`, `results/e2b_segments.pcap`, analysed by `e2_metadata/e2b_capture_gaps.py` -> `results/e2b_capture_gaps.csv`
- Raw data: `results/e2b_bytes.csv`, `results/e2b_latency.csv`, `results/e2b_run_environment.csv`, network condition in `results/e2b_netem_setup.txt`

Main results (median latency): ML-DSA-65 791.0 us vs ES256 368.7 us (+114.5%), against +3.5% on plain loopback (E2). The sweep cost is 80-81 ns/byte below 3 KB and above 4 KB (serialization at 100 Mbit/s), with a transition of about 60 us between 3 and 4 KB; the capture shows one request segment per call and no extra packets, so its cause is left open.

## DAFB reference path (for E4-E5)

`interceptors/dafb_engine.py` now implements the path E3 is the baseline for. Tokens that fit the HPACK
budget (4096 - 512 bytes) stay inline and are verified on every call. Larger tokens (every ML-DSA token) are
sent once with `x-dafb-mode: register`; the server verifies them and returns a handle
(`x-dafb-handle`, `x-dafb-handle-ttl`, capped by the token's `exp`), and later calls send only the handle.
An unknown or expired handle is rejected (`x-dafb-error: handle-invalid`) and the client retries once with
the full token. Token format: `interceptors/jws_tokens.py` (same as E2/E3). Tests: `python -m pytest tests/`.
