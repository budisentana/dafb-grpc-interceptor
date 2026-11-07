# DAFB experiments

Each experiment has its own folder with its scripts and a `results/` folder.
Run everything from the project folder with the venv active. All experiments
ran on the machine described in `common/environment.txt`.

| Folder | What it measures | Paper |
| --- | --- | --- |
| `e1_crypto/` | E1: ML-DSA-65 key generation, signing and verification time (default CPU settings) | Lontar Komputer (Paper 1) |
| `e1b_signatures/` | E1b: ML-DSA-44/65/87 vs ECDSA P-256 and Ed25519, fixed CPU frequency | Lontar Komputer (Paper 1) |
| `e2_metadata/` | E2: bytes on the wire and latency of bearer tokens in gRPC metadata | Paper 2 |
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

## E2b: E2 over a bandwidth-limited link (100 Mbit/s, tc netem)

E2 repeated with gRPC traffic (TCP port 50060) limited to 100 Mbit/s on loopback; no delay added. 5 runs, fixed CPU frequency, 84,150 calls, 0 failures, 0 netem drops (7 Nov 2026).

- Procedure: `e2_metadata/e2b_netem.sh` (on/off/status), `e2_metadata/e2b_run.sh` (5 runs, analysis, comparison)
- Comparison with E2: `e2_metadata/e2b_compare.py` -> `results/e2b_comparison.csv`
- Packet capture (S3000/S3500/S4000): `e2_metadata/e2b_capture.sh`, `results/e2b_segments.pcap`, analysed by `e2_metadata/e2b_capture_gaps.py` -> `results/e2b_capture_gaps.csv`
- Raw data: `results/e2b_bytes.csv`, `results/e2b_latency.csv`, `results/e2b_run_environment.csv`, network condition in `results/e2b_netem_setup.txt`

Main results (median latency): ML-DSA-65 791.0 us vs ES256 368.7 us (+114.5%), against +3.5% on plain loopback (E2). The sweep cost is 80-81 ns/byte below 3 KB and above 4 KB (serialization at 100 Mbit/s), with a transition of about 60 us between 3 and 4 KB; the capture shows one request segment per call and no extra packets, so its cause is left open.
