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
