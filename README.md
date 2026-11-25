# DAFB: post-quantum bearer tokens for gRPC without oversized headers

Code, data and scripts for the paper

> I Wayan Budi Sentana¹, Yusuke Takahashi², I Nyoman Kusuma Wardana¹, Muhammad Ikram³, Junda Lu⁴.
>
> ¹ Politeknik Negeri Bali · ² Musashino University · ³ Macquarie University · ⁴ Western Sydney University
>
>
> **When Tokens Outgrow Their Headers: Efficient Post-Quantum Authentication for Microservice Communication.**
> Submitted to the *Journal of Information Security and Applications* (JISA), 2026.

This README is written for reviewers. It explains what DAFB is, where each result in the paper comes from,
and how to rerun the experiments.

## What DAFB is

A JWS bearer token signed with ML-DSA is several kilobytes long (ML-DSA-65: 4,766 bytes of HTTP/2 HEADERS
per call). That is more than the default 4,096-byte HPACK table, so gRPC sends the whole token on every call.
DAFB (Dynamic Adaptive Frame Budget) is a pair of gRPC interceptors (`interceptors/dafb_engine.py`) that
replace the large token with a short handle:

- **Inline (small tokens):** a token that fits the HPACK budget (4,096 - 512 bytes), such as ES256 or Ed25519,
  is sent unchanged and verified on every call.
- **Register:** a larger token (every ML-DSA token) is sent once with `x-dafb-mode: register`. The server
  verifies it and returns a handle (`x-dafb-handle`, `x-dafb-handle-ttl`; the TTL is capped by the token's `exp`).
- **Reference:** later calls send only the handle, and the server does not verify the signature again.
- **Fallback:** an unknown or expired handle is rejected (`x-dafb-error: handle-invalid`), and the client
  retries once with the full token, which registers it again.

The token format is in `interceptors/jws_tokens.py` and the verified-token cache baseline is in
`interceptors/token_cache.py`.

## Main results

All results use ML-DSA-65 unless stated otherwise.

| Result | Value | Source (in `experiments/`) |
| --- | --- | --- |
| HEADERS bytes per call | 4,766 B → 98 B | `e4_dafb/results/e4_report.txt` |
| Median latency vs no mitigation, loopback | −20.5 % | `e4_dafb/results/e4_report.txt` |
| Median latency vs no mitigation, 100 Mbit/s | −56.5 % | `e4_dafb/results/e4_report.txt` |
| Registration cost (first call), all schemes and both links | +48 to +70 µs over a verified bearer call | `e4_dafb/results/e4_report.txt` |
| vs verified-token cache, loopback | on par (+2.4 % plaintext, +0.7 % TLS) | `e5_baselines/results/e5_report.txt` |
| vs verified-token cache, 1 Gbit/s (L1) | 6 % faster (−6.3 %) | `e6_network/results/e6_report.txt` |
| vs verified-token cache, 100 Mbit/s | 50–58 % faster (ML-DSA-65 and ML-DSA-87; 42 % for ML-DSA-44) | `e5_baselines/results/e5_report.txt` |
| Throughput, 16 channels, 100 Mbit/s | ~2,500 → ~4,700 calls/s | `e7_load/results/e7_report.txt` |

There were no failed calls in any experiment.

## Experiments in the paper → repository folders

The repository numbers experiments in the order they were run, so its numbers differ from the experiment numbers in the paper. Below, "Experiment E1" etc. always means the experiment as numbered in the paper:

| Experiment (paper) | Repository folder (repo numbering) | What it measures |
| --- | --- | --- |
| Experiment E1 | `experiments/e3_combined/` (repo E3) | Signing, server-side verification and gRPC transport in one call (the baseline) |
| Experiment E2 | `experiments/e4_dafb/` (repo E4) | DAFB (inline, adaptive, reference, register) vs no mitigation, loopback and 100 Mbit/s |
| Experiment E3 | `experiments/e5_baselines/` (repo E5) | DAFB vs fair baselines: no mitigation, 64 KiB HPACK tables, verified-token cache; plaintext and TLS |
| Experiment E4 | `experiments/e6_network/` (repo E6) | Realistic links L1–L4 (rate, delay, loss) and the crossover model |
| Experiment E5 | `experiments/e7_load/` (repo E7) | Concurrent load (1–64 channels) and handle-store scaling |

`experiments/e1_crypto/`, `experiments/e1b_signatures/` and `experiments/e2_metadata/` belong to other
papers and are not part of the DAFB paper. Each folder has its scripts and a `results/` folder with the raw
CSV files and the analysis report. `experiments/README.md` describes each experiment's design in detail.

## Environment

All results were measured on one machine (`experiments/common/environment.txt`):

- Intel Core i3-12100 (4 cores / 8 threads), 7 GiB RAM
- Ubuntu 26.04.1 LTS, Linux kernel 7.0.0
- Python 3.14.4, grpcio 1.84.1, liboqs-python 0.16.0.1
- CPU frequency fixed during benchmarks (governor `performance`, turbo off); client pinned to core 2
  and server to core 3 (for Experiment E5, server on cores 2–3 and clients on cores 0–1)
- Network conditions emulated on loopback with `tc netem`

## Installation

```bash
git clone https://github.com/budisentana/dafb-grpc-interceptor.git
cd dafb-grpc-interceptor
python3.14 -m venv venv
source venv/bin/activate
pip install grpcio==1.84.1 grpcio-tools==1.84.1 protobuf==7.36.2 \
            cryptography==50.0.2 liboqs-python==0.16.0.1 pytest==9.1.1
```

The first time `oqs` is imported, liboqs-python downloads and builds the liboqs C library into `~/_oqs`
(or into `$OQS_INSTALL_PATH` if it is set). This needs `git`, `cmake` and a C compiler.
To build it right away:

```bash
python -c "import oqs; print(oqs.oqs_version())"
```

The network experiments also need `tc` (package `iproute2`) and `sudo`.

## Running the tests

```bash
python -m pytest tests/
```

The 44 tests cover the DAFB engine (register, reference, inline, fallback and expiry), the token cache and
the shared benchmark code for Experiments E2 and E3 (folders `e4_dafb` and `e5_baselines`).

## Reproducing the paper experiments

Run every command from the repository root with the venv active. Each benchmark script runs one pass, and
each `*_run.sh` script runs 5 passes followed by the analysis. Fix the CPU frequency before running a
benchmark, and restore it afterwards:

```bash
sudo bash experiments/common/cpu_setup.sh            # governor performance, turbo off
# ... experiments ...
sudo bash experiments/common/cpu_setup.sh restore
```

**Experiment E1 (paper): combined cost** (folder `e3_combined`, repo E3). The server starts and stops by itself. Run the benchmark 5 times,
then the analysis:

```bash
python experiments/e3_combined/e3_benchmark.py      # run 5 times
python experiments/e3_combined/e3_analyze.py
```

**Experiment E2 (paper): DAFB vs no mitigation** (folder `e4_dafb`, repo E4), on loopback and on a 100 Mbit/s link:

```bash
bash experiments/e4_dafb/e4_run.sh loopback
sudo bash experiments/e2_metadata/e2b_netem.sh on 100mbit 50080
bash experiments/e4_dafb/e4_run.sh netem100
sudo bash experiments/e2_metadata/e2b_netem.sh off
```

`e2b_netem.sh` belongs to `e2_metadata` (another paper). It is used here only to limit port 50080, which the `e4_dafb` benchmark uses, to 100 Mbit/s.

**Experiment E3 (paper): fair baselines** (folder `e5_baselines`, repo E5), plaintext and TLS, on loopback and on 100 Mbit/s:

```bash
bash experiments/e5_baselines/e5_run.sh plaintext
bash experiments/e5_baselines/e5_run.sh tls
sudo bash experiments/e2_metadata/e2b_netem.sh on 100mbit 50100
bash experiments/e5_baselines/e5_run.sh plaintext netem100
bash experiments/e5_baselines/e5_run.sh tls netem100
sudo bash experiments/e2_metadata/e2b_netem.sh off
```

**Experiments E4 and E5 (paper): realistic links and concurrent load** (folders `e6_network` and `e7_load`, repo E6 and E7). One script runs all the
steps that need root (CPU governor and netem profiles). The benchmarks run as your user:

```bash
sudo bash experiments/run_e6_e7.sh        # Experiments E4 + E5 (paper), about 2.5 hours
sudo bash experiments/run_e6_e7.sh e6     # only Experiment E4 (paper; argument uses repo name e6), ~45 min
sudo bash experiments/run_e6_e7.sh e7     # only Experiment E5 (paper; argument uses repo name e7), ~1.7 h
sudo bash experiments/common/cpu_setup.sh restore
```

Progress is written to `experiments/run_e6_e7.log`.

To reanalyse the committed data without rerunning anything, run the analysis script in each folder
(`e3_analyze.py`, `e4_analyze.py`, `e5_analyze.py`, `e6_analyze.py`, `e7_analyze.py`).

## Security notes and limitations

- **Handles are bearer secrets.** A handle grants the same access as the token it replaces until it expires,
  so use DAFB only over TLS. (The plaintext runs exist only to measure overhead.)
- **Single server only.** The handle store is kept in memory in one server process. Handles are not shared
  between replicas, so a call that a load balancer sends to another replica falls back to registration.
  Using a shared store across replicas is future work.

## License and contact

This project is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).

For questions about the code or the paper, contact I Wayan Budi Sentana at budisentana@pnb.ac.id.
