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
| `e4_dafb/` | E4: DAFB (policies inline, adaptive, reference) vs no mitigation (E3 verify path), loopback and 100 Mbit/s netem | DAFB paper |
| `e5_baselines/` | E5: DAFB vs fair baselines (no mitigation, 64 KiB HPACK tables, verified-token cache), plaintext and TLS | DAFB paper |
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

## E4: DAFB vs no mitigation

Schemes ES256, EdDSA, ML-DSA-44/65/87 (+ `none`), JWS tokens in `authorization` with a 200-byte claim set.
The E2/E3 claim set has `exp` = 1 Jan 2026 (already past); E4 keeps the same fields and size with
`exp` = 1 Jan 2028. One E4 server (`e4_server.py`) runs `DAFBServerInterceptor` with
`jws_tokens.TokenVerifier` (exp check on) for every arm, so the baseline and DAFB share one verifier:

- `e3_verify`: plain bearer token, verified on every call (no mitigation)
- `dafb_inline`, `dafb_adaptive`, `dafb_reference`: DAFB client interceptor with that policy
- `dafb_register`: policy reference, handle forgotten before every call (every call registers),
  used as the registration cost in the break-even

Per scenario (fresh connection, fresh handle cache): 10-call byte pass through the E2 relay
(HEADERS bytes counted client->server and server->client), then 50 warm-up + 500 measured calls.
Client on core 2, server on core 3, port 50080. Break-even k* = reference calls needed after the
registration call: `k* = ceil((R - B) / (B - F))`, R = registration, F = reference call, B = e3_verify,
for median latency and for HEADERS bytes.

```bash
sudo bash experiments/common/cpu_setup.sh
bash experiments/e4_dafb/e4_run.sh loopback                       # 5 runs + analysis
sudo bash experiments/e2_metadata/e2b_netem.sh on 100mbit 50080   # E2b condition on the E4 port
bash experiments/e4_dafb/e4_run.sh netem100
sudo bash experiments/e2_metadata/e2b_netem.sh off
sudo bash experiments/common/cpu_setup.sh restore
```

Output (`e4_dafb/results/`): `e4_latency.csv`, `e4_bytes.csv`, `e4_scenarios.csv`, `e4_run_environment.csv`
(all tagged with `link`), and from `e4_analyze.py`: `e4_latency_summary.csv`, `e4_bytes_summary.csv`,
`e4_breakeven.csv`, `e4_report.txt`.

## E5: DAFB vs fair baselines

Same schemes, tokens, verifier and procedure as E4 (byte pass + 50 warm-up + 500 measured, cores 2/3,
5 runs per condition). Server groups (one process each, order shuffled): plain (`e3_verify`,
`dafb_adaptive`, `dafb_reference`, `dafb_register`, `none`), `--hpack-table 65536` (`hpack_64k`) and
`--token-cache` (`token_cache`, `token_cache_miss`: every call a fresh pre-signed token).

- Baseline 1, no mitigation: `e3_verify`.
- Baseline 2, larger HPACK table: client `grpc.http2.hpack_table_size.encoder` and server
  `grpc.http2.hpack_table_size.decoder` = 65536. **grpcio 1.84.1 never indexes application metadata**:
  every custom header (`authorization` or any other name, any size) is sent as a "literal header field
  without indexing" (representation byte 0x00) on every call, while gRPC's own headers are indexed. The
  table options take effect (4-byte size update on the first call) but the token is still sent in full;
  `e5_analyze.py` reports this as the indexing check.
  Reported as not achievable in grpcio (option A). RFC 7541 section 7.1.3 also allows encoders to send
  `authorization` never-indexed as a sensitive header (compression side channels); grpcio does not use
  that representation but sends all metadata without indexing. Analytic bound `2a indexed*` in the
  comparison: if the token were indexed, a later call would carry a 1-byte indexed field (dynamic-table
  index <= 126), i.e. `none` HEADERS + 1 B (about 19 B, below DAFB reference's 98 B, whose handle is not
  indexed either); verification still runs on every call, so its latency is taken as `e3_verify`.
- Baseline 3, verified-token cache: `interceptors/token_cache.py` (SHA-256 of the token, TTL 3600 s capped
  by `exp`, 100,000 entries, as DAFB handles). The full token is sent; verification is skipped on a hit.
- Baseline 4, TLS: `--transport tls` runs every arm over TLS (self-signed P-256 certificate per run).
  Under TLS the relay counts TCP payload bytes per call, since the HTTP/2 frames are encrypted.

Break-even against a baseline with first-call cost M and steady cost B: smallest k with
`R + k*F <= M + k*B` (R = DAFB registration, F = DAFB reference call); "never" when F >= B.

```bash
sudo bash experiments/common/cpu_setup.sh
bash experiments/e5_baselines/e5_run.sh plaintext
bash experiments/e5_baselines/e5_run.sh tls
sudo bash experiments/common/cpu_setup.sh restore
```

Output (`e5_baselines/results/`): `e5_latency.csv`, `e5_bytes.csv`, `e5_scenarios.csv`, `e5_run_environment.csv`
(tagged with transport and link), and `e5_latency_summary.csv`, `e5_bytes_summary.csv`, `e5_comparison.csv`,
`e5_report.txt`.
