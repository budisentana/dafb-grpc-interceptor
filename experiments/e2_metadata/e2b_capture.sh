#!/usr/bin/env bash
# E2b packet capture: short trial of S3000, S3500 and S4000 over the netem link,
# capturing TCP port 50060 on lo (first 128 bytes of each packet).
# Run from the repo root with the venv active and the E2b tc rule in place.
# Output: /tmp/e2b_seg.pcap (copy it to experiments/e2_metadata/results/).
set -euo pipefail
sudo -v
(sudo timeout 90 tcpdump -i lo -nn -s 128 -w /tmp/e2b_seg.pcap 'tcp port 50060' 2>/dev/null &)
sleep 2
python -c "import sys; sys.path.insert(0,'experiments/e2_metadata'); import e2_benchmark as b; from pathlib import Path; f=b.scenarios; b.scenarios=lambda: [s for s in f() if s['scenario'] in ('S3000','S3500','S4000')]; b.WARMUP_REQUESTS=5; b.MEASURED_REQUESTS=20; b.BYTES_FILE=Path('/tmp/e2s_bytes.csv'); b.LATENCY_FILE=Path('/tmp/e2s_latency.csv'); b.ENV_FILE=Path('/tmp/e2s_env.csv'); b.main()"
sleep 1
sudo pkill -INT tcpdump || true
