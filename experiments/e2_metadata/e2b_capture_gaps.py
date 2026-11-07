"""Split each gRPC call in the E2b capture into a client-side and a server-side gap.

client gap: last response -> next request (client work + sending the request over the link)
server gap: request -> response (server work)
serial.:    time to send the request packet at 100 Mbit/s, incl. 66 B of TCP/IP/link headers
Usage: python e2b_capture_gaps.py [pcap]   (default: results/e2b_segments.pcap)
Writes results/e2b_capture_gaps.csv. Times are medians in microseconds."""
import csv, statistics as st, subprocess, sys
from collections import defaultdict
from pathlib import Path

R = Path(__file__).resolve().parent / "results"
pcap = sys.argv[1] if len(sys.argv) > 1 else str(R / "e2b_segments.pcap")
out = subprocess.run(["tcpdump", "-r", pcap, "-nn", "-tt", "tcp port 50060"],
                     capture_output=True, text=True, check=True).stdout

last, req, size = {}, {}, {}
cg, sg = defaultdict(list), defaultdict(list)
for line in out.splitlines():
    f = line.split()
    if len(f) < 6 or f[1] not in ("IP", "IP6"):
        continue
    t, src, dst, n = float(f[0]), f[2], f[4].rstrip(":"), int(f[-1])
    if dst.endswith(".50060"):
        c = src.rsplit(".", 1)[1]
        if n >= 1000:
            if c in last and last[c][1] == "resp":
                cg[c].append((t - last[c][0]) * 1e6)
            req[c], size[c], last[c] = t, n, (t, "req")
        else:
            last[c] = (t, "other")
    else:
        c = dst.rsplit(".", 1)[1]
        if n == 68 and c in last and last[c][1] == "req":
            sg[c].append((t - req[c]) * 1e6); last[c] = (t, "resp")
        else:
            last[c] = (t, "other")

rows = []
print(f"{'port':>6}{'req B':>7}{'calls':>6}{'client gap':>12}{'server gap':>12}{'serial.':>9}{'client-serial':>15}")
for c in sorted(sg, key=lambda c: (size[c], c)):
    if len(sg[c]) < 5 or not cg[c]:
        continue
    ser = (size[c] + 66) * 8 / 100
    a, b = st.median(cg[c]), st.median(sg[c])
    rows.append(dict(port=c, request_bytes=size[c], calls=len(sg[c]), client_gap_us=round(a, 1),
                     server_gap_us=round(b, 1), serialization_us=round(ser, 1), client_minus_serial_us=round(a - ser, 1)))
    print(f"{c:>6}{size[c]:>7}{len(sg[c]):>6}{a:>12.1f}{b:>12.1f}{ser:>9.1f}{a - ser:>15.1f}")
if rows:
    with (R / "e2b_capture_gaps.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
