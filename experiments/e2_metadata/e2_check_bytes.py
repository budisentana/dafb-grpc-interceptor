"""E2: check which byte counts differ between the 5 runs.

For each column, counts the scenario/call pairs whose value is not
identical in all runs, and lists which call numbers are affected.
Output: experiments/e2_metadata/results/e2_byte_check.txt
"""
import csv, collections
from pathlib import Path

HERE = Path(__file__).resolve().parent
BYTES_FILE = HERE / 'results' / 'e2_bytes.csv'
OUT_FILE = HERE / 'results' / 'e2_byte_check.txt'
COLUMNS = ('header_bytes', 'header_frames', 'data_bytes', 'c2s_bytes')

d = collections.defaultdict(lambda: collections.defaultdict(set))
for r in csv.DictReader(open(BYTES_FILE)):
    k = (r['scenario'], int(r['call']))
    for c in COLUMNS:
        d[c][k].add(int(r[c]))

lines = []
for c in COLUMNS:
    diff = {k: sorted(v) for k, v in d[c].items() if len(v) > 1}
    calls = sorted({k[1] for k in diff})
    lines.append(f"{c}: {len(diff)} scenario/call pairs differ; calls affected: {calls}")
    for k in sorted(diff)[:4]:
        lines.append(f"    {k} {diff[k]}")

text = '\n'.join(lines)
print(text)
OUT_FILE.write_text(text + '\n')
print(f"\nWritten: {OUT_FILE}")
