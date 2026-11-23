"""
Shared helpers for E6/E7: server start/stop, link check against tc, TCP retransmit and
netem counters, CPU state, and the paper's paired-run statistics.
"""

import glob
import math
import re
import statistics
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]

# Expected `tc qdisc show` fragments per profile (netem_profile.sh)
PROFILES = {
    "L1": dict(rate="1Gbit", delay=None, loss=None),
    "L2": dict(rate="100Mbit", delay="5ms", loss=None),
    "L3": dict(rate="100Mbit", delay="5ms", loss="0.5%"),
    "L4": dict(rate="20Mbit", delay="20ms", loss=None),
    "N100": dict(rate="100Mbit", delay=None, loss=None),
}
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}


def read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def tc_text():
    out = []
    for cmd in (["tc", "-s", "qdisc", "show", "dev", "lo"], ["tc", "filter", "show", "dev", "lo"]):
        try:
            out.append(subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip())
        except (OSError, subprocess.SubprocessError) as exc:
            out.append(f"{cmd} failed: {exc}")
    return out


def check_link(link, port):
    """Exit unless the tc state matches `link` ('loopback' or a profile id) on `port`."""
    qdisc, filters = tc_text()
    netem = next((line for line in qdisc.splitlines() if "netem" in line), "")
    if link == "loopback":
        if netem:
            sys.exit("netem is active on lo; turn it off for --link loopback")
        return "no netem"
    want = PROFILES[link]
    problems = []
    if not netem:
        problems.append("no netem qdisc")
    if f"rate {want['rate']}" not in netem:
        problems.append(f"rate {want['rate']}")
    for key in ("delay", "loss"):
        has = f" {key} " in netem + " "
        if want[key] and f"{key} {want[key]}" not in netem:
            problems.append(f"{key} {want[key]}")
        if not want[key] and has:
            problems.append(f"unexpected {key}")
    if f"{port:04x}" not in filters:
        problems.append(f"filter on port {port}")
    if problems:
        sys.exit(f"tc state does not match link {link}: missing/wrong {', '.join(problems)}. "
                 f"Run: sudo bash experiments/common/netem_profile.sh on {link} {port}")
    return netem.strip()


def tcp_retrans_segs():
    """System-wide TCP RetransSegs (/proc/net/snmp)."""
    lines = [line.split() for line in read("/proc/net/snmp").splitlines() if line.startswith("Tcp:")]
    if len(lines) >= 2:
        return int(lines[1][lines[0].index("RetransSegs")])
    return 0


def netem_counters():
    """(sent bytes, sent packets, dropped) of the netem qdisc, or zeros."""
    qdisc = tc_text()[0]
    m = re.search(r"qdisc netem.*?\n\s*Sent (\d+) bytes (\d+) pkt \(dropped (\d+)", qdisc, re.S)
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def cpu_state():
    governors = sorted({read(p) for p in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")} - {""})
    topo = []
    for cpu in sorted(glob.glob("/sys/devices/system/cpu/cpu[0-9]*"), key=lambda p: int(p.rsplit("cpu", 1)[1])):
        core = read(f"{cpu}/topology/core_id")
        if core:
            topo.append(f"{cpu.rsplit('/', 1)[1]}:core{core}")
    return dict(cpu_governor="/".join(governors),
                intel_no_turbo=read("/sys/devices/system/cpu/intel_pstate/no_turbo"),
                cpu_topology=" ".join(topo))


def start_server(cmd, name):
    server = subprocess.Popen([sys.executable] + [str(c) for c in cmd],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    seen = []
    for _ in range(20):
        line = server.stdout.readline()
        if not line:
            break
        seen.append(line.strip())
        if "ready" in line:
            return server
    server.kill()
    raise RuntimeError(f"{name} server did not start: " + " | ".join(seen))


def stop_server(server):
    server.terminate()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()


def pct(sorted_values, p):
    if not sorted_values:
        return float("nan")
    k = (len(sorted_values) - 1) * p
    lo, hi = math.floor(k), math.ceil(k)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def mean_ci(values):
    """Mean and 95% t-interval half-width (df = n-1)."""
    values = [v for v in values if v is not None and not math.isnan(v)]
    if not values:
        return float("nan"), float("nan"), 0
    m = statistics.mean(values)
    if len(values) < 2:
        return m, float("nan"), len(values)
    return m, T95.get(len(values) - 1, 1.96) * statistics.stdev(values) / math.sqrt(len(values)), len(values)


def paired(a_by_run, b_by_run, relative=True):
    """Paired-within-run comparison of a vs b: per-run (a-b)/b*100 (or a-b); mean, CI half-width, n."""
    diffs = []
    for run, a in a_by_run.items():
        b = b_by_run.get(run)
        if b is not None and b != 0:
            diffs.append(100.0 * (a - b) / b if relative else a - b)
    return mean_ci(diffs)


def fmt_ci(m, h, nd=1, unit=""):
    if math.isnan(m):
        return "-"
    return f"{m:+.{nd}f}{unit} ± {h:.{nd}f}" if not math.isnan(h) else f"{m:+.{nd}f}{unit}"
