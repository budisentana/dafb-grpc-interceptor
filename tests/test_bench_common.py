"""bench_common: link check against tc output, netem counters, paired statistics."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments" / "common"))
import bench_common as bc  # noqa: E402

FILTERS = "filter parent 1: protocol ip pref 1 u32 ...\n  match 0000c3be/0000ffff at 20\n"
QDISC = ("qdisc prio 1: root refcnt 2 bands 3 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1\n"
         " Sent 999 bytes 9 pkt (dropped 0, overlimits 0 requeues 0)\n"
         "qdisc netem 30: parent 1:3 limit 10000 {args}\n"
         " Sent 163934415 bytes 187533 pkt (dropped 7, overlimits 0 requeues 0)\n backlog 0b 0p requeues 0\n")


def fake(monkeypatch, args, filters=FILTERS):
    monkeypatch.setattr(bc, "tc_text", lambda: [QDISC.format(args=args), filters])


@pytest.mark.parametrize("link,args", [
    ("L1", "rate 1Gbit"), ("L2", "delay 5ms rate 100Mbit"), ("L3", "delay 5ms loss 0.5% rate 100Mbit"),
    ("L4", "delay 20ms rate 20Mbit"), ("N100", "rate 100Mbit")])
def test_profiles_accepted(monkeypatch, link, args):
    fake(monkeypatch, args)
    assert "netem" in bc.check_link(link, 50110)


@pytest.mark.parametrize("link,args", [
    ("L1", "rate 100Mbit"), ("L2", "delay 5ms loss 0.5% rate 100Mbit"), ("L3", "delay 5ms rate 100Mbit"),
    ("L4", "delay 5ms rate 20Mbit"), ("N100", "delay 5ms rate 100Mbit")])
def test_wrong_profile_rejected(monkeypatch, link, args):
    fake(monkeypatch, args)
    with pytest.raises(SystemExit):
        bc.check_link(link, 50110)


def test_wrong_port_rejected(monkeypatch):
    fake(monkeypatch, "rate 1Gbit")
    with pytest.raises(SystemExit):
        bc.check_link("L1", 50120)


def test_loopback_requires_no_netem(monkeypatch):
    fake(monkeypatch, "rate 1Gbit")
    with pytest.raises(SystemExit):
        bc.check_link("loopback", 50110)


def test_netem_counters(monkeypatch):
    fake(monkeypatch, "rate 1Gbit")
    assert bc.netem_counters() == (163934415, 187533, 7)


def test_paired_ci():
    a = {1: 90.0, 2: 95.0, 3: 100.0, 4: 85.0, 5: 92.0}
    b = {1: 100.0, 2: 100.0, 3: 100.0, 4: 100.0, 5: 100.0}
    m, h, n = bc.paired(a, b)
    import statistics
    diffs = [-10.0, -5.0, 0.0, -15.0, -8.0]
    assert n == 5 and m == pytest.approx(-7.6)
    assert h == pytest.approx(2.776 * statistics.stdev(diffs) / 5 ** 0.5)
