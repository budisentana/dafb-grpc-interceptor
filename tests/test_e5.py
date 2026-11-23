"""E5 break-even with a baseline whose first call differs from its steady call."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments" / "e5_baselines"))

import e5_analyze  # noqa: E402


def test_breakeven_equal_first_and_steady():
    # DAFB 550 + k*370 <= 490 + k*490 -> k >= 0.5 -> 1 (same as E4)
    assert e5_analyze.breakeven(550, 370, 490, 490)[0] == 1


def test_breakeven_cache_baseline():
    # cache: miss 500, hit 360; DAFB: register 560, reference 350 -> (560-500)/(360-350) = 6
    assert e5_analyze.breakeven(560, 350, 500, 360)[0] == 6


def test_breakeven_never_when_reference_not_cheaper():
    assert e5_analyze.breakeven(560, 370, 500, 360) == (None, None)


def test_breakeven_zero_when_registration_cheaper_than_first_call():
    assert e5_analyze.breakeven(450, 350, 500, 360)[0] == 0
