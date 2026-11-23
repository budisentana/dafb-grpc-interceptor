"""E4 helpers: claim set size and expiry, break-even formula."""

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments" / "e4_dafb"))

import e4_analyze  # noqa: E402
import e4_benchmark  # noqa: E402
from interceptors.jws_tokens import TokenSigner, TokenVerifier  # noqa: E402


def test_claim_set_is_200_bytes_and_not_expired():
    claims = e4_benchmark.claim_set()
    assert len(json.dumps(claims, separators=(",", ":")).encode()) == 200
    assert claims["exp"] > time.time()


def test_e4_token_passes_verifier_with_exp_check():
    signer = TokenSigner("ES256")
    verifier = TokenVerifier({"ES256": signer.public_key}, check_exp=True)
    assert verifier(signer.make_token(e4_benchmark.claim_set())) is not None


def test_breakeven():
    # registration 550, reference 370, baseline 490: 550 + k*370 <= (k+1)*490 -> k >= 0.5 -> 1
    assert e4_analyze.breakeven(550, 370, 490)[0] == 1
    # registration no dearer than baseline: break-even right away
    assert e4_analyze.breakeven(400, 370, 490)[0] == 0
    # exact boundary counts as break-even
    assert e4_analyze.breakeven(590, 390, 490)[0] == 1
    # reference not cheaper than baseline: never
    assert e4_analyze.breakeven(550, 500, 490) == (None, None)
