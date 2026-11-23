"""VerifiedTokenCache (E5 baseline 3)."""

from interceptors.jws_tokens import TokenSigner, TokenVerifier
from interceptors.token_cache import VerifiedTokenCache


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def setup(ttl=60, max_entries=10):
    clock = Clock()
    signer = TokenSigner("ES256")
    verifier = TokenVerifier({"ES256": signer.public_key}, clock=clock)
    return signer, verifier, VerifiedTokenCache(verifier, ttl=ttl, max_entries=max_entries, clock=clock), clock


def test_second_call_skips_verification():
    signer, verifier, cache, clock = setup()
    token = signer.make_token({"sub": "a", "exp": clock() + 600})
    assert cache(token)["sub"] == "a"
    assert cache(token)["sub"] == "a"
    assert verifier.calls == 1
    assert cache.stats == {"hit": 1, "miss": 1, "rejected": 0}


def test_invalid_token_not_cached():
    signer, verifier, cache, clock = setup()
    token = signer.make_token({"sub": "a", "exp": clock() + 600})
    bad = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    assert cache(bad) is None and cache(bad) is None
    assert verifier.calls == 2 and not cache.entries


def test_entry_expires_with_ttl_and_exp():
    signer, verifier, cache, clock = setup(ttl=60)
    token = signer.make_token({"sub": "a", "exp": clock() + 30})    # exp before ttl
    cache(token)
    clock.t += 31
    assert cache(token) is None                                      # expired token: re-verified, rejected
    assert verifier.calls == 2


def test_ttl_forces_reverification():
    signer, verifier, cache, clock = setup(ttl=60)
    token = signer.make_token({"sub": "a", "exp": clock() + 6000})
    cache(token)
    clock.t += 61
    assert cache(token) is not None
    assert verifier.calls == 2


def test_bounded():
    signer, verifier, cache, clock = setup(max_entries=3)
    tokens = [signer.make_token({"sub": str(i), "exp": clock() + 600}) for i in range(5)]
    for t in tokens:
        cache(t)
    assert len(cache.entries) == 3
