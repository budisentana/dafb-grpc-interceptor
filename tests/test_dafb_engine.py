"""Unit tests for the DAFB reference path (interceptors/dafb_engine.py).

Run from the project folder:  python -m pytest tests/
"""

import sys
import time
from concurrent import futures
from pathlib import Path

import grpc
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from interceptors import dafb_engine as dafb  # noqa: E402
from interceptors.jws_tokens import TokenSigner, TokenVerifier  # noqa: E402
from protobufs import security_service_pb2 as pb2  # noqa: E402
from protobufs import security_service_pb2_grpc as pb2_grpc  # noqa: E402

AUTH_KEY = "authorization"


class FakeClock:
    def __init__(self, start=None):
        self.now = time.time() if start is None else start

    def __call__(self):
        return self.now


class EchoBroker(pb2_grpc.CredentialBrokerServicer):
    """Returns the caller's `sub` and records the metadata the service received."""

    def __init__(self):
        self.seen_metadata = []

    def RegisterCredential(self, request, context):
        self.seen_metadata.append(dict(context.invocation_metadata()))
        claims = dafb.current_claims() or {}
        return pb2.RegistrationResponse(opaque_handle=claims.get("sub", ""), expires_at=0)


@pytest.fixture(scope="module")
def signers():
    return {scheme: TokenSigner(scheme) for scheme in ("ML-DSA-65", "ES256")}


class Harness:
    def __init__(self, signers, policy="adaptive", handle_ttl=60.0, max_handles=1000, require_auth=True):
        self.server_clock = FakeClock()
        self.client_clock = FakeClock(start=0.0)
        self.verifier = TokenVerifier({s: k.public_key for s, k in signers.items()}, clock=self.server_clock)
        self.server_interceptor = dafb.DAFBServerInterceptor(
            AUTH_KEY, token_verifier=self.verifier, require_auth=require_auth,
            handle_ttl=handle_ttl, max_handles=max_handles, clock=self.server_clock)
        self.broker = EchoBroker()
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=2), interceptors=(self.server_interceptor,))
        pb2_grpc.add_CredentialBrokerServicer_to_server(self.broker, self.server)
        port = self.server.add_insecure_port("127.0.0.1:0")
        self.server.start()
        self.raw_channel = grpc.insecure_channel(f"127.0.0.1:{port}")
        self.client_interceptor = dafb.DAFBClientInterceptor(
            metadata_auth_key=AUTH_KEY, policy=policy, clock=self.client_clock)
        self.stub = pb2_grpc.CredentialBrokerStub(grpc.intercept_channel(self.raw_channel, self.client_interceptor))
        self.raw_stub = pb2_grpc.CredentialBrokerStub(self.raw_channel)

    def call(self, token, stub=None, extra=()):
        metadata = ([(AUTH_KEY, token)] if token is not None else []) + list(extra)
        response, _ = (stub or self.stub).RegisterCredential.with_call(
            pb2.RegistrationRequest(), metadata=metadata, timeout=5)
        return response.opaque_handle

    def close(self):
        self.raw_channel.close()
        self.server.stop(0)


@pytest.fixture
def make_harness(signers):
    created = []

    def factory(**kwargs):
        h = Harness(signers, **kwargs)
        created.append(h)
        return h
    yield factory
    for h in created:
        h.close()


def token_for(signer, sub="client-a", exp_in=3600, now=None):
    now = time.time() if now is None else now
    return signer.make_token({"sub": sub, "iat": int(now), "exp": int(now + exp_in)})


def trailer(exc, key):
    return dict(exc.trailing_metadata() or ()).get(key)


# --------------------------------------------------

def test_mldsa65_token_exceeds_hpack_budget(signers):
    assert dafb.DAFBSecurityContext.exceeds_hpack_budget(AUTH_KEY, token_for(signers["ML-DSA-65"]))
    assert not dafb.DAFBSecurityContext.exceeds_hpack_budget(AUTH_KEY, token_for(signers["ES256"]))


def test_first_call_registers_and_returns_handle(make_harness, signers):
    h = make_harness()
    token = token_for(signers["ML-DSA-65"])

    assert h.call(token) == "client-a"

    assert h.client_interceptor.stats["register"] == 1
    assert h.server_interceptor.stats["verified"] == 1
    assert h.server_interceptor.stats["issued"] == 1
    assert h.broker.seen_metadata[0][AUTH_KEY] == token
    assert h.broker.seen_metadata[0][dafb.MODE_KEY] == dafb.MODE_REGISTER
    handle = h.client_interceptor.cached_handle(token)
    assert handle and handle.startswith(dafb.HANDLE_PREFIX)
    assert handle in h.server_interceptor.validation_cache


def test_cache_hit_sends_handle_only_and_skips_verification(make_harness, signers):
    h = make_harness()
    token = token_for(signers["ML-DSA-65"])
    h.call(token)

    for _ in range(5):
        assert h.call(token) == "client-a"

    assert h.verifier.calls == 1
    assert h.server_interceptor.stats["handle_hit"] == 5
    assert h.client_interceptor.stats["reference"] == 5
    for seen in h.broker.seen_metadata[1:]:
        assert AUTH_KEY not in seen
        assert seen[dafb.MODE_KEY] == dafb.MODE_REFERENCE
        assert seen[dafb.HANDLE_KEY] == h.client_interceptor.cached_handle(token)


def test_handle_expired_on_server_falls_back_to_full_token(make_harness, signers):
    h = make_harness(handle_ttl=60)
    token = token_for(signers["ML-DSA-65"])
    h.call(token)
    old_handle = h.client_interceptor.cached_handle(token)

    h.server_clock.now += 120          # server expired the handle, client still thinks it is valid
    assert h.call(token) == "client-a"

    cs, ss = h.client_interceptor.stats, h.server_interceptor.stats
    assert cs["reference"] == 1 and cs["handle_rejected"] == 1 and cs["register"] == 2
    assert ss["handle_miss"] == 1 and ss["verified"] == 2 and ss["issued"] == 2
    new_handle = h.client_interceptor.cached_handle(token)
    assert new_handle and new_handle != old_handle
    assert old_handle not in h.server_interceptor.validation_cache


def test_handle_expired_on_client_registers_without_trying_it(make_harness, signers):
    h = make_harness(handle_ttl=60)
    token = token_for(signers["ML-DSA-65"])
    h.call(token)

    h.client_clock.now += 59.5         # inside the 1 s refresh margin
    h.call(token)

    assert h.client_interceptor.stats["reference"] == 0
    assert h.client_interceptor.stats["register"] == 2
    assert h.server_interceptor.stats["handle_miss"] == 0


def test_unknown_handle_is_rejected(make_harness):
    h = make_harness()
    with pytest.raises(grpc.RpcError) as err:
        h.call(None, stub=h.raw_stub,
               extra=[(dafb.MODE_KEY, dafb.MODE_REFERENCE), (dafb.HANDLE_KEY, "dafb_ref_forged")])
    assert err.value.code() == grpc.StatusCode.UNAUTHENTICATED
    assert trailer(err.value, dafb.ERROR_KEY) == dafb.ERROR_HANDLE_INVALID
    assert h.broker.seen_metadata == []


def test_reference_mode_without_handle_is_rejected(make_harness):
    h = make_harness()
    with pytest.raises(grpc.RpcError) as err:
        h.call(None, stub=h.raw_stub, extra=[(dafb.MODE_KEY, dafb.MODE_REFERENCE)])
    assert trailer(err.value, dafb.ERROR_KEY) == dafb.ERROR_HANDLE_INVALID


def test_server_restart_recovers_transparently(make_harness, signers):
    h = make_harness()
    token = token_for(signers["ML-DSA-65"])
    h.call(token)

    h.server_interceptor.clear_handles()
    assert h.call(token) == "client-a"
    assert h.client_interceptor.stats["handle_rejected"] == 1
    assert h.call(token) == "client-a"
    assert h.server_interceptor.stats["handle_hit"] == 1


@pytest.mark.parametrize("part", [1, 2])   # 1 = claims, 2 = signature
def test_tampered_token_is_rejected_and_gets_no_handle(make_harness, signers, part):
    h = make_harness()
    token = token_for(signers["ML-DSA-65"])
    pieces = token[len("Bearer "):].split(".")
    pieces[part] = pieces[part][:10] + ("A" if pieces[part][10] != "A" else "B") + pieces[part][11:]
    tampered = "Bearer " + ".".join(pieces)

    with pytest.raises(grpc.RpcError) as err:
        h.call(tampered)

    assert err.value.code() == grpc.StatusCode.UNAUTHENTICATED
    assert trailer(err.value, dafb.ERROR_KEY) == dafb.ERROR_TOKEN_INVALID
    assert h.client_interceptor.handle_cache == {}
    assert h.client_interceptor.stats["register"] == 1     # no retry loop
    assert h.server_interceptor.stats["issued"] == 0
    assert len(h.server_interceptor.validation_cache) == 0


def test_expired_token_is_rejected(make_harness, signers):
    h = make_harness()
    with pytest.raises(grpc.RpcError) as err:
        h.call(token_for(signers["ML-DSA-65"], exp_in=-5))
    assert trailer(err.value, dafb.ERROR_KEY) == dafb.ERROR_TOKEN_INVALID


def test_handle_never_outlives_token_exp(make_harness, signers):
    h = make_harness(handle_ttl=3600)
    token = token_for(signers["ML-DSA-65"], exp_in=30, now=h.server_clock.now)
    h.call(token)
    handle = h.client_interceptor.cached_handle(token)
    _, expires = h.server_interceptor.validation_cache[handle]
    assert expires <= h.server_clock.now + 30

    h.server_clock.now += 31
    with pytest.raises(grpc.RpcError) as err:   # reference rejected, re-registration fails: token expired
        h.call(token)
    assert trailer(err.value, dafb.ERROR_KEY) == dafb.ERROR_TOKEN_INVALID


def test_small_token_stays_inline_and_is_verified_every_call(make_harness, signers):
    h = make_harness()
    token = token_for(signers["ES256"])
    for _ in range(3):
        assert h.call(token) == "client-a"
    assert h.client_interceptor.stats["inline"] == 3
    assert h.verifier.calls == 3
    assert h.server_interceptor.stats["issued"] == 0
    assert all(seen[dafb.MODE_KEY] == dafb.MODE_INLINE and seen[AUTH_KEY] == token
               for seen in h.broker.seen_metadata)


def test_reference_policy_uses_handles_for_small_tokens(make_harness, signers):
    h = make_harness(policy="reference")
    token = token_for(signers["ES256"])
    h.call(token)
    h.call(token)
    assert h.verifier.calls == 1
    assert h.server_interceptor.stats["handle_hit"] == 1


def test_inline_policy_never_uses_handles(make_harness, signers):
    h = make_harness(policy="inline")
    token = token_for(signers["ML-DSA-65"])
    h.call(token)
    h.call(token)
    assert h.verifier.calls == 2
    assert h.server_interceptor.stats["issued"] == 0


def test_missing_credential(make_harness):
    h = make_harness()
    with pytest.raises(grpc.RpcError) as err:
        h.call(None)
    assert err.value.code() == grpc.StatusCode.UNAUTHENTICATED
    assert trailer(err.value, dafb.ERROR_KEY) == dafb.ERROR_MISSING

    open_h = make_harness(require_auth=False)
    assert open_h.call(None) == ""


def test_handles_are_per_token(make_harness, signers):
    h = make_harness()
    a, b = token_for(signers["ML-DSA-65"], sub="a"), token_for(signers["ML-DSA-65"], sub="b")
    assert [h.call(a), h.call(b), h.call(a), h.call(b)] == ["a", "b", "a", "b"]
    assert h.verifier.calls == 2
    assert h.client_interceptor.cached_handle(a) != h.client_interceptor.cached_handle(b)


def test_cache_size_is_bounded(signers):
    clock = FakeClock()
    server = dafb.DAFBServerInterceptor(AUTH_KEY, handle_ttl=10, max_handles=3, clock=clock)
    handles = [server.issue_handle({"sub": str(i)})[0] for i in range(3)]
    clock.now += 5
    handles.append(server.issue_handle({"sub": "3"})[0])     # full: evicts the oldest
    assert handles[0] not in server.validation_cache
    assert len(server.validation_cache) == 3
    clock.now += 6                                              # the first three have expired
    server.issue_handle({"sub": "4"})
    assert set(server.validation_cache) >= {handles[3]}
    assert len(server.validation_cache) == 2
