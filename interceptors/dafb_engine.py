"""
DAFB engine: adaptive inline / by-reference bearer tokens for gRPC.

A post-quantum bearer token (ML-DSA-65: about 4.4 KB once encoded) does not fit
the 4 KB HPACK dynamic table, so it is sent in full on every call, and the
server verifies it on every call (E2/E3). DAFB keeps small tokens inline and
sends large ones by reference:

  1. register   the client sends the full token with x-dafb-mode: register.
                The server verifies it, stores the claims under a random handle
                with a TTL, and returns x-dafb-handle / x-dafb-handle-ttl in the
                response's initial metadata.
  2. reference  later calls carry only x-dafb-mode: reference and
                x-dafb-handle. The server looks the handle up; no token is sent
                and no signature is verified.
  3. fallback   if the handle is unknown or expired, the server fails the call
                with UNAUTHENTICATED and trailing x-dafb-error: handle-invalid.
                The client drops the handle and retries once with step 1.

  inline        tokens whose wire size fits the HPACK budget
                (4096 - 512 bytes) are sent as plain bearer tokens with
                x-dafb-mode: inline and verified on every call.

The client decides the mode (`policy`: adaptive, reference or inline). The
server enforces it: a token that fails verification is rejected with
x-dafb-error: token-invalid and never gets a handle. A handle never lives
longer than the token's own `exp` claim.

The service reads the caller's claims with `current_claims()`.

A handle is a bearer secret, like the token it stands for: it is not bound to
the connection, so use it only over TLS in deployment. The client interceptor
covers unary-unary calls; the server interceptor covers all four call types.
"""

import secrets
import threading
import time
from collections import OrderedDict
from contextvars import ContextVar
from typing import Any, Callable, Dict, NamedTuple, Optional, Tuple

import grpc

HPACK_DYNAMIC_TABLE_BUDGET = 4096
HYSTERESIS_PADDING = 512
DEFAULT_HANDLE_TTL = 3600
DEFAULT_MAX_HANDLES = 100_000

MODE_KEY = "x-dafb-mode"
HANDLE_KEY = "x-dafb-handle"
HANDLE_TTL_KEY = "x-dafb-handle-ttl"
ERROR_KEY = "x-dafb-error"

MODE_INLINE = "inline"
MODE_REGISTER = "register"
MODE_REFERENCE = "reference"

ERROR_HANDLE_INVALID = "handle-invalid"
ERROR_TOKEN_INVALID = "token-invalid"
ERROR_MISSING = "credential-missing"

HANDLE_PREFIX = "dafb_ref_"

ClaimsVerifier = Callable[[str], Optional[Dict[str, Any]]]

_current_claims: ContextVar[Optional[Dict[str, Any]]] = ContextVar("dafb_claims", default=None)


def current_claims() -> Optional[Dict[str, Any]]:
    """Claims of the authenticated caller, inside a service method behind DAFBServerInterceptor."""
    return _current_claims.get()


class DAFBSecurityContext:
    @staticmethod
    def calculate_wire_size(metadata_key: str, token: str) -> int:
        """HPACK entry size of one header field: name + value + 32 bytes (RFC 7541, 4.1)."""
        return len(metadata_key.encode("utf-8")) + len(token.encode("utf-8")) + 32

    @staticmethod
    def exceeds_hpack_budget(metadata_key: str, token: str) -> bool:
        threshold = HPACK_DYNAMIC_TABLE_BUDGET - HYSTERESIS_PADDING
        return DAFBSecurityContext.calculate_wire_size(metadata_key, token) > threshold


class ModifiedClientCallDetails(NamedTuple("_CallDetails", [
        ("method", str), ("timeout", Optional[float]), ("metadata", Any), ("credentials", Any),
        ("wait_for_ready", Optional[bool]), ("compression", Any)]), grpc.ClientCallDetails):
    """grpc.ClientCallDetails is immutable; this copy carries the rewritten metadata."""

    @classmethod
    def replace_metadata(cls, details: Any, metadata: list) -> "ModifiedClientCallDetails":
        return cls(details.method, details.timeout, metadata, details.credentials,
                   getattr(details, "wait_for_ready", None), getattr(details, "compression", None))


def _metadata_value(metadata, key: str) -> Optional[str]:
    for k, v in metadata or ():
        if k == key:
            return v
    return None


# --------------------------------------------------
# Client
# --------------------------------------------------

class DAFBClientInterceptor(grpc.UnaryUnaryClientInterceptor):
    """Rewrites the bearer token under `metadata_auth_key` into the DAFB modes.

    policy:  adaptive   reference path only for tokens over the HPACK budget (default)
             reference  reference path for every token
             inline     never use handles (plain bearer token, tagged inline)
    refresh_margin: seconds before the server-announced expiry at which the
             client stops using a handle and registers again.
    """

    POLICIES = ("adaptive", "reference", "inline")

    def __init__(self, target_endpoint: str = "", metadata_auth_key: str = "authorization-pq",
                 policy: str = "adaptive", refresh_margin: float = 1.0,
                 clock: Callable[[], float] = time.monotonic):
        if policy not in self.POLICIES:
            raise ValueError(f"policy must be one of {self.POLICIES}")
        self.target_endpoint = target_endpoint
        self.auth_key = metadata_auth_key
        self.policy = policy
        self.refresh_margin = refresh_margin
        self.clock = clock
        self.handle_cache: Dict[str, Tuple[str, float]] = {}   # token -> (handle, local expiry)
        self.cache_lock = threading.Lock()
        self.stats = {"inline": 0, "register": 0, "reference": 0, "handle_rejected": 0, "no_handle_issued": 0}
        self._stats_lock = threading.Lock()

    # -- cache ----------------------------------------------------------

    def cached_handle(self, token: str) -> Optional[str]:
        with self.cache_lock:
            entry = self.handle_cache.get(token)
            if entry is None:
                return None
            handle, expires = entry
            if self.clock() >= expires:
                del self.handle_cache[token]
                return None
            return handle

    def forget(self, token: Optional[str] = None) -> None:
        """Drop the handle for one token, or every handle."""
        with self.cache_lock:
            if token is None:
                self.handle_cache.clear()
            else:
                self.handle_cache.pop(token, None)

    def _store(self, token: str, handle: str, ttl: float) -> None:
        expires = self.clock() + ttl - self.refresh_margin
        if expires <= self.clock():
            return
        with self.cache_lock:
            self.handle_cache[token] = (handle, expires)

    def _count(self, name: str) -> None:
        with self._stats_lock:
            self.stats[name] += 1

    # -- interception ---------------------------------------------------

    def _use_reference(self, token: str) -> bool:
        if self.policy == "reference":
            return True
        if self.policy == "inline":
            return False
        return DAFBSecurityContext.exceeds_hpack_budget(self.auth_key, token)

    def intercept_unary_unary(self, continuation, client_call_details, request):
        metadata = list(client_call_details.metadata or [])
        token_index = next((i for i, (k, _) in enumerate(metadata) if k == self.auth_key), -1)
        if token_index < 0:
            return continuation(client_call_details, request)
        token = metadata[token_index][1]

        if not self._use_reference(token):
            self._count("inline")
            details = ModifiedClientCallDetails.replace_metadata(
                client_call_details, metadata + [(MODE_KEY, MODE_INLINE)])
            return continuation(details, request)

        handle = self.cached_handle(token)
        if handle is not None:
            self._count("reference")
            without_token = metadata[:token_index] + metadata[token_index + 1:]
            details = ModifiedClientCallDetails.replace_metadata(
                client_call_details, without_token + [(MODE_KEY, MODE_REFERENCE), (HANDLE_KEY, handle)])
            outcome = continuation(details, request)
            if not self._handle_rejected(outcome):
                return outcome
            self._count("handle_rejected")
            with self.cache_lock:
                if self.handle_cache.get(token, (None,))[0] == handle:
                    del self.handle_cache[token]

        self._count("register")
        details = ModifiedClientCallDetails.replace_metadata(
            client_call_details, metadata + [(MODE_KEY, MODE_REGISTER)])
        outcome = continuation(details, request)
        self._remember(outcome, token)
        return outcome

    @staticmethod
    def _handle_rejected(outcome) -> bool:
        if outcome.code() != grpc.StatusCode.UNAUTHENTICATED:
            return False
        return _metadata_value(outcome.trailing_metadata(), ERROR_KEY) == ERROR_HANDLE_INVALID

    def _remember(self, outcome, token: str) -> None:
        if outcome.code() != grpc.StatusCode.OK:
            return
        initial = outcome.initial_metadata()
        handle = _metadata_value(initial, HANDLE_KEY)
        ttl = _metadata_value(initial, HANDLE_TTL_KEY)
        if handle is None or ttl is None:
            self._count("no_handle_issued")
            return
        try:
            self._store(token, handle, float(ttl))
        except ValueError:
            self._count("no_handle_issued")


# --------------------------------------------------
# Server
# --------------------------------------------------

class DAFBServerInterceptor(grpc.ServerInterceptor):
    """Authenticates every call: inline/register tokens by `token_verifier`, references by handle lookup.

    token_verifier: token string -> claims dict, or None when the token is invalid
                    (for example interceptors.jws_tokens.TokenVerifier).
    require_auth:   reject calls that carry neither a token nor a handle.
    handle_ttl:     seconds a handle stays valid (capped by the token's `exp`).
    max_handles:    cache size; when full, expired handles go first, then the oldest.
    clock:          wall clock in seconds (compared with `exp`).
    """

    def __init__(self, metadata_auth_key: str = "authorization-pq",
                 token_verifier: Optional[ClaimsVerifier] = None, require_auth: bool = True,
                 handle_ttl: float = DEFAULT_HANDLE_TTL, max_handles: int = DEFAULT_MAX_HANDLES,
                 clock: Callable[[], float] = time.time):
        self.auth_key = metadata_auth_key
        self.token_verifier = token_verifier
        self.require_auth = require_auth
        self.handle_ttl = handle_ttl
        self.max_handles = max_handles
        self.clock = clock
        # handle -> (claims, absolute expiry on `clock`)
        self.validation_cache: "OrderedDict[str, Tuple[Dict[str, Any], float]]" = OrderedDict()
        self.cache_lock = threading.Lock()
        self.stats = {"verified": 0, "rejected_token": 0, "issued": 0, "handle_hit": 0,
                      "handle_miss": 0, "missing": 0}
        self._stats_lock = threading.Lock()

    # -- handle store ---------------------------------------------------

    def register_incoming_handle(self, handle: str, validated_claims: Dict[str, Any],
                                 ttl: Optional[float] = None) -> float:
        """Store claims under `handle`. Returns the expiry time (on `clock`)."""
        now = self.clock()
        expires = now + (self.handle_ttl if ttl is None else ttl)
        exp = validated_claims.get("exp")
        if isinstance(exp, (int, float)):
            expires = min(expires, float(exp))
        with self.cache_lock:
            if handle not in self.validation_cache and len(self.validation_cache) >= self.max_handles:
                self._evict(now)
            self.validation_cache[handle] = (validated_claims, expires)
        return expires

    def issue_handle(self, validated_claims: Dict[str, Any]) -> Tuple[str, float]:
        """New random handle for already-verified claims. Returns (handle, expiry)."""
        handle = HANDLE_PREFIX + secrets.token_urlsafe(24)
        return handle, self.register_incoming_handle(handle, validated_claims)

    def lookup_handle(self, handle: str) -> Optional[Dict[str, Any]]:
        with self.cache_lock:
            entry = self.validation_cache.get(handle)
            if entry is None:
                return None
            claims, expires = entry
            if self.clock() >= expires:
                del self.validation_cache[handle]
                return None
            return claims

    def revoke_handle(self, handle: str) -> None:
        with self.cache_lock:
            self.validation_cache.pop(handle, None)

    def clear_handles(self) -> None:
        """Forget every handle (simulates a server restart)."""
        with self.cache_lock:
            self.validation_cache.clear()

    def _evict(self, now: float) -> None:
        expired = [h for h, (_, exp) in self.validation_cache.items() if exp <= now]
        for h in expired:
            del self.validation_cache[h]
        while len(self.validation_cache) >= self.max_handles:
            self.validation_cache.popitem(last=False)

    def _count(self, name: str) -> None:
        with self._stats_lock:
            self.stats[name] += 1

    # -- authentication -------------------------------------------------

    def authenticate(self, metadata, context) -> Optional[Dict[str, Any]]:
        """Claims for this call; aborts the call (raises) when it must be rejected."""
        mode = _metadata_value(metadata, MODE_KEY)
        token = _metadata_value(metadata, self.auth_key)

        if mode == MODE_REFERENCE:
            handle = _metadata_value(metadata, HANDLE_KEY)
            claims = self.lookup_handle(handle) if handle else None
            if claims is None:
                self._count("handle_miss")
                self._abort(context, ERROR_HANDLE_INVALID, "unknown or expired DAFB handle")
            self._count("handle_hit")
            return claims

        if token is None:
            if self.require_auth:
                self._count("missing")
                self._abort(context, ERROR_MISSING, "credential required")
            return None

        claims = self.token_verifier(token) if self.token_verifier is not None else None
        if claims is None:
            self._count("rejected_token")
            self._abort(context, ERROR_TOKEN_INVALID, "invalid bearer token")
        self._count("verified")

        if mode == MODE_REGISTER:
            handle, expires = self.issue_handle(claims)
            ttl = int(expires - self.clock())
            if ttl > 0:
                self._count("issued")
                context.send_initial_metadata(((HANDLE_KEY, handle), (HANDLE_TTL_KEY, str(ttl))))
            else:
                self.revoke_handle(handle)
        return claims

    @staticmethod
    def _abort(context, error: str, details: str) -> None:
        context.set_trailing_metadata(((ERROR_KEY, error),))
        context.abort(grpc.StatusCode.UNAUTHENTICATED, details)

    # -- interception ---------------------------------------------------

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None:
            return None
        metadata = handler_call_details.invocation_metadata

        def wrap_unary_response(behavior):
            def wrapped(request_or_iterator, context):
                claims = self.authenticate(metadata, context)
                reset = _current_claims.set(claims)
                try:
                    return behavior(request_or_iterator, context)
                finally:
                    _current_claims.reset(reset)
            return wrapped

        def wrap_stream_response(behavior):
            def wrapped(request_or_iterator, context):
                claims = self.authenticate(metadata, context)
                reset = _current_claims.set(claims)
                try:
                    yield from behavior(request_or_iterator, context)
                finally:
                    _current_claims.reset(reset)
            return wrapped

        kwargs = dict(request_deserializer=handler.request_deserializer,
                      response_serializer=handler.response_serializer)
        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(wrap_unary_response(handler.unary_unary), **kwargs)
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(wrap_stream_response(handler.unary_stream), **kwargs)
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(wrap_unary_response(handler.stream_unary), **kwargs)
        return grpc.stream_stream_rpc_method_handler(wrap_stream_response(handler.stream_stream), **kwargs)
