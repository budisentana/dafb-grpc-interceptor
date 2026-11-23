"""
Server-side verified-token cache (E5 baseline 3).

The client keeps sending the full bearer token on every call; the server
skips signature verification when it has already verified the same token.
Entries are keyed by SHA-256 of the token string and follow the same rules as
DAFB handles, so the two are compared on equal terms:

  - an entry lives `ttl` seconds (default 3600, as DAFB_HANDLE_TTL), capped by the token's `exp`
  - at most `max_entries` entries; when full, expired entries go first, then the oldest
  - only tokens that pass the verifier are cached

  cache = VerifiedTokenCache(TokenVerifier(keys))
  claims = cache(token)            # dict, or None if the token is invalid

Drop-in replacement for a token verifier (e.g. DAFBServerInterceptor(token_verifier=cache)).
"""

import hashlib
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, Optional, Tuple

from interceptors.dafb_engine import DEFAULT_HANDLE_TTL, DEFAULT_MAX_HANDLES


class VerifiedTokenCache:
    def __init__(self, verifier: Callable[[str], Optional[Dict[str, Any]]], ttl: float = DEFAULT_HANDLE_TTL,
                 max_entries: int = DEFAULT_MAX_HANDLES, clock: Callable[[], float] = time.time):
        self.verifier = verifier
        self.ttl = ttl
        self.max_entries = max_entries
        self.clock = clock
        self.entries: "OrderedDict[bytes, Tuple[Dict[str, Any], float]]" = OrderedDict()
        self.lock = threading.Lock()
        self.stats = {"hit": 0, "miss": 0, "rejected": 0}

    def __call__(self, token: str) -> Optional[Dict[str, Any]]:
        key = hashlib.sha256(token.encode("utf-8")).digest()
        now = self.clock()
        with self.lock:
            entry = self.entries.get(key)
            if entry is not None:
                claims, expires = entry
                if now < expires:
                    self.stats["hit"] += 1
                    return claims
                del self.entries[key]
        claims = self.verifier(token)
        with self.lock:
            if claims is None:
                self.stats["rejected"] += 1
                return None
            self.stats["miss"] += 1
            expires = now + self.ttl
            exp = claims.get("exp")
            if isinstance(exp, (int, float)):
                expires = min(expires, float(exp))
            if expires > now:
                if key not in self.entries and len(self.entries) >= self.max_entries:
                    self._evict(now)
                self.entries[key] = (claims, expires)
        return claims

    def _evict(self, now: float) -> None:
        for k in [k for k, (_, exp) in self.entries.items() if exp <= now]:
            del self.entries[k]
        while len(self.entries) >= self.max_entries:
            self.entries.popitem(last=False)
