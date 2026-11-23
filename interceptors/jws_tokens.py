"""
DAFB bearer tokens in JWS compact form (header.claims.signature), as used in E2/E3.

Same format as experiments/e3_combined (raw r||s for ES256, raw Ed25519, raw
ML-DSA signatures, base64url without padding, "Bearer " prefix), packaged so
that the DAFB interceptors and E4/E5 can share it. E3's own scripts are left
unchanged so their published results stay reproducible.

  signer = TokenSigner("ML-DSA-65")
  token = signer.make_token({"sub": "client", "exp": int(time.time()) + 3600})
  verifier = TokenVerifier({"ML-DSA-65": signer.public_key})
  claims = verifier(token)          # dict, or None if invalid

Signer and verifier objects stay open for their whole life (as in E3).
"""

import base64
import binascii
import json
import time
from typing import Any, Callable, Dict, Optional

SCHEMES = ("ES256", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
BEARER_PREFIX = "Bearer "


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class TokenSigner:
    """One key pair per instance. `secret_key` (liboqs schemes only) reuses an existing key."""

    def __init__(self, scheme: str, secret_key: Optional[bytes] = None, public_key: Optional[bytes] = None):
        if scheme not in SCHEMES:
            raise ValueError(f"unsupported scheme: {scheme}")
        self.scheme = scheme
        if scheme == "ES256":
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
            key = ec.generate_private_key(ec.SECP256R1())
            self.public_key = key.public_key().public_bytes(serialization.Encoding.X962,
                                                            serialization.PublicFormat.UncompressedPoint)

            def sign(message: bytes) -> bytes:
                r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
                return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        elif scheme == "EdDSA":
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
            key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = key.public_key().public_bytes(serialization.Encoding.Raw,
                                                            serialization.PublicFormat.Raw)
            sign = key.sign
        else:
            import oqs
            if secret_key is not None:
                if public_key is None:
                    raise ValueError("public_key is required with secret_key")
                self._oqs = oqs.Signature(scheme, secret_key=secret_key)
                self.public_key = public_key
            else:
                self._oqs = oqs.Signature(scheme)
                self.public_key = self._oqs.generate_keypair()
            sign = self._oqs.sign
        self.sign = sign
        self.header_b64 = b64url(json.dumps({"alg": scheme, "typ": "JWT"}, separators=(",", ":")).encode())

    def make_token(self, claims: Dict[str, Any]) -> str:
        claims_b64 = b64url(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{self.header_b64}.{claims_b64}"
        return f"{BEARER_PREFIX}{signing_input}.{b64url(self.sign(signing_input.encode('ascii')))}"


def _make_verify(scheme: str, public_key: bytes) -> Callable[[bytes, bytes], bool]:
    if scheme == "ES256":
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)

        def verify(message: bytes, sig: bytes) -> bool:
            if len(sig) != 64:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            try:
                key.verify(der, message, ec.ECDSA(hashes.SHA256()))
                return True
            except InvalidSignature:
                return False
        return verify
    if scheme == "EdDSA":
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519
        key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)

        def verify(message: bytes, sig: bytes) -> bool:
            try:
                key.verify(sig, message)
                return True
            except InvalidSignature:
                return False
        return verify
    if scheme in SCHEMES:
        import oqs
        verifier = oqs.Signature(scheme)

        def verify(message: bytes, sig: bytes) -> bool:
            return bool(verifier.verify(message, sig, public_key))
        return verify
    raise ValueError(f"unsupported scheme: {scheme}")


class TokenVerifier:
    """Callable: token string -> claims dict, or None if malformed, unknown scheme, bad signature or expired.

    `check_exp`: reject tokens whose numeric `exp` claim is in the past (wall clock `clock()`).
    `last_verify_ns` holds the duration of the most recent signature check (0 if none ran).
    """

    def __init__(self, public_keys: Dict[str, bytes], check_exp: bool = True,
                 clock: Callable[[], float] = time.time):
        self._verify = {scheme: _make_verify(scheme, pub) for scheme, pub in public_keys.items()}
        self.check_exp = check_exp
        self.clock = clock
        self.last_verify_ns = 0
        self.calls = 0

    def __call__(self, token: str) -> Optional[Dict[str, Any]]:
        self.last_verify_ns = 0
        if not token.startswith(BEARER_PREFIX):
            return None
        try:
            header_b64, claims_b64, sig_b64 = token[len(BEARER_PREFIX):].split(".")
            header = json.loads(b64url_decode(header_b64))
            claims = json.loads(b64url_decode(claims_b64))
            signature = b64url_decode(sig_b64)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return None
        if not isinstance(header, dict) or not isinstance(claims, dict):
            return None
        verify = self._verify.get(header.get("alg"))
        if verify is None:
            return None
        self.calls += 1
        start = time.perf_counter_ns()
        ok = verify(f"{header_b64}.{claims_b64}".encode("ascii"), signature)
        self.last_verify_ns = time.perf_counter_ns() - start
        if not ok:
            return None
        exp = claims.get("exp")
        if self.check_exp and isinstance(exp, (int, float)) and exp <= self.clock():
            return None
        return claims
