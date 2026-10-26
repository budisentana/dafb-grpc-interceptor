"""
DAFB: ML-DSA-65 credential signing and verification.

This module provides the cryptographic operations needed by the
DAFB gRPC client and server.
"""

import oqs

ALGORITHM = "ML-DSA-65"


def sign_credential(credential: bytes) -> tuple[bytes, bytes]:
    """
    Generate an ML-DSA-65 key pair and sign a credential.

    Returns:
        (public_key, signature)
    """
    if not isinstance(credential, bytes):
        raise TypeError("credential must be bytes")

    with oqs.Signature(ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(credential)

    return public_key, signature


def verify_credential(
    credential: bytes,
    signature: bytes,
    public_key: bytes,
) -> bool:
    """Verify an ML-DSA-65 signature against a credential."""

    if not all(
        isinstance(value, bytes)
        for value in (credential, signature, public_key)
    ):
        raise TypeError(
            "credential, signature, and public_key must be bytes"
        )

    with oqs.Signature(ALGORITHM) as verifier:
        return verifier.verify(credential, signature, public_key)