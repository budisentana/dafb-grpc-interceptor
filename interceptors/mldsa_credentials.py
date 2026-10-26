"""
DAFB: ML-DSA-65 credential signing and verification.

Provides key generation, credential signing, and signature verification
for the DAFB gRPC experiment.
"""

import oqs

ALGORITHM = "ML-DSA-65"


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate an ML-DSA-65 key pair.

    Returns:
        (public_key, secret_key)
    """
    with oqs.Signature(ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    return public_key, secret_key


def sign_credential(
    credential: bytes,
    secret_key: bytes,
) -> bytes:
    """
    Sign a credential using an existing ML-DSA-65 secret key.

    Returns:
        signature
    """
    if not isinstance(credential, bytes):
        raise TypeError("credential must be bytes")

    if not isinstance(secret_key, bytes):
        raise TypeError("secret_key must be bytes")

    with oqs.Signature(ALGORITHM, secret_key=secret_key) as signer:
        return signer.sign(credential)


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