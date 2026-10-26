"""
DAFB: ML-DSA-65 credential signing and verification tests.

Tests:
1. Valid credential signature verification.
2. Rejection of a tampered credential.

Run from the project root:
    python test_mldsa_credentials.py
"""

from interceptors.mldsa_credentials import (
    sign_credential,
    verify_credential,
)


def test_valid_credential():
    """A valid credential must pass signature verification."""

    credential = b'{"subject":"alice","role":"researcher"}'

    public_key, signature = sign_credential(credential)

    valid = verify_credential(
        credential,
        signature,
        public_key,
    )

    print("Public key size:", len(public_key), "bytes")
    print("Signature size:", len(signature), "bytes")
    print("Valid credential accepted:", valid)

    assert valid is True, "Valid credential was rejected!"

    return public_key, signature


def test_tampered_credential():
    """A modified credential must fail signature verification."""

    credential = b'{"subject":"alice","role":"researcher"}'
    tampered_credential = b'{"subject":"mallory","role":"researcher"}'

    public_key, signature = sign_credential(credential)

    tampered_valid = verify_credential(
        tampered_credential,
        signature,
        public_key,
    )

    print("Tampered credential accepted:", tampered_valid)

    assert tampered_valid is False, (
        "Tampered credential was incorrectly accepted!"
    )


if __name__ == "__main__":
    print("\n=== Test 1: Valid Credential ===")
    test_valid_credential()
    print("RESULT: PASS")

    print("\n=== Test 2: Tampered Credential ===")
    test_tampered_credential()
    print("RESULT: PASS")

    print("\nAll credential tests passed.")