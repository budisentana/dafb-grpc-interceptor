"""
DAFB Project: ML-DSA-65 Cryptographic Tests

Tests:
1. ML-DSA-65 key generation
2. Digital signature generation
3. Signature verification
4. Rejection of a tampered message

Dependency:
    liboqs-python

Run:
    python test_mldsa65.py
"""

import oqs


def test_mldsa65_sign_and_verify():
    """Test ML-DSA-65 signing and verification."""

    message = b"DAFB ML-DSA-65 installation test"

    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)

    with oqs.Signature("ML-DSA-65") as verifier:
        valid = verifier.verify(message, signature, public_key)

    print("\n=== Test 1: ML-DSA-65 Signing and Verification ===")
    print("Algorithm: ML-DSA-65")
    print("Message signed:", len(signature) > 0)
    print("Signature verified:", valid)
    print("Public key size:", len(public_key), "bytes")
    print("Signature size:", len(signature), "bytes")

    assert len(signature) > 0, "Signature generation failed!"
    assert valid is True, "Signature verification failed!"

    print("RESULT: PASS")

    return public_key, signature


def test_mldsa65_tamper_detection():
    """Test whether ML-DSA-65 rejects a modified message."""

    message = b"DAFB credential: user=alice"
    tampered_message = b"DAFB credential: user=mallory"

    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)

    with oqs.Signature("ML-DSA-65") as verifier:
        original_valid = verifier.verify(
            message, signature, public_key
        )

        tampered_valid = verifier.verify(
            tampered_message, signature, public_key
        )

    print("\n=== Test 2: ML-DSA-65 Tamper Detection ===")
    print("Original message accepted:", original_valid)
    print("Tampered message accepted:", tampered_valid)

    assert original_valid is True, (
        "The original message should be accepted!"
    )

    assert tampered_valid is False, (
        "The tampered message should be rejected!"
    )

    print("RESULT: PASS")


if __name__ == "__main__":
    test_mldsa65_sign_and_verify()
    test_mldsa65_tamper_detection()

    print("\nAll ML-DSA-65 tests passed.")