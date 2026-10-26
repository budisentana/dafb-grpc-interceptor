from interceptors.mldsa_credentials import (
    generate_keypair,
    sign_credential,
    verify_credential,
)

credential = b"DAFB experimental credential"

public_key, secret_key = generate_keypair()
signature = sign_credential(credential, secret_key)

valid = verify_credential(
    credential,
    signature,
    public_key,
)

tampered = verify_credential(
    b"DAFB tampered credential",
    signature,
    public_key,
)

print(f"Public key size: {len(public_key)} bytes")
print(f"Signature size: {len(signature)} bytes")
print(f"Valid credential accepted: {valid}")
print(f"Tampered credential accepted: {tampered}")

assert valid is True
assert tampered is False

print("RESULT: PASS")