from pathlib import Path

from interceptors.mldsa_credentials import generate_keypair

KEY_DIR = Path("keys")
PUBLIC_KEY_FILE = KEY_DIR / "mldsa65_public.key"
SECRET_KEY_FILE = KEY_DIR / "mldsa65_secret.key"


def main():
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    # Avoid accidentally replacing an existing experimental identity.
    if PUBLIC_KEY_FILE.exists() or SECRET_KEY_FILE.exists():
        raise FileExistsError(
            "A key file already exists. Refusing to overwrite it."
        )

    public_key, secret_key = generate_keypair()

    try:
        PUBLIC_KEY_FILE.write_bytes(public_key)
        SECRET_KEY_FILE.write_bytes(secret_key)

        # Restrict secret-key access to the current user.
        SECRET_KEY_FILE.chmod(0o600)

    except Exception:
        # Remove partially written files if generation or writing fails.
        PUBLIC_KEY_FILE.unlink(missing_ok=True)
        SECRET_KEY_FILE.unlink(missing_ok=True)
        raise

    print("ML-DSA-65 key pair generated.")
    print(f"Public key: {PUBLIC_KEY_FILE} ({len(public_key)} bytes)")
    print(f"Secret key: {SECRET_KEY_FILE} ({len(secret_key)} bytes)")
    print("Secret key permissions restricted to the current user.")


if __name__ == "__main__":
    main()