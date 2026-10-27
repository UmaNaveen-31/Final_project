import os
from pathlib import Path

from cryptography.fernet import Fernet

PREFIX = "fernet:v1:"

KEY_FILE = Path(
    os.getenv(
        "SBOM_CLAIMS_KEY_FILE",
        "/run/secrets/sbom_claims.key"
    )
)


def _get_fernet():
    try:
        key = KEY_FILE.read_bytes().strip()
        return Fernet(key)
    except Exception as exc:
        raise RuntimeError(
            f"Cannot load the claims encryption key from {KEY_FILE}"
        ) from exc


def encrypt_claims(serialized_claims: str) -> str:
    if not isinstance(serialized_claims, str):
        raise TypeError("Claims must be provided as a JSON string")

    encrypted = _get_fernet().encrypt(
        serialized_claims.encode("utf-8")
    )

    return PREFIX + encrypted.decode("ascii")


def decrypt_claims(stored_claims: str) -> str:
    if not isinstance(stored_claims, str):
        raise TypeError("Stored claims must be a string")

    # Preserve compatibility with existing plaintext records
    # until the database migration is completed.
    if not stored_claims.startswith(PREFIX):
        return stored_claims

    encrypted = stored_claims[len(PREFIX):]

    try:
        return _get_fernet().decrypt(
            encrypted.encode("ascii")
        ).decode("utf-8")
    except Exception as exc:
        raise ValueError(
            "Unable to decrypt claims; check the configured key"
        ) from exc
