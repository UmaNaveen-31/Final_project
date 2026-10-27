
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


KEY_PATH = Path(
    os.getenv(
        "SBOM_REPORT_SIGNING_KEY_FILE",
        str(
            Path.home()
            / ".config"
            / "sbom-sentinel"
            / "report-signing-key.pem"
        ),
    )
)


def load_signing_key():
    if not KEY_PATH.exists():
        raise RuntimeError(
            "Signing key not found. Create the report-signing key first."
        )

    with open(KEY_PATH, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )


def canonical_json(report):
    return json.dumps(
        report,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_report(report):
    private_key = load_signing_key()
    signature = private_key.sign(canonical_json(report))

    return base64.b64encode(signature).decode("ascii")


def verify_report(report, signature):
    try:
        private_key = load_signing_key()
        public_key = private_key.public_key()

        signature_bytes = base64.b64decode(
            signature,
            validate=True,
        )

        public_key.verify(
            signature_bytes,
            canonical_json(report),
        )

        return True

    except Exception:
        return False
