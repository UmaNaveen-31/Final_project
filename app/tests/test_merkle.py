from security.merkle import (
    build_merkle_root,
    build_merkle_proof,
    verify_merkle_proof,
)


def test_merkle_claim_verification():
    values = [
        "CycloneDX",
        "1.7",
        "fastapi:0.141.1",
        "pydantic:2.13.5",
        "requests:2.34.2",
    ]

    root = build_merkle_root(values)
    proof = build_merkle_proof(values, 2)

    assert verify_merkle_proof(
        "fastapi:0.141.1",
        proof,
        root
    )


def test_tampered_claim_is_rejected():
    values = [
        "CycloneDX",
        "1.7",
        "fastapi:0.141.1",
        "pydantic:2.13.5",
        "requests:2.34.2",
    ]

    root = build_merkle_root(values)
    proof = build_merkle_proof(values, 2)

    assert not verify_merkle_proof(
        "fastapi:9.99.99",
        proof,
        root
    )
