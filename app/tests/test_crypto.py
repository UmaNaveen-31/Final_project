from security.crypto import sha256_file


def test_sha256_file():
    file_path = "tests/test_sample.txt"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("SBOM verification test")

    result = sha256_file(file_path)

    assert len(result) == 64
    assert result.isalnum()
