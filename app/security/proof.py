import hashlib
import json


def generate_proof(claims):
    claims_json = json.dumps(claims, sort_keys=True)

    return hashlib.sha256(
        claims_json.encode("utf-8")
    ).hexdigest()
