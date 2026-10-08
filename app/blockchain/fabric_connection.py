import os


FABRIC_CHANNEL = os.getenv("FABRIC_CHANNEL", "sbomchannel")
FABRIC_CHAINCODE = os.getenv("FABRIC_CHAINCODE", "sbom-verifier")
FABRIC_ORG = os.getenv("FABRIC_ORG", "Org1")
FABRIC_USER = os.getenv("FABRIC_USER", "Admin")


def get_fabric_config():
    return {
        "channel": FABRIC_CHANNEL,
        "chaincode": FABRIC_CHAINCODE,
        "organization": FABRIC_ORG,
        "user": FABRIC_USER,
    }
