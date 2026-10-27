
import os
import subprocess
import json

FABRIC_SAMPLES_DIR = os.environ.get("FABRIC_SAMPLES_DIR")

if FABRIC_SAMPLES_DIR:
    TEST_NETWORK = os.path.join(FABRIC_SAMPLES_DIR, "test-network")
    FABRIC_BIN = os.path.join(FABRIC_SAMPLES_DIR, "bin")
    FABRIC_CONFIG = os.environ.get(
        "FABRIC_CFG_PATH",
        os.path.join(FABRIC_SAMPLES_DIR, "config")
    )
else:
    TEST_NETWORK = None
    FABRIC_BIN = None
    FABRIC_CONFIG = None


def submit_verification(verification_id, proof, component_name, sbom_hash, merkle_root):
    if not FABRIC_SAMPLES_DIR:
        raise RuntimeError(
            "Hyperledger Fabric is not configured in this environment."
        )

    if not os.path.isdir(TEST_NETWORK):
        raise RuntimeError(
            f"Fabric test network directory not found: {TEST_NETWORK}"
        )

    args = json.dumps({
        "function": "createVerification",
        "Args": [verification_id, proof, component_name, sbom_hash, merkle_root]
    })

    env = os.environ.copy()
    env["PATH"] = f"{FABRIC_BIN}:{env.get('PATH', '')}"
    env["FABRIC_CFG_PATH"] = FABRIC_CONFIG

    command = f'''
        source scripts/envVar.sh
        setGlobals 1
        export CORE_PEER_ADDRESS=peer0.org1.example.com:7051
        peer chaincode invoke \
          -o orderer.example.com:7050 \
          --ordererTLSHostnameOverride orderer.example.com \
          --tls \
          --cafile "$ORDERER_CA" \
          -C sbomchannel \
          -n sbom-verifier \
          --peerAddresses peer0.org1.example.com:7051 \
          --tlsRootCertFiles "$PEER0_ORG1_CA" \
          --peerAddresses peer0.org2.example.com:9051 \
          --tlsRootCertFiles "$PEER0_ORG2_CA" \
          -c '{args}' \
          --waitForEvent
    '''

    result = subprocess.run(
        ["bash", "-c", command],
        cwd=TEST_NETWORK,
        capture_output=True,
        text=True,
        env=env
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)

    return {
        "status": "submitted",
        "verification_id": verification_id,
        "output": result.stdout.strip()
    }
