import os
import subprocess
import json

TEST_NETWORK = os.path.expanduser("~/sbom-project/fabric-samples/test-network")
FABRIC_BIN = os.path.expanduser("~/sbom-project/fabric-samples/bin")


def submit_verification(verification_id, proof, component_name, sbom_hash, merkle_root):
    args = json.dumps({
        "function": "createVerification",
        "Args": [verification_id, proof, component_name, sbom_hash, merkle_root]
    })

    env = os.environ.copy()
    env["PATH"] = f"{FABRIC_BIN}:{env.get('PATH', '')}"
    env["FABRIC_CFG_PATH"] = os.path.expanduser("~/sbom-project/fabric-samples/config")

    command = f'''
        source scripts/envVar.sh
        setGlobals 1
        peer chaincode invoke \
          -o localhost:7050 \
          --ordererTLSHostnameOverride orderer.example.com \
          --tls \
          --cafile "$ORDERER_CA" \
          -C sbomchannel \
          -n sbom-verifier \
          --peerAddresses localhost:7051 \
          --tlsRootCertFiles "$PEER0_ORG1_CA" \
          --peerAddresses localhost:9051 \
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
