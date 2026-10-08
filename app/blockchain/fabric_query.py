import os
import subprocess

TEST_NETWORK = os.path.expanduser("~/sbom-project/fabric-samples/test-network")
FABRIC_BIN = os.path.expanduser("~/sbom-project/fabric-samples/bin")
FABRIC_CONFIG = os.path.expanduser("~/sbom-project/fabric-samples/config")


def get_verification(verification_id):
    env = os.environ.copy()
    env["PATH"] = f"{FABRIC_BIN}:{env.get('PATH', '')}"
    env["FABRIC_CFG_PATH"] = FABRIC_CONFIG

    command = f'''
        source scripts/envVar.sh
        setGlobals 1
        export CORE_PEER_LOCALMSPID="$CORE_PEER_LOCALMSPID"
        export CORE_PEER_ADDRESS="$CORE_PEER_ADDRESS"
        export CORE_PEER_TLS_ROOTCERT_FILE="$CORE_PEER_TLS_ROOTCERT_FILE"
        export CORE_PEER_MSPCONFIGPATH="$CORE_PEER_MSPCONFIGPATH"
        peer chaincode query \
          -C sbomchannel \
          -n sbom-verifier \
          -c '{{"function":"readVerification","Args":["{verification_id}"]}}'
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

    return result.stdout.strip().splitlines()[-1].splitlines()[-1]
