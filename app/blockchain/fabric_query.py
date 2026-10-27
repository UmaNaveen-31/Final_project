import os
import subprocess

FABRIC_SAMPLES_DIR = os.environ.get("FABRIC_SAMPLES_DIR")
if not FABRIC_SAMPLES_DIR:
    raise RuntimeError(
        "Set FABRIC_SAMPLES_DIR to the location of the fabric-samples directory."
    )
TEST_NETWORK = os.path.join(FABRIC_SAMPLES_DIR, "test-network")
FABRIC_BIN = os.path.join(FABRIC_SAMPLES_DIR, "bin")
FABRIC_CONFIG = os.environ.get(
    "FABRIC_CFG_PATH",
    os.path.join(FABRIC_SAMPLES_DIR, "config"),
)


def get_verification(verification_id):
    env = os.environ.copy()
    env["PATH"] = f"{FABRIC_BIN}:{env.get('PATH', '')}"
    env["FABRIC_CFG_PATH"] = FABRIC_CONFIG

    command = f'''
        source scripts/envVar.sh
        setGlobals 1
        export CORE_PEER_LOCALMSPID="$CORE_PEER_LOCALMSPID"
        export CORE_PEER_ADDRESS=peer0.org1.example.com:7051
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
