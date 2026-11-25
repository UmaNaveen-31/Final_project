# Decentralized Blockchain-Based Confidential SBOM Verification

## Project Overview

This project provides a confidentiality-preserving system for verifying Software Bills of Materials (SBOMs) without exposing the full SBOM on-chain.

Key capabilities:
- **Complete SBOM integrity verification** using SHA-256 hashing
- **Selective dependency/claim verification** using Merkle trees and cryptographic proofs
- **Encrypted claim storage** and **privacy-preserving policy enforcement**
- **Decentralized verification records** on Hyperledger Fabric via Node.js chaincode
- **Signed compliance reports** with cryptographic signature verification
- **Vulnerability scanning** against SBOM packages
- **Verification history** persisted off-chain in SQLite
- **Web UI** (`/ui`) and **Dockerized FastAPI** service

## Technologies

- **Backend & API:** Python 3.12, FastAPI, Uvicorn, SQLAlchemy, SQLite
- **Cryptography & Security:** SHA-256, Merkle Tree, `cryptography` (encrypted claims & signed compliance reports)
- **Blockchain:** Hyperledger Fabric, Node.js Chaincode (`fabric-contract-api`, `fabric-shim`)
- **SBOM & Scanning:** Syft
- **Deployment & CI:** Docker, Docker Compose, Pytest, GitHub Actions

## Main Workflow

```text
SBOM
  -> SHA-256 Hash
  -> Selected Claims (Encrypted + Privacy Policy)
  -> Merkle Root & Cryptographic Proof
  -> Hyperledger Fabric Ledger
  -> Verification & Signed Compliance Report
```

## Repository Structure

```text
.
├── .github/workflows/ci.yml       # GitHub Actions CI (pytest)
├── compose.api.yaml               # Docker Compose config for the API service
├── install-fabric.sh              # Hyperledger Fabric installation script
├── research-evidence-final/       # Benchmark & evaluation CSVs
└── app/
    ├── Dockerfile                 # Container image for FastAPI app
    ├── requirements.txt           # Python dependencies
    ├── api/main.py                # FastAPI endpoints & Web UI serving
    ├── blockchain/
    │   ├── chaincode/             # Hyperledger Fabric Node.js smart contract
    │   │   ├── package.json
    │   │   └── sbomContract.js
    │   ├── fabric_connection.py
    │   ├── fabric_query.py
    │   └── fabric_submit.py
    ├── database/                  # SQLAlchemy models & SQLite setup
    ├── policy/engine.py           # Privacy & verification policy engine
    ├── security/                  # Hashing, Merkle tree, proofs, encryption, signing
    ├── web/index.html             # Web UI
    └── tests/                     # Pytest unit tests
```

## Key API Endpoints

- `GET /ui` — Interactive Web UI
- `GET /healthz` — Service health check
- `POST /hash-sbom` — Compute SHA-256 hash of an SBOM
- `POST /claims-sbom` — Extract claims from an SBOM
- `POST /prepare-verification` — Generate Merkle root and proofs
- `POST /register-verification` — Store verification record on Hyperledger Fabric & SQLite
- `POST /verify/{verification_id}` — Verify full SBOM integrity against the ledger
- `POST /verify-claim/{verification_id}` — Selectively verify an encrypted/Merkle claim
- `POST /compliance-report/{verification_id}` — Generate a signed compliance report
- `POST /verify-compliance-report` — Verify a compliance report signature
- `GET /download-compliance-report/{verification_id}` — Download compliance report JSON
- `POST /scan-vulnerabilities` — Scan SBOM components for vulnerabilities
- `GET /verification-history` — List past verification records

## Running the Project

### Prerequisites

- Docker and Docker Compose
- Python 3.12+
- Node.js >= 18 (for Hyperledger Fabric chaincode)
- Hyperledger Fabric samples and binaries

### 1. Install and Start Hyperledger Fabric

If `fabric-samples` is not yet installed, run:

```bash
./install-fabric.sh
```

Start the Fabric test network and create the channel:

```bash
cd fabric-samples/test-network
./network.sh up createChannel
```

Deploy the SBOM smart contract from `app/blockchain/chaincode` (`sbomContract.js`) onto the network.

### 2. Configure Secrets & Environment Variables

`compose.api.yaml` requires the following environment variables and mounted files:

- `HOST_FABRIC_SAMPLES_DIR`: Path to your local `fabric-samples` directory
- `CLAIMS_KEY_FILE`: Path to your local symmetric key file for claims encryption
- Signing key file mounted to `/run/secrets/report-signing-key.pem` (update the bind source in `compose.api.yaml` if needed)
- `app/verification.db` present locally for SQLite persistence

### 3. Build and Start the API & Web UI

From the repository root:

```bash
docker compose -f compose.api.yaml up --build
```

Once running:
- **Web UI:** `http://127.0.0.1:8000/ui`
- **API Docs (Swagger):** `http://127.0.0.1:8000/docs`

## Running Tests

Unit tests are located in `app/tests/` and run automatically in CI on push/pull request:

```bash
cd app
pip install -r requirements.txt pytest
PYTHONPATH=. pytest -v
```

## Research Evidence

Benchmark results for verification latency, tamper detection, compliance signatures, and vulnerability scanning are stored in `research-evidence-final/`.
