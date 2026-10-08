# Decentralized Blockchain-Based Confidential SBOM Verification

## Project Overview

This project provides a confidentiality-preserving method for verifying Software Bills of Materials (SBOMs).

The system allows:
- Complete SBOM integrity verification using SHA-256
- Selected dependency verification using Merkle proofs
- Decentralized verification records using Hyperledger Fabric
- Off-chain storage of the complete SBOM
- Verification history using SQLite
- Dockerized deployment of the FastAPI application

## Technologies

- Python
- FastAPI
- SHA-256
- Merkle Tree
- Hyperledger Fabric
- Chaincode
- SQLite
- Docker
- Syft
- Pytest

## Main Workflow

SBOM
-> SHA-256 Hash
-> Selected Claims
-> Cryptographic Proof
-> Merkle Root
-> Hyperledger Fabric
-> Verification

## Running the Project

### 1. Start Fabric

```bash
cd ~/sbom-project/fabric-samples/test-network
./network.sh up


