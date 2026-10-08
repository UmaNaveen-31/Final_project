from database.database import engine
from database.database import SessionLocal
from database.models import Base, Verification
from datetime import datetime

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from security.crypto import sha256_file

from security.privacy import extract_selected_claims
from security.proof import generate_proof
from security.merkle import build_merkle_root, verify_merkle_proof
import os
import tempfile
import json

app = FastAPI(title="Confidential SBOM Verification API")
Base.metadata.create_all(bind=engine)

@app.post("/verify-claim/{verification_id}")
async def verify_claim(verification_id: str, claim: str, merkle_proof: str):
    try:
        blockchain_record = get_verification(verification_id)
        record = json.loads(blockchain_record)

        stored_root = record.get("merkleRoot")

        if not stored_root:
            return {
                "verification_id": verification_id,
                "status": "ERROR",
                "message": "Merkle root is missing from the blockchain record."
            }

        proof = json.loads(merkle_proof)

        valid = verify_merkle_proof(
            claim,
            proof,
            stored_root
        )

        return {
            "verification_id": verification_id,
            "claim": claim,
            "merkle_root": stored_root,
            "proof_valid": valid
        }

    except Exception as e:
        return {
            "verification_id": verification_id,
            "status": "ERROR",
            "message": str(e)
        }
    


@app.post("/hash-sbom")
async def hash_sbom(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1]

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
        temp.write(await file.read())
        temp_path = temp.name

    try:
        file_hash = sha256_file(temp_path)
        return {
            "filename": file.filename,
            "sha256": file_hash
        }
    finally:
        os.remove(temp_path)


@app.post("/claims-sbom")
async def claims_sbom(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
        temp.write(await file.read())
        temp_path = temp.name
    try:
        claims = extract_selected_claims(temp_path)
        return {"filename": file.filename, "claims": claims}
    finally:
        os.remove(temp_path)


@app.post("/prepare-verification")
async def prepare_verification(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
        temp.write(await file.read())
        temp_path = temp.name
    try:
        file_hash = sha256_file(temp_path)
        claims = extract_selected_claims(temp_path)
        proof = generate_proof(claims)
        merkle_values = [claims["bom_format"], claims["spec_version"]] + [f"{item["name"]}:{item["version"]}" for item in claims["dependencies"]]
        merkle_root = build_merkle_root(merkle_values)
        return {
            "filename": file.filename,
            "sha256": file_hash,
            "claims": claims,
            "proof": proof,
            "merkle_root": merkle_root,
        }
    finally:
        os.remove(temp_path)

from blockchain.fabric_submit import submit_verification
from blockchain.fabric_query import get_verification
import uuid


@app.post("/register-verification")
async def register_verification(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename or "")[1]

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
        temp.write(await file.read())
        temp_path = temp.name

    try:
        file_hash = sha256_file(temp_path)
        claims = extract_selected_claims(temp_path)
        proof = generate_proof(claims)

        merkle_values = (
            [claims["bom_format"], claims["spec_version"]]
            + [
                f'{item["name"]}:{item["version"]}'
                for item in claims["dependencies"]
            ]
        )

        merkle_root = build_merkle_root(merkle_values)

        verification_id = "VER-" + uuid.uuid4().hex[:8].upper()

        blockchain_result = submit_verification(
            verification_id,
            proof,
            claims.get("component_name"),
            file_hash,
            merkle_root
        )
        db = SessionLocal()

        verification = Verification(
            verification_id=verification_id,
            sbom_hash=file_hash,
            proof=proof,
            merkle_root=merkle_root,
            component_name=claims.get("component_name"),
            timestamp=datetime.now().isoformat()
        )

        db.add(verification)
        db.commit()
        db.close()

        return {
            "filename": file.filename,
            "verification_id": verification_id,
            "sha256": file_hash,
            "claims": claims,
            "proof": proof,
            "merkle_root": merkle_root,
            "blockchain": blockchain_result
        }

    finally:
        os.remove(temp_path)

@app.post("/verify/{verification_id}")
async def verify_verification(verification_id: str, proof: str, file: UploadFile = File(...)):
    blockchain_record = get_verification(verification_id)

    record = json.loads(blockchain_record)
    stored_proof = record.get("proof")
    stored_hash = record.get("sbomHash")

    suffix = os.path.splitext(file.filename or "")[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
        temp.write(await file.read())
        temp_path = temp.name

    try:
        submitted_hash = sha256_file(temp_path)

        if proof == stored_proof and submitted_hash == stored_hash:
            return {
                "verification_id": verification_id,
                "status": "VERIFIED",
                "message": "The submitted proof and SBOM hash match the blockchain record.",
                "component_name": record.get("componentName"),
                "sbom_hash": submitted_hash,
                "timestamp": record.get("timestamp")
            }

        return {
            "verification_id": verification_id,
            "status": "NOT VERIFIED",
            "message": "The submitted proof or SBOM hash does not match the blockchain record.",
            "submitted_hash": submitted_hash,
            "stored_hash": stored_hash
        }
    finally:
        os.remove(temp_path)
@app.get("/verification-history")
async def verification_history():
    db = SessionLocal()

    records = db.query(Verification).order_by(Verification.id.desc()).all()

    result = [
        {
            "verification_id": record.verification_id,
            "sbom_hash": record.sbom_hash,
            "proof": record.proof,
            "merkle_root": record.merkle_root,
            "timestamp": record.timestamp
        }
        for record in records
    ]

    db.close()

    return {"records": result}
@app.get("/ui")
async def ui():
    return FileResponse(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "web",
            "index.html"
        )
    )
