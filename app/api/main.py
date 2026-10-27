from security.privacy import extract_selected_claims
from policy.engine import evaluate_policy
from security.report_signing import sign_report, verify_report


from sqlalchemy import inspect, text
from database.database import engine
from database.database import SessionLocal
from database.models import Base, Verification
from datetime import datetime

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from security.crypto import sha256_file

from security.privacy import extract_selected_claims
from security.claims_encryption import encrypt_claims, decrypt_claims
from security.proof import generate_proof
from security.merkle import build_merkle_root, build_merkle_proof, verify_merkle_proof
import os
import tempfile
import json

app = FastAPI(title="Confidential SBOM Verification API")
@app.get("/healthz")
def health_check():
    return {"status": "ok"}
Base.metadata.create_all(bind=engine)

# Add claims_json to existing databases without deleting existing records.
columns = {col["name"] for col in inspect(engine).get_columns("verifications")}
if "claims_json" not in columns:
    with engine.begin() as connection:
        connection.execute(
            text("ALTER TABLE verifications ADD COLUMN claims_json TEXT")
        )


@app.post("/verify-claim/{verification_id}")
async def verify_claim(
    verification_id: str,
    claim: str,
    merkle_proof: str | None = None
):
    try:
        blockchain_record = get_verification(verification_id)
        record = json.loads(blockchain_record)
        stored_root = record.get("merkleRoot") or record.get("merkle_root")

        if not stored_root:
            return {
                "verification_id": verification_id,
                "status": "ERROR",
                "message": "Merkle root is missing from the blockchain record."
            }

        if merkle_proof:
            # Backward-compatible support for a manually supplied proof.
            proof = json.loads(merkle_proof)
            proof_source = "provided"
        else:
            # Generate the proof from the claims stored at registration.
            proof_source = "generated"
            db = SessionLocal()
            try:
                local_record = (
                    db.query(Verification)
                    .filter(Verification.verification_id == verification_id)
                    .first()
                )

                if not local_record or not local_record.claims_json:
                    return {
                        "verification_id": verification_id,
                        "status": "ERROR",
                        "message": (
                            "Automatic proof generation is unavailable for this "
                            "older registration. Register the SBOM again."
                        )
                    }

                if local_record.merkle_root != stored_root:
                    return {
                        "verification_id": verification_id,
                        "status": "ERROR",
                        "message": (
                            "The local Merkle root does not match the "
                            "blockchain record."
                        )
                    }

                claims = json.loads(decrypt_claims(local_record.claims_json))
                merkle_values = (
                    [claims["bom_format"], claims["spec_version"]]
                    + [
                        f'{item["name"]}:{item["version"]}'
                        for item in claims["dependencies"]
                    ]
                )

                try:
                    claim_index = merkle_values.index(claim)
                except ValueError:
                    return {
                        "verification_id": verification_id,
                        "claim": claim,
                        "status": "NOT VERIFIED",
                        "proof_valid": False,
                        "message": "This claim was not found in the registered SBOM."
                    }

                proof = build_merkle_proof(merkle_values, claim_index)
            finally:
                db.close()

        valid = verify_merkle_proof(claim, proof, stored_root)

        return {
            "verification_id": verification_id,
            "claim": claim,
            "merkle_root": stored_root,
            "proof_valid": valid,
            "status": "VERIFIED" if valid else "NOT VERIFIED",
            "proof_source": proof_source,
            "merkle_proof": proof
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
            claims_json=encrypt_claims(json.dumps(claims)),
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

from fastapi import HTTPException
from pydantic import BaseModel


class ComplianceReportRequest(BaseModel):
    verification_id: str


class SignedReportVerificationRequest(BaseModel):
    report: dict
    signature: str


@app.post("/compliance-report/{verification_id}")
async def create_compliance_report(verification_id: str):
    db = SessionLocal()

    try:
        record = (
            db.query(Verification)
            .filter(Verification.verification_id == verification_id)
            .first()
        )

        if record is None:
            raise HTTPException(
                status_code=404,
                detail="Verification record not found."
            )

        if not record.claims_json:
            raise HTTPException(
                status_code=400,
                detail="No stored claims are available for this record."
            )

        try:
            claims = json.loads(decrypt_claims(record.claims_json))
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="Stored claims could not be decrypted."
            )

        policy_result = evaluate_policy(claims)

        report = {
            "report_type": "SBOM Compliance Report",
            "report_version": "1.0",
            "verification_id": record.verification_id,
            "sbom_sha256": record.sbom_hash,
            "merkle_root": record.merkle_root,
            "policy": policy_result,
            "issued_at": datetime.utcnow().isoformat() + "Z"
        }

        signature = sign_report(report)

        return {
            "report": report,
            "signature": signature,
            "signature_algorithm": "Ed25519"
        }

    finally:
        db.close()


@app.post("/verify-compliance-report")
async def verify_compliance_report(
    request: SignedReportVerificationRequest
):
    valid = verify_report(request.report, request.signature)

    return {
        "signature_valid": valid,
        "status": "VALID" if valid else "INVALID"
    }

from fastapi.responses import JSONResponse


@app.get("/download-compliance-report/{verification_id}")
async def download_compliance_report(verification_id: str):
    db = SessionLocal()

    try:
        record = (
            db.query(Verification)
            .filter(Verification.verification_id == verification_id)
            .first()
        )

        if record is None:
            raise HTTPException(
                status_code=404,
                detail="Verification record not found."
            )

        if not record.claims_json:
            raise HTTPException(
                status_code=400,
                detail="No stored claims are available."
            )

        try:
            claims = json.loads(decrypt_claims(record.claims_json))
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="Stored claims could not be decrypted."
            )

        policy_result = evaluate_policy(claims)

        report = {
            "report_type": "SBOM Compliance Report",
            "report_version": "1.0",
            "verification_id": record.verification_id,
            "sbom_sha256": record.sbom_hash,
            "merkle_root": record.merkle_root,
            "policy": policy_result,
            "issued_at": datetime.utcnow().isoformat() + "Z"
        }

        signature = sign_report(report)

        return JSONResponse(
            content={
                "report": report,
                "signature": signature,
                "signature_algorithm": "Ed25519"
            },
            headers={
                "Content-Disposition":
                    f'attachment; filename="compliance-report-{verification_id}.json"'
            }
        )

    finally:
        db.close()
