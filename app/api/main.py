import hashlib
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
    file: UploadFile = File(...),
    merkle_proof: str | None = None
):
    db = SessionLocal()

    try:
        local_record = (
            db.query(Verification)
            .filter(Verification.verification_id == verification_id)
            .first()
        )

        if not local_record:
            return {
                "verification_id": verification_id,
                "status": "ERROR",
                "message": "Verification record not found."
            }
        uploaded_bytes = await file.read()
        submitted_hash = hashlib.sha256(uploaded_bytes).hexdigest()
        stored_hash = local_record.sbom_hash

        if not stored_hash or submitted_hash != stored_hash:
            return {
                "verification_id": verification_id,
                "claim": claim,
                "status": "NOT VERIFIED",
                "proof_valid": False,
                "message": (
                    "The uploaded SBOM hash does not match the registered "
                    "SBOM. Tampering or a different file was detected."
                ),
                "submitted_hash": submitted_hash,
                "stored_hash": stored_hash
            }
        stored_root = local_record.merkle_root

        try:
            blockchain_record = get_verification(verification_id)
            blockchain_data = json.loads(blockchain_record)
            blockchain_root = (
                blockchain_data.get("merkleRoot")
                or blockchain_data.get("merkle_root")
            )

            if blockchain_root and blockchain_root != stored_root:
                return {
                    "verification_id": verification_id,
                    "status": "ERROR",
                    "message": "The database Merkle root does not match the blockchain record."
                }

        except RuntimeError as e:
            if "Hyperledger Fabric is not configured" not in str(e):
                raise

        if not stored_root:
            return {
                "verification_id": verification_id,
                "status": "ERROR",
                "message": "Merkle root is missing from the verification record."
            }

        if merkle_proof:
            proof = json.loads(merkle_proof)
            proof_source = "provided"
        else:
            proof_source = "generated"

            if not local_record.claims_json:
                return {
                    "verification_id": verification_id,
                    "status": "ERROR",
                    "message": "Stored claims are unavailable. Register the SBOM again."
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
    finally:
        db.close()



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
        try:
            blockchain_result = submit_verification(
                verification_id,
                proof,
                claims.get("component_name"),
                file_hash,
                merkle_root
            )
        except RuntimeError as e:
            if "Hyperledger Fabric is not configured" in str(e):
                blockchain_result = {
                    "status": "not_configured",
                    "message": "Hyperledger Fabric is unavailable in this environment."
                }
            else:
                raise




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
async def verify_verification(
    verification_id: str,
    proof: str,
    file: UploadFile = File(...)
):
    db = SessionLocal()

    try:
        try:
            blockchain_record = get_verification(verification_id)
            record = json.loads(blockchain_record)

            stored_proof = record.get("proof")
            stored_hash = record.get("sbomHash")
            component_name = record.get("componentName")
            timestamp = record.get("timestamp")

        except RuntimeError as e:
            if "Hyperledger Fabric is not configured" not in str(e):
                raise

            record = db.query(Verification).filter(
                Verification.verification_id == verification_id
            ).first()

            if record is None:
                return {
                    "verification_id": verification_id,
                    "status": "NOT VERIFIED",
                    "message": "Verification record not found."
                }

            stored_proof = record.proof
            stored_hash = record.sbom_hash
            component_name = record.component_name
            timestamp = record.timestamp

        suffix = os.path.splitext(file.filename or "")[1]

        with tempfile.NamedTemporaryFile(
            delete=False, suffix=suffix
        ) as temp:
            temp.write(await file.read())
            temp_path = temp.name

        try:
            submitted_hash = sha256_file(temp_path)

            if proof == stored_proof and submitted_hash == stored_hash:
                return {
                    "verification_id": verification_id,
                    "status": "VERIFIED",
                    "message": "The submitted proof and SBOM hash match the verification record.",
                    "component_name": component_name,
                    "sbom_hash": submitted_hash,
                    "timestamp": timestamp
                }

            return {
                "verification_id": verification_id,
                "status": "NOT VERIFIED",
                "message": "The submitted proof or SBOM hash does not match the verification record.",
                "submitted_hash": submitted_hash,
                "stored_hash": stored_hash
            }

        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    finally:
        db.close()
 
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


@app.post("/scan-vulnerabilities")
async def scan_vulnerabilities(file: UploadFile = File(...)):
    import json
    import urllib.request
    import urllib.error
    from collections import Counter
    from fastapi import HTTPException

    try:
        sbom = json.loads(await file.read())
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Upload a valid JSON SBOM.")

    components = sbom.get("components", [])
    if not isinstance(components, list):
        raise HTTPException(status_code=400, detail="SBOM components must be a list.")

    findings = []
    query_errors = []
    skipped = []
    checked = 0

    for component in components:
        if not isinstance(component, dict):
            skipped.append({"reason": "Invalid component entry"})
            continue

        name = component.get("name")
        version = component.get("version")
        purl = component.get("purl", "")

        if not name or not version:
            is_file_path = (
                isinstance(name, str)
                and (
                    name.startswith("/")
                    or ".dist-info/" in name
                    or name.endswith(("/METADATA", "/RECORD", "/top_level.txt"))
                )
            )

            skipped.append({
                "package": name,
                "reason": (
                    "File-level SBOM entry; not a package record"
                    if is_file_path
                    else "Missing package name or version"
                )
            })
            continue
        if not isinstance(purl, str) or not purl.startswith("pkg:pypi/"):
            skipped.append({
                "package": name,
                "version": version,
                "reason": "Currently supports PyPI packages only"
            })
            continue

        payload = {
            "version": str(version),
            "package": {
                "name": name,
                "ecosystem": "PyPI"
            }
        }

        request = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                result = json.loads(response.read().decode("utf-8"))

            checked += 1

            for vuln in result.get("vulns", []):
                findings.append({
                    "package": name,
                    "version": version,
                    "id": vuln.get("id"),
                    "summary": vuln.get("summary", ""),
                    "severity": vuln.get("severity", []),
                    "references": [
                        ref.get("url")
                        for ref in vuln.get("references", [])
                        if isinstance(ref, dict) and ref.get("url")
                    ]
                })

        except Exception as exc:
            query_errors.append({
                "package": name,
                "version": version,
                "error": str(exc)
            })

    unique_ids = {
        (item.get("package"), item.get("id"))
        for item in findings
        if item.get("id")
    }

    # Transparent provisional exposure score, NOT a CVSS score.
    risk_score = min(100, len(unique_ids) * 5)

    return {
        "source": "OSV",
        "filename": file.filename,
        "components_total": len(components),
        "packages_checked": checked,
        "components_skipped": len(skipped),
        "query_errors": len(query_errors),
        "findings_count": len(findings),
        "unique_package_vulnerabilities": len(unique_ids),
        "risk_score": risk_score,
        "risk_score_method": "5 points per unique package-vulnerability pair, capped at 100; not CVSS severity",
        "scan_status": (
            "COMPLETE"
            if not skipped and not query_errors
            else "PARTIAL"
        ),
        "findings": findings,
        "skipped_components": skipped,
        "query_error_details": query_errors
    }
