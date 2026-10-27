ALLOWED_BOM_FORMATS = {"CycloneDX"}
ALLOWED_SPEC_VERSIONS = {"1.4", "1.5", "1.6"}

WATCHED_COMPONENTS = {
    "fastapi",
    "pydantic",
    "requests",
}

def evaluate_policy(claims):
    results = []

    bom_format = claims.get("bom_format")
    spec_version = claims.get("spec_version")
    dependencies = claims.get("dependencies", [])

    results.append({
        "rule": "SBOM_FORMAT",
        "passed": bom_format in ALLOWED_BOM_FORMATS,
        "message": (
            "SBOM format is supported."
            if bom_format in ALLOWED_BOM_FORMATS
            else "Unsupported SBOM format."
        ),
    })

    results.append({
        "rule": "SBOM_SPEC_VERSION",
        "passed": spec_version in ALLOWED_SPEC_VERSIONS,
        "message": (
            "SBOM specification version is allowed."
            if spec_version in ALLOWED_SPEC_VERSIONS
            else "SBOM specification version is not allowed."
        ),
    })

    names = {
        str(item.get("name", "")).lower()
        for item in dependencies
        if isinstance(item, dict)
    }

    results.append({
        "rule": "SELECTED_DEPENDENCIES",
        "passed": names.issubset(WATCHED_COMPONENTS),
        "message": (
            "Selected dependencies satisfy the allowlist."
            if names.issubset(WATCHED_COMPONENTS)
            else "A dependency is outside the configured allowlist."
        ),
    })

    passed = all(item["passed"] for item in results)

    return {
        "policy_version": "1.0",
        "status": "COMPLIANT" if passed else "NON_COMPLIANT",
        "passed": passed,
        "results": results,
    }
