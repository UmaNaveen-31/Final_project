import json

def extract_selected_claims(sbom_file):
    with open(sbom_file, "r", encoding="utf-8") as file:
        sbom = json.load(file)

    components = sbom.get("components", [])

    selected_dependencies = []

    for component in components:
        if component.get("name") in {"fastapi", "pydantic", "requests"}:
            selected_dependencies.append({
                "name": component.get("name"),
                "version": component.get("version")
            })

    return {
        "bom_format": sbom.get("bomFormat"),
        "spec_version": sbom.get("specVersion"),
        "dependencies": selected_dependencies
    }
