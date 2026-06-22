from __future__ import annotations

from pathlib import Path

from .model import LabSpec


ENTERPRISE_TACTICS = {
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
}


def validate_lab(root: Path) -> list[str]:
    spec = LabSpec.load(root)
    errors: list[str] = []

    for key in ("id", "title", "summary", "final_objective"):
        if not spec.scenario.get(key):
            errors.append(f"scenario.yaml missing required field: {key}")

    network_names = {str(item.get("name")) for item in spec.networks}
    if not network_names:
        errors.append("topology.yaml must define at least one network")

    service_names = set()
    exposed_services = []
    for service in spec.services:
        name = str(service.get("name", ""))
        if not name:
            errors.append("topology.yaml service missing name")
            continue
        service_names.add(name)
        if service.get("exposed"):
            exposed_services.append(name)
        for network in service.get("networks", []):
            if str(network) not in network_names:
                errors.append(f"service {name} references unknown network: {network}")
        if "healthcheck" not in service:
            errors.append(f"service {name} missing healthcheck")

    if "attacker-workstation" not in service_names:
        errors.append("topology.yaml should include attacker-workstation")
    if not exposed_services:
        errors.append("topology.yaml should mark at least one service as exposed")

    for stage in spec.stage_list:
        stage_id = stage.get("id", "<missing>")
        if not stage.get("title"):
            errors.append(f"stage {stage_id} missing title")
        if not stage.get("procedure"):
            errors.append(f"stage {stage_id} missing procedure")
        mitre = stage.get("mitre", {})
        tactic = mitre.get("tactic")
        if tactic not in ENTERPRISE_TACTICS:
            errors.append(f"stage {stage_id} has invalid or missing tactic: {tactic}")
        techniques = mitre.get("techniques", [])
        if not techniques:
            errors.append(f"stage {stage_id} missing MITRE techniques")
        for technique in techniques:
            if not technique.get("id") or not technique.get("name"):
                errors.append(f"stage {stage_id} has incomplete technique entry")

    return errors

