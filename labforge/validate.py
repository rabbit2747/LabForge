from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from .model import LabSpec
from .spec_models import ENTERPRISE_TACTICS


def validate_lab(root: Path) -> list[str]:
    errors: list[str] = []
    try:
        spec = LabSpec.load(root)
    except FileNotFoundError as exc:
        return [str(exc)]
    except ValidationError as exc:
        return [
            f"{'.'.join(str(item) for item in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        ]
    except ValueError as exc:
        return [str(exc)]

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

    artifact_model = spec.artifacts_model
    if artifact_model and artifact_model.service_artifacts:
        artifact_services = {artifact.service for artifact in artifact_model.service_artifacts}
        unknown = sorted(artifact_services - service_names)
        missing = sorted(service_names - artifact_services)
        for name in unknown:
            errors.append(f"artifacts.yaml service_artifacts references unknown service: {name}")
        for name in missing:
            errors.append(f"service {name} missing service_artifacts contract")
        for artifact in artifact_model.service_artifacts:
            if not artifact.source_path:
                errors.append(f"service artifact {artifact.service} missing source_path")
            if not artifact.healthcheck:
                errors.append(f"service artifact {artifact.service} missing healthcheck contract")
            if not artifact.reset:
                errors.append(f"service artifact {artifact.service} missing reset contract")
            if not artifact.safety_boundaries:
                errors.append(f"service artifact {artifact.service} missing safety_boundaries")

    return errors
