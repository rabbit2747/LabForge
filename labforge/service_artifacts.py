from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .io import dump_yaml, write_text
from .model import LabSpec


RECOMMENDED_DIRECTORIES = ("seed", "noise", "tests")
REQUIRED_FILES = ("README.md", "labforge-service.yaml", "healthcheck.sh", "reset.sh")


@dataclass(frozen=True)
class ServiceCheckResult:
    errors: list[str]
    warnings: list[str]


def declared_service_artifacts(spec: LabSpec):
    if not spec.artifacts_model:
        return []
    return spec.artifacts_model.service_artifacts


def service_check(spec: LabSpec) -> ServiceCheckResult:
    errors: list[str] = []
    warnings: list[str] = []
    service_names = {str(service["name"]) for service in spec.services}
    artifacts = declared_service_artifacts(spec)
    artifact_names = {artifact.service for artifact in artifacts}

    for missing in sorted(service_names - artifact_names):
        errors.append(f"service `{missing}` is missing a service_artifacts contract")
    for unknown in sorted(artifact_names - service_names):
        errors.append(f"service_artifacts references unknown service `{unknown}`")

    for artifact in artifacts:
        service_root = spec.root / artifact.source_path
        if not service_root.exists():
            errors.append(f"`{artifact.service}` source_path does not exist: {artifact.source_path}")
            continue
        if not service_root.is_dir():
            errors.append(f"`{artifact.service}` source_path is not a directory: {artifact.source_path}")
            continue

        for filename in REQUIRED_FILES:
            if not (service_root / filename).exists():
                errors.append(f"`{artifact.service}` missing required file: {artifact.source_path}/{filename}")
        for dirname in RECOMMENDED_DIRECTORIES:
            if not (service_root / dirname).exists():
                warnings.append(f"`{artifact.service}` missing recommended directory: {artifact.source_path}/{dirname}")

    return ServiceCheckResult(errors=errors, warnings=warnings)


def scaffold_service_artifacts(spec: LabSpec, force: bool = False) -> list[Path]:
    written: list[Path] = []
    for artifact in declared_service_artifacts(spec):
        service_root = spec.root / artifact.source_path
        service_root.mkdir(parents=True, exist_ok=True)

        for dirname in RECOMMENDED_DIRECTORIES:
            directory = service_root / dirname
            directory.mkdir(parents=True, exist_ok=True)
            keep = directory / ".gitkeep"
            if not keep.exists():
                write_text(keep, "")
                written.append(keep)

        files = {
            "README.md": render_service_readme(artifact),
            "labforge-service.yaml": render_labforge_service_yaml(artifact),
            "healthcheck.sh": render_healthcheck_script(artifact),
            "reset.sh": render_reset_script(artifact),
        }
        for filename, content in files.items():
            path = service_root / filename
            if path.exists() and not force:
                continue
            write_text(path, content)
            written.append(path)
    return written


def render_service_readme(artifact) -> str:
    lines = [
        f"# {artifact.service}",
        "",
        artifact.purpose,
        "",
        "## Runtime",
        "",
        f"- {artifact.runtime}",
        "",
        "## Attack Surface",
        "",
    ]
    lines.extend(f"- {item}" for item in artifact.attack_surface or ["No attack surface declared."])
    lines += [
        "",
        "## Healthcheck Contract",
        "",
        artifact.healthcheck,
        "",
        "## Reset Contract",
        "",
        artifact.reset,
        "",
        "## Evidence Logs",
        "",
    ]
    lines.extend(f"- `{item}`" for item in artifact.evidence_logs or ["No evidence logs declared."])
    lines += [
        "",
        "## Safety Boundaries",
        "",
    ]
    lines.extend(f"- {item}" for item in artifact.safety_boundaries or ["No safety boundaries declared."])
    lines.append("")
    return "\n".join(lines)


def render_labforge_service_yaml(artifact) -> str:
    data = {
        "service": artifact.service,
        "runtime": artifact.runtime,
        "purpose": artifact.purpose,
        "attack_surface": artifact.attack_surface,
        "seed_inputs": artifact.seed_inputs,
        "noise_inputs": artifact.noise_inputs,
        "healthcheck": artifact.healthcheck,
        "reset": artifact.reset,
        "evidence_logs": artifact.evidence_logs,
        "safety_boundaries": artifact.safety_boundaries,
    }
    return dump_yaml(data)


def render_healthcheck_script(artifact) -> str:
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            "set -eu",
            f"echo '[labforge] healthcheck placeholder for {artifact.service}'",
            "echo '[labforge] replace this with the service-specific healthcheck implementation'",
            "exit 0",
            "",
        ]
    )


def render_reset_script(artifact) -> str:
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            "set -eu",
            f"echo '[labforge] reset placeholder for {artifact.service}'",
            "echo '[labforge] replace this with deterministic service reset logic'",
            "exit 0",
            "",
        ]
    )
