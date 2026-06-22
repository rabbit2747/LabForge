from __future__ import annotations

import os
import platform
import shutil
import subprocess
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


@dataclass(frozen=True)
class ServiceHookRun:
    service: str
    hook: str
    path: Path
    returncode: int
    stdout: str
    stderr: str


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


def run_service_hooks(
    spec: LabSpec,
    hook: str,
    service: str | None = None,
    dry_run: bool = False,
) -> tuple[list[ServiceHookRun], list[str]]:
    if hook not in {"healthcheck", "reset"}:
        raise ValueError(f"unsupported service hook: {hook}")

    selected = []
    for artifact in declared_service_artifacts(spec):
        if service and artifact.service != service:
            continue
        selected.append(artifact)

    if service and not selected:
        return [], [f"unknown service or missing service_artifacts contract: {service}"]

    errors: list[str] = []
    runs: list[ServiceHookRun] = []
    for artifact in selected:
        script = spec.root / artifact.source_path / f"{hook}.sh"
        if not script.exists():
            errors.append(f"`{artifact.service}` missing hook: {script}")
            continue
        if dry_run:
            runs.append(ServiceHookRun(artifact.service, hook, script, 0, f"DRY RUN: {script}", ""))
            continue
        command = shell_command_for_script(script)
        if command is None:
            errors.append(
                f"`{artifact.service}` cannot run {hook}.sh: no POSIX shell found. "
                "Install sh/Git Bash/WSL or run the hook inside a Linux-capable provider."
            )
            continue
        completed = subprocess.run(
            command,
            cwd=script.parent,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        runs.append(
            ServiceHookRun(
                artifact.service,
                hook,
                script,
                completed.returncode,
                completed.stdout.strip(),
                completed.stderr.strip(),
            )
        )
    return runs, errors


def shell_command_for_script(script: Path) -> list[str] | None:
    sh = shutil.which("sh")
    if sh:
        return [sh, str(script)]
    if platform.system().lower() == "windows" and shutil.which("wsl.exe"):
        distro = []
        distro_name = os.environ.get("LABFORGE_WSL_DISTRO")
        if distro_name:
            distro = ["-d", distro_name]
        return ["wsl.exe", *distro, "--", "sh", windows_to_wsl_path(script)]
    return None


def windows_to_wsl_path(path: Path) -> str:
    resolved = str(path.resolve())
    if len(resolved) >= 3 and resolved[1:3] == ":\\":
        drive = resolved[0].lower()
        rest = resolved[3:].replace("\\", "/")
        return f"/mnt/{drive}/{rest}"
    return resolved.replace("\\", "/")


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
