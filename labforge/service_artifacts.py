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
RUNTIME_FILES = ("Dockerfile", "app.py")


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


def materialize_service_runtimes(spec: LabSpec, force: bool = False) -> list[Path]:
    written: list[Path] = []
    services_by_name = {str(service.get("name")): service for service in spec.services}
    for artifact in declared_service_artifacts(spec):
        service_root = spec.root / artifact.source_path
        service_root.mkdir(parents=True, exist_ok=True)
        service = services_by_name.get(artifact.service, {})
        port = service_runtime_port(service)
        files = {
            "Dockerfile": render_runtime_dockerfile(artifact, port),
            "app.py": render_runtime_app(artifact, port),
            "seed/metadata.json": render_runtime_metadata(artifact, port),
        }
        for filename, content in files.items():
            path = service_root / filename
            if path.exists() and not force:
                continue
            write_text(path, content)
            written.append(path)
    return written


def service_runtime_port(service: dict) -> int:
    exposed = service.get("expose") or []
    if exposed:
        return int(str(exposed[0]).split(":", maxsplit=1)[-1])
    ports = service.get("ports") or []
    if ports:
        return int(str(ports[0]).split(":")[-1])
    return 8080


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


def render_runtime_dockerfile(artifact, port: int) -> str:
    return "\n".join(
        [
            "FROM python:3.12-alpine",
            "",
            "WORKDIR /app",
            f"ENV LABFORGE_SERVICE={artifact.service}",
            f"ENV PORT={port}",
            "COPY app.py /app/app.py",
            "COPY seed /app/seed",
            "RUN mkdir -p /home/attacker /var/log/labforge && chmod -R 755 /app /home/attacker /var/log/labforge",
            f"EXPOSE {port}",
            "CMD [\"python\", \"/app/app.py\"]",
            "",
        ]
    )


def render_runtime_app(artifact, port: int) -> str:
    service = str(artifact.service)
    purpose = str(artifact.purpose).replace("\\", "\\\\").replace('"', '\\"')
    runtime = str(artifact.runtime).replace("\\", "\\\\").replace('"', '\\"')
    return "\n".join(
        [
            "from __future__ import annotations",
            "",
            "import json",
            "import os",
            "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer",
            "",
            f"SERVICE = {service!r}",
            f"PURPOSE = \"{purpose}\"",
            f"RUNTIME = \"{runtime}\"",
            f"DEFAULT_PORT = {port}",
            "",
            "",
            "class Handler(BaseHTTPRequestHandler):",
            "    def do_GET(self):",
            "        if self.path in {'/', '/metadata'}:",
            "            self.write_json({",
            "                'service': SERVICE,",
            "                'purpose': PURPOSE,",
            "                'runtime': RUNTIME,",
            "                'status': 'placeholder-runtime',",
            "                'endpoints': ['/', '/metadata', '/healthz'],",
            "            })",
            "            return",
            "        if self.path == '/healthz':",
            "            self.send_response(200)",
            "            self.end_headers()",
            "            self.wfile.write(b'ok\\n')",
            "            return",
            "        self.send_response(404)",
            "        self.end_headers()",
            "",
            "    def log_message(self, fmt, *args):",
            "        return",
            "",
            "    def write_json(self, value):",
            "        data = json.dumps(value, indent=2).encode('utf-8')",
            "        self.send_response(200)",
            "        self.send_header('Content-Type', 'application/json')",
            "        self.send_header('Content-Length', str(len(data)))",
            "        self.end_headers()",
            "        self.wfile.write(data)",
            "",
            "",
            "def main():",
            "    port = int(os.environ.get('PORT', DEFAULT_PORT))",
            "    ThreadingHTTPServer(('0.0.0.0', port), Handler).serve_forever()",
            "",
            "",
            "if __name__ == '__main__':",
            "    main()",
            "",
        ]
    )


def render_runtime_metadata(artifact, port: int) -> str:
    import json

    data = {
        "service": artifact.service,
        "runtime": artifact.runtime,
        "purpose": artifact.purpose,
        "port": port,
        "status": "placeholder-runtime",
        "safety_boundaries": artifact.safety_boundaries,
    }
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"
