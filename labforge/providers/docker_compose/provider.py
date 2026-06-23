from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from labforge.io import dump_yaml, write_text
from labforge.model import LabSpec
from labforge.providers.base import Provider
from labforge.security_controls import control_placements, has_selected_category, selected_controls


class DockerComposeProvider(Provider):
    name = "docker-compose"

    def generate(self, spec: LabSpec, out: Path, **kwargs: Any) -> None:
        profile = str(kwargs.get("profile", "unprotected"))
        write_text(out / "docker-compose.yml", render_compose(spec, profile=profile))
        write_text(out / "docs" / "provider-security-plan.md", render_security_plan(spec, profile))
        write_text(out / "docs" / "provider-service-plan.md", render_provider_service_plan(spec))
        copy_service_sources(spec, out)
        write_runtime_scripts(out)


def service_artifact_map(spec: LabSpec) -> dict[str, Any]:
    if not spec.artifacts_model:
        return {}
    return {artifact.service: artifact for artifact in spec.artifacts_model.service_artifacts}


def service_build_context(spec: LabSpec, service: dict[str, Any], artifacts: dict[str, Any]) -> str:
    name = str(service["name"])
    if service.get("build"):
        return str(service["build"])
    artifact = artifacts.get(name)
    if artifact:
        source = spec.root / artifact.source_path
        if source.exists():
            return f"./{artifact.source_path}"
    return f"./services/{name}"


def copy_service_sources(spec: LabSpec, out: Path) -> None:
    for artifact in service_artifact_map(spec).values():
        source = spec.root / artifact.source_path
        if not source.exists() or not source.is_dir():
            continue
        target = out / artifact.source_path
        shutil.copytree(
            source,
            target,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
        )


def render_compose(spec: LabSpec, profile: str = "unprotected") -> str:
    artifacts = service_artifact_map(spec)
    compose: dict[str, Any] = {
        "name": spec.lab_id,
        "networks": {},
        "volumes": {},
        "services": {},
    }
    used_host_ports: set[int] = set()

    for network in spec.networks:
        name = str(network["name"])
        compose["networks"][name] = {"driver": "bridge"}
        if network.get("internal", False):
            compose["networks"][name]["internal"] = True
        if profile == "protected":
            compose["networks"][name]["labels"] = [
                f"labforge.profile={profile}",
                f"labforge.network={name}",
            ]

    for service in spec.services:
        name = str(service["name"])
        artifact = artifacts.get(name)
        entry: dict[str, Any] = {
            "build": service_build_context(spec, service, artifacts),
            "networks": service.get("networks", []),
            "restart": "unless-stopped",
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
            "pids_limit": 200,
            "labels": [
                f"labforge.profile={profile}",
                f"labforge.role={service.get('role', 'service')}",
            ],
        }
        if artifact:
            entry["labels"].extend(
                [
                    f"labforge.service.source={artifact.source_path}",
                    f"labforge.service.runtime={artifact.runtime}",
                    "labforge.service.contract=docs/service-artifact-contract.md",
                ]
            )
        if profile == "protected":
            entry["labels"].append("labforge.security-controls=enabled")
            if has_selected_category(spec, "siem"):
                entry["logging"] = {
                    "driver": "json-file",
                    "options": {
                        "max-size": "10m",
                        "max-file": "3",
                    },
                }
        if service.get("read_only", True):
            entry["read_only"] = True
        if "user" in service:
            entry["user"] = str(service["user"])
        if service.get("expose"):
            entry["expose"] = [str(port) for port in service["expose"]]
        if service.get("ports"):
            entry["ports"] = normalize_port_mappings(service["ports"], used_host_ports)
        if service.get("environment"):
            entry["environment"] = service["environment"]
        if service.get("volumes"):
            entry["volumes"] = service["volumes"]
        if service.get("depends_on"):
            entry["depends_on"] = service["depends_on"]
        if service.get("healthcheck"):
            entry["healthcheck"] = service["healthcheck"]
        compose["services"][name] = entry

    if profile == "protected":
        add_security_control_services(spec, compose)

    return dump_yaml(compose)


def normalize_port_mappings(ports: list[Any], used_host_ports: set[int]) -> list[str]:
    mappings: list[str] = []
    next_dynamic = 18080
    for item in ports:
        text = str(item)
        if ":" not in text:
            host = parse_port(text)
            container = text
        else:
            host_text, container = text.rsplit(":", maxsplit=1)
            host = parse_port(host_text)
        if host is None:
            mappings.append(text)
            continue
        if host in used_host_ports:
            while next_dynamic in used_host_ports:
                next_dynamic += 1
            host = next_dynamic
        used_host_ports.add(host)
        if ":" in text and ":" in host_text:
            bind_ip = host_text.rsplit(":", maxsplit=1)[0]
            mappings.append(f"{bind_ip}:{host}:{container}")
        else:
            mappings.append(f"{host}:{container}")
    return mappings


def parse_port(value: str) -> int | None:
    try:
        return int(value.rsplit(":", maxsplit=1)[-1])
    except ValueError:
        return None


def add_security_control_services(spec: LabSpec, compose: dict[str, Any]) -> None:
    controls = selected_controls(spec)
    if not controls:
        return

    compose["volumes"].setdefault("labforge_logs", {})
    networks = [str(network["name"]) for network in spec.networks]

    for control in controls:
        service_name = f"control-{control.category}-{control.control_id}"
        placement = next(
            (item for item in control_placements(spec) if item["id"] == control.control_id),
            {},
        )
        scope = placement.get("scope", {})
        entry: dict[str, Any] = {
            "image": "alpine:3.20",
            "command": [
                "sh",
                "-lc",
                "echo '[labforge] control container online'; while true; do sleep 3600; done",
            ],
            "restart": "unless-stopped",
            "networks": networks,
            "read_only": True,
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
            "pids_limit": 100,
            "environment": {
                "LABFORGE_CONTROL_ID": control.control_id,
                "LABFORGE_CONTROL_CATEGORY": control.category,
                "LABFORGE_CONTROL_MODE": control.mode,
                "LABFORGE_MONITORED_NETWORKS": ",".join(scope.get("networks") or networks),
                "LABFORGE_MONITORED_SERVICES": ",".join(scope.get("services") or []),
            },
            "labels": [
                "labforge.generated=true",
                "labforge.profile=protected",
                f"labforge.control.category={control.category}",
                f"labforge.control.id={control.control_id}",
                f"labforge.control.mode={control.mode}",
            ],
        }
        if control.category in {"siem", "ids", "edr"}:
            entry["volumes"] = ["labforge_logs:/var/log/labforge"]
        compose["services"][service_name] = entry


def render_security_plan(spec: LabSpec, profile: str) -> str:
    lines = [
        f"# Docker Compose Provider Security Plan - {spec.title}",
        "",
        f"- Active profile: `{profile}`",
        "",
    ]
    if profile != "protected":
        lines += [
            "The unprotected provider output keeps only the base scenario services.",
            "Security controls are documented but not materialized as Compose services.",
            "",
        ]
        return "\n".join(lines)

    controls = selected_controls(spec)
    placements = control_placements(spec)
    lines += [
        "The protected provider output materializes selected controls as Compose services.",
        "These services are safe scaffolds: they mark placement, networking, labels, and log volumes so a later implementation can replace them with real WAF/IDS/SIEM/EDR components.",
        "",
        "## Selected Controls",
        "",
    ]
    if not controls:
        lines.append("- No controls selected.")
    for control in controls:
        lines += [
            f"- `{control.control_id}` ({control.category}, mode: `{control.mode}`)",
            f"  - Compose service: `control-{control.category}-{control.control_id}`",
            f"  - Purpose: {control.description or control.name}",
        ]
    lines += [
        "",
        "## Placement Matrix",
        "",
        "| Control | Networks | Services | Effect |",
        "|---|---|---|---|",
    ]
    for placement in placements:
        scope = placement.get("scope", {})
        networks = ", ".join(scope.get("networks", [])) or "-"
        services = ", ".join(scope.get("services", [])) or "-"
        lines.append(f"| `{placement['id']}` | {networks} | {services} | {placement['effect']} |")
    lines += [
        "",
        "## Provider Effects",
        "",
        "- Adds `labforge.profile` and role labels to generated services.",
        "- Adds security-control labels to generated services in protected mode.",
        "- Adds safe control-plane services for selected controls.",
        "- Adds `labforge_logs` volume when selected controls need central log collection.",
        "- Adds Docker json-file log rotation when SIEM collection is selected.",
        "",
    ]
    return "\n".join(lines)


def render_provider_service_plan(spec: LabSpec) -> str:
    artifacts = service_artifact_map(spec)
    lines = [
        f"# Docker Compose Provider Service Plan - {spec.title}",
        "",
        "This document explains how the Docker Compose provider uses service artifact contracts.",
        "",
        "## Provider Rules",
        "",
        "- If `topology.yaml` defines an explicit `build`, that build context wins.",
        "- Otherwise, if the service has a `service_artifacts` entry and its `source_path` exists, the provider uses that path as the build context.",
        "- If the source path does not exist yet, the provider keeps the conventional `./services/<service-name>` build context so the scaffold remains predictable.",
        "- Healthcheck and reset contracts are emitted in documentation. Compose labels point back to `docs/service-artifact-contract.md`.",
        "- Compose healthcheck commands still come from `topology.yaml`.",
        "",
        "## Services",
        "",
        "| Service | Build Context | Artifact Source | Runtime | Healthcheck Contract | Reset Contract | Evidence Logs |",
        "|---|---|---|---|---|---|---|",
    ]
    for service in spec.services:
        name = str(service["name"])
        artifact = artifacts.get(name)
        context = service_build_context(spec, service, artifacts)
        source = artifact.source_path if artifact else ""
        runtime = artifact.runtime if artifact else ""
        healthcheck = artifact.healthcheck if artifact else ""
        reset = artifact.reset if artifact else ""
        logs = "<br>".join(artifact.evidence_logs) if artifact and artifact.evidence_logs else ""
        lines.append(
            f"| `{name}` | `{context}` | `{source}` | `{runtime}` | {healthcheck} | {reset} | {logs} |"
        )
    lines += [
        "",
        "## Reset Notes",
        "",
        "The generated `scripts/reset.*` currently performs a Compose volume reset.",
        "The generated `scripts/services-reset.*` runs copied service `reset.sh` hooks.",
        "The generated `scripts/services-healthcheck.*` runs copied service `healthcheck.sh` hooks.",
        "Service-specific hooks should replace placeholders with deterministic implementation logic before the lab is treated as runnable.",
        "",
    ]
    return "\n".join(lines)


def write_runtime_scripts(out: Path) -> None:
    scripts = {
        "validate": ["config"],
        "start": ["up", "--build", "-d"],
        "stop": ["down"],
        "destroy": ["down", "-v"],
        "reset": ["down", "-v", "&&", "up", "--build", "-d"],
    }
    for name, args in scripts.items():
        write_text(out / "scripts" / f"{name}.sh", render_shell_script(args))
        write_text(out / "scripts" / f"{name}.ps1", render_powershell_script(args))
    for hook in ("healthcheck", "reset"):
        write_text(out / "scripts" / f"services-{hook}.sh", render_service_hook_shell_script(hook))
        write_text(out / "scripts" / f"services-{hook}.ps1", render_service_hook_powershell_script(hook))
    write_text(out / "scripts" / "README.md", render_scripts_readme())


def render_shell_script(compose_args: list[str]) -> str:
    if "&&" in compose_args:
        first = compose_args[: compose_args.index("&&")]
        second = compose_args[compose_args.index("&&") + 1 :]
        body = "\n".join(
            [
                f"docker compose -f docker-compose.yml {' '.join(first)}",
                f"docker compose -f docker-compose.yml {' '.join(second)}",
            ]
        )
    else:
        body = f"docker compose -f docker-compose.yml {' '.join(compose_args)}"
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            "set -eu",
            'LAB_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"',
            'cd "$LAB_ROOT"',
            body,
            "",
        ]
    )


def render_service_hook_shell_script(hook: str) -> str:
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            "set -eu",
            'LAB_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"',
            'cd "$LAB_ROOT"',
            f"FOUND=0",
            f"for script in services/*/{hook}.sh; do",
            '    [ -f "$script" ] || continue',
            "    FOUND=1",
            '    echo "[labforge] running $script"',
            '    sh "$script"',
            "done",
            'if [ "$FOUND" -eq 0 ]; then',
            f"    echo '[labforge] no services/*/{hook}.sh hooks found'",
            "fi",
            "",
        ]
    )


def render_service_hook_powershell_script(hook: str) -> str:
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
            "$LabRoot = (Resolve-Path (Join-Path $ScriptDir '..')).Path",
            f"$HookScript = Join-Path $ScriptDir 'services-{hook}.sh'",
            "",
            "function ConvertTo-LabForgeWslPath([string]$Path) {",
            "    $FullPath = (Resolve-Path $Path).Path",
            "    if ($FullPath -match '^([A-Za-z]):\\\\(.*)$') {",
            "        $Drive = $Matches[1].ToLowerInvariant()",
            "        $Rest = $Matches[2] -replace '\\\\', '/'",
            "        return \"/mnt/$Drive/$Rest\"",
            "    }",
            "    return ($FullPath -replace '\\\\', '/')",
            "}",
            "",
            "if (Get-Command sh -ErrorAction SilentlyContinue) {",
            "    Push-Location $LabRoot",
            "    try {",
            "        & sh $HookScript",
            "        if ($LASTEXITCODE -ne 0) { throw \"service hook failed with exit code $LASTEXITCODE\" }",
            "    } finally {",
            "        Pop-Location",
            "    }",
            "    return",
            "}",
            "",
            "if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {",
            "    throw 'No POSIX shell found. Install sh/Git Bash/WSL to run service hooks on Windows.'",
            "}",
            "",
            "$DistroArgs = @()",
            "if ($env:LABFORGE_WSL_DISTRO) { $DistroArgs = @('-d', $env:LABFORGE_WSL_DISTRO) }",
            "$WslHook = ConvertTo-LabForgeWslPath $HookScript",
            "wsl.exe @DistroArgs -- sh $WslHook",
            "if ($LASTEXITCODE -ne 0) { throw \"WSL service hook failed with exit code $LASTEXITCODE\" }",
            "",
        ]
    )


def render_powershell_script(compose_args: list[str]) -> str:
    if "&&" in compose_args:
        first = compose_args[: compose_args.index("&&")]
        second = compose_args[compose_args.index("&&") + 1 :]
        command_lines = [
            f"Invoke-LabForgeCompose @({powershell_array(first)})",
            f"Invoke-LabForgeCompose @({powershell_array(second)})",
        ]
    else:
        command_lines = [f"Invoke-LabForgeCompose @({powershell_array(compose_args)})"]

    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
            "$LabRoot = (Resolve-Path (Join-Path $ScriptDir '..')).Path",
            "",
            "function Test-LabForgeDocker {",
            "    try {",
            "        docker compose version *> $null",
            "        return $LASTEXITCODE -eq 0",
            "    } catch {",
            "        return $false",
            "    }",
            "}",
            "",
            "function ConvertTo-LabForgeWslPath([string]$Path) {",
            "    $FullPath = (Resolve-Path $Path).Path",
            "    if ($FullPath -match '^([A-Za-z]):\\\\(.*)$') {",
            "        $Drive = $Matches[1].ToLowerInvariant()",
            "        $Rest = $Matches[2] -replace '\\\\', '/'",
            "        return \"/mnt/$Drive/$Rest\"",
            "    }",
            "    return ($FullPath -replace '\\\\', '/')",
            "}",
            "",
            "function Join-LabForgeShellArgs([string[]]$Items) {",
            "    return ($Items | ForEach-Object { \"'\" + ($_ -replace \"'\", \"'\\''\") + \"'\" }) -join ' '",
            "}",
            "",
            "function Get-LabForgeWslDistros {",
            "    $Raw = wsl.exe -l -q 2>$null",
            "    if ($LASTEXITCODE -ne 0) { return @() }",
            "    $Distros = @()",
            "    foreach ($Line in $Raw) {",
            "        $Name = ($Line -replace \"`0\", '').Trim()",
            "        if ($Name) { $Distros += $Name }",
            "    }",
            "    return $Distros",
            "}",
            "",
            "function Test-LabForgeWslDocker([string]$Distro) {",
            "    wsl.exe -d $Distro -- docker version --format '{{.Server.Version}}' *> $null",
            "    return $LASTEXITCODE -eq 0",
            "}",
            "",
            "function Select-LabForgeWslDistro {",
            "    if ($env:LABFORGE_WSL_DISTRO) {",
            "        if (Test-LabForgeWslDocker $env:LABFORGE_WSL_DISTRO) { return $env:LABFORGE_WSL_DISTRO }",
            "        throw \"LABFORGE_WSL_DISTRO is set to '$env:LABFORGE_WSL_DISTRO', but Docker is not reachable there.\"",
            "    }",
            "    foreach ($Distro in Get-LabForgeWslDistros) {",
            "        if (Test-LabForgeWslDocker $Distro) { return $Distro }",
            "    }",
            "    throw 'Docker is not available in this shell and no WSL distro with a reachable Docker server was found.'",
            "}",
            "",
            "function Invoke-LabForgeCompose([string[]]$ComposeArgs) {",
            "    if (Test-LabForgeDocker) {",
            "        Push-Location $LabRoot",
            "        try {",
            "            & docker compose -f docker-compose.yml @ComposeArgs",
            "            if ($LASTEXITCODE -ne 0) { throw \"docker compose failed with exit code $LASTEXITCODE\" }",
            "        } finally {",
            "            Pop-Location",
            "        }",
            "        return",
            "    }",
            "",
            "    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {",
            "        throw 'Docker is not available in this shell and wsl.exe was not found.'",
            "    }",
            "",
            "    $Distro = Select-LabForgeWslDistro",
            "    $WslLabRoot = ConvertTo-LabForgeWslPath $LabRoot",
            "    $ArgString = Join-LabForgeShellArgs $ComposeArgs",
            "    $Command = \"cd '$WslLabRoot' && docker compose -f docker-compose.yml $ArgString\"",
            "    wsl.exe -d $Distro -- bash -lc $Command",
            "    if ($LASTEXITCODE -ne 0) { throw \"WSL docker compose failed with exit code $LASTEXITCODE\" }",
            "}",
            "",
            *command_lines,
            "",
        ]
    )


def powershell_array(items: list[str]) -> str:
    return ", ".join("'" + item.replace("'", "''") + "'" for item in items)


def render_scripts_readme() -> str:
    return "\n".join(
        [
            "# Runtime Scripts",
            "",
            "These scripts are generated by the Docker Compose provider.",
            "",
            "| Script | Purpose |",
            "|---|---|",
            "| `validate.ps1` / `validate.sh` | Run `docker compose config`. |",
            "| `start.ps1` / `start.sh` | Build and start the lab. |",
            "| `stop.ps1` / `stop.sh` | Stop the lab without deleting volumes. |",
            "| `destroy.ps1` / `destroy.sh` | Stop the lab and delete Compose volumes. |",
            "| `reset.ps1` / `reset.sh` | Delete volumes and rebuild the lab. |",
            "| `services-healthcheck.ps1` / `services-healthcheck.sh` | Run service `healthcheck.sh` hooks copied into the generated lab. |",
            "| `services-reset.ps1` / `services-reset.sh` | Run service `reset.sh` hooks copied into the generated lab. |",
            "",
            "PowerShell scripts first try Docker in the current shell. If Docker is not available, they delegate to WSL.",
            "When WSL delegation is needed, the scripts auto-detect a WSL distro with a reachable Docker server.",
            "Set `LABFORGE_WSL_DISTRO` only when you want to force a specific distro.",
            "",
        ]
    )
