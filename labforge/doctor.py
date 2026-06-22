from __future__ import annotations

import json
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .model import LabSpec


@dataclass(frozen=True)
class CommandResult:
    available: bool
    command: str
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class WslDistro:
    name: str
    state: str = ""
    version: str = ""
    docker_cli: bool = False
    docker_server: bool = False
    docker_server_version: str = ""


@dataclass(frozen=True)
class HostDoctorReport:
    host_os: str
    platform: str
    architecture: str
    shell_hint: str
    cwd: str
    wsl_available: bool
    wsl_distros: list[WslDistro] = field(default_factory=list)
    host_docker_cli: bool = False
    host_docker_server: bool = False
    host_docker_server_version: str = ""
    recommended_execution: str = "unknown"
    findings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)


def run_command(command: list[str], timeout: int = 10) -> CommandResult:
    executable = shutil.which(command[0])
    if executable is None:
        return CommandResult(False, " ".join(command))
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(
            True,
            " ".join(command),
            stdout="",
            stderr=str(exc),
        )
    return CommandResult(
        True,
        " ".join(command),
        completed.returncode,
        completed.stdout.strip(),
        completed.stderr.strip(),
    )


def detect_host_os() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "macos"
    if system == "linux":
        if "microsoft" in platform.release().lower():
            return "wsl-linux"
        return "linux"
    return system or "unknown"


def detect_shell_hint() -> str:
    if detect_host_os() == "windows":
        return "powershell"
    shell = Path(str(shutil.which("bash") or "")).name
    return shell or "sh"


def docker_status(command_prefix: list[str] | None = None, timeout: int = 12) -> tuple[bool, bool, str]:
    prefix = command_prefix or []
    cli = run_command(prefix + ["docker", "--version"], timeout=timeout)
    if not cli.available or cli.returncode != 0:
        return False, False, ""
    server = run_command(
        prefix + ["docker", "version", "--format", "{{.Server.Version}}"],
        timeout=timeout,
    )
    if server.returncode == 0 and server.stdout:
        return True, True, server.stdout.strip()
    return True, False, ""


def parse_wsl_list(output: str) -> list[tuple[str, str, str]]:
    distros: list[tuple[str, str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.replace("\x00", "").strip()
        if not line or "NAME" in line.upper() and "STATE" in line.upper():
            continue
        line = line.lstrip("*").strip()
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        state = parts[1] if len(parts) > 1 else ""
        version = parts[2] if len(parts) > 2 else ""
        distros.append((name, state, version))
    return distros


def detect_wsl_distros() -> tuple[bool, list[WslDistro]]:
    wsl = run_command(["wsl.exe", "-l", "-v"], timeout=10)
    if not wsl.available or wsl.returncode != 0:
        return False, []
    distros: list[WslDistro] = []
    for name, state, version in parse_wsl_list(wsl.stdout):
        docker_cli, docker_server, docker_version = docker_status(
            ["wsl.exe", "-d", name, "--"],
            timeout=90,
        )
        distros.append(
            WslDistro(
                name=name,
                state=state,
                version=version,
                docker_cli=docker_cli,
                docker_server=docker_server,
                docker_server_version=docker_version,
            )
        )
    return True, distros


def provider_from_lab(root: Path | None) -> str | None:
    if root is None:
        return None
    try:
        spec = LabSpec.load(root)
    except Exception:
        return None
    deployment = spec.topology.get("deployment", {})
    return str(deployment.get("recommended_model", "")) or None


def inspect_host(lab_root: Path | None = None) -> HostDoctorReport:
    host_os = detect_host_os()
    host_cli, host_server, host_version = docker_status()
    wsl_available, wsl_distros = detect_wsl_distros() if host_os == "windows" else (False, [])
    recommended_model = provider_from_lab(lab_root)

    findings: list[str] = []
    warnings: list[str] = []
    next_steps: list[str] = []
    recommended_execution = "host"

    if host_os == "windows":
        findings.append("Local host OS is Windows.")
        if wsl_available:
            findings.append("WSL is installed.")
        else:
            warnings.append("WSL is not available from this shell.")
        docker_wsl = [distro for distro in wsl_distros if distro.docker_server]
        if docker_wsl:
            recommended_execution = "wsl"
            names = ", ".join(distro.name for distro in docker_wsl)
            findings.append(f"Docker server is reachable inside WSL distro(s): {names}.")
            next_steps.append("Run Docker-backed lab build/deploy commands inside the WSL distro that can reach Docker.")
        elif host_server:
            recommended_execution = "host"
            findings.append("Docker server is reachable from Windows directly.")
            next_steps.append("Docker-backed lab commands can run from the Windows shell.")
        else:
            recommended_execution = "wsl-required"
            warnings.append("Docker server was not reachable from Windows or detected WSL distros.")
            next_steps.append("Install/enable Docker Desktop WSL integration or Docker Engine inside WSL.")
    elif host_os in {"linux", "wsl-linux", "macos"}:
        if host_server:
            findings.append(f"Docker server is reachable from {host_os}.")
            next_steps.append("Docker-backed lab commands can run from the current shell.")
        elif host_cli:
            warnings.append("Docker CLI exists, but the Docker server is not reachable.")
            next_steps.append("Start Docker Engine or check the Docker context.")
        else:
            warnings.append("Docker CLI was not found in the current shell.")
            next_steps.append("Install Docker Engine/Desktop or use a non-Docker provider.")

    if recommended_model in {"hybrid", "vm", "proxmox", "ludus"}:
        warnings.append(
            f"The lab recommends `{recommended_model}`; Docker-only execution may be a prototype, not the realistic deployment model."
        )
        next_steps.append("Check deployment requirements for hypervisor, Windows Server, and VM prerequisites.")

    return HostDoctorReport(
        host_os=host_os,
        platform=platform.platform(),
        architecture=platform.machine(),
        shell_hint=detect_shell_hint(),
        cwd=str(Path.cwd()),
        wsl_available=wsl_available,
        wsl_distros=wsl_distros,
        host_docker_cli=host_cli,
        host_docker_server=host_server,
        host_docker_server_version=host_version,
        recommended_execution=recommended_execution,
        findings=findings,
        warnings=warnings,
        next_steps=next_steps,
    )


def report_to_markdown(report: HostDoctorReport) -> str:
    lines = [
        "# LabForge Host Doctor",
        "",
        "## Host",
        "",
        f"- OS: `{report.host_os}`",
        f"- Platform: `{report.platform}`",
        f"- Architecture: `{report.architecture}`",
        f"- Shell hint: `{report.shell_hint}`",
        f"- Current directory: `{report.cwd}`",
        f"- Recommended execution: `{report.recommended_execution}`",
        "",
        "## Docker",
        "",
        f"- Host Docker CLI: `{str(report.host_docker_cli).lower()}`",
        f"- Host Docker server: `{str(report.host_docker_server).lower()}`",
    ]
    if report.host_docker_server_version:
        lines.append(f"- Host Docker server version: `{report.host_docker_server_version}`")
    lines += [
        "",
        "## WSL",
        "",
        f"- WSL available: `{str(report.wsl_available).lower()}`",
    ]
    if report.wsl_distros:
        lines += ["", "| Distro | State | WSL Version | Docker CLI | Docker Server | Docker Version |", "|---|---|---|---|---|---|"]
        for distro in report.wsl_distros:
            lines.append(
                f"| `{distro.name}` | {distro.state} | {distro.version} | "
                f"{str(distro.docker_cli).lower()} | {str(distro.docker_server).lower()} | "
                f"{distro.docker_server_version or ''} |"
            )
    lines += ["", "## Findings", ""]
    lines.extend(f"- {item}" for item in report.findings or ["No findings."])
    lines += ["", "## Warnings", ""]
    lines.extend(f"- {item}" for item in report.warnings or ["No warnings."])
    lines += ["", "## Next Steps", ""]
    lines.extend(f"- {item}" for item in report.next_steps or ["No action required."])
    lines.append("")
    return "\n".join(lines)


def report_to_json(report: HostDoctorReport) -> str:
    return json.dumps(asdict(report), ensure_ascii=False, indent=2)
