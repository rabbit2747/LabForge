from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .doctor import HostDoctorReport, WslDistro, inspect_host
from .model import LabSpec


@dataclass(frozen=True)
class PlanStep:
    order: int
    title: str
    location: str
    commands: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ExecutionPlan:
    lab_id: str
    title: str
    provider: str
    profile: str
    recommended_model: str
    docker_only_supported: bool
    host: HostDoctorReport
    execution_location: str
    wsl_distro: str | None
    output_dir: str
    warnings: list[str]
    steps: list[PlanStep]


def preferred_wsl_distro(report: HostDoctorReport) -> WslDistro | None:
    for distro in report.wsl_distros:
        if distro.docker_server:
            return distro
    return None


def deployment_summary(spec: LabSpec) -> tuple[str, bool]:
    deployment = spec.topology.get("deployment", {})
    if not isinstance(deployment, dict):
        deployment = {}
    recommended_model = str(deployment.get("recommended_model", "docker-compose"))
    docker_only_supported = bool(deployment.get("docker_only_supported", True))
    return recommended_model, docker_only_supported


def windows_to_wsl_mount_path(path: Path) -> str:
    resolved = str(path.resolve())
    if len(resolved) >= 3 and resolved[1:3] == ":\\":
        drive = resolved[0].lower()
        rest = resolved[3:].replace("\\", "/")
        return f"/mnt/{drive}/{rest}"
    return resolved.replace("\\", "/")


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def make_host_commands(lab: Path, out: Path, provider: str, profile: str) -> list[str]:
    return [
        f"python -m labforge doctor --lab {lab}",
        f"python -m labforge validate {lab}",
        f"python -m labforge build {lab} --out {out} --provider {provider} --profile {profile} --force",
    ]


def make_wsl_commands(lab: Path, out: Path, provider: str, profile: str, distro: str) -> list[str]:
    repo_path = windows_to_wsl_mount_path(Path.cwd())
    lab_rel = lab.as_posix()
    out_rel = out.as_posix()
    inner_commands = [
        f"cd {shell_quote(repo_path)}",
        f"python -m labforge doctor --lab {shell_quote(lab_rel)}",
        f"python -m labforge validate {shell_quote(lab_rel)}",
        (
            "python -m labforge build "
            f"{shell_quote(lab_rel)} --out {shell_quote(out_rel)} "
            f"--provider {shell_quote(provider)} --profile {shell_quote(profile)} --force"
        ),
    ]
    joined = " && ".join(inner_commands)
    return [f"wsl.exe -d {distro} -- bash -lc {shell_quote(joined)}"]


def make_runtime_command(command: str, runtime_cwd: str | None) -> str:
    if runtime_cwd:
        return f"cd {shell_quote(runtime_cwd)} && {command}"
    return command


def make_script_command(out: Path, script_name: str, host_os: str, runtime_cwd: str | None) -> str:
    if runtime_cwd:
        return make_runtime_command(f"sh {out.as_posix()}/scripts/{script_name}.sh", runtime_cwd)
    if host_os == "windows":
        return f"& {out}\\scripts\\{script_name}.ps1"
    return f"sh {out.as_posix()}/scripts/{script_name}.sh"


def make_runtime_steps(
    out: Path,
    provider: str,
    location: str,
    host_os: str,
    runtime_cwd: str | None = None,
) -> list[PlanStep]:
    if provider != "docker-compose":
        return [
            PlanStep(
                5,
                "Provider Runtime",
                location,
                notes=[
                    f"`{provider}` provider currently generates a scaffold. Runtime deployment commands are provider-specific and must be implemented in the next provider phase."
                ],
            )
        ]

    compose_file = out / "docker-compose.yml"
    return [
        PlanStep(
            5,
            "Compose Validation",
            location,
            commands=[make_script_command(out, "validate", host_os, runtime_cwd)],
            notes=["Validates generated Compose syntax before starting services."],
        ),
        PlanStep(
            6,
            "Start Lab",
            location,
            commands=[make_script_command(out, "start", host_os, runtime_cwd)],
            notes=["Starts or rebuilds the lab services."],
        ),
        PlanStep(
            7,
            "Reset Lab State",
            location,
            commands=[make_script_command(out, "reset", host_os, runtime_cwd)],
            notes=["Prototype reset path for Docker-backed labs. VM/hybrid labs should use snapshot revert instead."],
        ),
    ]


def create_execution_plan(
    spec: LabSpec,
    lab: Path,
    out: Path,
    provider: str,
    profile: str,
) -> ExecutionPlan:
    report = inspect_host(lab)
    recommended_model, docker_only_supported = deployment_summary(spec)
    warnings = list(report.warnings)

    execution_location = report.recommended_execution
    distro = preferred_wsl_distro(report)
    distro_name = distro.name if distro else None

    steps: list[PlanStep] = [
        PlanStep(
            1,
            "Host Readiness",
            "current shell",
            commands=[f"python -m labforge doctor --lab {lab}"],
            notes=["Confirms OS, WSL, Docker, and realistic deployment prerequisites."],
        )
    ]

    if execution_location == "wsl" and distro_name:
        runtime_cwd = windows_to_wsl_mount_path(Path.cwd())
        steps.append(
            PlanStep(
                2,
                "Generate Lab Scaffold",
                f"Windows shell launching WSL distro {distro_name}",
                commands=make_wsl_commands(lab, out, provider, profile, distro_name),
                notes=[
                    "This quick path runs from the Windows-mounted repository path.",
                    "For large Docker volumes, prefer cloning or syncing the repo into the WSL ext4 filesystem before running Docker.",
                ],
            )
        )
        runtime_location = f"WSL distro {distro_name}"
    elif execution_location == "wsl-required":
        runtime_cwd = None
        steps.append(
            PlanStep(
                2,
                "Enable Docker Runtime",
                "Windows / WSL",
                notes=[
                    "No reachable Docker server was detected.",
                    "Enable Docker Desktop WSL integration or install Docker Engine inside a WSL distro.",
                ],
            )
        )
        runtime_location = "WSL after Docker is enabled"
    else:
        runtime_cwd = None
        steps.append(
            PlanStep(
                2,
                "Generate Lab Scaffold",
                "current shell",
                commands=make_host_commands(lab, out, provider, profile),
                notes=["Runs directly from the current host shell."],
            )
        )
        runtime_location = "current shell"

    steps.append(
        PlanStep(
            3,
            "Review Generated Design",
            "current shell",
            commands=[
                f"type {out / 'README.md'}",
                f"type {out / 'docs' / 'deployment-requirements.md'}",
                f"type {out / 'docs' / 'security-control-selection.md'}",
            ],
            notes=["On Linux/macOS/WSL, replace `type` with `cat`."],
        )
    )
    steps.append(
        PlanStep(
            4,
            "Supervisor Gate",
            "supervisor review",
            notes=[
                f"Recommended deployment model: `{recommended_model}`.",
                f"Docker-only supported: `{str(docker_only_supported).lower()}`.",
                "Confirm selected controls, exposed entrypoints, reset strategy, and whether VM/hybrid infrastructure is required.",
            ],
        )
    )
    steps.extend(make_runtime_steps(out, provider, runtime_location, report.host_os, runtime_cwd=runtime_cwd))

    return ExecutionPlan(
        lab_id=spec.lab_id,
        title=spec.title,
        provider=provider,
        profile=profile,
        recommended_model=recommended_model,
        docker_only_supported=docker_only_supported,
        host=report,
        execution_location=execution_location,
        wsl_distro=distro_name,
        output_dir=str(out),
        warnings=warnings,
        steps=steps,
    )


def plan_to_markdown(plan: ExecutionPlan) -> str:
    lines = [
        f"# Execution Plan - {plan.title}",
        "",
        "## Summary",
        "",
        f"- Lab ID: `{plan.lab_id}`",
        f"- Provider: `{plan.provider}`",
        f"- Profile: `{plan.profile}`",
        f"- Recommended deployment model: `{plan.recommended_model}`",
        f"- Docker-only supported: `{str(plan.docker_only_supported).lower()}`",
        f"- Execution location: `{plan.execution_location}`",
        f"- WSL distro: `{plan.wsl_distro or ''}`",
        f"- Output directory: `{plan.output_dir}`",
        "",
        "## Host Decision",
        "",
        f"- Host OS: `{plan.host.host_os}`",
        f"- Platform: `{plan.host.platform}`",
        f"- Host Docker server: `{str(plan.host.host_docker_server).lower()}`",
        f"- WSL available: `{str(plan.host.wsl_available).lower()}`",
        "",
    ]
    if plan.host.wsl_distros:
        lines += [
            "| WSL Distro | State | Docker CLI | Docker Server | Docker Version |",
            "|---|---|---:|---:|---|",
        ]
        for distro in plan.host.wsl_distros:
            lines.append(
                f"| `{distro.name}` | {distro.state} | "
                f"{str(distro.docker_cli).lower()} | {str(distro.docker_server).lower()} | "
                f"{distro.docker_server_version or ''} |"
            )
        lines.append("")

    lines += ["## Warnings", ""]
    lines.extend(f"- {warning}" for warning in plan.warnings or ["No warnings."])
    lines += ["", "## Steps", ""]
    for step in plan.steps:
        lines += [
            f"### {step.order}. {step.title}",
            "",
            f"- Location: {step.location}",
            "",
        ]
        if step.commands:
            lines.append("Commands:")
            lines.append("")
            lines.append("```powershell")
            lines.extend(step.commands)
            lines.append("```")
            lines.append("")
        if step.notes:
            lines.append("Notes:")
            lines.append("")
            lines.extend(f"- {note}" for note in step.notes)
            lines.append("")
    return "\n".join(lines)


def plan_to_json(plan: ExecutionPlan) -> str:
    return json.dumps(asdict(plan), ensure_ascii=False, indent=2)
