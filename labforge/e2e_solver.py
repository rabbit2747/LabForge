from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .access_playtest import AccessPlaytestReport, run_access_playtest
from .doctor import HostDoctorReport, inspect_host, report_to_markdown
from .io import dump_yaml, write_text
from .provider_lifecycle import ProviderLifecycleResult, provider_lifecycle
from .solver_runner import SolverRunReport, run_solver_plan


class E2ESolverModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class E2ESolverReport(E2ESolverModel):
    provider: str
    mode: Literal["dry-run", "execute"]
    status: Literal["planned", "passed", "warning", "failed"]
    provider_output: str
    solver_plan: str
    access_manifest: str
    host_preflight: dict = Field(default_factory=dict)
    preflight_ready: bool = False
    lifecycle: list[ProviderLifecycleResult] = Field(default_factory=list)
    access_playtest: AccessPlaytestReport | None = None
    solver_run: SolverRunReport | None = None
    cleanup_requested: bool = False
    next_actions: list[str] = Field(default_factory=list)


def run_e2e_solver(
    provider_output: Path,
    solver_plan: Path,
    access_manifest: Path,
    out: Path,
    *,
    provider: str = "docker-compose",
    execute: bool = False,
    cleanup: bool = False,
    timeout_seconds: int = 60,
    host_preflight: HostDoctorReport | None = None,
) -> E2ESolverReport:
    provider_output = provider_output.resolve()
    solver_plan = solver_plan.resolve()
    access_manifest = access_manifest.resolve()
    out.mkdir(parents=True, exist_ok=True)
    host_preflight = host_preflight or inspect_host()
    host_preflight_data = host_preflight_to_dict(host_preflight)
    preflight_ready = provider_preflight_ready(host_preflight, provider)
    write_text(out / "host-preflight.md", report_to_markdown(host_preflight))
    write_text(out / "host-preflight.json", json.dumps(host_preflight_data, ensure_ascii=False, indent=2) + "\n")
    lifecycle: list[ProviderLifecycleResult] = []
    if execute and not preflight_ready:
        lifecycle.append(
            ProviderLifecycleResult(
                provider=provider,
                action="validate",
                mode="execute",
                status="failed",
                output_dir=str(provider_output),
                message="Host preflight is not ready for this provider. Review host-preflight.md before executing lifecycle commands.",
            )
        )
        access_report = run_access_playtest(access_manifest, out / "access-playtest", execute=False, timeout_seconds=min(timeout_seconds, 15))
        solver_report = run_solver_plan(
            solver_plan,
            out / "solver-run",
            access_manifest=access_manifest,
            execute=False,
            timeout_seconds=min(timeout_seconds, 15),
        )
    else:
        lifecycle.append(
            provider_lifecycle(
                provider_output,
                provider=provider,
                action="validate",
                execute=execute,
                timeout_seconds=timeout_seconds,
            )
        )
        lifecycle.append(
            provider_lifecycle(
                provider_output,
                provider=provider,
                action="deploy",
                execute=execute,
                timeout_seconds=timeout_seconds,
            )
        )
        lifecycle.append(
            provider_lifecycle(
                provider_output,
                provider=provider,
                action="status",
                execute=execute,
                timeout_seconds=timeout_seconds,
            )
        )
        access_report = run_access_playtest(access_manifest, out / "access-playtest", execute=execute, timeout_seconds=min(timeout_seconds, 15))
        solver_report = run_solver_plan(
            solver_plan,
            out / "solver-run",
            access_manifest=access_manifest,
            execute=execute,
            timeout_seconds=min(timeout_seconds, 15),
        )
        if cleanup:
            lifecycle.append(
                provider_lifecycle(
                    provider_output,
                    provider=provider,
                    action="destroy",
                    execute=execute,
                    remove_volumes=False,
                    timeout_seconds=timeout_seconds,
                )
            )
    mode: Literal["dry-run", "execute"] = "execute" if execute else "dry-run"
    report = E2ESolverReport(
        provider=provider,
        mode=mode,
        status=aggregate_e2e_status(lifecycle, access_report, solver_report, execute=execute),
        provider_output=str(provider_output),
        solver_plan=str(solver_plan),
        access_manifest=str(access_manifest),
        host_preflight=host_preflight_data,
        preflight_ready=preflight_ready,
        lifecycle=lifecycle,
        access_playtest=access_report,
        solver_run=solver_report,
        cleanup_requested=cleanup,
        next_actions=e2e_next_actions(provider_output, solver_plan, access_manifest, execute=execute, cleanup=cleanup),
    )
    write_text(out / "e2e-solver.yaml", dump_yaml(report.model_dump()))
    write_text(out / "e2e-solver.json", report.model_dump_json(indent=2))
    write_text(out / "e2e-solver.md", render_e2e_solver_markdown(report))
    return report


def aggregate_e2e_status(
    lifecycle: list[ProviderLifecycleResult],
    access_report: AccessPlaytestReport,
    solver_report: SolverRunReport,
    *,
    execute: bool,
) -> Literal["planned", "passed", "warning", "failed"]:
    if not execute:
        return "planned"
    if any(item.status == "failed" for item in lifecycle):
        return "failed"
    if access_report.status == "failed" or solver_report.status == "failed":
        return "failed"
    if any(item.status in {"planned", "not-implemented"} for item in lifecycle):
        return "warning"
    if access_report.status == "warning" or solver_report.status == "warning":
        return "warning"
    return "passed"


def provider_preflight_ready(report: HostDoctorReport, provider: str) -> bool:
    if provider != "docker-compose":
        return True
    return report.host_docker_server or any(distro.docker_server for distro in report.wsl_distros)


def host_preflight_to_dict(report: HostDoctorReport) -> dict:
    return {
        "host_os": report.host_os,
        "platform": report.platform,
        "architecture": report.architecture,
        "shell_hint": report.shell_hint,
        "cwd": report.cwd,
        "wsl_available": report.wsl_available,
        "wsl_distros": [
            {
                "name": distro.name,
                "state": distro.state,
                "version": distro.version,
                "docker_cli": distro.docker_cli,
                "docker_server": distro.docker_server,
                "docker_server_version": distro.docker_server_version,
            }
            for distro in report.wsl_distros
        ],
        "host_docker_cli": report.host_docker_cli,
        "host_docker_server": report.host_docker_server,
        "host_docker_server_version": report.host_docker_server_version,
        "recommended_execution": report.recommended_execution,
        "findings": list(report.findings),
        "warnings": list(report.warnings),
        "next_steps": list(report.next_steps),
    }


def e2e_next_actions(provider_output: Path, solver_plan: Path, access_manifest: Path, *, execute: bool, cleanup: bool) -> list[str]:
    if execute:
        actions = ["Review e2e-solver.md, solver-run.md, and access-playtest.md for failed or warning checks."]
        if not cleanup:
            actions.append("Stop the generated provider output when finished.")
        return actions
    return [
        f"Review provider output: {provider_output}",
        f"Review solver plan: {solver_plan}",
        f"Review access manifest: {access_manifest}",
        "Re-run this command with --execute after confirming the provider can run on this host.",
    ]


def render_e2e_solver_markdown(report: E2ESolverReport) -> str:
    lines = [
        "# E2E Solver Report",
        "",
        f"- Provider: `{report.provider}`",
        f"- Mode: `{report.mode}`",
        f"- Status: `{report.status}`",
        f"- Provider output: `{report.provider_output}`",
        f"- Solver plan: `{report.solver_plan}`",
        f"- Access manifest: `{report.access_manifest}`",
        f"- Host preflight ready: `{str(report.preflight_ready).lower()}`",
        f"- Cleanup requested: `{str(report.cleanup_requested).lower()}`",
        "",
        "## Host Preflight",
        "",
        f"- OS: `{report.host_preflight.get('host_os', '-') if report.host_preflight else '-'}`",
        f"- Recommended execution: `{report.host_preflight.get('recommended_execution', '-') if report.host_preflight else '-'}`",
        f"- Host Docker server: `{str(report.host_preflight.get('host_docker_server', '-')).lower() if report.host_preflight else '-'}`",
        f"- WSL available: `{str(report.host_preflight.get('wsl_available', '-')).lower() if report.host_preflight else '-'}`",
        "",
        "## Lifecycle",
        "",
        "| Action | Mode | Status | Message |",
        "|---|---|---|---|",
    ]
    for item in report.lifecycle:
        lines.append(f"| `{item.action}` | `{item.mode}` | {item.status} | {escape_cell(item.message or '-')} |")
    lines += [
        "",
        "## Access Playtest",
        "",
        f"- Status: `{report.access_playtest.status if report.access_playtest else 'missing'}`",
        f"- Browser targets: `{len(report.access_playtest.browser_targets) if report.access_playtest else 0}`",
        f"- Terminal targets: `{len(report.access_playtest.terminal_targets) if report.access_playtest else 0}`",
        "",
        "## Solver Run",
        "",
        f"- Status: `{report.solver_run.status if report.solver_run else 'missing'}`",
        f"- Steps: `{len(report.solver_run.steps) if report.solver_run else 0}`",
        "",
        "## Next Actions",
        "",
    ]
    lines.extend(f"- {item}" for item in report.next_actions)
    lines.append("")
    return "\n".join(lines)


def escape_cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")
