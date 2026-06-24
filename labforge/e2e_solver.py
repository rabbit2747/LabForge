from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .access_playtest import AccessPlaytestReport, run_access_playtest
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
) -> E2ESolverReport:
    provider_output = provider_output.resolve()
    solver_plan = solver_plan.resolve()
    access_manifest = access_manifest.resolve()
    out.mkdir(parents=True, exist_ok=True)
    lifecycle: list[ProviderLifecycleResult] = []
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
        f"- Cleanup requested: `{str(report.cleanup_requested).lower()}`",
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
