from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Literal
from urllib.error import URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, write_text


SolverStepStatus = Literal["planned", "passed", "warning", "failed", "skipped"]


class SolverRunnerModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class SolverRunStep(SolverRunnerModel):
    order: int
    step_id: str
    action_type: str
    service: str = ""
    plugin: str = ""
    status: SolverStepStatus
    command: str = ""
    target: str = ""
    evidence: list[str] = Field(default_factory=list)
    message: str = ""
    stdout: str = ""
    stderr: str = ""


class SolverRunReport(SolverRunnerModel):
    lab_id: str
    title: str
    mode: Literal["dry-run", "execute"]
    status: Literal["planned", "passed", "warning", "failed"]
    solver_plan: str
    access_manifest: str = ""
    steps: list[SolverRunStep] = Field(default_factory=list)
    browser_targets: list[str] = Field(default_factory=list)
    terminal_targets: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)


def run_solver_plan(
    solver_plan: Path,
    out: Path,
    *,
    access_manifest: Path | None = None,
    execute: bool = False,
    timeout_seconds: int = 5,
) -> SolverRunReport:
    solver_plan = solver_plan.resolve()
    out.mkdir(parents=True, exist_ok=True)
    plan = load_json_object(solver_plan)
    access = load_json_object(access_manifest.resolve()) if access_manifest else {}
    browser_targets = browser_targets_from(plan, access)
    terminal_targets = terminal_targets_from(plan, access)
    steps: list[SolverRunStep] = []
    for raw_step in plan.get("steps", []) or []:
        if isinstance(raw_step, dict):
            steps.append(run_solver_step(raw_step, browser_targets, terminal_targets, execute=execute, timeout_seconds=timeout_seconds))
    mode: Literal["dry-run", "execute"] = "execute" if execute else "dry-run"
    status = aggregate_solver_status(steps, execute=execute)
    report = SolverRunReport(
        lab_id=str(plan.get("lab_id", "")),
        title=str(plan.get("title", "")),
        mode=mode,
        status=status,
        solver_plan=str(solver_plan),
        access_manifest=str(access_manifest.resolve()) if access_manifest else "",
        steps=steps,
        browser_targets=browser_targets,
        terminal_targets=terminal_targets,
        next_actions=solver_next_actions(plan, browser_targets, terminal_targets, execute=execute),
    )
    write_text(out / "solver-run.yaml", dump_yaml(report.model_dump()))
    write_text(out / "solver-run.json", report.model_dump_json(indent=2))
    write_text(out / "solver-run.md", render_solver_run_markdown(report))
    return report


def load_json_object(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON document is not an object: {path}")
    return data


def browser_targets_from(plan: dict, access: dict) -> list[str]:
    targets: list[str] = []
    for value in [plan.get("learner_start"), *(item.get("connect") for item in access.get("learner_entrypoints", []) or [] if isinstance(item, dict))]:
        target = str(value or "")
        if target.startswith("http") and target not in targets:
            targets.append(target)
    return targets


def terminal_targets_from(plan: dict, access: dict) -> list[str]:
    targets: list[str] = []
    for value in [plan.get("attacker_shell"), *(item.get("connect") for item in access.get("attacker_entrypoints", []) or [] if isinstance(item, dict))]:
        target = str(value or "")
        if target.startswith("ssh ") and target not in targets:
            targets.append(target)
    return targets


def run_solver_step(raw_step: dict, browser_targets: list[str], terminal_targets: list[str], *, execute: bool, timeout_seconds: int) -> SolverRunStep:
    action_type = str(raw_step.get("action_type", "verification"))
    order = int(raw_step.get("order") or 0)
    step_id = str(raw_step.get("step_id", ""))
    service = str(raw_step.get("service", ""))
    plugin = str(raw_step.get("plugin", ""))
    evidence = [str(item) for item in raw_step.get("evidence", []) or []]
    if not execute:
        return SolverRunStep(
            order=order,
            step_id=step_id,
            action_type=action_type,
            service=service,
            plugin=plugin,
            status="planned",
            target=planned_target(action_type, browser_targets, terminal_targets),
            evidence=evidence,
            message="dry-run",
        )
    if action_type == "access":
        return run_access_solver_step(order, step_id, browser_targets, terminal_targets, evidence, timeout_seconds=timeout_seconds)
    if action_type == "final-submission":
        target = str(raw_step.get("evidence", [""])[0] if raw_step.get("evidence") else "")
        if "http" in target:
            target = target.split("http", maxsplit=1)[1]
            target = "http" + target
        return run_http_probe(order, step_id, action_type, target or planned_target(action_type, browser_targets, terminal_targets), service, plugin, evidence, timeout_seconds=timeout_seconds)
    if action_type == "vulnerability-behavior":
        status: SolverStepStatus = "passed" if evidence else "warning"
        return SolverRunStep(
            order=order,
            step_id=step_id,
            action_type=action_type,
            service=service,
            plugin=plugin,
            status=status,
            evidence=evidence,
            message="runtime evidence present; exploit-specific browser/terminal automation remains plugin-driven",
        )
    return SolverRunStep(
        order=order,
        step_id=step_id,
        action_type=action_type,
        service=service,
        plugin=plugin,
        status="passed" if evidence else "planned",
        evidence=evidence,
        message="non-interactive solver checkpoint",
    )


def run_access_solver_step(order: int, step_id: str, browser_targets: list[str], terminal_targets: list[str], evidence: list[str], *, timeout_seconds: int) -> SolverRunStep:
    if browser_targets:
        return run_http_probe(order, step_id, "access", browser_targets[0], "", "", evidence, timeout_seconds=timeout_seconds)
    if terminal_targets:
        return run_ssh_probe(order, step_id, terminal_targets[0], evidence, timeout_seconds=timeout_seconds)
    return SolverRunStep(order=order, step_id=step_id, action_type="access", status="failed", evidence=evidence, message="no browser or terminal target")


def run_http_probe(order: int, step_id: str, action_type: str, target: str, service: str, plugin: str, evidence: list[str], *, timeout_seconds: int) -> SolverRunStep:
    if not target.startswith("http"):
        return SolverRunStep(order=order, step_id=step_id, action_type=action_type, service=service, plugin=plugin, status="skipped", target=target, evidence=evidence, message="no HTTP target")
    try:
        request = Request(target, headers={"User-Agent": "LabForge-SolverRunner/1.0"})
        with urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(256).decode("utf-8", "replace")
            ok = 200 <= int(response.status) < 500
            return SolverRunStep(
                order=order,
                step_id=step_id,
                action_type=action_type,
                service=service,
                plugin=plugin,
                status="passed" if ok else "failed",
                target=target,
                evidence=evidence,
                stdout=body,
                message=f"http_status={response.status}",
            )
    except URLError as exc:
        return SolverRunStep(order=order, step_id=step_id, action_type=action_type, service=service, plugin=plugin, status="failed", target=target, evidence=evidence, message=str(exc))


def run_ssh_probe(order: int, step_id: str, command: str, evidence: list[str], *, timeout_seconds: int) -> SolverRunStep:
    argv = ssh_batch_argv(command)
    if not argv:
        return SolverRunStep(order=order, step_id=step_id, action_type="access", status="skipped", command=command, evidence=evidence, message="unsupported SSH command")
    if not shutil.which(argv[0]):
        return SolverRunStep(order=order, step_id=step_id, action_type="access", status="skipped", command=command, evidence=evidence, message="ssh executable missing")
    try:
        completed = subprocess.run(argv, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return SolverRunStep(order=order, step_id=step_id, action_type="access", status="failed", command=command, evidence=evidence, message=f"ssh timed out after {timeout_seconds}s")
    return SolverRunStep(
        order=order,
        step_id=step_id,
        action_type="access",
        status="passed" if completed.returncode == 0 else "failed",
        command=command,
        evidence=evidence,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
        message=f"exit_code={completed.returncode}",
    )


def ssh_batch_argv(command: str) -> list[str]:
    if not command.startswith("ssh "):
        return []
    parts = command.split()
    if "-o" not in parts:
        parts[1:1] = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
    if "true" not in parts:
        parts.append("true")
    return parts


def planned_target(action_type: str, browser_targets: list[str], terminal_targets: list[str]) -> str:
    if action_type in {"access", "final-submission"} and browser_targets:
        return browser_targets[0]
    if action_type == "access" and terminal_targets:
        return terminal_targets[0]
    return ""


def aggregate_solver_status(steps: list[SolverRunStep], *, execute: bool) -> Literal["planned", "passed", "warning", "failed"]:
    if not execute:
        return "planned"
    if any(step.status == "failed" for step in steps):
        return "failed"
    if any(step.status in {"warning", "skipped", "planned"} for step in steps):
        return "warning"
    return "passed"


def solver_next_actions(plan: dict, browser_targets: list[str], terminal_targets: list[str], *, execute: bool) -> list[str]:
    actions = []
    if browser_targets:
        actions.append(f"Open learner browser target: {browser_targets[0]}")
    if terminal_targets:
        actions.append(f"Open attacker terminal target: {terminal_targets[0]}")
    if final_submission := str(plan.get("final_submission", "")).strip():
        actions.append(f"Use final submission endpoint when proof is collected: {final_submission}")
    if not execute:
        actions.append("Re-run with --execute after provider startup to probe browser and SSH access.")
    return actions


def render_solver_run_markdown(report: SolverRunReport) -> str:
    lines = [
        f"# Solver Run - {report.title or report.lab_id}",
        "",
        f"- Lab ID: `{report.lab_id}`",
        f"- Mode: `{report.mode}`",
        f"- Status: `{report.status}`",
        f"- Solver plan: `{report.solver_plan}`",
        f"- Access manifest: `{report.access_manifest or '-'}`",
        "",
        "## Steps",
        "",
        "| # | Step | Type | Status | Service | Plugin | Target/Command | Message |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for step in report.steps:
        target = step.target or step.command or "-"
        lines.append(
            f"| {step.order} | `{escape_cell(step.step_id)}` | `{escape_cell(step.action_type)}` | {step.status} | "
            f"`{escape_cell(step.service or '-')}` | `{escape_cell(step.plugin or '-')}` | `{escape_cell(target)}` | {escape_cell(step.message or '-')} |"
        )
    lines.extend(["", "## Next Actions", ""])
    lines.extend(f"- {item}" for item in report.next_actions)
    lines.append("")
    return "\n".join(lines)


def escape_cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")
