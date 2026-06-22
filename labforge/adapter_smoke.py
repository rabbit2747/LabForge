from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .agent_adapters import get_agent_adapter
from .agent_orchestration import create_agent_execution_packages, scaffold_agent_workspace, validate_agent_workspace
from .io import write_text
from .model import LabSpec


class AdapterSmokeModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class AdapterSmokeCheck(AdapterSmokeModel):
    adapter: str
    check: str
    status: Literal["passed", "failed", "skipped"]
    message: str = ""
    files: list[str] = Field(default_factory=list)


class AdapterSmokeReport(AdapterSmokeModel):
    lab_id: str
    status: Literal["passed", "failed"]
    workspace: str
    context_root: str
    agent_id: str
    adapters: list[str] = Field(default_factory=list)
    checks: list[AdapterSmokeCheck] = Field(default_factory=list)


DEFAULT_SMOKE_ADAPTERS = ["manual", "openai", "codex", "claude-cli", "claude-code", "mcp"]


def run_adapter_smoke(
    lab_root: Path,
    out: Path,
    *,
    adapters: list[str] | None = None,
    agent_id: str = "scenario-designer",
    force: bool = False,
) -> AdapterSmokeReport:
    lab_root = lab_root.resolve()
    out = out.resolve()
    selected = adapters or DEFAULT_SMOKE_ADAPTERS
    if out.exists() and force:
        shutil.rmtree(out)
    spec = LabSpec.load(lab_root)
    scaffold_agent_workspace(spec, out)
    workspace = out / ".ai"
    validation_errors = validate_agent_workspace(workspace)
    checks: list[AdapterSmokeCheck] = []
    if validation_errors:
        checks.append(
            AdapterSmokeCheck(
                adapter="-",
                check="workspace-validation",
                status="failed",
                message="; ".join(validation_errors),
            )
        )
    else:
        checks.append(
            AdapterSmokeCheck(
                adapter="-",
                check="workspace-validation",
                status="passed",
                message="agent workspace is valid",
            )
        )

    for adapter_name in selected:
        try:
            adapter = get_agent_adapter(adapter_name)
        except Exception as exc:  # noqa: BLE001 - smoke report should preserve adapter errors.
            checks.append(AdapterSmokeCheck(adapter=adapter_name, check="lookup", status="failed", message=str(exc)))
            continue

        try:
            written = create_agent_execution_packages(
                workspace,
                adapter=adapter_name,
                agent_id=agent_id,
                context_root=lab_root,
            )
            package_files = [path for path in written if path.name.endswith(".package.yaml")]
            prepared_files: list[str] = []
            for package_file in package_files:
                result = adapter.prepare(package_file)
                if result.status != "prepared":
                    checks.append(
                        AdapterSmokeCheck(
                            adapter=adapter_name,
                            check="prepare",
                            status="failed",
                            message=result.message,
                            files=[result.package_file],
                        )
                    )
                    continue
                files = [result.package_file]
                if result.invocation_file:
                    files.append(result.invocation_file)
                    prepared_files.append(result.invocation_file)
                checks.append(
                    AdapterSmokeCheck(
                        adapter=adapter_name,
                        check="prepare",
                        status="passed",
                        message=result.message,
                        files=files,
                    )
                )
            if not package_files:
                checks.append(
                    AdapterSmokeCheck(
                        adapter=adapter_name,
                        check="prepare",
                        status="failed",
                        message=f"no package files were created for agent `{agent_id}`",
                    )
                )
            missing = [path for path in prepared_files if not Path(path).exists()]
            if missing:
                checks.append(
                    AdapterSmokeCheck(
                        adapter=adapter_name,
                        check="prepared-file-exists",
                        status="failed",
                        message="prepared invocation files are missing",
                        files=missing,
                    )
                )
        except Exception as exc:  # noqa: BLE001 - smoke report should preserve generation errors.
            checks.append(AdapterSmokeCheck(adapter=adapter_name, check="prepare", status="failed", message=str(exc)))

    checks.extend(execution_guard_checks(workspace, lab_root, agent_id))
    status: Literal["passed", "failed"] = "failed" if any(check.status == "failed" for check in checks) else "passed"
    return AdapterSmokeReport(
        lab_id=spec.lab_id,
        status=status,
        workspace=str(workspace.resolve()),
        context_root=str(lab_root),
        agent_id=agent_id,
        adapters=selected,
        checks=checks,
    )


def execution_guard_checks(workspace: Path, lab_root: Path, agent_id: str) -> list[AdapterSmokeCheck]:
    checks: list[AdapterSmokeCheck] = []
    written = create_agent_execution_packages(workspace, adapter="manual", agent_id=agent_id, context_root=lab_root)
    package_file = next((path for path in written if path.name.endswith(".package.yaml")), None)
    if not package_file:
        return [
            AdapterSmokeCheck(
                adapter="manual",
                check="execute-guard",
                status="failed",
                message="could not create package file for execute guard",
            )
        ]
    manual_result = get_agent_adapter("manual").execute(package_file)
    checks.append(
        AdapterSmokeCheck(
            adapter="manual",
            check="execute-guard",
            status="passed" if manual_result.status == "not-implemented" else "failed",
            message=manual_result.message,
            files=[manual_result.package_file],
        )
    )

    old_key = os.environ.pop("OPENAI_API_KEY", None)
    try:
        openai_result = get_agent_adapter("openai").execute(package_file)
    finally:
        if old_key is not None:
            os.environ["OPENAI_API_KEY"] = old_key
    checks.append(
        AdapterSmokeCheck(
            adapter="openai",
            check="missing-credential-guard",
            status="passed" if openai_result.status == "failed" and "OPENAI_API_KEY" in openai_result.message else "failed",
            message=openai_result.message,
            files=[openai_result.package_file],
        )
    )
    return checks


def adapter_smoke_to_json(report: AdapterSmokeReport) -> str:
    return json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + "\n"


def adapter_smoke_to_markdown(report: AdapterSmokeReport) -> str:
    lines = [
        f"# Agent Adapter Smoke Report - {report.lab_id}",
        "",
        f"- Status: `{report.status}`",
        f"- Workspace: `{report.workspace}`",
        f"- Context root: `{report.context_root}`",
        f"- Agent ID: `{report.agent_id}`",
        f"- Adapters: {', '.join(f'`{item}`' for item in report.adapters)}",
        "",
        "| Adapter | Check | Status | Message | Files |",
        "|---|---|---|---|---:|",
    ]
    for check in report.checks:
        lines.append(
            f"| `{check.adapter}` | `{check.check}` | `{check.status}` | {check.message or '-'} | {len(check.files)} |"
        )
    failed = [check for check in report.checks if check.status == "failed"]
    if failed:
        lines += ["", "## Failed Checks", ""]
        for check in failed:
            lines.append(f"- `{check.adapter}` / `{check.check}`: {check.message}")
    lines.append("")
    return "\n".join(lines)


ADAPTER_SMOKE_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "agent-adapter-smoke-report.schema.json": AdapterSmokeReport,
}
