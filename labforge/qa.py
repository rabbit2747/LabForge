from __future__ import annotations

import shutil
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, write_text
from .linting import lint_lab
from .model import LabSpec
from .render import build_lab
from .service_artifacts import materialize_service_runtimes, service_check
from .validate import validate_lab


class QaModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class QaCheck(QaModel):
    name: str
    status: Literal["passed", "warning", "failed"]
    messages: list[str] = Field(default_factory=list)


class QaSmokeReport(QaModel):
    lab_id: str
    provider: str
    profile: str
    status: Literal["passed", "warning", "failed"]
    checks: list[QaCheck] = Field(default_factory=list)
    output_dir: str


def run_qa_smoke(
    lab_root: Path,
    out: Path,
    *,
    provider: str,
    profile: str,
    materialize: bool = False,
    force: bool = False,
) -> QaSmokeReport:
    working_lab = lab_root.resolve()
    if materialize:
        working_lab = out / "materialized-source"
        if working_lab.exists() and force:
            shutil.rmtree(working_lab)
        if not working_lab.exists():
            shutil.copytree(lab_root, working_lab, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        spec_for_materialize = LabSpec.load(working_lab)
        materialize_service_runtimes(spec_for_materialize, force=force)

    checks: list[QaCheck] = []
    validation_errors = validate_lab(working_lab)
    checks.append(
        QaCheck(
            name="schema-validation",
            status="failed" if validation_errors else "passed",
            messages=validation_errors,
        )
    )

    lint_report = lint_lab(working_lab)
    checks.append(
        QaCheck(
            name="quality-lint",
            status="passed" if lint_report.status == "passed" else "warning",
            messages=[
                f"{finding.location}: {finding.message}"
                for finding in lint_report.findings
            ],
        )
    )

    spec = LabSpec.load(working_lab)
    service_result = service_check(spec)
    service_status: Literal["passed", "warning", "failed"]
    if service_result.errors:
        service_status = "failed"
    elif service_result.warnings:
        service_status = "warning"
    else:
        service_status = "passed"
    checks.append(
        QaCheck(
            name="service-artifacts",
            status=service_status,
            messages=[*service_result.errors, *service_result.warnings],
        )
    )

    provider_out = out / "provider-output"
    provider_messages: list[str] = []
    provider_status: Literal["passed", "warning", "failed"] = "passed"
    try:
        build_lab(spec, provider_out, provider_name=provider, profile=profile)
    except Exception as exc:  # noqa: BLE001 - QA report should capture provider failures.
        provider_status = "failed"
        provider_messages.append(str(exc))
    checks.append(QaCheck(name="provider-build", status=provider_status, messages=provider_messages))

    overall = aggregate_status(checks)
    report = QaSmokeReport(
        lab_id=spec.lab_id,
        provider=provider,
        profile=profile,
        status=overall,
        checks=checks,
        output_dir=str(out.resolve()),
    )
    write_text(out / "qa-smoke-report.yaml", dump_yaml(report.model_dump()))
    write_text(out / "qa-smoke-report.md", render_qa_smoke_markdown(report))
    return report


def aggregate_status(checks: list[QaCheck]) -> Literal["passed", "warning", "failed"]:
    if any(check.status == "failed" for check in checks):
        return "failed"
    if any(check.status == "warning" for check in checks):
        return "warning"
    return "passed"


def render_qa_smoke_markdown(report: QaSmokeReport) -> str:
    lines = [
        f"# QA Smoke Report - {report.lab_id}",
        "",
        f"- Provider: `{report.provider}`",
        f"- Profile: `{report.profile}`",
        f"- Status: `{report.status}`",
        f"- Output directory: `{report.output_dir}`",
        "",
        "| Check | Status | Messages |",
        "|---|---|---|",
    ]
    for check in report.checks:
        messages = "<br>".join(check.messages) if check.messages else "-"
        lines.append(f"| `{check.name}` | {check.status} | {messages} |")
    lines.append("")
    return "\n".join(lines)


QA_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "qa-smoke-report.schema.json": QaSmokeReport,
}
