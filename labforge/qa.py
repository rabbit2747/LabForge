from __future__ import annotations

import shutil
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .agent_orchestration import AgentResultSpec
from .io import dump_yaml, write_text
from .io import load_yaml
from .linting import lint_lab
from .model import LabSpec
from .render import build_lab
from .service_artifacts import materialize_service_runtimes, service_check
from .service_verification import verify_services
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


class ReleaseGateReport(QaModel):
    lab_id: str
    provider: str
    profile: str
    status: Literal["passed", "failed"]
    checks: list[QaCheck] = Field(default_factory=list)
    output_dir: str
    release_ready: bool = False


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

    service_verification = verify_services(spec)
    checks.append(
        QaCheck(
            name="service-verification",
            status="passed" if service_verification.status == "passed" else service_verification.status,
            messages=[
                f"{finding.service}:{finding.category}:{finding.path}: {finding.message}"
                for finding in service_verification.findings
            ],
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


def run_release_gate(
    lab_root: Path,
    out: Path,
    *,
    provider: str,
    profile: str,
    materialize: bool = False,
    force: bool = False,
    agent_result_dir: Path | None = None,
) -> ReleaseGateReport:
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

    spec = LabSpec.load(working_lab)
    lint_report = lint_lab(working_lab)
    checks.append(
        QaCheck(
            name="quality-lint-strict",
            status="passed" if lint_report.status == "passed" else "failed",
            messages=[f"{finding.location}: {finding.message}" for finding in lint_report.findings],
        )
    )

    service_verification = verify_services(spec)
    checks.append(
        QaCheck(
            name="service-verification-strict",
            status="passed" if service_verification.status == "passed" else "failed",
            messages=[
                f"{finding.service}:{finding.category}:{finding.path}: {finding.message}"
                for finding in service_verification.findings
            ],
        )
    )

    checks.append(industry_realism_release_check(agent_result_dir))

    provider_out = out / "provider-output"
    provider_messages: list[str] = []
    provider_status: Literal["passed", "warning", "failed"] = "passed"
    try:
        build_lab(spec, provider_out, provider_name=provider, profile=profile)
    except Exception as exc:  # noqa: BLE001 - release gate should preserve provider failures.
        provider_status = "failed"
        provider_messages.append(str(exc))
    checks.append(QaCheck(name="provider-build", status=provider_status, messages=provider_messages))

    status: Literal["passed", "failed"] = "failed" if any(check.status != "passed" for check in checks) else "passed"
    report = ReleaseGateReport(
        lab_id=spec.lab_id,
        provider=provider,
        profile=profile,
        status=status,
        checks=checks,
        output_dir=str(out.resolve()),
        release_ready=status == "passed",
    )
    write_text(out / "release-gate-report.yaml", dump_yaml(report.model_dump()))
    write_text(out / "release-gate-report.md", render_release_gate_markdown(report))
    return report


def industry_realism_release_check(agent_result_dir: Path | None) -> QaCheck:
    if not agent_result_dir:
        return QaCheck(
            name="industry-realism-review",
            status="failed",
            messages=[
                "Missing --agent-results. Release gate requires `industry-realism-reviewer` output, not only static realism check."
            ],
        )
    result_file = find_industry_realism_result(agent_result_dir)
    if not result_file:
        return QaCheck(
            name="industry-realism-review",
            status="failed",
            messages=[f"Missing 10-industry-realism-reviewer.result.yaml under {agent_result_dir}."],
        )
    result = AgentResultSpec.model_validate(load_yaml(result_file))
    verdicts = industry_realism_verdicts(result)
    messages = [
        f"result={result_file}",
        f"status={result.status}",
        f"verdicts={','.join(sorted(verdicts)) or 'none'}",
        f"open_questions={len(result.open_questions)}",
    ]
    if result.status != "complete":
        return QaCheck(name="industry-realism-review", status="failed", messages=[*messages, "Reviewer result is not complete."])
    if "fail" in verdicts:
        return QaCheck(name="industry-realism-review", status="failed", messages=[*messages, "Reviewer returned fail verdict."])
    if {"conditional-pass", "not-reviewable"} & verdicts:
        return QaCheck(
            name="industry-realism-review",
            status="failed",
            messages=[*messages, "Reviewer result is not a full pass."],
        )
    if result.open_questions:
        return QaCheck(
            name="industry-realism-review",
            status="failed",
            messages=[*messages, "Reviewer still has open questions."],
        )
    return QaCheck(name="industry-realism-review", status="passed", messages=messages)


def find_industry_realism_result(agent_result_dir: Path) -> Path | None:
    root = agent_result_dir.resolve()
    candidates = [
        root / "10-industry-realism-reviewer.result.yaml",
        root / ".ai" / "outputs" / "10-industry-realism-reviewer.result.yaml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    matches = sorted(root.glob("**/10-industry-realism-reviewer.result.yaml"))
    return matches[0] if matches else None


def industry_realism_verdicts(result: AgentResultSpec) -> set[str]:
    verdicts: set[str] = set()
    for finding in result.findings:
        if isinstance(finding, dict) and finding.get("verdict"):
            verdicts.add(str(finding["verdict"]).strip().lower())
    return verdicts


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


def render_release_gate_markdown(report: ReleaseGateReport) -> str:
    lines = [
        f"# Release Gate Report - {report.lab_id}",
        "",
        f"- Provider: `{report.provider}`",
        f"- Profile: `{report.profile}`",
        f"- Status: `{report.status}`",
        f"- Release ready: `{str(report.release_ready).lower()}`",
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
    "release-gate-report.schema.json": ReleaseGateReport,
}
