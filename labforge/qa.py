from __future__ import annotations

import shutil
from pathlib import Path
from typing import Literal
import json

from pydantic import BaseModel, ConfigDict, Field

from .access_playtest import BrowserProbeEngine
from .agent_orchestration import AgentResultSpec
from .e2e_solver import run_e2e_solver
from .io import dump_yaml, write_text
from .io import load_yaml
from .linting import lint_lab
from .model import LabSpec
from .plugin_runtime_smoke import run_plugin_runtime_smoke
from .playtest import run_playtest
from .render import build_lab
from .service_artifacts import materialize_service_runtimes, service_check
from .service_verification import verify_services
from .validate import validate_lab
from .vulnerability_coverage import (
    build_vulnerability_coverage_report,
    vulnerability_coverage_to_json,
    vulnerability_coverage_to_markdown,
)


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

    runtime_smoke = run_plugin_runtime_smoke(spec, out / "plugin-runtime-smoke")
    checks.append(
        QaCheck(
            name="plugin-runtime-smoke",
            status=runtime_smoke.status,
            messages=[
                f"{item.service}:{item.plugin}:{item.status}:{item.message or item.endpoint or 'ok'}"
                for item in runtime_smoke.items
                if item.status != "passed"
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
    checks.append(learner_experience_check(spec, provider_out, strict=False))

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
    execute_e2e: bool = False,
    cleanup_e2e: bool = False,
    e2e_timeout_seconds: int = 60,
    browser_engine: BrowserProbeEngine = "http",
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

    runtime_smoke = run_plugin_runtime_smoke(spec, out / "plugin-runtime-smoke")
    checks.append(
        QaCheck(
            name="plugin-runtime-smoke-strict",
            status="passed" if runtime_smoke.status == "passed" else "failed",
            messages=[
                f"{item.service}:{item.plugin}:{item.status}:{item.message or item.endpoint or 'ok'}"
                for item in runtime_smoke.items
                if item.status != "passed"
            ],
        )
    )

    checks.append(vulnerability_coverage_release_check(out / "vulnerability-coverage"))

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
    checks.append(learner_experience_check(spec, provider_out, strict=True))
    learner_playtest_out = out / "learner-playtest"
    checks.append(learner_playtest_release_check(working_lab, learner_playtest_out, provider=provider, profile=profile))
    checks.append(
        e2e_solver_release_check(
            provider_out,
            learner_playtest_out,
            out / "e2e-solver",
            provider=provider,
            execute=execute_e2e,
            cleanup=cleanup_e2e,
            timeout_seconds=e2e_timeout_seconds,
            browser_engine=browser_engine,
        )
    )

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


def vulnerability_coverage_release_check(out: Path) -> QaCheck:
    report = build_vulnerability_coverage_report()
    write_text(out / "vulnerability-coverage.json", vulnerability_coverage_to_json(report))
    write_text(out / "vulnerability-coverage.md", vulnerability_coverage_to_markdown(report))
    failed_or_warning = [item for item in report.items if item.status != "passed"]
    messages = [
        f"status={report.status}",
        f"total_plugins={report.total_plugins}",
        f"runnable_plugins={report.runnable_plugins}",
        f"complete_plugins={report.complete_plugins}",
        f"report={out / 'vulnerability-coverage.md'}",
    ]
    for item in failed_or_warning[:10]:
        messages.append(f"{item.plugin_id}:{item.status}:{'; '.join(item.gaps) or 'coverage incomplete'}")
    return QaCheck(
        name="vulnerability-coverage-strict",
        status="passed" if report.status == "passed" else "failed",
        messages=messages,
    )


def learner_playtest_release_check(lab_root: Path, out: Path, *, provider: str, profile: str) -> QaCheck:
    messages: list[str] = []
    try:
        report = run_playtest(lab_root, out, provider=provider, profile=profile, materialize=False, force=True)
    except Exception as exc:  # noqa: BLE001 - release gate should preserve playtest failures.
        return QaCheck(
            name="learner-playtest-evidence",
            status="failed",
            messages=[f"Could not generate learner playtest evidence: {exc}"],
        )
    required_files = [
        out / "learner-access.json",
        out / "learner-access.md",
        out / "access-playtest" / "access-playtest.yaml",
        out / "solver-plan.json",
        out / "solver-run" / "solver-run.yaml",
        out / "playtest-walkthrough.md",
        out / "lab-access-bundle.md",
        out / "lab-access-bundle.json",
        out / "playtest-report.yaml",
    ]
    missing = [str(path) for path in required_files if not path.exists()]
    if missing:
        messages.extend(f"missing={path}" for path in missing)
    if not report.learner_entrypoints:
        messages.append("No learner entrypoint in playtest report.")
    if not report.steps:
        messages.append("No playtest steps generated.")
    if report.failures:
        messages.extend(f"failure={item}" for item in report.failures[:10])
    critical_gap_messages = critical_playtest_gap_messages(report)
    if critical_gap_messages:
        messages.extend(critical_gap_messages)
    if messages:
        return QaCheck(name="learner-playtest-evidence", status="failed", messages=messages)
    advisory = [f"advisory={item}" for item in report.warnings[:5]]
    return QaCheck(
        name="learner-playtest-evidence",
        status="passed",
        messages=[
            f"status={report.status}",
            f"learner_entrypoints={len(report.learner_entrypoints)}",
            f"attacker_entrypoints={len(report.attacker_entrypoints)}",
            f"final_submission_endpoints={len(report.final_submission_endpoints)}",
            f"steps={len(report.steps)}",
            f"report={out / 'playtest-report.yaml'}",
            f"access_bundle={out / 'lab-access-bundle.json'}",
            *advisory,
        ],
    )


def critical_playtest_gap_messages(report) -> list[str]:
    critical_ids = {
        "implementation-01": "stage implementation coverage",
    }
    messages: list[str] = []
    for step in report.steps:
        label = critical_ids.get(step.step_id)
        if not label or step.status == "passed":
            continue
        messages.append(f"critical={step.step_id}:{label}:{step.status}")
        messages.extend(f"critical_detail={item}" for item in step.evidence[:10])
    return messages


def e2e_solver_release_check(
    provider_out: Path,
    learner_playtest_out: Path,
    out: Path,
    *,
    provider: str,
    execute: bool = False,
    cleanup: bool = False,
    timeout_seconds: int = 60,
    browser_engine: BrowserProbeEngine = "http",
) -> QaCheck:
    solver_plan = learner_playtest_out / "solver-plan.json"
    access_manifest = learner_playtest_out / "learner-access.json"
    required = [provider_out / "endpoints.json", solver_plan, access_manifest]
    if provider == "docker-compose":
        required.append(provider_out / "docker-compose.yml")
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        return QaCheck(
            name="e2e-solver-evidence",
            status="failed",
            messages=[f"missing={path}" for path in missing],
        )
    try:
        report = run_e2e_solver(
            provider_out,
            solver_plan,
            access_manifest,
            out,
            provider=provider,
            execute=execute,
            cleanup=cleanup,
            timeout_seconds=timeout_seconds,
            browser_engine=browser_engine,
        )
    except Exception as exc:  # noqa: BLE001 - release gate should preserve E2E planning failures.
        return QaCheck(
            name="e2e-solver-evidence",
            status="failed",
            messages=[f"Could not create E2E solver evidence: {exc}"],
        )
    required_files = [
        out / "e2e-solver.md",
        out / "e2e-solver.yaml",
        out / "e2e-solver.json",
        out / "host-preflight.md",
        out / "host-preflight.json",
        out / "access-playtest" / "access-playtest.yaml",
        out / "solver-run" / "solver-run.yaml",
    ]
    missing_outputs = [str(path) for path in required_files if not path.exists()]
    if missing_outputs:
        return QaCheck(
            name="e2e-solver-evidence",
            status="failed",
            messages=[f"missing_output={path}" for path in missing_outputs],
        )
    acceptable_statuses = {"passed"} if execute else {"planned", "passed", "warning"}
    if report.status not in acceptable_statuses:
        return QaCheck(
            name="e2e-solver-evidence",
            status="failed",
            messages=[
                f"status={report.status}",
                f"mode={report.mode}",
                f"execute={str(execute).lower()}",
                f"browser_engine={browser_engine}",
                f"report={out / 'e2e-solver.md'}",
            ],
        )
    return QaCheck(
        name="e2e-solver-evidence",
        status="passed",
        messages=[
            f"status={report.status}",
            f"mode={report.mode}",
            f"execute={str(execute).lower()}",
            f"cleanup={str(cleanup).lower()}",
            f"browser_engine={browser_engine}",
            f"preflight_ready={str(report.preflight_ready).lower()}",
            f"lifecycle_steps={len(report.lifecycle)}",
            f"access_status={report.access_playtest.status if report.access_playtest else 'missing'}",
            f"solver_status={report.solver_run.status if report.solver_run else 'missing'}",
            f"report={out / 'e2e-solver.md'}",
        ],
    )


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


def learner_experience_check(spec: LabSpec, provider_out: Path, *, strict: bool) -> QaCheck:
    messages: list[str] = []
    learner_entrypoint = str(spec.scenario.get("learner_entrypoint", "")).strip()
    if not learner_entrypoint:
        messages.append("scenario.learner_entrypoint is missing or empty.")

    endpoint_manifest = provider_out / "endpoints.json"
    published: list[dict] = []
    if endpoint_manifest.exists():
        try:
            data = json.loads(endpoint_manifest.read_text(encoding="utf-8"))
            value = data.get("published_endpoints", [])
            if isinstance(value, list):
                published = [item for item in value if isinstance(item, dict)]
        except Exception as exc:  # noqa: BLE001 - QA should preserve malformed endpoint manifests.
            messages.append(f"Could not parse endpoint manifest {endpoint_manifest}: {exc}")
    else:
        messages.append(f"Provider output did not include endpoint manifest: {endpoint_manifest}")

    learner_visible = [
        item for item in published
        if item.get("url") or item.get("connect")
    ]
    if not learner_visible:
        messages.append("No learner-visible URL or SSH connect command is published.")
    if not any(str(item.get("role", "")).lower().startswith("learner") or "attacker" in str(item.get("service", "")).lower() for item in published):
        messages.append("No learner attacker/workstation endpoint is published.")
    if not any("drop" in str(item.get("service", "")).lower() for item in published):
        messages.append("No controlled drop or final submission endpoint is published.")

    http_without_health = [
        str(item.get("service", "unknown"))
        for item in published
        if item.get("protocol") == "http" and not item.get("health_url")
    ]
    if http_without_health:
        messages.append(f"HTTP learner endpoints without health_url: {', '.join(http_without_health)}")

    status: Literal["passed", "warning", "failed"]
    if not messages:
        status = "passed"
        messages = [
            f"learner_entrypoint={learner_entrypoint}",
            f"published_entrypoints={len(learner_visible)}",
        ]
    else:
        status = "failed" if strict else "warning"
    return QaCheck(
        name="learner-experience-strict" if strict else "learner-experience",
        status=status,
        messages=messages,
    )


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
