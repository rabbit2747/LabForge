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
from .verified_mvp import live_execution_summary, verification_level_for
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
    verification_level: Literal["not-ready", "scaffold", "live"] = "not-ready"
    live_verified: bool = False
    live_execution: dict = Field(default_factory=dict)


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
    execute_tunnels: bool = False,
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
            execute_tunnels=execute_tunnels,
        )
    )

    status: Literal["passed", "failed"] = "failed" if any(check.status != "passed" for check in checks) else "passed"
    release_ready = status == "passed"
    live_metadata = release_gate_live_metadata(checks, release_ready=release_ready)
    report = ReleaseGateReport(
        lab_id=spec.lab_id,
        provider=provider,
        profile=profile,
        status=status,
        checks=checks,
        output_dir=str(out.resolve()),
        release_ready=release_ready,
        verification_level=live_metadata["verification_level"],
        live_verified=live_metadata["live_verified"],
        live_execution=live_metadata["live_execution"],
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


def release_gate_live_metadata(checks: list[QaCheck], *, release_ready: bool) -> dict:
    live_execution = live_execution_summary(
        {
            "release_ready": release_ready,
            "checks": [check.model_dump() for check in checks],
        }
    )
    verification_level = verification_level_for({"release_ready": release_ready}, live_execution)
    return {
        "verification_level": verification_level,
        "live_verified": verification_level == "live",
        "live_execution": live_execution,
    }


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
        out / "human-readiness.md",
        out / "human-readiness.yaml",
        out / "human-readiness.json",
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
    access_evidence_messages = learner_access_plugin_evidence_messages(out)
    if access_evidence_messages:
        messages.extend(access_evidence_messages)
    stage_handoff_messages = learner_access_stage_handoff_messages(out)
    if stage_handoff_messages:
        messages.extend(stage_handoff_messages)
    human_messages = human_readiness_gap_messages(out)
    if human_messages:
        messages.extend(human_messages)
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
            f"plugin_evidence_checks={plugin_evidence_check_count(out)}",
            f"stage_handoffs={stage_handoff_count(out)}",
            f"human_readiness_checks={human_readiness_check_count(out)}",
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


def learner_access_plugin_evidence_messages(out: Path) -> list[str]:
    messages: list[str] = []
    solver_plan_path = out / "solver-plan.json"
    access_manifest_path = out / "learner-access.json"
    access_playtest_path = out / "access-playtest" / "access-playtest.yaml"
    if not solver_plan_path.exists() or not access_manifest_path.exists() or not access_playtest_path.exists():
        return messages
    solver_plan = load_yaml(solver_plan_path)
    access_manifest = load_yaml(access_manifest_path)
    access_playtest = load_yaml(access_playtest_path)
    vulnerability_steps = [
        step
        for step in solver_plan.get("steps", [])
        if isinstance(step, dict) and str(step.get("action_type", "")) == "vulnerability-behavior"
    ]
    if not vulnerability_steps:
        return messages
    plugin_checks = [item for item in access_manifest.get("plugin_checks", []) if isinstance(item, dict)]
    if not plugin_checks:
        return ["critical=plugin-evidence:learner access manifest has vulnerability steps but no plugin_checks"]
    check_keys = {
        (str(item.get("service", "")), str(item.get("plugin", "")))
        for item in plugin_checks
    }
    for step in vulnerability_steps:
        key = (str(step.get("service", "")), str(step.get("plugin", "")))
        if key not in check_keys:
            messages.append(f"critical=plugin-evidence:missing access plugin_check for {key[0]}:{key[1]}")
    for item in plugin_checks:
        service = str(item.get("service", "-"))
        plugin = str(item.get("plugin", "-"))
        expected = item.get("expected_evidence", [])
        if not isinstance(expected, list) or not expected:
            messages.append(f"critical=plugin-evidence:{service}:{plugin}:missing expected_evidence")
        if not str(item.get("state_verification", "")).strip():
            messages.append(f"critical=plugin-evidence:{service}:{plugin}:missing state_verification")
    access_items = [item for item in access_playtest.get("items", []) if isinstance(item, dict)]
    plugin_items = [item for item in access_items if str(item.get("kind", "")) == "plugin-evidence"]
    if len(plugin_items) < len(plugin_checks):
        messages.append(
            f"critical=plugin-evidence:access-playtest planned {len(plugin_items)} plugin-evidence checks for {len(plugin_checks)} plugin_checks"
        )
    return messages


def plugin_evidence_check_count(out: Path) -> int:
    access_manifest_path = out / "learner-access.json"
    if not access_manifest_path.exists():
        return 0
    access_manifest = load_yaml(access_manifest_path)
    checks = access_manifest.get("plugin_checks", [])
    return len(checks) if isinstance(checks, list) else 0


def learner_access_stage_handoff_messages(out: Path) -> list[str]:
    solver_plan_path = out / "solver-plan.json"
    access_bundle_path = out / "lab-access-bundle.json"
    if not solver_plan_path.exists() or not access_bundle_path.exists():
        return []
    solver_plan = load_yaml(solver_plan_path)
    access_bundle = load_yaml(access_bundle_path)
    stage_steps = [
        step
        for step in solver_plan.get("steps", [])
        if isinstance(step, dict) and str(step.get("action_type", "")) in {"stage-chain", "implementation-coverage"}
    ]
    if not stage_steps:
        return []
    handoffs = [item for item in access_bundle.get("stage_handoffs", []) if isinstance(item, dict)]
    if not handoffs:
        return ["critical=stage-handoff:access bundle has stage-chain solver steps but no stage_handoffs"]
    missing_evidence = [
        f"{item.get('from_stage', '-')}->{item.get('to_stage', '-')}"
        for item in handoffs
        if not item.get("carried_evidence")
    ]
    if missing_evidence:
        return [f"critical=stage-handoff:handoffs missing carried_evidence: {', '.join(missing_evidence[:10])}"]
    clue_messages: list[str] = []
    for item in handoffs:
        clue_messages.extend(stage_handoff_clue_messages(item))
    coverage_messages = stage_handoff_solver_coverage_messages(solver_plan, access_bundle)
    runtime_messages = stage_handoff_runtime_check_messages(access_bundle)
    return [*clue_messages, *coverage_messages, *runtime_messages]


def stage_handoff_runtime_check_messages(access_bundle: dict) -> list[str]:
    handoffs = [item for item in access_bundle.get("stage_handoffs", []) if isinstance(item, dict)]
    checks = [item for item in access_bundle.get("stage_chain_checks", []) if isinstance(item, dict)]
    if not handoffs:
        return []
    if not checks:
        return ["critical=stage-handoff:no stage_chain_checks verify handoff runtime context"]
    messages: list[str] = []
    check_keys = {
        (
            str(check.get("from_stage", "")),
            str(check.get("to_stage") or check.get("expected_stage", "")),
            str(check.get("service", "")),
        ): check
        for check in checks
    }
    for handoff in handoffs:
        from_stage = str(handoff.get("from_stage", ""))
        to_stage = str(handoff.get("to_stage", ""))
        to_services = [str(item) for item in handoff.get("to_services", []) or [] if str(item).strip()]
        from_services = [str(item) for item in handoff.get("from_services", []) or [] if str(item).strip()]
        acceptable_services = list(dict.fromkeys(to_services + from_services))
        if not acceptable_services:
            continue
        matching = [check_keys.get((from_stage, to_stage, service)) for service in acceptable_services]
        matching = [item for item in matching if isinstance(item, dict)]
        if not matching:
            matching = [
                check
                for check in checks
                if str(check.get("from_stage", "")) == from_stage
                and str(check.get("to_stage") or check.get("expected_stage", "")) == to_stage
                and str(check.get("check_scope", "")) == "chain-observer"
            ]
        if not matching:
            messages.append(
                f"critical=stage-handoff:{from_stage}->{to_stage}:no runtime stage_chain_check for source or target service"
            )
            continue
        for check in matching:
            missing_fields = [
                field
                for field in ("chain_url", "stage_url", "expected_stage", "expected_from_stage")
                if not str(check.get(field, "")).strip()
            ]
            if missing_fields:
                messages.append(
                    f"critical=stage-handoff:{from_stage}->{to_stage}:runtime check missing {', '.join(missing_fields)}"
                )
            expected = [str(item) for item in check.get("expected_evidence", []) or [] if str(item).strip()]
            carried = [str(item) for item in handoff.get("carried_evidence", []) or [] if str(item).strip()]
            missing_evidence = [item for item in carried if item not in expected]
            if missing_evidence:
                messages.append(
                    f"critical=stage-handoff:{from_stage}->{to_stage}:runtime check missing carried evidence {', '.join(missing_evidence[:10])}"
                )
    return messages


def stage_handoff_solver_coverage_messages(solver_plan: dict, access_bundle: dict) -> list[str]:
    handoffs = [item for item in access_bundle.get("stage_handoffs", []) if isinstance(item, dict)]
    expected = sorted(
        {
            str(evidence).strip()
            for handoff in handoffs
            for evidence in handoff.get("carried_evidence", []) or []
            if str(evidence).strip()
        }
    )
    if not expected:
        return []
    covered = solver_plan_evidence_tokens(solver_plan)
    covered.update(access_bundle_plugin_evidence_tokens(access_bundle))
    missing = [evidence for evidence in expected if evidence not in covered]
    if not missing:
        return []
    return [
        "critical=stage-handoff:solver plan does not verify carried evidence: "
        + ", ".join(missing[:10])
    ]


def solver_plan_evidence_tokens(solver_plan: dict) -> set[str]:
    tokens: set[str] = set()
    for step in solver_plan.get("steps", []) or []:
        if not isinstance(step, dict):
            continue
        for field in ("evidence", "expected_texts", "discovery_cues"):
            values = step.get(field, [])
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                tokens.update(str(item).strip() for item in values if str(item).strip())
        for field in ("learner_action", "expected_result", "next_step_condition", "automation_hint"):
            text = str(step.get(field, "")).strip()
            if text:
                tokens.update(extract_evidence_tokens_from_text(text))
    return tokens


def access_bundle_plugin_evidence_tokens(access_bundle: dict) -> set[str]:
    tokens: set[str] = set()
    for check in access_bundle.get("plugin_checks", []) or []:
        if not isinstance(check, dict):
            continue
        expected = check.get("expected_evidence", [])
        if isinstance(expected, str):
            expected = [expected]
        if isinstance(expected, list):
            tokens.update(str(item).strip() for item in expected if str(item).strip())
    return tokens


def extract_evidence_tokens_from_text(text: str) -> set[str]:
    tokens: set[str] = set()
    current: list[str] = []
    for ch in text:
        if ch.isalnum() or ch in {"_", "-", "."}:
            current.append(ch)
        else:
            if current:
                token = "".join(current).strip()
                if looks_like_evidence_token(token):
                    tokens.add(token)
                current = []
    if current:
        token = "".join(current).strip()
        if looks_like_evidence_token(token):
            tokens.add(token)
    return tokens


def looks_like_evidence_token(value: str) -> bool:
    if len(value) < 3:
        return False
    return "_" in value or "-" in value or "." in value


def stage_handoff_clue_messages(handoff: dict) -> list[str]:
    from_stage = str(handoff.get("from_stage", "-"))
    to_stage = str(handoff.get("to_stage", "-"))
    clue = " ".join(str(handoff.get("learner_clue", "")).split())
    normalized = clue.lower()
    if not clue:
        return [f"critical=stage-handoff:{from_stage}->{to_stage}:missing learner_clue"]
    direct_answer_terms = (
        "flag",
        "ctf",
        "answer key",
        "copy paste",
        "copy/paste",
        "simulated for the lab",
        "intentionally simulated",
        "training lab",
        "정답",
        "플래그",
    )
    if any(term in normalized for term in direct_answer_terms):
        return [f"critical=stage-handoff:{from_stage}->{to_stage}:learner_clue contains answer-key wording"]
    if normalized.startswith("review normal business behavior related to"):
        return [f"critical=stage-handoff:{from_stage}->{to_stage}:learner_clue is generic fallback text"]
    if len(clue) < 24:
        return [f"critical=stage-handoff:{from_stage}->{to_stage}:learner_clue is too thin"]
    anchors = [
        *[str(item) for item in handoff.get("carried_evidence", []) or []],
        str(handoff.get("from_title", "")),
        str(handoff.get("to_title", "")),
        *[str(item) for item in handoff.get("from_services", []) or []],
        *[str(item) for item in handoff.get("to_services", []) or []],
    ]
    if not clue_references_handoff_anchor(clue, anchors):
        return [f"critical=stage-handoff:{from_stage}->{to_stage}:learner_clue does not reference carried evidence or stage context"]
    return []


def clue_references_handoff_anchor(clue: str, anchors: list[str]) -> bool:
    clue_text = normalize_anchor_text(clue)
    if not clue_text:
        return False
    for anchor in anchors:
        anchor_text = normalize_anchor_text(anchor)
        if not anchor_text:
            continue
        if anchor_text in clue_text:
            return True
        parts = [
            part
            for part in anchor_text.split()
            if len(part) >= 4 and part not in GENERIC_ANCHOR_WORDS
        ]
        if parts and any(part in clue_text for part in parts):
            return True
    return False


GENERIC_ANCHOR_WORDS = {
    "review",
    "normal",
    "business",
    "stage",
    "step",
    "next",
    "internal",
    "external",
    "public",
    "private",
    "console",
    "service",
    "system",
    "workflow",
    "operation",
    "operations",
    "material",
    "notes",
    "context",
}


def normalize_anchor_text(value: str) -> str:
    chars = [ch.lower() if ch.isalnum() else " " for ch in str(value)]
    return " ".join("".join(chars).split())


def stage_handoff_count(out: Path) -> int:
    access_bundle_path = out / "lab-access-bundle.json"
    if not access_bundle_path.exists():
        return 0
    access_bundle = load_yaml(access_bundle_path)
    handoffs = access_bundle.get("stage_handoffs", [])
    return len(handoffs) if isinstance(handoffs, list) else 0


def human_readiness_gap_messages(out: Path) -> list[str]:
    report_path = out / "human-readiness.json"
    if not report_path.exists():
        return ["critical=human-readiness:missing human-readiness.json"]
    report = load_yaml(report_path)
    messages: list[str] = []
    status = str(report.get("status", ""))
    if status in {"failed", "warning"}:
        messages.append(f"critical=human-readiness:status={status}")
    elif not status:
        messages.append("critical=human-readiness:status=missing")
    checks = [item for item in report.get("checks", []) if isinstance(item, dict)]
    if not checks:
        messages.append("critical=human-readiness:no checks")
        return messages
    for item in checks:
        if str(item.get("status", "")) != "failed":
            continue
        check_id = str(item.get("check_id", "-"))
        step_id = str(item.get("step_id", "-"))
        for message in item.get("messages", [])[:5]:
            messages.append(f"critical=human-readiness:{check_id}:{step_id}:{message}")
    return messages


def human_readiness_check_count(out: Path) -> int:
    report_path = out / "human-readiness.json"
    if not report_path.exists():
        return 0
    report = load_yaml(report_path)
    checks = report.get("checks", [])
    return len(checks) if isinstance(checks, list) else 0


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
    execute_tunnels: bool = False,
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
            execute_tunnels=execute_tunnels,
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
                f"execute_tunnels={str(execute_tunnels).lower()}",
                f"live_readiness={((getattr(report, 'execution_proof', {}) or {}).get('live_readiness') or {}).get('status', 'missing') if isinstance(getattr(report, 'execution_proof', {}), dict) else 'missing'}",
                f"report={out / 'e2e-solver.md'}",
            ],
        )
    proof = getattr(report, "execution_proof", {}) if isinstance(getattr(report, "execution_proof", {}), dict) else {}
    live = proof.get("live_readiness") or {}
    access_counts = proof.get("access") or {}
    solver_counts = proof.get("solver") or {}
    live_requirement_messages = [
        f"live_requirement={item.get('name', '-')}:required={item.get('required', 0)}:passed={item.get('passed', 0)}:status={item.get('status', '-')}"
        for item in live.get("requirement_checks", []) or []
        if isinstance(item, dict)
    ]
    return QaCheck(
        name="e2e-solver-evidence",
        status="passed",
        messages=[
            f"status={report.status}",
            f"mode={report.mode}",
            f"execute={str(execute).lower()}",
            f"cleanup={str(cleanup).lower()}",
            f"browser_engine={browser_engine}",
            f"execute_tunnels={str(execute_tunnels).lower()}",
            f"preflight_ready={str(report.preflight_ready).lower()}",
            f"lifecycle_steps={len(report.lifecycle)}",
            f"access_status={report.access_playtest.status if report.access_playtest else 'missing'}",
            f"solver_status={report.solver_run.status if report.solver_run else 'missing'}",
            f"live_readiness={live.get('status', 'missing')}",
            f"executed_access_passed={access_counts.get('passed', 0)}",
            f"executed_solver_passed={solver_counts.get('passed', 0)}",
            *live_requirement_messages,
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
    live_requirements = report.live_execution.get("requirements", []) if isinstance(report.live_execution, dict) else []
    lines = [
        f"# Release Gate Report - {report.lab_id}",
        "",
        f"- Provider: `{report.provider}`",
        f"- Profile: `{report.profile}`",
        f"- Status: `{report.status}`",
        f"- Release ready: `{str(report.release_ready).lower()}`",
        f"- Verification level: `{report.verification_level}`",
        f"- Live verified: `{str(report.live_verified).lower()}`",
        f"- Output directory: `{report.output_dir}`",
        "",
        "## Live Execution",
        "",
        f"- Status: `{report.live_execution.get('status', 'unknown')}`",
        f"- Mode: `{report.live_execution.get('mode', 'unknown')}`",
        f"- Execute enabled: `{str(report.live_execution.get('execute', False)).lower()}`",
        f"- Browser engine: `{report.live_execution.get('browser_engine') or '-'}`",
        f"- Tunnel execution: `{str(report.live_execution.get('execute_tunnels', False)).lower()}`",
        f"- Live readiness: `{report.live_execution.get('live_readiness', 'unknown')}`",
        f"- Access checks passed: `{report.live_execution.get('executed_access_passed', 0)}`",
        f"- Solver checks passed: `{report.live_execution.get('executed_solver_passed', 0)}`",
        "",
        "| Requirement | Required | Passed | Status |",
        "|---|---:|---:|---|",
    ]
    if live_requirements:
        for item in live_requirements:
            lines.append(
                f"| `{item.get('name', '-')}` | `{item.get('required', 0)}` | "
                f"`{item.get('passed', 0)}` | {item.get('status', '-')} |"
            )
    else:
        lines.append("| `-` | `0` | `0` | not-recorded |")
    lines.extend(
        [
            "",
            "| Check | Status | Messages |",
            "|---|---|---|",
        ]
    )
    for check in report.checks:
        messages = "<br>".join(check.messages) if check.messages else "-"
        lines.append(f"| `{check.name}` | {check.status} | {messages} |")
    lines.append("")
    return "\n".join(lines)


QA_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "qa-smoke-report.schema.json": QaSmokeReport,
    "release-gate-report.schema.json": ReleaseGateReport,
}
