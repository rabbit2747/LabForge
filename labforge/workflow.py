from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .agent_orchestration import AgentResultSpec
from .io import load_yaml
from .linting import lint_lab
from .model import LabSpec
from .service_artifacts import declared_service_artifacts, review_service_results, service_check
from .service_verification import verify_services
from .validate import validate_lab


WorkflowStatus = Literal["done", "ready", "pending", "warning", "blocked"]


class WorkflowModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class WorkflowStep(WorkflowModel):
    id: str
    title: str
    status: WorkflowStatus
    purpose: str
    evidence: list[str] = Field(default_factory=list)
    next_commands: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class WorkflowReport(WorkflowModel):
    lab_id: str
    title: str
    status: Literal["ready", "in-progress", "blocked"]
    current_step: str = ""
    provider: str = "docker-compose"
    profile: str = "protected"
    result_dir: str | None = None
    agent_result_dir: str | None = None
    steps: list[WorkflowStep] = Field(default_factory=list)
    next_commands: list[str] = Field(default_factory=list)


def create_workflow_report(
    lab_root: Path,
    *,
    provider: str = "docker-compose",
    profile: str = "protected",
    result_dir: Path | None = None,
    agent_result_dir: Path | None = None,
    package_dir: Path | None = None,
) -> WorkflowReport:
    lab_root = lab_root.resolve()
    package_root = package_dir or Path("output") / f"{lab_root.name}-package"
    result_root = result_dir.resolve() if result_dir else None
    agent_result_root = agent_result_dir.resolve() if agent_result_dir else None

    try:
        spec = LabSpec.load(lab_root)
        lab_id = spec.lab_id
        title = spec.title
    except Exception as exc:  # noqa: BLE001 - workflow must report incomplete labs.
        step = WorkflowStep(
            id="lab-spec",
            title="Load Lab Specification",
            status="blocked",
            purpose="Confirm that the lab root contains the required LabForge YAML files.",
            evidence=[str(exc)],
            next_commands=[
                f"python -m labforge intake template --out {quote_path(Path('output') / f'{lab_root.name}-intake')} --lab-id {lab_root.name} --title \"{lab_root.name}\"",
                f"python -m labforge intake scaffold --from {quote_path(Path('output') / f'{lab_root.name}-intake' / 'scenario-intake.yaml')} --out {quote_path(lab_root)}",
            ],
        )
        return WorkflowReport(
            lab_id=lab_root.name,
            title=lab_root.name,
            status="blocked",
            current_step=step.id,
            provider=provider,
            profile=profile,
            result_dir=str(result_root) if result_root else None,
            agent_result_dir=str(agent_result_root) if agent_result_root else None,
            steps=[step],
            next_commands=step.next_commands,
        )

    steps = [
        lab_spec_step(spec, lab_root),
        architecture_step(spec, lab_root, provider, profile),
        service_contract_step(spec, lab_root),
        service_runtime_step(spec, lab_root),
        service_plan_step(lab_root),
        service_agent_step(lab_root, result_root),
        service_review_step(spec, result_root),
        service_apply_step(spec, result_root),
        service_verify_step(spec),
        industry_realism_review_step(lab_root, agent_result_root),
        provider_build_step(lab_root, provider, profile),
        release_gate_step(lab_root, provider, profile, agent_result_root),
        supervisor_package_step(lab_root, package_root, provider, profile),
    ]
    report_status: Literal["ready", "in-progress", "blocked"]
    if any(step.status == "blocked" for step in steps):
        report_status = "blocked"
    elif all(step.status == "done" for step in steps):
        report_status = "ready"
    else:
        report_status = "in-progress"
    current = current_workflow_step(steps, report_status)

    return WorkflowReport(
        lab_id=lab_id,
        title=title,
        status=report_status,
        current_step=current.id,
        provider=provider,
        profile=profile,
        result_dir=str(result_root) if result_root else None,
        agent_result_dir=str(agent_result_root) if agent_result_root else None,
        steps=steps,
        next_commands=current.next_commands,
    )


def current_workflow_step(steps: list[WorkflowStep], report_status: str) -> WorkflowStep:
    if report_status == "blocked":
        return next((step for step in steps if step.status == "blocked"), steps[-1])
    return next((step for step in steps if step.status in {"warning", "ready", "pending"}), steps[-1])


def lab_spec_step(spec: LabSpec, lab_root: Path) -> WorkflowStep:
    errors = validate_lab(lab_root)
    lint_report = lint_lab(lab_root)
    evidence = [f"validation_errors={len(errors)}", f"lint_findings={len(lint_report.findings)}"]
    if errors:
        return WorkflowStep(
            id="lab-spec",
            title="Validate Lab Specification",
            status="blocked",
            purpose="Schema and reference validation must pass before LabForge can generate infrastructure.",
            evidence=[*evidence, *errors],
            next_commands=[f"python -m labforge validate {quote_path(lab_root)}"],
        )
    if lint_report.status != "passed":
        return WorkflowStep(
            id="lab-spec",
            title="Validate Lab Specification",
            status="warning",
            purpose="The lab is structurally valid, but scenario quality warnings remain.",
            evidence=evidence,
            next_commands=[f"python -m labforge lint {quote_path(lab_root)}"],
            notes=[f"{finding.location}: {finding.message}" for finding in lint_report.findings[:5]],
        )
    return WorkflowStep(
        id="lab-spec",
        title="Validate Lab Specification",
        status="done",
        purpose="The lab YAML files are structurally valid and lint-clean.",
        evidence=evidence,
    )


def architecture_step(spec: LabSpec, lab_root: Path, provider: str, profile: str) -> WorkflowStep:
    return WorkflowStep(
        id="architecture",
        title="Render Architecture And Execution Plan",
        status="ready",
        purpose="Generate host-aware architecture, security profile, provider, and execution documentation.",
        evidence=[
            f"networks={len(spec.networks)}",
            f"services={len(spec.services)}",
            f"stages={len(spec.stage_list)}",
        ],
        next_commands=[
            f"python -m labforge doctor --lab {quote_path(lab_root)}",
            f"python -m labforge plan {quote_path(lab_root)} --provider {provider} --profile {profile} --out {quote_path(Path('output') / f'{lab_root.name}-plan')}",
            f"python -m labforge docs {quote_path(lab_root)} --profile {profile} --out {quote_path(Path('output') / f'{lab_root.name}-docs')}",
        ],
    )


def service_contract_step(spec: LabSpec, lab_root: Path) -> WorkflowStep:
    artifacts = list(declared_service_artifacts(spec))
    check = service_check(spec)
    if check.errors:
        return WorkflowStep(
            id="service-contracts",
            title="Validate Service Contracts",
            status="blocked",
            purpose="Every service must have a service artifact contract before service builders can work safely.",
            evidence=[f"service_artifacts={len(artifacts)}", *check.errors],
            next_commands=[f"python -m labforge services check {quote_path(lab_root)}"],
        )
    if check.warnings:
        return WorkflowStep(
            id="service-contracts",
            title="Validate Service Contracts",
            status="warning",
            purpose="Service contracts exist, but recommended folders or metadata are incomplete.",
            evidence=[f"service_artifacts={len(artifacts)}"],
            next_commands=[f"python -m labforge services scaffold {quote_path(lab_root)}"],
            notes=check.warnings[:5],
        )
    return WorkflowStep(
        id="service-contracts",
        title="Validate Service Contracts",
        status="done",
        purpose="Service artifact contracts and required directories are present.",
        evidence=[f"service_artifacts={len(artifacts)}"],
    )


def service_runtime_step(spec: LabSpec, lab_root: Path) -> WorkflowStep:
    missing: list[str] = []
    for artifact in declared_service_artifacts(spec):
        root = lab_root / artifact.source_path
        for filename in ("Dockerfile", "app.py"):
            if not (root / filename).exists():
                missing.append(f"{artifact.service}:{filename}")
    if missing:
        return WorkflowStep(
            id="service-runtime",
            title="Materialize Or Implement Service Runtimes",
            status="ready",
            purpose="Create runnable service source trees before provider build and QA.",
            evidence=[f"missing_runtime_files={len(missing)}"],
            next_commands=[f"python -m labforge services materialize {quote_path(lab_root)} --force"],
            notes=missing[:8],
        )
    return WorkflowStep(
        id="service-runtime",
        title="Materialize Or Implement Service Runtimes",
        status="done",
        purpose="Runtime files exist for declared service artifacts.",
        evidence=["missing_runtime_files=0"],
    )


def service_plan_step(lab_root: Path) -> WorkflowStep:
    out = Path("output") / f"{lab_root.name}-service-plan"
    status: WorkflowStatus = "done" if (out / "service-implementation-plan.md").exists() else "ready"
    return WorkflowStep(
        id="service-plan",
        title="Create Service Implementation Plan",
        status=status,
        purpose="Split the lab into per-service implementation tasks for humans or LLM agents.",
        evidence=[f"expected_output={out / 'service-implementation-plan.md'}"],
        next_commands=[f"python -m labforge services plan {quote_path(lab_root)} --out {quote_path(out)}"],
    )


def service_agent_step(lab_root: Path, result_root: Path | None) -> WorkflowStep:
    package_root = result_root.parent.parent if result_root and result_root.name == "outputs" else Path("output") / f"{lab_root.name}-service-agents"
    exists = result_root is not None and result_root.exists()
    return WorkflowStep(
        id="service-agent-packages",
        title="Create Service Builder Agent Packages",
        status="done" if exists else "ready",
        purpose="Create per-service packages and result contracts for implementation agents.",
        evidence=[f"result_dir={result_root}" if result_root else "result_dir=not-provided"],
        next_commands=[f"python -m labforge services agent-packages {quote_path(lab_root)} --out {quote_path(package_root)} --adapter manual"],
    )


def service_review_step(spec: LabSpec, result_root: Path | None) -> WorkflowStep:
    if not result_root:
        return WorkflowStep(
            id="service-result-review",
            title="Review Service Builder Results",
            status="pending",
            purpose="Review service-builder outputs before applying them to the lab source tree.",
            evidence=["result_dir=not-provided"],
            notes=["Pass --results <service-agent-output-dir> to workflow status after creating service-builder packages."],
        )
    report = review_service_results(spec, result_root, force=True)
    if report.status == "ready":
        status: WorkflowStatus = "done"
    elif report.status == "needs-review":
        status = "warning"
    else:
        status = "blocked"
    return WorkflowStep(
        id="service-result-review",
        title="Review Service Builder Results",
        status=status,
        purpose="Confirm service-builder outputs are complete, path-safe, and ready to apply.",
        evidence=[
            f"ready={report.ready_count}",
            f"needs_review={report.needs_review_count}",
            f"failed={report.failed_count}",
        ],
        next_commands=[f"python -m labforge services review-results {quote_path(spec.root)} --results {quote_path(result_root)} --force"],
        notes=[f"missing:{service}" for service in report.missing_service_results[:5]],
    )


def service_apply_step(spec: LabSpec, result_root: Path | None) -> WorkflowStep:
    if not result_root:
        return WorkflowStep(
            id="service-result-apply",
            title="Apply Service Builder Results",
            status="pending",
            purpose="Apply reviewed service-builder outputs into each declared service directory.",
            evidence=["result_dir=not-provided"],
        )
    report = review_service_results(spec, result_root, force=True)
    if report.status != "ready":
        return WorkflowStep(
            id="service-result-apply",
            title="Apply Service Builder Results",
            status="blocked",
            purpose="Apply reviewed service-builder outputs into each declared service directory.",
            evidence=[f"review_status={report.status}"],
            next_commands=[f"python -m labforge services review-results {quote_path(spec.root)} --results {quote_path(result_root)} --force"],
        )
    return WorkflowStep(
        id="service-result-apply",
        title="Apply Service Builder Results",
        status="ready",
        purpose="Apply reviewed service-builder outputs into each declared service directory.",
        evidence=[f"review_status={report.status}"],
        next_commands=[f"python -m labforge services apply-results {quote_path(spec.root)} --results {quote_path(result_root)} --execute --force"],
    )


def service_verify_step(spec: LabSpec) -> WorkflowStep:
    report = verify_services(spec)
    if report.status == "failed":
        status: WorkflowStatus = "blocked"
    elif report.status == "warning":
        status = "warning"
    else:
        status = "done"
    return WorkflowStep(
        id="service-verification",
        title="Verify Service Implementations",
        status=status,
        purpose="Check service realism, placeholders, vulnerability boundaries, and required files.",
        evidence=[f"status={report.status}", f"findings={len(report.findings)}"],
        next_commands=[f"python -m labforge services verify {quote_path(spec.root)} --strict"],
        notes=[f"{item.service}:{item.category}:{item.message}" for item in report.findings[:5]],
    )


def industry_realism_review_step(lab_root: Path, agent_result_root: Path | None) -> WorkflowStep:
    default_workspace = Path("output") / f"{lab_root.name}-agents"
    if not agent_result_root:
        return WorkflowStep(
            id="industry-realism-review",
            title="Review Industry Realism",
            status="ready",
            purpose="Run the independent industry realism reviewer before a lab is treated as release-ready.",
            evidence=["agent_result_dir=not-provided"],
            next_commands=[
                f"python -m labforge agents scaffold {quote_path(lab_root)} --out {quote_path(default_workspace)}",
                f"python -m labforge agents run {quote_path(default_workspace)} --dry-run --adapter manual --agent industry-realism-reviewer --context-root {quote_path(lab_root)}",
            ],
            notes=[
                "Static `realism check` is a pre-check only. The industry realism reviewer must inspect infrastructure, services, UI, workflows, data, security controls, and operational noise."
            ],
        )

    result_file = find_industry_realism_result(agent_result_root)
    if not result_file:
        workspace = agent_workspace_from_results(agent_result_root)
        return WorkflowStep(
            id="industry-realism-review",
            title="Review Industry Realism",
            status="blocked",
            purpose="Run the independent industry realism reviewer before a lab is treated as release-ready.",
            evidence=[f"agent_result_dir={agent_result_root}", "result=missing"],
            next_commands=[
                f"python -m labforge agents run {quote_path(workspace)} --dry-run --adapter manual --agent industry-realism-reviewer --context-root {quote_path(lab_root)}",
            ],
            notes=["Missing `10-industry-realism-reviewer.result.yaml`."],
        )

    result = AgentResultSpec.model_validate(load_yaml(result_file))
    verdicts = industry_realism_verdicts(result)
    if result.status in {"not-started", "draft"}:
        status: WorkflowStatus = "pending"
    elif result.status in {"blocked", "needs-review"}:
        status = "blocked"
    elif "fail" in verdicts:
        status = "blocked"
    elif {"conditional-pass", "not-reviewable"} & verdicts or result.open_questions:
        status = "warning"
    else:
        status = "done"

    return WorkflowStep(
        id="industry-realism-review",
        title="Review Industry Realism",
        status=status,
        purpose="Confirm the lab genuinely resembles the declared target industry beyond static keyword checks.",
        evidence=[
            f"result={result_file}",
            f"status={result.status}",
            f"verdicts={','.join(sorted(verdicts)) or 'none'}",
            f"findings={len(result.findings)}",
            f"open_questions={len(result.open_questions)}",
        ],
        next_commands=[
            f"python -m labforge agents review {quote_path(agent_workspace_from_results(agent_result_root))} --write",
        ],
        notes=industry_realism_notes(result),
    )


def find_industry_realism_result(agent_result_root: Path) -> Path | None:
    candidates = [
        agent_result_root / "10-industry-realism-reviewer.result.yaml",
        agent_result_root / ".ai" / "outputs" / "10-industry-realism-reviewer.result.yaml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    matches = sorted(agent_result_root.glob("**/10-industry-realism-reviewer.result.yaml"))
    return matches[0] if matches else None


def agent_workspace_from_results(agent_result_root: Path) -> Path:
    if agent_result_root.name == "outputs" and agent_result_root.parent.name == ".ai":
        return agent_result_root.parent.parent
    if (agent_result_root / ".ai").exists():
        return agent_result_root
    return agent_result_root.parent.parent if agent_result_root.parent.name == "outputs" else agent_result_root


def industry_realism_verdicts(result: AgentResultSpec) -> set[str]:
    verdicts: set[str] = set()
    for finding in result.findings:
        if isinstance(finding, dict) and finding.get("verdict"):
            verdicts.add(str(finding["verdict"]).strip().lower())
    return verdicts


def industry_realism_notes(result: AgentResultSpec) -> list[str]:
    notes: list[str] = []
    for finding in result.findings[:6]:
        if isinstance(finding, dict):
            category = finding.get("category", "finding")
            verdict = finding.get("verdict", "unknown")
            gap = finding.get("gap") or finding.get("evidence") or finding
            notes.append(f"{category}:{verdict}: {gap}")
        else:
            notes.append(str(finding))
    return notes


def provider_build_step(lab_root: Path, provider: str, profile: str) -> WorkflowStep:
    out = Path("output") / f"{lab_root.name}-{provider}-{profile}"
    return WorkflowStep(
        id="provider-build",
        title="Render Provider Output",
        status="ready",
        purpose="Render deployable provider output and profile-specific documentation.",
        evidence=[f"expected_output={out}"],
        next_commands=[f"python -m labforge build {quote_path(lab_root)} --out {quote_path(out)} --provider {provider} --profile {profile} --force"],
    )


def release_gate_step(lab_root: Path, provider: str, profile: str, agent_result_root: Path | None = None) -> WorkflowStep:
    out = Path("output") / f"{lab_root.name}-release-gate"
    agent_results_arg = f" --agent-results {quote_path(agent_result_root)}" if agent_result_root else ""
    return WorkflowStep(
        id="release-gate",
        title="Run Release Gate",
        status="ready",
        purpose="Run strict validation before a lab package is treated as releasable.",
        evidence=[f"expected_output={out}"],
        next_commands=[
            f"python -m labforge qa release-gate {quote_path(lab_root)} --out {quote_path(out)} --provider {provider} --profile {profile}{agent_results_arg} --materialize --force"
        ],
    )


def supervisor_package_step(lab_root: Path, package_root: Path, provider: str, profile: str) -> WorkflowStep:
    report_file = package_root / "package-report.md"
    return WorkflowStep(
        id="supervisor-package",
        title="Create Supervisor Package",
        status="done" if report_file.exists() else "ready",
        purpose="Create the supervisor-facing final package with docs, provider output, QA, and reports.",
        evidence=[f"expected_report={report_file}"],
        next_commands=[
            f"python -m labforge package {quote_path(lab_root)} --out {quote_path(package_root)} --provider {provider} --profile {profile} --all-profiles --materialize --force"
        ],
    )


def quote_path(path: Path) -> str:
    return f'"{path}"'


def workflow_report_to_json(report: WorkflowReport) -> str:
    return json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + "\n"


def workflow_report_to_markdown(report: WorkflowReport) -> str:
    lines = [
        f"# LabForge Workflow Status - {report.title}",
        "",
        f"- Lab ID: `{report.lab_id}`",
        f"- Status: `{report.status}`",
        f"- Current step: `{report.current_step}`",
        f"- Provider: `{report.provider}`",
        f"- Profile: `{report.profile}`",
        f"- Result directory: `{report.result_dir or '-'}`",
        f"- Agent result directory: `{report.agent_result_dir or '-'}`",
        "",
        "## Steps",
        "",
        "| Step | Status | Purpose |",
        "|---|---|---|",
    ]
    for step in report.steps:
        lines.append(f"| `{step.id}` | `{step.status}` | {step.purpose} |")
    lines += [
        "",
        "## Next Commands",
        "",
    ]
    lines.extend(f"```powershell\n{command}\n```" for command in report.next_commands or ["# No next command."])
    lines += [
        "",
        "## Details",
        "",
    ]
    for step in report.steps:
        lines += [
            f"### {step.title}",
            "",
            f"- Step ID: `{step.id}`",
            f"- Status: `{step.status}`",
        ]
        if step.evidence:
            lines.append(f"- Evidence: {', '.join(f'`{item}`' for item in step.evidence)}")
        if step.notes:
            lines.append("")
            lines.extend(f"- {note}" for note in step.notes)
        lines.append("")
    return "\n".join(lines)


WORKFLOW_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "workflow-report.schema.json": WorkflowReport,
}
