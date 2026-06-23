from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .design import create_design_workspace_from_prompt, review_design_workspace
from .implementation_plan import create_service_agent_packages, create_service_implementation_plan
from .io import dump_yaml, write_text
from .model import LabSpec
from .service_artifacts import materialize_service_runtimes, scaffold_service_artifacts
from .service_blueprints import create_service_blueprints, inspect_service_implementation_status
from .service_verification import verify_services
from .workflow import create_workflow_report, workflow_report_to_markdown


PipelineStepStatus = Literal["done", "warning", "skipped", "failed"]


class PipelineModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class PipelineStepResult(PipelineModel):
    id: str
    title: str
    status: PipelineStepStatus = "done"
    summary: str = ""
    artifacts: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class PipelineCreateResult(PipelineModel):
    workspace: str
    lab_dir: str
    status: Literal["complete", "warning", "failed"]
    industry: str = "enterprise"
    provider: str = "auto"
    adapter: str = "manual"
    service_count: int = 0
    service_ready_count: int = 0
    steps: list[PipelineStepResult] = Field(default_factory=list)
    next_commands: list[str] = Field(default_factory=list)


def create_lab_pipeline(
    out: Path,
    *,
    prompt: str,
    lab_id: str | None = None,
    title: str | None = None,
    industry: str | None = None,
    difficulty: str = "intermediate",
    provider: str = "auto",
    profile: str = "protected",
    adapter: str = "manual",
    force: bool = False,
    materialize: bool = True,
    package_service_agents: bool = True,
) -> PipelineCreateResult:
    out = out.resolve()
    steps: list[PipelineStepResult] = []

    design = create_design_workspace_from_prompt(
        out,
        prompt=prompt,
        lab_id=lab_id,
        title=title,
        industry=industry,
        difficulty=difficulty,
        provider=provider,
        adapter=adapter,
        force=force,
    )
    lab_dir = Path(design.lab_dir).resolve()
    steps.append(
        PipelineStepResult(
            id="design-workspace",
            title="Create design workspace",
            status="warning" if design.validation_errors else "done",
            summary="Created intake, draft lab, agent workspace, and dry-run agent packages.",
            artifacts=[design.intake_dir, design.lab_dir, design.agent_workspace_dir],
            warnings=design.validation_errors,
        )
    )

    review = review_design_workspace(out, out=out / "review", industry=industry, force=True)
    steps.append(
        PipelineStepResult(
            id="design-review",
            title="Review draft design",
            status="warning" if review.status in {"warning", "needs-agent-output"} else "done",
            summary=f"Design review status: {review.status}; realism score: {review.realism_score}.",
            artifacts=[str(out / "review" / "design-review-report.md"), str(out / "review" / "realism-report.md")],
            warnings=review.warnings[:20],
        )
    )

    spec = LabSpec.load(lab_dir)
    scaffolded = scaffold_service_artifacts(spec, force=force)
    steps.append(
        PipelineStepResult(
            id="service-scaffold",
            title="Scaffold service artifacts",
            summary=f"Prepared {len(scaffolded)} service artifact files and folders.",
            artifacts=[str(path) for path in scaffolded[:20]],
        )
    )

    blueprint_dir = out / "service-blueprints"
    blueprints = create_service_blueprints(spec, blueprint_dir)
    steps.append(
        PipelineStepResult(
            id="service-blueprints",
            title="Create service blueprints",
            summary=f"Created blueprints for {blueprints.service_count} services.",
            artifacts=[
                str(blueprint_dir / "service-blueprints.md"),
                str(blueprint_dir / "service-blueprints.yaml"),
                str(blueprint_dir / "service-blueprints.json"),
            ],
        )
    )

    plan_dir = out / "service-plan"
    plan = create_service_implementation_plan(spec, plan_dir)
    steps.append(
        PipelineStepResult(
            id="service-plan",
            title="Create service implementation plan",
            summary=f"Created {len(plan.tasks)} service implementation tasks.",
            artifacts=[str(plan_dir / "service-implementation-plan.md"), str(plan_dir / "service-implementation-plan.yaml")],
        )
    )

    if materialize:
        materialized = materialize_service_runtimes(spec, force=force)
        steps.append(
            PipelineStepResult(
                id="service-materialize",
                title="Materialize runnable service scaffolds",
                summary=f"Materialized {len(materialized)} files across service runtime folders.",
                artifacts=[str(path) for path in materialized[:20]],
            )
        )
    else:
        steps.append(
            PipelineStepResult(
                id="service-materialize",
                title="Materialize runnable service scaffolds",
                status="skipped",
                summary="Skipped by request.",
            )
        )

    service_agent_dir = out / "service-agents"
    if package_service_agents:
        agent_files = create_service_agent_packages(spec, service_agent_dir, adapter=adapter)
        steps.append(
            PipelineStepResult(
                id="service-agent-packages",
                title="Create service-builder agent packages",
                summary=f"Created {len(agent_files)} service-builder package and result files.",
                artifacts=[str(service_agent_dir / ".ai" / "service-build")],
            )
        )
    else:
        steps.append(
            PipelineStepResult(
                id="service-agent-packages",
                title="Create service-builder agent packages",
                status="skipped",
                summary="Skipped by request.",
            )
        )

    verification_dir = out / "service-verification"
    verification_dir.mkdir(parents=True, exist_ok=True)
    verification = verify_services(spec)
    write_text(verification_dir / "service-verification.json", verification.model_dump_json(indent=2))
    steps.append(
        PipelineStepResult(
            id="service-verification",
            title="Verify service implementation quality gates",
            status="warning" if verification.status == "warning" else ("failed" if verification.status == "failed" else "done"),
            summary=f"Service verification status: {verification.status}; findings: {len(verification.findings)}.",
            artifacts=[str(verification_dir / "service-verification.json")],
            warnings=[f"{finding.service}: {finding.message}" for finding in verification.findings[:20]],
        )
    )

    status_dir = out / "service-status"
    service_status = inspect_service_implementation_status(spec, status_dir)
    steps.append(
        PipelineStepResult(
            id="service-status",
            title="Inspect service implementation status",
            status="done" if service_status.ready_count == service_status.service_count else "warning",
            summary=f"{service_status.ready_count}/{service_status.service_count} services are tested.",
            artifacts=[str(status_dir / "service-status.md"), str(status_dir / "service-status.yaml")],
        )
    )

    workflow_dir = out / "workflow"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    workflow = create_workflow_report(
        lab_dir,
        provider=provider if provider != "auto" else "docker-compose",
        profile=profile,
        result_dir=service_agent_dir / ".ai" / "outputs",
        agent_result_dir=Path(design.agent_workspace_dir) / "outputs",
        package_dir=out / "supervisor-package",
    )
    write_text(workflow_dir / "workflow-report.md", workflow_report_to_markdown(workflow))
    write_text(workflow_dir / "workflow-report.json", workflow.model_dump_json(indent=2))
    steps.append(
        PipelineStepResult(
            id="workflow",
            title="Create workflow report",
            status="warning" if workflow.status != "ready" else "done",
            summary=f"Workflow status: {workflow.status}; current step: {workflow.current_step}.",
            artifacts=[str(workflow_dir / "workflow-report.md"), str(workflow_dir / "workflow-report.json")],
            warnings=[note for step in workflow.steps for note in step.notes[:2]][:20],
        )
    )

    result_status: Literal["complete", "warning", "failed"] = "complete"
    if any(step.status == "failed" for step in steps):
        result_status = "failed"
    elif any(step.status == "warning" for step in steps):
        result_status = "warning"

    result = PipelineCreateResult(
        workspace=str(out),
        lab_dir=str(lab_dir),
        status=result_status,
        industry=industry or str(spec.scenario.get("target_industry", "enterprise")),
        provider=provider,
        adapter=adapter,
        service_count=service_status.service_count,
        service_ready_count=service_status.ready_count,
        steps=steps,
        next_commands=[
            f"python -m labforge studio serve --workspace {out.parent / 'studio'} --host 127.0.0.1 --port 8767",
            f"python -m labforge workflow status {lab_dir} --provider {provider if provider != 'auto' else 'docker-compose'} --profile {profile}",
            f"python -m labforge services status {lab_dir}",
            f"python -m labforge services run-agents {service_agent_dir} --adapter {adapter} --dry-run",
        ],
    )
    write_text(out / "pipeline-result.yaml", dump_yaml(result.model_dump()))
    write_text(out / "pipeline-result.json", json.dumps(result.model_dump(), ensure_ascii=False, indent=2) + "\n")
    write_text(out / "pipeline-summary.md", pipeline_result_to_markdown(result))
    return result


def pipeline_result_to_markdown(result: PipelineCreateResult) -> str:
    lines = [
        "# LabForge Pipeline Result",
        "",
        f"- Workspace: `{result.workspace}`",
        f"- Lab directory: `{result.lab_dir}`",
        f"- Status: `{result.status}`",
        f"- Industry: `{result.industry}`",
        f"- Provider: `{result.provider}`",
        f"- Adapter: `{result.adapter}`",
        f"- Service readiness: `{result.service_ready_count}/{result.service_count}`",
        "",
        "## Steps",
        "",
    ]
    for step in result.steps:
        lines.extend(
            [
                f"### {step.title}",
                "",
                f"- ID: `{step.id}`",
                f"- Status: `{step.status}`",
                f"- Summary: {step.summary}",
            ]
        )
        if step.artifacts:
            lines.append("- Artifacts:")
            lines.extend(f"  - `{artifact}`" for artifact in step.artifacts)
        if step.warnings:
            lines.append("- Warnings:")
            lines.extend(f"  - {warning}" for warning in step.warnings[:20])
        lines.append("")
    lines.extend(["## Next Commands", ""])
    lines.extend(f"```bash\n{command}\n```" for command in result.next_commands)
    return "\n".join(lines).rstrip() + "\n"


PIPELINE_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "pipeline-create-result.schema.json": PipelineCreateResult,
}
