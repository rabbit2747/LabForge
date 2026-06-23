from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .design import create_design_fix_task_packages, create_design_fix_tasks, create_design_workspace_from_prompt, review_design_workspace
from .agent_orchestration import write_baseline_agent_results
from .implementation_plan import create_service_agent_packages, create_service_implementation_plan
from .intake import normalize_prompt_text
from .io import dump_yaml, load_yaml, write_text
from .model import LabSpec
from .packaging import create_supervisor_package
from .plugin_runtime_smoke import run_plugin_runtime_smoke
from .service_artifacts import materialize_service_runtimes, review_service_results, scaffold_service_artifacts, service_result_batch_review_to_markdown
from .service_blueprints import create_service_blueprints, inspect_service_implementation_status
from .service_verification import verify_services
from .workflow import create_workflow_report, workflow_report_to_markdown


PipelineStepStatus = Literal["done", "warning", "skipped", "failed"]
PipelineGateStatus = Literal["passed", "warning", "failed", "missing"]
PipelineGateDecision = Literal["draft", "needs-agent-work", "ready-for-supervisor", "release-candidate", "blocked"]


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


class PipelineGateItem(PipelineModel):
    name: str
    status: PipelineGateStatus
    evidence: list[str] = Field(default_factory=list)
    required_action: str = ""


class PipelineGateReport(PipelineModel):
    workspace: str
    lab_dir: str | None = None
    decision: PipelineGateDecision
    ready_for_supervisor: bool = False
    ready_for_release_gate: bool = False
    items: list[PipelineGateItem] = Field(default_factory=list)
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
    prompt = normalize_prompt_text(prompt)
    title = normalize_prompt_text(title) if title else None
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

    baseline_agent_files = write_baseline_agent_results(Path(design.agent_workspace_dir), context_root=lab_dir)
    steps.append(
        PipelineStepResult(
            id="baseline-agent-results",
            title="Write baseline specialist-agent evidence",
            summary=f"Generated {len(baseline_agent_files)} baseline specialist-agent review artifacts from the draft lab.",
            artifacts=[str(path) for path in baseline_agent_files[:20]],
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

    fix_tasks = create_design_fix_tasks(out)
    steps.append(
        PipelineStepResult(
            id="design-fix-tasks",
            title="Create design correction task list",
            status="done" if fix_tasks.status in {"pending", "no-tasks"} else "warning",
            summary=f"Created {len(fix_tasks.tasks)} design correction tasks for specialist review.",
            artifacts=[str(out / "review" / "design-fix-tasks.md"), str(out / "review" / "design-fix-tasks.yaml")],
            warnings=[f"{task.task_id}:{task.assigned_agent}:{task.title}" for task in fix_tasks.tasks[:20]],
        )
    )

    fix_packages = create_design_fix_task_packages(out, adapter=adapter)
    steps.append(
        PipelineStepResult(
            id="design-fix-packages",
            title="Package design correction tasks for agents",
            status="done" if fix_packages.status in {"packaged", "no-tasks"} else "warning",
            summary=f"Prepared {len(fix_packages.packages)} design correction agent packages.",
            artifacts=[
                str(out / "review" / "fix-agent-packages"),
                str(out / "review" / "fix-agent-results"),
                str(out / "review" / "fix-agent-package-report.md"),
            ],
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
        agent_files = create_service_agent_packages(spec, service_agent_dir, adapter=adapter, baseline_from_runtime=materialize)
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

    service_result_review_dir = out / "service-result-review"
    service_result_review_dir.mkdir(parents=True, exist_ok=True)
    service_result_review = review_service_results(spec, service_agent_dir / ".ai" / "outputs", force=True)
    write_text(service_result_review_dir / "service-result-review.md", service_result_batch_review_to_markdown(service_result_review))
    write_text(service_result_review_dir / "service-result-review.yaml", dump_yaml(service_result_review.model_dump()))
    steps.append(
        PipelineStepResult(
            id="service-result-review",
            title="Review service-builder result readiness",
            status=(
                "done"
                if service_result_review.status == "ready"
                else ("failed" if service_result_review.status == "failed" else "warning")
            ),
            summary=(
                f"Service result review status: {service_result_review.status}; "
                f"ready={service_result_review.ready_count}, needs_review={service_result_review.needs_review_count}, "
                f"failed={service_result_review.failed_count}."
            ),
            artifacts=[
                str(service_result_review_dir / "service-result-review.md"),
                str(service_result_review_dir / "service-result-review.yaml"),
            ],
            warnings=[
                f"{review.service or 'unknown'}:{review.status}:{'; '.join(review.errors) or 'review required'}"
                for review in service_result_review.reviews
                if review.status != "ready"
            ][:20],
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

    runtime_smoke_dir = out / "plugin-runtime-smoke"
    runtime_smoke = run_plugin_runtime_smoke(spec, runtime_smoke_dir)
    steps.append(
        PipelineStepResult(
            id="plugin-runtime-smoke",
            title="Execute generated plugin runtime smoke checks",
            status="done" if runtime_smoke.status == "passed" else ("failed" if runtime_smoke.status == "failed" else "warning"),
            summary=f"Plugin runtime smoke status: {runtime_smoke.status}; checked {len(runtime_smoke.items)} plugin instances.",
            artifacts=[str(runtime_smoke_dir / "plugin-runtime-smoke.md"), str(runtime_smoke_dir / "plugin-runtime-smoke.yaml")],
            warnings=[
                f"{item.service}:{item.plugin}:{item.status}:{item.message or item.endpoint or 'ok'}"
                for item in runtime_smoke.items
                if item.status != "passed"
            ][:20],
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

    package_dir = out / "supervisor-package"
    try:
        package = create_supervisor_package(
            lab_dir,
            package_dir,
            provider=provider if provider != "auto" else "docker-compose",
            profile=profile,
            materialize=False,
            force=force,
            all_profiles=True,
        )
        steps.append(
            PipelineStepResult(
                id="supervisor-package",
                title="Create runnable supervisor package",
                status="done" if package.status == "passed" else ("failed" if package.status == "failed" else "warning"),
                summary=f"Supervisor package status: {package.status}; artifacts: {len(package.artifacts)}.",
                artifacts=[
                    str(package_dir / "package-report.md"),
                    str(package_dir / "generated"),
                    str(package_dir / "qa" / "qa-smoke-report.md"),
                ],
                warnings=package.warnings[:20],
            )
        )
    except Exception as exc:  # noqa: BLE001 - pipeline should preserve packaging failures.
        steps.append(
            PipelineStepResult(
                id="supervisor-package",
                title="Create runnable supervisor package",
                status="failed",
                summary="Supervisor package generation failed.",
                artifacts=[str(package_dir)],
                warnings=[str(exc)],
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
        workspace_dir=out,
    )
    write_text(workflow_dir / "workflow-report.md", workflow_report_to_markdown(workflow))
    write_text(workflow_dir / "workflow-report.json", workflow.model_dump_json(indent=2))
    steps.append(
        PipelineStepResult(
            id="workflow",
            title="Create workflow report",
            status="failed" if workflow.status == "blocked" else "done",
            summary=f"Workflow status: {workflow.status}; current step: {workflow.current_step}.",
            artifacts=[str(workflow_dir / "workflow-report.md"), str(workflow_dir / "workflow-report.json")],
            warnings=[note for step in workflow.steps for note in step.notes[:2]][:20] if workflow.status == "blocked" else [],
        )
    )

    result_status: Literal["complete", "warning", "failed"] = "complete"
    if any(step.status == "failed" for step in steps):
        result_status = "failed"
    elif any(step.status == "warning" for step in steps):
        result_status = "warning"

    next_commands = [
        f"python -m labforge studio serve --workspace {out.parent / 'studio'} --host 127.0.0.1 --port 8767",
        f"cd {out / 'supervisor-package' / 'generated'}",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\validate.ps1",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\start.ps1",
        f"python -m labforge workflow status {lab_dir} --provider {provider if provider != 'auto' else 'docker-compose'} --profile {profile}",
        f"python -m labforge services status {lab_dir}",
    ]
    if package_service_agents:
        next_commands.append(f"python -m labforge services review-results {lab_dir} --results {service_agent_dir / '.ai' / 'outputs'} --force")
        next_commands.append(f"python -m labforge services apply-results {lab_dir} --results {service_agent_dir / '.ai' / 'outputs'} --force")
        next_commands.append(f"python -m labforge services run-agents {service_agent_dir} --adapter {adapter} --dry-run")
    else:
        next_commands.append(f"python -m labforge services agent-packages {lab_dir} --out {service_agent_dir} --adapter {adapter}")

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
        next_commands=next_commands,
    )
    write_text(out / "pipeline-result.yaml", dump_yaml(result.model_dump()))
    write_text(out / "pipeline-result.json", json.dumps(result.model_dump(), ensure_ascii=False, indent=2) + "\n")
    write_text(out / "pipeline-summary.md", pipeline_result_to_markdown(result))
    gate = evaluate_pipeline_gate(out)
    write_pipeline_gate_report(gate, out)
    return result


def evaluate_pipeline_gate(workspace: Path) -> PipelineGateReport:
    workspace = workspace.resolve()
    pipeline_path = workspace / "pipeline-result.yaml"
    lab_dir = workspace / "lab"
    items: list[PipelineGateItem] = []

    if not pipeline_path.exists():
        report = PipelineGateReport(
            workspace=str(workspace),
            lab_dir=str(lab_dir) if lab_dir.exists() else None,
            decision="draft",
            items=[
                PipelineGateItem(
                    name="pipeline-result",
                    status="missing",
                    evidence=[str(pipeline_path)],
                    required_action="Run `python -m labforge pipeline create ...` before gate review.",
                )
            ],
            next_commands=["python -m labforge pipeline create --prompt-file <prompt.md> --out <workspace> --force"],
        )
        write_pipeline_gate_report(report, workspace)
        return report

    pipeline_data = load_yaml(pipeline_path)
    pipeline_result = PipelineCreateResult.model_validate(pipeline_data)
    lab_dir = Path(pipeline_result.lab_dir)

    items.append(
        PipelineGateItem(
            name="pipeline-result",
            status="failed" if pipeline_result.status == "failed" else ("warning" if pipeline_result.status == "warning" else "passed"),
            evidence=[f"status={pipeline_result.status}", f"services={pipeline_result.service_ready_count}/{pipeline_result.service_count}"],
            required_action="Review warning steps before assigning implementation work." if pipeline_result.status == "warning" else "",
        )
    )

    design_review_path = workspace / "review" / "design-review-report.yaml"
    if design_review_path.exists():
        design_review = load_yaml(design_review_path)
        review_status = str(design_review.get("status", "failed"))
        realism_score = design_review.get("realism_score", "unknown")
        items.append(
            PipelineGateItem(
                name="design-review",
                status="passed" if review_status == "passed" else "warning",
                evidence=[f"status={review_status}", f"realism_score={realism_score}"],
                required_action="Run design fix tasks and specialist-agent review before release work." if review_status != "passed" else "",
            )
        )
    else:
        items.append(
            PipelineGateItem(
                name="design-review",
                status="missing",
                evidence=[str(design_review_path)],
                required_action="Run `python -m labforge design review <workspace>`.",
            )
        )

    fix_tasks_path = workspace / "review" / "design-fix-tasks.yaml"
    fix_packages_path = workspace / "review" / "fix-agent-package-report.yaml"
    if fix_tasks_path.exists() and fix_packages_path.exists():
        fix_tasks = load_yaml(fix_tasks_path)
        fix_packages = load_yaml(fix_packages_path)
        tasks = fix_tasks.get("tasks", [])
        packages = fix_packages.get("packages", [])
        task_count = len(tasks) if isinstance(tasks, list) else 0
        package_count = len(packages) if isinstance(packages, list) else 0
        items.append(
            PipelineGateItem(
                name="design-fix-packages",
                status="passed" if isinstance(packages, list) else "warning",
                evidence=[
                    f"tasks={task_count if isinstance(tasks, list) else 'unknown'}",
                    f"packages={package_count if isinstance(packages, list) else 'unknown'}",
                ],
                required_action="Run the prepared design correction agents and review their results." if task_count else "",
            )
        )
    else:
        items.append(
            PipelineGateItem(
                name="design-fix-packages",
                status="missing",
                evidence=[str(fix_tasks_path), str(fix_packages_path)],
                required_action="Run `python -m labforge design tasks <workspace>` and `python -m labforge design package-tasks <workspace>`.",
            )
        )

    if lab_dir.exists():
        try:
            spec = LabSpec.load(lab_dir)
            service_status = inspect_service_implementation_status(spec)
            service_ok = service_status.ready_count == service_status.service_count
            items.append(
                PipelineGateItem(
                    name="service-status",
                    status="passed" if service_ok else "warning",
                    evidence=[f"tested={service_status.ready_count}/{service_status.service_count}"],
                    required_action="Run service-builder agents or materialize missing services." if not service_ok else "",
                )
            )
            service_verification = verify_services(spec)
            items.append(
                PipelineGateItem(
                    name="service-verification",
                    status="passed" if service_verification.status == "passed" else service_verification.status,
                    evidence=[f"status={service_verification.status}", f"findings={len(service_verification.findings)}"],
                    required_action="Fix service verification findings before release gate." if service_verification.status != "passed" else "",
                )
            )
            runtime_smoke_path = workspace / "plugin-runtime-smoke" / "plugin-runtime-smoke.yaml"
            if runtime_smoke_path.exists():
                runtime_smoke = load_yaml(runtime_smoke_path)
                runtime_status = str(runtime_smoke.get("status", "failed"))
                runtime_items = runtime_smoke.get("items", [])
                items.append(
                    PipelineGateItem(
                        name="plugin-runtime-smoke",
                        status="passed" if runtime_status == "passed" else ("failed" if runtime_status == "failed" else "warning"),
                        evidence=[f"status={runtime_status}", f"items={len(runtime_items) if isinstance(runtime_items, list) else 'unknown'}"],
                        required_action="Fix generated plugin runtime smoke failures before packaging or release gate." if runtime_status != "passed" else "",
                    )
                )
            else:
                items.append(
                    PipelineGateItem(
                        name="plugin-runtime-smoke",
                        status="missing",
                        evidence=[str(runtime_smoke_path)],
                        required_action="Run `python -m labforge qa smoke <lab> --out <workspace>/qa-smoke --materialize --force` or regenerate the pipeline.",
                    )
                )
        except Exception as exc:  # noqa: BLE001 - gate should report partial workspace state.
            items.append(
                PipelineGateItem(
                    name="lab-load",
                    status="failed",
                    evidence=[str(exc)],
                    required_action="Fix the generated lab YAML before continuing.",
                )
            )
    else:
        items.append(
            PipelineGateItem(
                name="lab-directory",
                status="missing",
                evidence=[str(lab_dir)],
                required_action="Regenerate the pipeline workspace.",
            )
        )

    package_report_path = workspace / "supervisor-package" / "package-report.json"
    if package_report_path.exists():
        package_report = json.loads(package_report_path.read_text(encoding="utf-8"))
        package_status = str(package_report.get("status", "failed"))
        artifacts = package_report.get("artifacts", [])
        generated_compose = workspace / "supervisor-package" / "generated" / "docker-compose.yml"
        quickstart = workspace / "supervisor-package" / "generated" / "QUICKSTART.md"
        endpoint_manifest = workspace / "supervisor-package" / "generated" / "endpoints.json"
        validate_plan = workspace / "supervisor-package" / "lifecycle" / "validate-plan.json"
        validate_status = "missing"
        if validate_plan.exists():
            validate_report = json.loads(validate_plan.read_text(encoding="utf-8"))
            validate_status = str(validate_report.get("status", "unknown"))
        endpoint_count = "missing"
        if endpoint_manifest.exists():
            try:
                endpoint_data = json.loads(endpoint_manifest.read_text(encoding="utf-8"))
                published = endpoint_data.get("published_endpoints", [])
                endpoint_count = str(len(published)) if isinstance(published, list) else "unknown"
            except Exception:  # noqa: BLE001 - gate should surface malformed manifests as failed evidence.
                endpoint_count = "invalid"
        evidence = [
            f"status={package_status}",
            f"artifacts={len(artifacts) if isinstance(artifacts, list) else 'unknown'}",
            f"docker_compose={'present' if generated_compose.exists() else 'missing'}",
            f"quickstart={'present' if quickstart.exists() else 'missing'}",
            f"endpoints={endpoint_count}",
            f"validate={validate_status}",
        ]
        package_gate_status: PipelineGateStatus
        if package_status == "failed" or not generated_compose.exists() or not quickstart.exists() or endpoint_count in {"missing", "invalid"}:
            package_gate_status = "failed"
        elif package_status == "warning":
            package_gate_status = "warning"
        else:
            package_gate_status = "passed"
        items.append(
            PipelineGateItem(
                name="supervisor-package",
                status=package_gate_status,
                evidence=evidence,
                required_action="Regenerate the supervisor package before release work." if package_gate_status != "passed" else "",
            )
        )
    else:
        items.append(
            PipelineGateItem(
                name="supervisor-package",
                status="missing",
                evidence=[str(package_report_path)],
                required_action="Run `python -m labforge package <lab> --out <workspace>/supervisor-package --provider docker-compose --profile protected --materialize --force`.",
            )
        )

    service_agents_dir = workspace / "service-agents" / ".ai" / "service-build"
    service_outputs_dir = workspace / "service-agents" / ".ai" / "outputs"
    service_packages = sorted(service_agents_dir.glob("*.package.yaml")) if service_agents_dir.exists() else []
    service_results = sorted(service_outputs_dir.glob("*.result.yaml")) if service_outputs_dir.exists() else []
    items.append(
        PipelineGateItem(
            name="service-agent-packages",
            status="passed" if service_packages else "missing",
            evidence=[f"packages={len(service_packages)}", f"results={len(service_results)}"],
            required_action="Run `python -m labforge services agent-packages <lab> --out <workspace>/service-agents`." if not service_packages else "Run service-builder agents and review results." if not service_results else "",
        )
    )

    service_result_review_path = workspace / "service-result-review" / "service-result-review.yaml"
    if service_result_review_path.exists():
        service_result_review = load_yaml(service_result_review_path)
        review_status = str(service_result_review.get("status", "failed"))
        items.append(
            PipelineGateItem(
                name="service-result-review",
                status="passed" if review_status == "ready" else ("failed" if review_status == "failed" else "warning"),
                evidence=[
                    f"status={review_status}",
                    f"ready={service_result_review.get('ready_count', 'unknown')}",
                    f"needs_review={service_result_review.get('needs_review_count', 'unknown')}",
                    f"failed={service_result_review.get('failed_count', 'unknown')}",
                ],
                required_action="Run service-builder agents, then `python -m labforge services review-results ...` until service results are ready."
                if review_status != "ready"
                else "",
            )
        )
    else:
        items.append(
            PipelineGateItem(
                name="service-result-review",
                status="missing",
                evidence=[str(service_result_review_path)],
                required_action="Run `python -m labforge services review-results <lab> --results <workspace>/service-agents/.ai/outputs --force`.",
            )
        )

    decision_items = [item for item in items if item.name != "pipeline-result"]
    pipeline_item = next((item for item in items if item.name == "pipeline-result"), None)
    if any(item.status == "failed" for item in decision_items) or (pipeline_item and pipeline_item.status == "failed"):
        decision: PipelineGateDecision = "blocked"
    elif any(item.status == "missing" for item in decision_items):
        decision = "draft"
    elif any(item.status == "warning" for item in decision_items):
        decision = "needs-agent-work"
    elif not service_results:
        decision = "ready-for-supervisor"
    else:
        decision = "release-candidate"

    next_commands = gate_next_commands(workspace, lab_dir, decision)
    report = PipelineGateReport(
        workspace=str(workspace),
        lab_dir=str(lab_dir) if lab_dir.exists() else None,
        decision=decision,
        ready_for_supervisor=decision in {"ready-for-supervisor", "release-candidate"},
        ready_for_release_gate=decision == "release-candidate",
        items=items,
        next_commands=next_commands,
    )
    write_pipeline_gate_report(report, workspace)
    return report


def gate_next_commands(workspace: Path, lab_dir: Path, decision: PipelineGateDecision) -> list[str]:
    if decision == "blocked":
        return [
            f"python -m labforge validate {lab_dir}",
            f"python -m labforge lint {lab_dir}",
        ]
    if decision == "draft":
        return [f"python -m labforge pipeline create --prompt-file <prompt.md> --out {workspace} --force"]
    if decision == "needs-agent-work":
        return [
            f"python -m labforge design run-task {workspace} --task <fix-task-id> --adapter manual",
            f"python -m labforge design review-fix-results {workspace}",
            f"python -m labforge services run-agents {workspace / 'service-agents'} --adapter manual --dry-run",
        ]
    if decision == "ready-for-supervisor":
        return [
            f"python -m labforge services run-agents {workspace / 'service-agents'} --adapter <codex|claude-code|openai> --execute",
            f"python -m labforge services review-results {lab_dir} --results {workspace / 'service-agents' / '.ai' / 'outputs'} --force",
        ]
    return [
        f"python -m labforge qa release-gate {lab_dir} --out {workspace / 'release-gate'} --provider docker-compose --profile protected --agent-results {workspace / 'agents' / '.ai' / 'outputs'} --materialize --force"
    ]


def write_pipeline_gate_report(report: PipelineGateReport, workspace: Path) -> None:
    write_text(workspace / "pipeline-gate.yaml", dump_yaml(report.model_dump()))
    write_text(workspace / "pipeline-gate.json", json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + "\n")
    write_text(workspace / "pipeline-gate.md", pipeline_gate_to_markdown(report))


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


def pipeline_gate_to_markdown(report: PipelineGateReport) -> str:
    lines = [
        "# LabForge Pipeline Gate",
        "",
        f"- Workspace: `{report.workspace}`",
        f"- Lab directory: `{report.lab_dir or '-'}`",
        f"- Decision: `{report.decision}`",
        f"- Ready for supervisor: `{str(report.ready_for_supervisor).lower()}`",
        f"- Ready for release gate: `{str(report.ready_for_release_gate).lower()}`",
        "",
        "| Item | Status | Evidence | Required Action |",
        "|---|---|---|---|",
    ]
    for item in report.items:
        evidence = "<br>".join(item.evidence) if item.evidence else "-"
        action = item.required_action or "-"
        lines.append(f"| `{item.name}` | {item.status} | {evidence} | {action} |")
    lines.extend(["", "## Next Commands", ""])
    lines.extend(f"```bash\n{command}\n```" for command in report.next_commands)
    return "\n".join(lines).rstrip() + "\n"


PIPELINE_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "pipeline-create-result.schema.json": PipelineCreateResult,
    "pipeline-gate-report.schema.json": PipelineGateReport,
}
