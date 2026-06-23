from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .agent_orchestration import (
    create_agent_execution_packages,
    create_agent_review,
    review_to_json,
    review_to_markdown,
    scaffold_agent_workspace,
    validate_agent_workspace,
    write_agent_review,
)
from .intake import create_intake_from_prompt, scaffold_lab_from_intake
from .io import dump_yaml, write_text
from .linting import lint_lab, lint_report_to_json, lint_report_to_markdown
from .model import LabSpec
from .realism import check_realism, realism_report_to_json, realism_report_to_markdown
from .validate import validate_lab


class DesignModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class DesignWorkspaceResult(DesignModel):
    root: str
    intake_dir: str
    lab_dir: str
    agent_workspace_dir: str
    adapter: str = "manual"
    agent: str | None = None
    files_written: list[str] = Field(default_factory=list)
    validation_errors: list[str] = Field(default_factory=list)
    next_commands: list[str] = Field(default_factory=list)


class DesignReviewReport(DesignModel):
    workspace: str
    lab_dir: str
    agent_workspace_dir: str
    status: Literal["passed", "needs-agent-output", "warning", "failed"]
    target_industry: str = "enterprise"
    validation_errors: list[str] = Field(default_factory=list)
    lint_status: str = "passed"
    realism_status: str = "passed"
    agent_ready_for_supervisor: bool = False
    artifacts: list[dict[str, str]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    next_commands: list[str] = Field(default_factory=list)


class DesignFixTask(DesignModel):
    task_id: str
    title: str
    source: str
    severity: Literal["info", "warning", "error"] = "warning"
    assigned_agent: str
    status: Literal["pending", "in-progress", "done", "blocked"] = "pending"
    rationale: str
    required_action: str
    expected_artifacts: list[str] = Field(default_factory=list)
    related_files: list[str] = Field(default_factory=list)


class DesignFixTaskReport(DesignModel):
    workspace: str
    lab_dir: str
    review_dir: str
    status: Literal["no-tasks", "pending", "blocked"] = "pending"
    tasks: list[DesignFixTask] = Field(default_factory=list)
    next_commands: list[str] = Field(default_factory=list)


def create_design_workspace_from_prompt(
    out: Path,
    *,
    prompt: str,
    lab_id: str | None = None,
    title: str | None = None,
    industry: str | None = None,
    difficulty: str = "intermediate",
    provider: str = "auto",
    adapter: str = "manual",
    agent: str | None = None,
    force: bool = False,
) -> DesignWorkspaceResult:
    intake_dir = out / "intake"
    lab_dir = out / "lab"
    agents_dir = out / "agents"

    written: list[Path] = []
    written.extend(
        create_intake_from_prompt(
            intake_dir,
            prompt=prompt,
            lab_id=lab_id,
            title=title,
            industry=industry,
            difficulty=difficulty,
            provider=provider,
            force=force,
        )
    )
    written.extend(scaffold_lab_from_intake(intake_dir / "scenario-intake.yaml", lab_dir, force=force))
    copied_context = copy_intake_context_to_lab(intake_dir, lab_dir, force=force)
    written.extend(copied_context)

    spec = LabSpec.load(lab_dir)
    extra_context_files = [path.name for path in copied_context]
    written.extend(scaffold_agent_workspace(spec, agents_dir, extra_context_files=extra_context_files))
    written.extend(
        create_agent_execution_packages(
            agents_dir,
            adapter=adapter,
            agent_id=agent,
            context_root=lab_dir,
        )
    )
    validation_errors = validate_agent_workspace(agents_dir)
    target_industry = spec.scenario.get("target_industry", "enterprise")
    result = DesignWorkspaceResult(
        root=str(out),
        intake_dir=str(intake_dir),
        lab_dir=str(lab_dir),
        agent_workspace_dir=str(agents_dir / ".ai"),
        adapter=adapter,
        agent=agent,
        files_written=[str(path) for path in written],
        validation_errors=validation_errors,
        next_commands=[
            f"python -m labforge validate {lab_dir}",
            f"python -m labforge lint {lab_dir}",
            f"python -m labforge realism check {lab_dir} --industry {target_industry}",
            f"python -m labforge agents validate {agents_dir}",
            f"python -m labforge agents run {agents_dir} --adapter {adapter} --context-root {lab_dir} --dry-run",
        ],
    )
    summary_path = out / "design-workspace-summary.md"
    yaml_path = out / "design-workspace-result.yaml"
    write_text(summary_path, render_design_workspace_summary(result))
    write_text(yaml_path, dump_yaml(result.model_dump()))
    result.files_written.extend([str(summary_path), str(yaml_path)])
    return result


def review_design_workspace(
    workspace: Path,
    *,
    out: Path | None = None,
    industry: str | None = None,
    force: bool = False,
) -> DesignReviewReport:
    workspace = workspace.resolve()
    lab_dir = workspace / "lab"
    agents_dir = workspace / "agents"
    report_dir = out or workspace / "review"
    report_dir.mkdir(parents=True, exist_ok=True)

    spec = LabSpec.load(lab_dir)
    target_industry = industry or spec.scenario.get("target_industry", "enterprise")
    validation_errors = validate_lab(lab_dir)
    lint_report = lint_lab(lab_dir)
    realism_report = check_realism(spec, industry=target_industry)
    agent_review = create_agent_review(agents_dir)
    write_agent_review(agents_dir)

    write_text(report_dir / "lint-report.md", lint_report_to_markdown(lint_report))
    write_text(report_dir / "lint-report.json", lint_report_to_json(lint_report))
    write_text(report_dir / "realism-report.md", realism_report_to_markdown(realism_report))
    write_text(report_dir / "realism-report.json", realism_report_to_json(realism_report))
    write_text(report_dir / "agent-review.md", review_to_markdown(agent_review))
    write_text(report_dir / "agent-review.json", review_to_json(agent_review))

    warnings = [
        *validation_errors,
        *[f"{finding.location}: {finding.message}" for finding in lint_report.findings],
        *[f"{finding.category}: {finding.message}" for finding in realism_report.findings],
    ]
    status = design_review_status(
        validation_errors=validation_errors,
        lint_status=lint_report.status,
        realism_status=realism_report.status,
        agent_ready_for_supervisor=agent_review.ready_for_supervisor,
    )
    report = DesignReviewReport(
        workspace=str(workspace),
        lab_dir=str(lab_dir),
        agent_workspace_dir=str(agents_dir / ".ai"),
        status=status,
        target_industry=target_industry,
        validation_errors=validation_errors,
        lint_status=lint_report.status,
        realism_status=realism_report.status,
        agent_ready_for_supervisor=agent_review.ready_for_supervisor,
        artifacts=[
            {"name": "source-prompt", "path": str((lab_dir / "scenario-prompt.md").resolve()), "purpose": "Original natural-language scenario intent."},
            {"name": "draft-lab", "path": str(lab_dir.resolve()), "purpose": "Draft LabForge scenario generated from the intake."},
            {"name": "agent-workspace", "path": str((agents_dir / ".ai").resolve()), "purpose": "Specialist agent tasks, prompts, and result contracts."},
            {"name": "lint-report", "path": str((report_dir / "lint-report.md").resolve()), "purpose": "Static scenario quality and placeholder report."},
            {"name": "realism-report", "path": str((report_dir / "realism-report.md").resolve()), "purpose": "Industry realism pre-check report."},
            {"name": "agent-review", "path": str((report_dir / "agent-review.md").resolve()), "purpose": "Specialist agent output readiness review."},
        ],
        warnings=warnings,
        next_commands=[
            f"python -m labforge agents run {agents_dir} --adapter manual --context-root {lab_dir} --dry-run",
            f"python -m labforge agents review {agents_dir} --write",
            f"python -m labforge workflow status {lab_dir} --agent-results {agents_dir / '.ai' / 'outputs'} --provider docker-compose --profile protected",
            f"python -m labforge package {lab_dir} --out {workspace / 'package'} --provider docker-compose --profile protected --all-profiles --materialize --force",
        ],
    )
    write_text(report_dir / "design-review-report.md", render_design_review_report(report))
    write_text(report_dir / "design-review-report.yaml", dump_yaml(report.model_dump()))
    return report


def create_design_fix_tasks(workspace: Path, *, review_dir: Path | None = None) -> DesignFixTaskReport:
    workspace = workspace.resolve()
    lab_dir = workspace / "lab"
    report_dir = review_dir or workspace / "review"
    review_path = report_dir / "design-review-report.yaml"
    if not review_path.exists():
        review_design_workspace(workspace, out=report_dir, force=True)
    review = DesignReviewReport.model_validate(load_design_yaml(review_path))
    tasks = fix_tasks_from_review(review)
    report = DesignFixTaskReport(
        workspace=str(workspace),
        lab_dir=str(lab_dir),
        review_dir=str(report_dir),
        status="no-tasks" if not tasks else "pending",
        tasks=tasks,
        next_commands=[
            f"python -m labforge agents run {workspace / 'agents'} --adapter manual --context-root {lab_dir} --dry-run",
            f"python -m labforge services plan {lab_dir} --out {workspace / 'service-plan'}",
            f"python -m labforge workflow status {lab_dir} --agent-results {workspace / 'agents' / '.ai' / 'outputs'} --provider docker-compose --profile protected",
        ],
    )
    write_text(report_dir / "design-fix-tasks.yaml", dump_yaml(report.model_dump()))
    write_text(report_dir / "design-fix-tasks.md", render_design_fix_tasks(report))
    return report


def load_design_yaml(path: Path) -> dict:
    from .io import load_yaml

    return load_yaml(path)


def fix_tasks_from_review(review: DesignReviewReport) -> list[DesignFixTask]:
    tasks: list[DesignFixTask] = []
    for index, warning in enumerate(review.warnings, start=1):
        tasks.append(fix_task_from_warning(index, warning, review))
    if not review.agent_ready_for_supervisor:
        tasks.append(
            DesignFixTask(
                task_id=f"fix-{len(tasks) + 1:03d}",
                title="Complete specialist agent outputs",
                source="agent-review",
                assigned_agent="orchestrator",
                rationale="The design workspace is not ready for supervisor approval until required agent outputs are drafted and reviewed.",
                required_action="Run or manually complete the pending specialist agent result files, then run `labforge agents review --write` again.",
                expected_artifacts=[".ai/outputs/*.result.yaml", ".ai/reviews/agent-review.md"],
                related_files=["agents/.ai/tasks/", "agents/.ai/outputs/"],
            )
        )
    return tasks


def fix_task_from_warning(index: int, warning: str, review: DesignReviewReport) -> DesignFixTask:
    lowered = warning.lower()
    assigned_agent = "scenario-designer"
    title = "Resolve design warning"
    required_action = "Review the warning and update the LabForge draft so the issue is resolved without adding hidden solver-only knowledge."
    expected_artifacts = ["scenario.yaml", "topology.yaml", "stages.yaml"]
    related_files = ["lab/scenario.yaml", "lab/topology.yaml", "lab/stages.yaml"]
    source = "design-review"

    if "missing industry capability" in lowered or lowered.startswith("capability:"):
        assigned_agent = "industry-realism-reviewer"
        capability = warning.split(":", 1)[-1].strip()
        capability = capability.removeprefix("Missing industry capability:").strip()
        title = f"Add realistic industry capability: {capability}"
        required_action = (
            "Update the scenario, topology, service contracts, and noise plan so the declared industry is represented by realistic services, workflows, data, and UI surfaces."
        )
        expected_artifacts = ["topology.yaml", "environment.yaml", "artifacts.yaml", "realism rationale"]
        related_files = ["lab/topology.yaml", "lab/environment.yaml", "lab/artifacts.yaml", "review/realism-report.md"]
        source = "realism-report"
    elif "expected industry network/zone" in lowered or lowered.startswith("zone:"):
        assigned_agent = "infrastructure-architect"
        zone = warning.split(":", 1)[-1].strip()
        zone = zone.removeprefix("Expected industry network/zone is not clearly represented:").strip()
        title = f"Represent missing industry zone: {zone}"
        required_action = "Revise network zones, service placement, and protected/unprotected architecture views so the missing enterprise zone is explicit."
        expected_artifacts = ["topology.yaml", "environment.yaml", "architecture diagram update"]
        related_files = ["lab/topology.yaml", "lab/environment.yaml"]
        source = "realism-report"
    elif "security" in lowered or "ids" in lowered or "siem" in lowered or "waf" in lowered:
        assigned_agent = "security-controls"
        title = "Add or refine security control coverage"
        required_action = "Map the warning to selectable security controls and update the protected architecture without changing the unprotected learning path."
        expected_artifacts = ["security-controls.yaml", "supervisor-selection.yaml", "protected architecture notes"]
        related_files = ["lab/security-controls.yaml", "lab/supervisor-selection.yaml", "lab/topology.yaml"]
    elif "service" in lowered or "healthcheck" in lowered or "artifact" in lowered:
        assigned_agent = "service-builder"
        title = "Repair service artifact or runtime contract"
        required_action = "Update service artifact contracts, healthchecks, reset behavior, and seed/noise requirements for the affected service."
        expected_artifacts = ["artifacts.yaml", "services/<service>/README.md", "healthcheck/reset contract"]
        related_files = ["lab/artifacts.yaml", "lab/services/"]
        source = "lint-report"
    elif "mitre" in lowered or "technique" in lowered or "tactic" in lowered:
        assigned_agent = "mitre-mapper"
        title = "Correct MITRE ATT&CK mapping"
        required_action = "Review the affected stage and map it to a precise ATT&CK Enterprise tactic and technique with learner-visible evidence."
        expected_artifacts = ["stages.yaml", "MITRE mapping note"]
        related_files = ["lab/stages.yaml"]

    return DesignFixTask(
        task_id=f"fix-{index:03d}",
        title=title,
        source=source,
        assigned_agent=assigned_agent,
        rationale=warning,
        required_action=required_action,
        expected_artifacts=expected_artifacts,
        related_files=related_files,
    )


def render_design_fix_tasks(report: DesignFixTaskReport) -> str:
    lines = [
        "# LabForge Design Fix Tasks",
        "",
        "## Summary",
        "",
        f"- Workspace: `{report.workspace}`",
        f"- Draft lab: `{report.lab_dir}`",
        f"- Status: `{report.status}`",
        f"- Task count: `{len(report.tasks)}`",
        "",
        "## Tasks",
        "",
        "| ID | Agent | Status | Title | Source |",
        "|---|---|---|---|---|",
    ]
    for task in report.tasks:
        lines.append(f"| `{task.task_id}` | `{task.assigned_agent}` | `{task.status}` | {task.title} | `{task.source}` |")
    for task in report.tasks:
        lines += [
            "",
            f"### {task.task_id} - {task.title}",
            "",
            f"- Assigned agent: `{task.assigned_agent}`",
            f"- Source: `{task.source}`",
            f"- Status: `{task.status}`",
            f"- Rationale: {task.rationale}",
            f"- Required action: {task.required_action}",
            "- Expected artifacts:",
        ]
        lines.extend(f"  - `{item}`" for item in task.expected_artifacts)
        lines.append("- Related files:")
        lines.extend(f"  - `{item}`" for item in task.related_files)
    lines += ["", "## Next Commands", "", "```powershell"]
    lines.extend(report.next_commands)
    lines += ["```", ""]
    return "\n".join(lines)


def design_review_status(
    *,
    validation_errors: list[str],
    lint_status: str,
    realism_status: str,
    agent_ready_for_supervisor: bool,
) -> Literal["passed", "needs-agent-output", "warning", "failed"]:
    if validation_errors or lint_status == "failed" or realism_status == "failed":
        return "failed"
    if not agent_ready_for_supervisor:
        return "needs-agent-output"
    if lint_status == "warning" or realism_status == "warning":
        return "warning"
    return "passed"


def copy_intake_context_to_lab(intake_dir: Path, lab_dir: Path, *, force: bool = False) -> list[Path]:
    names = [
        "scenario-prompt.md",
        "scenario-intake.yaml",
        "natural-language-intake-package.yaml",
        "llm-transformation-brief.md",
    ]
    written: list[Path] = []
    for name in names:
        source = intake_dir / name
        target = lab_dir / name
        if not source.exists():
            continue
        if target.exists() and not force:
            continue
        write_text(target, source.read_text(encoding="utf-8"))
        written.append(target)
    return written


def render_design_workspace_summary(result: DesignWorkspaceResult) -> str:
    lines = [
        "# LabForge Design Workspace",
        "",
        "This workspace was generated from a natural-language scenario prompt.",
        "It contains the preserved source prompt, a draft LabForge lab, an agent workspace, and dry-run execution packages.",
        "",
        "## Directories",
        "",
        f"- Intake package: `{result.intake_dir}`",
        f"- Draft lab: `{result.lab_dir}`",
        f"- Agent workspace: `{result.agent_workspace_dir}`",
        "",
        "## Agent Runtime",
        "",
        f"- Adapter: `{result.adapter}`",
        f"- Agent filter: `{result.agent or 'all agents'}`",
        "",
        "## Next Commands",
        "",
        "```powershell",
    ]
    lines.extend(result.next_commands)
    lines += ["```", ""]
    if result.validation_errors:
        lines += ["## Validation Errors", ""]
        lines.extend(f"- {error}" for error in result.validation_errors)
        lines.append("")
    else:
        lines += ["## Validation", "", "Agent workspace validation passed.", ""]
    return "\n".join(lines)


def render_design_review_report(report: DesignReviewReport) -> str:
    lines = [
        "# LabForge Design Review Report",
        "",
        "## Summary",
        "",
        f"- Workspace: `{report.workspace}`",
        f"- Draft lab: `{report.lab_dir}`",
        f"- Agent workspace: `{report.agent_workspace_dir}`",
        f"- Target industry: `{report.target_industry}`",
        f"- Status: `{report.status}`",
        f"- Lint status: `{report.lint_status}`",
        f"- Realism status: `{report.realism_status}`",
        f"- Agent ready for supervisor: `{report.agent_ready_for_supervisor}`",
        "",
        "## Artifacts",
        "",
        "| Name | Path | Purpose |",
        "|---|---|---|",
    ]
    for artifact in report.artifacts:
        lines.append(f"| `{artifact['name']}` | `{artifact['path']}` | {artifact['purpose']} |")
    lines += ["", "## Warnings", ""]
    lines.extend(f"- {warning}" for warning in report.warnings or ["No warnings."])
    lines += ["", "## Next Commands", "", "```powershell"]
    lines.extend(report.next_commands)
    lines += ["```", ""]
    return "\n".join(lines)


DESIGN_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "design-workspace-result.schema.json": DesignWorkspaceResult,
    "design-review-report.schema.json": DesignReviewReport,
    "design-fix-task-report.schema.json": DesignFixTaskReport,
}
