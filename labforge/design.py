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
}
