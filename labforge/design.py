from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .agent_orchestration import (
    create_agent_execution_packages,
    scaffold_agent_workspace,
    validate_agent_workspace,
)
from .intake import create_intake_from_prompt, scaffold_lab_from_intake
from .io import dump_yaml, write_text
from .model import LabSpec


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


DESIGN_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "design-workspace-result.schema.json": DesignWorkspaceResult,
}
