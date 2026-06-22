from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .io import dump_yaml, load_yaml, write_text
from .model import LabSpec


class AgentModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class AgentTaskSpec(AgentModel):
    task_id: str
    agent_id: str
    agent_name: str
    phase: str
    lab_id: str
    mission: str
    context_files: list[str] = Field(default_factory=list)
    inputs: list[str] = Field(default_factory=list)
    expected_outputs: list[str] = Field(default_factory=list)
    guardrails: list[str] = Field(default_factory=list)
    status: Literal["pending", "in-progress", "complete", "blocked"] = "pending"
    assigned_runtime: str = "dry-run"
    output_file: str


class AgentResultSpec(AgentModel):
    task_id: str
    status: Literal["not-started", "draft", "complete", "blocked", "needs-review"] = "not-started"
    summary: str = ""
    findings: list[dict[str, Any] | str] = Field(default_factory=list)
    artifacts: list[dict[str, Any] | str] = Field(default_factory=list)
    open_questions: list[dict[str, Any] | str] = Field(default_factory=list)


class AgentDecisionLog(AgentModel):
    items: list[dict[str, Any] | str] = Field(default_factory=list)


class AgentReviewItem(AgentModel):
    task_id: str
    agent_id: str
    phase: str
    status: str
    summary: str = ""
    findings_count: int = 0
    artifacts_count: int = 0
    open_questions_count: int = 0
    output_file: str


class AgentReviewSpec(AgentModel):
    workspace: str
    ready_for_supervisor: bool
    totals: dict[str, int] = Field(default_factory=dict)
    items: list[AgentReviewItem] = Field(default_factory=list)
    validation_errors: list[str] = Field(default_factory=list)
    open_questions: list[dict[str, Any] | str] = Field(default_factory=list)


class OrchestrationPlanSpec(AgentModel):
    lab_id: str
    title: str
    mode: str
    orchestrator: dict[str, Any]
    phases: list[dict[str, Any]]
    artifact_contract: dict[str, Any]

    @model_validator(mode="after")
    def validate_phases(self) -> "OrchestrationPlanSpec":
        agent_ids = {role.agent_id for role in DEFAULT_AGENT_ROLES}
        for phase in self.phases:
            for agent_id in phase.get("agents", []):
                if agent_id not in agent_ids:
                    raise ValueError(f"unknown agent id in phase plan: {agent_id}")
        return self


class AgentRunStepSpec(AgentModel):
    task_id: str
    agent_id: str
    phase: str
    adapter: str = "manual"
    mode: Literal["dry-run"] = "dry-run"
    status: Literal["ready", "blocked"] = "ready"
    system_prompt_file: str
    task_prompt_file: str
    task_manifest_file: str
    output_file: str
    context_files: list[str] = Field(default_factory=list)
    missing_context_files: list[str] = Field(default_factory=list)


class AgentRunPlanSpec(AgentModel):
    workspace: str
    context_root: str
    mode: Literal["dry-run"] = "dry-run"
    adapter: str = "manual"
    steps: list[AgentRunStepSpec] = Field(default_factory=list)


class AgentExecutionPackageSpec(AgentModel):
    task_id: str
    agent_id: str
    adapter: str = "manual"
    mode: Literal["dry-run"] = "dry-run"
    context_root: str
    system_prompt_file: str
    task_prompt_file: str
    task_manifest_file: str
    output_file: str
    context_files: list[str] = Field(default_factory=list)
    missing_context_files: list[str] = Field(default_factory=list)
    system_prompt: str
    task_prompt: str
    task_manifest: dict[str, Any]


@dataclass(frozen=True)
class AgentRole:
    agent_id: str
    name: str
    mission: str
    inputs: list[str]
    outputs: list[str]
    guardrails: list[str]
    phase: str


DEFAULT_AGENT_ROLES: list[AgentRole] = [
    AgentRole(
        "scenario-designer",
        "Scenario Designer Agent",
        "Convert an incident theme or scenario brief into a coherent learner stage flow.",
        ["scenario brief", "target learner level", "training objective"],
        ["scenario draft", "stage outline", "learner objective summary"],
        ["Do not write exploit commands.", "Keep the scenario educational and lab-scoped."],
        "design",
    ),
    AgentRole(
        "mitre-mapper",
        "MITRE Mapping Agent",
        "Map each stage to ATT&CK Matrix for Enterprise tactics and techniques.",
        ["stage outline", "procedure summary"],
        ["MITRE tactic/technique matrix", "mapping rationale", "coverage gaps"],
        ["Use Enterprise tactics only.", "Flag uncertain mappings instead of inventing technique IDs."],
        "design",
    ),
    AgentRole(
        "infrastructure-architect",
        "Infrastructure Architect Agent",
        "Design realistic networks, services, trust boundaries, and deployment requirements.",
        ["scenario draft", "MITRE matrix", "deployment constraints"],
        ["topology proposal", "service inventory", "network segmentation plan"],
        ["Prefer realistic enterprise patterns.", "Separate logical design from provider implementation."],
        "architecture",
    ),
    AgentRole(
        "security-controls",
        "Security Controls Agent",
        "Recommend firewall, WAF, IDS, SIEM, EDR, and logging controls for protected profiles.",
        ["topology proposal", "stage flow", "supervisor training mode"],
        ["security-controls.yaml proposal", "control placement notes", "telemetry expectations"],
        ["Controls must be lab-contained.", "Distinguish alert-only controls from enforcement controls."],
        "architecture",
    ),
    AgentRole(
        "provider-engineer",
        "Provider Engineer Agent",
        "Translate approved lab design into Docker, hybrid, Ludus, Ansible, or Terraform provider outputs.",
        ["approved topology", "provider choice", "host doctor report", "execution plan"],
        ["provider scaffold", "start/stop/reset plan", "implementation gaps"],
        ["Provider output must be deterministic.", "Do not depend on hidden LLM state at runtime."],
        "implementation",
    ),
    AgentRole(
        "service-builder",
        "Vulnerable Service Builder Agent",
        "Design and implement lab-scoped services, seed data, noise data, and health checks.",
        ["stage requirements", "service inventory", "safety constraints"],
        ["service artifact plan", "seed/noise data plan", "healthcheck plan"],
        ["No uncontrolled external callbacks.", "Dangerous behavior must stay inside lab networks."],
        "implementation",
    ),
    AgentRole(
        "content-guide",
        "Content and Guide Agent",
        "Generate student guide, instructor guide, hints, and supervisor operation notes.",
        ["approved stages", "final objective", "expected learner path"],
        ["student guide", "instructor guide", "hint ladder", "operation notes"],
        ["Separate student hints from instructor answers.", "Avoid leaking final answers in student docs."],
        "content",
    ),
    AgentRole(
        "qa-playtester",
        "QA and Playtest Agent",
        "Act like a learner and identify blockers, magic strings, unrealistic hints, and broken stage flow.",
        ["built lab", "student guide", "execution plan"],
        ["playtest report", "blocker list", "difficulty notes", "fix recommendations"],
        ["Do not read instructor answer keys during learner-path playtest.", "Report exact reproduction steps."],
        "qa",
    ),
    AgentRole(
        "safety-reviewer",
        "Safety Reviewer Agent",
        "Review isolation, egress, reset, credentials, and controlled exploit boundaries.",
        ["provider outputs", "service artifacts", "security controls"],
        ["safety review report", "required mitigations", "release gate decision"],
        ["Block uncontrolled malware-like behavior.", "Require explicit lab containment for offensive actions."],
        "qa",
    ),
]


SYSTEM_PROMPT_REQUIRED_SECTIONS = (
    "## Role",
    "## Mission",
    "## Inputs",
    "## Outputs",
    "## Guardrails",
    "## Validation Checklist",
)

TASK_PROMPT_REQUIRED_SECTIONS = (
    "## Task",
    "## Context Files",
    "## Inputs",
    "## Expected Outputs",
    "## Guardrails",
    "## Output Contract",
    "## Done Criteria",
)


def agent_role_dict(role: AgentRole) -> dict[str, Any]:
    return {
        "agent_id": role.agent_id,
        "name": role.name,
        "mission": role.mission,
        "phase": role.phase,
        "inputs": role.inputs,
        "outputs": role.outputs,
        "guardrails": role.guardrails,
    }


def roles_by_phase() -> dict[str, list[AgentRole]]:
    phases: dict[str, list[AgentRole]] = {}
    for role in DEFAULT_AGENT_ROLES:
        phases.setdefault(role.phase, []).append(role)
    return phases


def render_agent_list() -> str:
    lines = [
        "# LabForge Agent Roles",
        "",
        "| Agent | Phase | Mission |",
        "|---|---|---|",
    ]
    for role in DEFAULT_AGENT_ROLES:
        lines.append(f"| `{role.agent_id}` | {role.phase} | {role.mission} |")
    lines.append("")
    return "\n".join(lines)


def orchestration_manifest(spec: LabSpec) -> dict[str, Any]:
    return {
        "lab_id": spec.lab_id,
        "title": spec.title,
        "mode": "dry-run",
        "orchestrator": {
            "role": "Coordinate specialist agents, merge outputs, and pass only validated artifacts to LabForge core.",
            "human_supervisor_gate": True,
        },
        "phases": [
            {
                "id": phase,
                "agents": [role.agent_id for role in roles],
            }
            for phase, roles in roles_by_phase().items()
        ],
        "artifact_contract": {
            "prompts_dir": ".ai/prompts",
            "task_prompts_dir": ".ai/prompts/tasks",
            "tasks_dir": ".ai/tasks",
            "outputs_dir": ".ai/outputs",
            "decisions_dir": ".ai/decisions",
            "llm_runtime": "not-configured",
            "rule": "Dry-run scaffolds prompts, tasks, and output contracts only. LLM adapters must be explicitly configured later.",
        },
    }


def task_manifest(spec: LabSpec, role: AgentRole, order: int) -> dict[str, Any]:
    return {
        "task_id": f"{order:02d}-{role.agent_id}",
        "agent_id": role.agent_id,
        "agent_name": role.name,
        "phase": role.phase,
        "lab_id": spec.lab_id,
        "mission": role.mission,
        "context_files": [
            "scenario.yaml",
            "topology.yaml",
            "stages.yaml",
            "lab.yaml",
            "environment.yaml",
            "artifacts.yaml",
            "security-controls.yaml",
            "supervisor-selection.yaml",
            "providers/",
        ],
        "inputs": role.inputs,
        "expected_outputs": role.outputs,
        "guardrails": role.guardrails,
        "status": "pending",
        "assigned_runtime": "dry-run",
        "output_file": f".ai/outputs/{order:02d}-{role.agent_id}.result.yaml",
    }


def scaffold_agent_workspace(spec: LabSpec, out: Path) -> list[Path]:
    written: list[Path] = []
    base = out / ".ai"
    prompts = base / "prompts"
    task_prompts = prompts / "tasks"
    tasks = base / "tasks"
    outputs = base / "outputs"
    decisions = base / "decisions"

    manifest_path = base / "orchestration-plan.yaml"
    write_text(manifest_path, dump_yaml(orchestration_manifest(spec)))
    written.append(manifest_path)

    readme_path = base / "README.md"
    write_text(readme_path, render_agent_workspace_readme(spec))
    written.append(readme_path)

    orchestrator_prompt = prompts / "orchestrator.system.md"
    write_text(orchestrator_prompt, render_orchestrator_prompt(spec))
    written.append(orchestrator_prompt)

    for order, role in enumerate(DEFAULT_AGENT_ROLES, start=1):
        prompt_path = prompts / f"{order:02d}-{role.agent_id}.system.md"
        write_text(prompt_path, render_agent_system_prompt(spec, role))
        written.append(prompt_path)

        task_prompt_path = task_prompts / f"{order:02d}-{role.agent_id}.task.md"
        write_text(task_prompt_path, render_agent_task_prompt(spec, role, order))
        written.append(task_prompt_path)

        task_path = tasks / f"{order:02d}-{role.agent_id}.yaml"
        write_text(task_path, dump_yaml(task_manifest(spec, role, order)))
        written.append(task_path)

        output_path = outputs / f"{order:02d}-{role.agent_id}.result.yaml"
        write_text(
            output_path,
            dump_yaml(
                {
                    "task_id": f"{order:02d}-{role.agent_id}",
                    "status": "not-started",
                    "summary": "",
                    "findings": [],
                    "artifacts": [],
                    "open_questions": [],
                }
            ),
        )
        written.append(output_path)

    for name in ("accepted.yaml", "rejected.yaml", "open-questions.yaml"):
        path = decisions / name
        write_text(path, dump_yaml({"items": []}))
        written.append(path)

    return written


def render_agent_workspace_readme(spec: LabSpec) -> str:
    return "\n".join(
        [
            f"# Agent Workspace - {spec.title}",
            "",
            "This workspace is a dry-run scaffold for future LLM orchestration.",
            "No LLM is called by this command.",
            "",
            "## Directories",
            "",
            "- `orchestration-plan.yaml`: orchestrator-level phase plan",
            "- `prompts/`: system prompts for the orchestrator and specialist agents",
            "- `prompts/tasks/`: task prompts for specialist agent execution",
            "- `tasks/`: specialist agent task manifests",
            "- `outputs/`: placeholder result files each agent must fill",
            "- `decisions/`: accepted, rejected, and open decision records",
            "",
            "## Rule",
            "",
            "Agent outputs are intermediate artifacts. LabForge core should consume only validated and supervisor-approved outputs.",
            "",
        ]
    )


def render_orchestrator_prompt(spec: LabSpec) -> str:
    return "\n".join(
        [
            "# LabForge Orchestrator System Prompt",
            "",
            "## Role",
            "",
            "You are the LabForge Orchestrator. Coordinate specialist agents, preserve the approved lab architecture, and pass only validated artifacts back to LabForge core.",
            "",
            "## Mission",
            "",
            f"Build and review lab artifacts for `{spec.lab_id}`: {spec.title}.",
            "Turn human-approved scenario intent into deterministic LabForge files, provider outputs, service contracts, and reviewable decisions.",
            "",
            "## Inputs",
            "",
            "- scenario.yaml",
            "- topology.yaml",
            "- stages.yaml",
            "- lab.yaml",
            "- environment.yaml",
            "- artifacts.yaml",
            "- security-controls.yaml",
            "- supervisor-selection.yaml",
            "- provider outputs",
            "- specialist task results",
            "",
            "## Outputs",
            "",
            "- accepted decision records",
            "- rejected decision records",
            "- open questions for human supervisor review",
            "- merged implementation plan",
            "- QA and safety gate status",
            "",
            "## Guardrails",
            "",
            "- Do not silently change the scenario objective or final target.",
            "- Do not accept agent output that violates LabForge open-source portability rules.",
            "- Do not accept uncontrolled external callbacks, real malware behavior, or non-lab-scoped offensive actions.",
            "- Do not merge artifacts that fail schema, service-check, provider, QA, or safety review.",
            "- Keep supervisor gates explicit when design choices affect realism, safety, cost, or required infrastructure.",
            "",
            "## Validation Checklist",
            "",
            "- Required LabForge files exist and validate.",
            "- Every stage maps to MITRE ATT&CK Matrix for Enterprise tactic and technique.",
            "- Service artifacts have healthcheck, reset, evidence logs, and safety boundaries.",
            "- Provider choice matches deployment requirements.",
            "- Protected and unprotected architectures are both reviewable.",
            "- Human supervisor decisions are recorded before implementation proceeds.",
            "",
        ]
    )


def render_agent_system_prompt(spec: LabSpec, role: AgentRole) -> str:
    lines = [
        f"# {role.name} System Prompt",
        "",
        "## Role",
        "",
        f"You are `{role.agent_id}`, a specialist agent in the LabForge workflow.",
        "",
        "## Mission",
        "",
        role.mission,
        "",
        "## Inputs",
        "",
    ]
    lines.extend(f"- {item}" for item in role.inputs)
    lines += [
        "",
        "Relevant LabForge context files may include:",
        "",
        "- scenario.yaml",
        "- topology.yaml",
        "- stages.yaml",
        "- lab.yaml",
        "- environment.yaml",
        "- artifacts.yaml",
        "- security-controls.yaml",
        "- supervisor-selection.yaml",
        "- providers/",
        "",
        "## Outputs",
        "",
    ]
    lines.extend(f"- {item}" for item in role.outputs)
    lines += [
        "",
        "Write results only through the assigned `.ai/outputs/<task>.result.yaml` contract unless the orchestrator explicitly requests a patch.",
        "",
        "## Guardrails",
        "",
    ]
    lines.extend(f"- {item}" for item in role.guardrails)
    lines += [
        "- Follow the LabForge Open Source Constitution.",
        "- Keep all offensive behavior educational, authorized, synthetic, and lab-scoped.",
        "- Prefer explicit uncertainty over invented facts, tools, CVEs, or MITRE technique IDs.",
        "- Do not modify provider outputs directly unless your role is provider-engineer or the orchestrator assigns that task.",
        "",
        "## Validation Checklist",
        "",
        "- Inputs were read from declared context files.",
        "- Outputs match the assigned task manifest.",
        "- Any assumption is recorded as an open question.",
        "- Safety and portability constraints are preserved.",
        "- The result can be reviewed by a human supervisor.",
        "",
        "## Lab Context",
        "",
        f"- Lab ID: `{spec.lab_id}`",
        f"- Title: {spec.title}",
        f"- Phase: `{role.phase}`",
        "",
    ]
    return "\n".join(lines)


def render_agent_task_prompt(spec: LabSpec, role: AgentRole, order: int) -> str:
    task_id = f"{order:02d}-{role.agent_id}"
    task_file = f".ai/tasks/{task_id}.yaml"
    output_file = f".ai/outputs/{task_id}.result.yaml"
    lines = [
        f"# {role.name} Task Prompt",
        "",
        "## Task",
        "",
        f"Complete task `{task_id}` for lab `{spec.lab_id}`.",
        role.mission,
        "",
        "Use this task prompt together with the matching system prompt and task manifest.",
        "",
        "## Context Files",
        "",
        f"- Task manifest: `{task_file}`",
        "- Scenario definition files in the LabForge scenario directory",
        "- Provider, environment, security-control, and artifact definitions when present",
        "- Existing generated outputs only when the orchestrator explicitly marks them as inputs",
        "",
        "## Inputs",
        "",
    ]
    lines.extend(f"- {item}" for item in role.inputs)
    lines += [
        "",
        "## Expected Outputs",
        "",
    ]
    lines.extend(f"- {item}" for item in role.outputs)
    lines += [
        "",
        "## Guardrails",
        "",
    ]
    lines.extend(f"- {item}" for item in role.guardrails)
    lines += [
        "- Preserve the approved scenario objective, final target, and safety boundary.",
        "- Keep assumptions explicit and route unresolved decisions to the human supervisor.",
        "- Do not introduce host-specific paths, private infrastructure names, or fixed local runtime assumptions.",
        "- Keep generated internal contracts, prompts, schemas, and code in English.",
        "",
        "## Output Contract",
        "",
        f"- Write the primary result to `{output_file}`.",
        "- Keep `task_id` unchanged.",
        "- Set `status` to one of `not-started`, `draft`, `complete`, `blocked`, or `needs-review`.",
        "- Put reviewable evidence, generated files, and open questions in the matching YAML fields.",
        "- Do not write directly to LabForge core files unless the orchestrator asks for a patch.",
        "",
        "## Done Criteria",
        "",
        "- Required inputs were read or explicitly marked unavailable.",
        "- Expected outputs are complete enough for human review.",
        "- Safety, portability, and provider constraints are preserved.",
        "- Any ambiguity is captured in `open_questions`.",
        "- The output validates against the LabForge agent result schema.",
        "",
    ]
    return "\n".join(lines)


def agent_workspace_root(path: Path) -> Path:
    path = path.resolve()
    return path if path.name == ".ai" else path / ".ai"


def pydantic_errors(prefix: str, exc: ValidationError) -> list[str]:
    return [
        f"{prefix}: {'.'.join(str(item) for item in error['loc'])}: {error['msg']}"
        for error in exc.errors()
    ]


def workspace_relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root.parent).as_posix()
    except ValueError:
        return path.as_posix()


def task_file_id(path: Path) -> str:
    name = path.name
    return name.removesuffix(".yaml")


def create_agent_run_plan(
    path: Path,
    *,
    adapter: str = "manual",
    context_root: Path | None = None,
) -> AgentRunPlanSpec:
    root = agent_workspace_root(path)
    resolved_context_root = (context_root or root.parent).resolve()
    tasks_dir = root / "tasks"
    prompts_dir = root / "prompts"
    task_prompts_dir = prompts_dir / "tasks"
    steps: list[AgentRunStepSpec] = []

    for task_path in sorted(tasks_dir.glob("*.yaml")):
        task = AgentTaskSpec.model_validate(load_yaml(task_path))
        order_prefix = task.task_id.split("-", 1)[0]
        system_prompt_file = prompts_dir / f"{order_prefix}-{task.agent_id}.system.md"
        task_prompt_file = task_prompts_dir / f"{task.task_id}.task.md"
        output_path = root.parent / task.output_file
        missing_context_files = [
            item
            for item in task.context_files
            if not (resolved_context_root / item).exists()
        ]
        missing_required = [
            path
            for path in (system_prompt_file, task_prompt_file, output_path)
            if not path.exists()
        ]
        status: Literal["ready", "blocked"] = "blocked" if missing_required else "ready"
        steps.append(
            AgentRunStepSpec(
                task_id=task.task_id,
                agent_id=task.agent_id,
                phase=task.phase,
                adapter=adapter,
                status=status,
                system_prompt_file=workspace_relative(root, system_prompt_file),
                task_prompt_file=workspace_relative(root, task_prompt_file),
                task_manifest_file=workspace_relative(root, task_path),
                output_file=task.output_file,
                context_files=task.context_files,
                missing_context_files=missing_context_files,
            )
        )

    return AgentRunPlanSpec(
        workspace=str(root),
        context_root=str(resolved_context_root),
        adapter=adapter,
        steps=steps,
    )


def run_plan_to_json(plan: AgentRunPlanSpec) -> str:
    return json.dumps(plan.model_dump(), ensure_ascii=False, indent=2) + "\n"


def run_plan_to_markdown(plan: AgentRunPlanSpec) -> str:
    lines = [
        "# Agent Run Plan",
        "",
        f"- Workspace: `{plan.workspace}`",
        f"- Context root: `{plan.context_root}`",
        f"- Mode: `{plan.mode}`",
        f"- Adapter: `{plan.adapter}`",
        "",
        "| Order | Task | Agent | Phase | Status | Missing Context |",
        "|---:|---|---|---|---|---|",
    ]
    for order, step in enumerate(plan.steps, start=1):
        missing = ", ".join(step.missing_context_files) if step.missing_context_files else "-"
        lines.append(
            f"| {order} | `{step.task_id}` | `{step.agent_id}` | {step.phase} | {step.status} | {missing} |"
        )
    lines.append("")
    lines.append("This is an execution readiness plan only. No LLM call is performed.")
    lines.append("")
    return "\n".join(lines)


def create_agent_execution_packages(
    path: Path,
    *,
    adapter: str = "manual",
    agent_id: str | None = None,
    context_root: Path | None = None,
) -> list[Path]:
    root = agent_workspace_root(path)
    validate_errors = validate_agent_workspace(root)
    if validate_errors:
        raise ValueError("agent workspace validation failed before run package creation")

    run_dir = root / "run"
    plan = create_agent_run_plan(root, adapter=adapter, context_root=context_root)
    written: list[Path] = []
    plan_path = run_dir / "run-plan.yaml"
    write_text(plan_path, dump_yaml(plan.model_dump()))
    written.append(plan_path)

    for step in plan.steps:
        if agent_id and step.agent_id != agent_id:
            continue
        system_prompt_path = root.parent / step.system_prompt_file
        task_prompt_path = root.parent / step.task_prompt_file
        task_manifest_path = root.parent / step.task_manifest_file
        task_manifest = load_yaml(task_manifest_path)
        package = AgentExecutionPackageSpec(
            task_id=step.task_id,
            agent_id=step.agent_id,
            adapter=adapter,
            context_root=plan.context_root,
            system_prompt_file=step.system_prompt_file,
            task_prompt_file=step.task_prompt_file,
            task_manifest_file=step.task_manifest_file,
            output_file=step.output_file,
            context_files=step.context_files,
            missing_context_files=step.missing_context_files,
            system_prompt=system_prompt_path.read_text(encoding="utf-8"),
            task_prompt=task_prompt_path.read_text(encoding="utf-8"),
            task_manifest=task_manifest,
        )
        package_path = run_dir / f"{step.task_id}.package.yaml"
        write_text(package_path, dump_yaml(package.model_dump()))
        written.append(package_path)

    return written


def create_agent_review(path: Path) -> AgentReviewSpec:
    root = agent_workspace_root(path)
    validation_errors = validate_agent_workspace(root)
    tasks: dict[str, AgentTaskSpec] = {}
    for task_path in sorted((root / "tasks").glob("*.yaml")):
        try:
            task = AgentTaskSpec.model_validate(load_yaml(task_path))
        except (ValidationError, ValueError):
            continue
        tasks[task.task_id] = task

    items: list[AgentReviewItem] = []
    open_questions: list[dict[str, Any] | str] = []
    totals: dict[str, int] = {}
    for output_path in sorted((root / "outputs").glob("*.result.yaml")):
        try:
            result = AgentResultSpec.model_validate(load_yaml(output_path))
        except (ValidationError, ValueError):
            continue
        task = tasks.get(result.task_id)
        status = result.status
        totals[status] = totals.get(status, 0) + 1
        open_questions.extend(result.open_questions)
        items.append(
            AgentReviewItem(
                task_id=result.task_id,
                agent_id=task.agent_id if task else "unknown",
                phase=task.phase if task else "unknown",
                status=status,
                summary=result.summary,
                findings_count=len(result.findings),
                artifacts_count=len(result.artifacts),
                open_questions_count=len(result.open_questions),
                output_file=workspace_relative(root, output_path),
            )
        )

    blocking_statuses = {"not-started", "blocked"}
    ready_for_supervisor = (
        not validation_errors
        and bool(items)
        and all(item.status not in blocking_statuses for item in items)
    )
    return AgentReviewSpec(
        workspace=str(root),
        ready_for_supervisor=ready_for_supervisor,
        totals=totals,
        items=items,
        validation_errors=validation_errors,
        open_questions=open_questions,
    )


def review_to_json(review: AgentReviewSpec) -> str:
    return json.dumps(review.model_dump(), ensure_ascii=False, indent=2) + "\n"


def review_to_markdown(review: AgentReviewSpec) -> str:
    lines = [
        "# Agent Review",
        "",
        f"- Workspace: `{review.workspace}`",
        f"- Ready for supervisor: `{str(review.ready_for_supervisor).lower()}`",
        "",
        "## Totals",
        "",
    ]
    if review.totals:
        for status, count in sorted(review.totals.items()):
            lines.append(f"- `{status}`: {count}")
    else:
        lines.append("- No agent result files found.")
    lines += [
        "",
        "## Results",
        "",
        "| Task | Agent | Phase | Status | Findings | Artifacts | Open Questions |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    for item in review.items:
        lines.append(
            f"| `{item.task_id}` | `{item.agent_id}` | {item.phase} | {item.status} | "
            f"{item.findings_count} | {item.artifacts_count} | {item.open_questions_count} |"
        )
    if review.validation_errors:
        lines += [
            "",
            "## Validation Errors",
            "",
        ]
        lines.extend(f"- {error}" for error in review.validation_errors)
    if review.open_questions:
        lines += [
            "",
            "## Open Questions",
            "",
        ]
        lines.extend(f"- {question}" for question in review.open_questions)
    lines.append("")
    return "\n".join(lines)


def write_agent_review(path: Path) -> list[Path]:
    root = agent_workspace_root(path)
    review = create_agent_review(root)
    review_dir = root / "reviews"
    yaml_path = review_dir / "agent-review.yaml"
    markdown_path = review_dir / "agent-review.md"
    write_text(yaml_path, dump_yaml(review.model_dump()))
    write_text(markdown_path, review_to_markdown(review))
    return [yaml_path, markdown_path]


def append_agent_decision(
    path: Path,
    *,
    decision: Literal["accepted", "rejected", "open-questions"],
    task_id: str,
    reason: str,
) -> Path:
    root = agent_workspace_root(path)
    decision_path = root / "decisions" / f"{decision}.yaml"
    log = AgentDecisionLog.model_validate(load_yaml(decision_path))
    log.items.append(
        {
            "task_id": task_id,
            "reason": reason,
        }
    )
    write_text(decision_path, dump_yaml(log.model_dump()))
    return decision_path


def write_agent_result_stub(
    path: Path,
    *,
    task_id: str,
    status: Literal["not-started", "draft", "complete", "blocked", "needs-review"],
    summary: str,
) -> Path:
    root = agent_workspace_root(path)
    task_path = root / "tasks" / f"{task_id}.yaml"
    if not task_path.exists():
        raise FileNotFoundError(f"unknown task id or missing task manifest: {task_id}")
    task = AgentTaskSpec.model_validate(load_yaml(task_path))
    output_path = root.parent / task.output_file
    existing = load_yaml(output_path) if output_path.exists() else {"task_id": task_id}
    existing["task_id"] = task_id
    existing["status"] = status
    existing["summary"] = summary
    existing.setdefault("findings", [])
    existing.setdefault("artifacts", [])
    existing.setdefault("open_questions", [])
    result = AgentResultSpec.model_validate(existing)
    write_text(output_path, dump_yaml(result.model_dump()))
    return output_path


def validate_agent_workspace(path: Path) -> list[str]:
    errors: list[str] = []
    root = agent_workspace_root(path)
    if not root.exists():
        return [f"agent workspace not found: {root}"]

    plan_path = root / "orchestration-plan.yaml"
    if not plan_path.exists():
        errors.append(f"missing orchestration plan: {plan_path}")
    else:
        try:
            OrchestrationPlanSpec.model_validate(load_yaml(plan_path))
        except ValidationError as exc:
            errors.extend(pydantic_errors(str(plan_path), exc))
        except ValueError as exc:
            errors.append(f"{plan_path}: {exc}")

    task_dir = root / "tasks"
    prompt_dir = root / "prompts"
    task_prompt_dir = prompt_dir / "tasks"
    output_dir = root / "outputs"
    decision_dir = root / "decisions"
    for directory in (prompt_dir, task_prompt_dir, task_dir, output_dir, decision_dir):
        if not directory.exists():
            errors.append(f"missing directory: {directory}")

    known_agents = {role.agent_id for role in DEFAULT_AGENT_ROLES}
    expected_prompts = {"orchestrator.system.md"} | {
        f"{order:02d}-{role.agent_id}.system.md"
        for order, role in enumerate(DEFAULT_AGENT_ROLES, start=1)
    }
    if prompt_dir.exists():
        found_prompts = {path.name for path in prompt_dir.glob("*.md")}
        for name in sorted(expected_prompts - found_prompts):
            errors.append(f"missing agent prompt: {prompt_dir / name}")
        for prompt_path in sorted(prompt_dir.glob("*.md")):
            text = prompt_path.read_text(encoding="utf-8")
            for section in SYSTEM_PROMPT_REQUIRED_SECTIONS:
                if section not in text:
                    errors.append(f"{prompt_path}: missing prompt section {section}")
    expected_task_prompts = {
        f"{order:02d}-{role.agent_id}.task.md"
        for order, role in enumerate(DEFAULT_AGENT_ROLES, start=1)
    }
    if task_prompt_dir.exists():
        found_task_prompts = {path.name for path in task_prompt_dir.glob("*.md")}
        for name in sorted(expected_task_prompts - found_task_prompts):
            errors.append(f"missing agent task prompt: {task_prompt_dir / name}")
        for prompt_path in sorted(task_prompt_dir.glob("*.md")):
            text = prompt_path.read_text(encoding="utf-8")
            for section in TASK_PROMPT_REQUIRED_SECTIONS:
                if section not in text:
                    errors.append(f"{prompt_path}: missing task prompt section {section}")

    task_ids: set[str] = set()
    if task_dir.exists():
        for task_path in sorted(task_dir.glob("*.yaml")):
            try:
                task = AgentTaskSpec.model_validate(load_yaml(task_path))
            except ValidationError as exc:
                errors.extend(pydantic_errors(str(task_path), exc))
                continue
            except ValueError as exc:
                errors.append(f"{task_path}: {exc}")
                continue
            task_ids.add(task.task_id)
            if task.agent_id not in known_agents:
                errors.append(f"{task_path}: unknown agent_id {task.agent_id}")
            output_path = root.parent / task.output_file
            if not output_path.exists():
                errors.append(f"{task_path}: referenced output file missing: {task.output_file}")

    if output_dir.exists():
        for output_path in sorted(output_dir.glob("*.yaml")):
            try:
                result = AgentResultSpec.model_validate(load_yaml(output_path))
            except ValidationError as exc:
                errors.extend(pydantic_errors(str(output_path), exc))
                continue
            except ValueError as exc:
                errors.append(f"{output_path}: {exc}")
                continue
            if task_ids and result.task_id not in task_ids:
                errors.append(f"{output_path}: result references unknown task_id {result.task_id}")

    expected_decisions = {"accepted.yaml", "rejected.yaml", "open-questions.yaml"}
    if decision_dir.exists():
        for name in expected_decisions:
            decision_path = decision_dir / name
            if not decision_path.exists():
                errors.append(f"missing decision log: {decision_path}")
                continue
            try:
                AgentDecisionLog.model_validate(load_yaml(decision_path))
            except ValidationError as exc:
                errors.extend(pydantic_errors(str(decision_path), exc))
            except ValueError as exc:
                errors.append(f"{decision_path}: {exc}")

    return errors


AGENT_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "agent-task.schema.json": AgentTaskSpec,
    "agent-result.schema.json": AgentResultSpec,
    "agent-decision-log.schema.json": AgentDecisionLog,
    "agent-review.schema.json": AgentReviewSpec,
    "orchestration-plan.schema.json": OrchestrationPlanSpec,
    "agent-run-plan.schema.json": AgentRunPlanSpec,
    "agent-execution-package.schema.json": AgentExecutionPackageSpec,
}
