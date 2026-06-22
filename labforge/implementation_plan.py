from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .agent_orchestration import AgentExecutionPackageSpec
from .io import dump_yaml, write_text
from .model import LabSpec
from .service_artifacts import declared_service_artifacts


class ImplementationModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class ServiceImplementationTask(ImplementationModel):
    task_id: str
    service: str
    category: Literal["runtime", "seed", "noise", "healthcheck", "reset", "evidence", "safety", "tests"]
    title: str
    details: list[str] = Field(default_factory=list)
    expected_files: list[str] = Field(default_factory=list)
    done_criteria: list[str] = Field(default_factory=list)


class ServiceImplementationPlan(ImplementationModel):
    lab_id: str
    title: str
    service_count: int
    tasks: list[ServiceImplementationTask] = Field(default_factory=list)


def create_service_implementation_plan(spec: LabSpec, out: Path | None = None) -> ServiceImplementationPlan:
    tasks: list[ServiceImplementationTask] = []
    services_by_name = {str(service.get("name")): service for service in spec.services}

    for artifact in declared_service_artifacts(spec):
        service = services_by_name.get(artifact.service, {})
        base = artifact.source_path
        task_prefix = normalize_task_prefix(artifact.service)
        tasks.extend(
            [
                ServiceImplementationTask(
                    task_id=f"{task_prefix}-runtime",
                    service=artifact.service,
                    category="runtime",
                    title="Implement bounded service runtime",
                    details=[
                        f"Runtime target: {artifact.runtime}",
                        f"Purpose: {artifact.purpose}",
                        f"Declared networks: {', '.join(str(item) for item in service.get('networks', [])) or 'not declared'}",
                        f"Public exposure: {str(bool(service.get('exposed') or service.get('ports'))).lower()}",
                    ],
                    expected_files=[f"{base}/Dockerfile", f"{base}/app.py"],
                    done_criteria=[
                        "Service starts deterministically from generated provider output.",
                        "No external network dependency is required for core learner flow.",
                        "Learner-visible behavior comes from implemented logic, not static fake response text.",
                    ],
                ),
                ServiceImplementationTask(
                    task_id=f"{task_prefix}-seed",
                    service=artifact.service,
                    category="seed",
                    title="Create deterministic seed data",
                    details=list_or_default(artifact.seed_inputs, "No seed inputs were declared. Add only if the service needs initial state."),
                    expected_files=[f"{base}/{item}" for item in artifact.seed_inputs] or [f"{base}/seed/metadata.json"],
                    done_criteria=[
                        "Resetting the service restores the same initial state.",
                        "Synthetic data looks realistic enough for the scenario but contains no real secrets.",
                    ],
                ),
                ServiceImplementationTask(
                    task_id=f"{task_prefix}-noise",
                    service=artifact.service,
                    category="noise",
                    title="Add realistic noise data",
                    details=list_or_default(artifact.noise_inputs, "No noise inputs were declared. Consider whether the service feels too CTF-like without noise."),
                    expected_files=[f"{base}/{item}" for item in artifact.noise_inputs] or [f"{base}/noise/"],
                    done_criteria=[
                        "Noise does not reveal the solution directly.",
                        "Noise is plausible for the service role and does not create unintended solve paths.",
                    ],
                ),
                ServiceImplementationTask(
                    task_id=f"{task_prefix}-healthcheck",
                    service=artifact.service,
                    category="healthcheck",
                    title="Implement healthcheck",
                    details=[artifact.healthcheck],
                    expected_files=[f"{base}/healthcheck.sh"],
                    done_criteria=[
                        "Healthcheck fails when the service is not ready.",
                        "Healthcheck passes without requiring learner-only secrets.",
                    ],
                ),
                ServiceImplementationTask(
                    task_id=f"{task_prefix}-reset",
                    service=artifact.service,
                    category="reset",
                    title="Implement deterministic reset",
                    details=[artifact.reset],
                    expected_files=[f"{base}/reset.sh"],
                    done_criteria=[
                        "Reset removes learner-created transient state.",
                        "Reset preserves intended seed and noise data.",
                    ],
                ),
                ServiceImplementationTask(
                    task_id=f"{task_prefix}-evidence",
                    service=artifact.service,
                    category="evidence",
                    title="Emit evidence logs",
                    details=list_or_default(artifact.evidence_logs, "No evidence logs were declared. Add logs if instructors need traceability."),
                    expected_files=[f"{base}/{item}" for item in artifact.evidence_logs] or [f"{base}/logs/"],
                    done_criteria=[
                        "Logs support instructor review without exposing answer keys to learners.",
                        "Logs are reset or rotated according to the reset contract.",
                    ],
                ),
                ServiceImplementationTask(
                    task_id=f"{task_prefix}-safety",
                    service=artifact.service,
                    category="safety",
                    title="Enforce safety boundaries",
                    details=list_or_default(artifact.safety_boundaries, "No safety boundaries were declared. Add explicit boundaries before implementation."),
                    expected_files=[f"{base}/labforge-service.yaml"],
                    done_criteria=[
                        "Dangerous behavior is constrained to lab networks and synthetic data.",
                        "No privileged Docker socket, host filesystem escape, or uncontrolled internet callback is required.",
                    ],
                ),
                ServiceImplementationTask(
                    task_id=f"{task_prefix}-tests",
                    service=artifact.service,
                    category="tests",
                    title="Add service tests",
                    details=[
                        "Cover startup, core learner-visible behavior, reset behavior, and expected failure cases.",
                    ],
                    expected_files=[f"{base}/tests/"],
                    done_criteria=[
                        "Tests can run in CI or local smoke mode.",
                        "Tests do not require solving the full lab chain unless explicitly marked as e2e.",
                    ],
                ),
            ]
        )

    plan = ServiceImplementationPlan(
        lab_id=spec.lab_id,
        title=spec.title,
        service_count=len(list(declared_service_artifacts(spec))),
        tasks=tasks,
    )
    if out:
        write_text(out / "service-implementation-plan.yaml", dump_yaml(plan.model_dump()))
        write_text(out / "service-implementation-plan.json", implementation_plan_to_json(plan))
        write_text(out / "service-implementation-plan.md", implementation_plan_to_markdown(plan))
    return plan


def create_service_agent_packages(spec: LabSpec, out: Path, *, adapter: str = "manual") -> list[Path]:
    plan = create_service_implementation_plan(spec)
    tasks_by_service: dict[str, list[ServiceImplementationTask]] = {}
    for task in plan.tasks:
        tasks_by_service.setdefault(task.service, []).append(task)

    written: list[Path] = []
    run_dir = out / ".ai" / "service-build"
    context_files = [
        "lab.yaml",
        "scenario.yaml",
        "topology.yaml",
        "stages.yaml",
        "environment.yaml",
        "artifacts.yaml",
        "security-controls.yaml",
        "supervisor-selection.yaml",
    ]
    for artifact in declared_service_artifacts(spec):
        task_id = f"service-build-{normalize_task_prefix(artifact.service)}"
        output_file = f".ai/outputs/{task_id}.result.yaml"
        missing_context_files = [
            item
            for item in [*context_files, artifact.source_path]
            if not (spec.root / item).exists()
        ]
        task_manifest = {
            "task_id": task_id,
            "agent_id": "service-builder",
            "agent_name": "Vulnerable Service Builder Agent",
            "phase": "implementation",
            "lab_id": spec.lab_id,
            "service": artifact.service,
            "mission": f"Implement the `{artifact.service}` service according to its LabForge service artifact contract.",
            "context_files": [*context_files, artifact.source_path],
            "inputs": [
                "service artifact contract",
                "stage requirements",
                "seed and noise requirements",
                "safety boundaries",
            ],
            "expected_outputs": [
                "service source changes",
                "seed/noise data updates",
                "healthcheck/reset hooks",
                "service tests",
                "implementation notes",
            ],
            "guardrails": [
                "Keep behavior lab-scoped and deterministic.",
                "Do not add uncontrolled external callbacks.",
                "Do not mount docker.sock or host-sensitive paths.",
                "Do not replace realistic behavior with static fake response text unless the contract explicitly permits it.",
            ],
            "status": "pending",
            "assigned_runtime": adapter,
            "output_file": output_file,
            "implementation_tasks": [task.model_dump() for task in tasks_by_service.get(artifact.service, [])],
        }
        package = AgentExecutionPackageSpec(
            task_id=task_id,
            agent_id="service-builder",
            adapter=adapter,
            context_root=str(spec.root.resolve()),
            system_prompt_file="generated/service-builder.system.md",
            task_prompt_file=f"generated/{task_id}.task.md",
            task_manifest_file=f"generated/{task_id}.yaml",
            output_file=output_file,
            context_files=task_manifest["context_files"],
            missing_context_files=missing_context_files,
            system_prompt=render_service_builder_system_prompt(),
            task_prompt=render_service_builder_task_prompt(artifact, tasks_by_service.get(artifact.service, [])),
            task_manifest=task_manifest,
        )
        package_path = run_dir / f"{task_id}.package.yaml"
        write_text(package_path, dump_yaml(package.model_dump()))
        written.append(package_path)
        if adapter == "manual":
            manual_path = package_path.with_name(package_path.name.replace(".package.yaml", ".package.manual.md"))
            write_text(manual_path, render_service_agent_manual_invocation(package, package_path))
            written.append(manual_path)
        output_path = out / ".ai" / "outputs" / f"{task_id}.result.yaml"
        write_text(
            output_path,
            dump_yaml(
                {
                    "task_id": task_id,
                    "status": "not-started",
                    "summary": "",
                    "findings": [],
                    "artifacts": [],
                    "open_questions": [],
                }
            ),
        )
        written.append(output_path)
    return written


def render_service_builder_system_prompt() -> str:
    return "\n".join(
        [
            "## Role",
            "",
            "You are the LabForge Service Builder Agent.",
            "",
            "## Mission",
            "",
            "Implement one lab-scoped service from its service artifact contract and implementation task list.",
            "",
            "## Guardrails",
            "",
            "- Keep all behavior deterministic and resettable.",
            "- Keep offensive behavior inside declared lab networks and synthetic data.",
            "- Do not add uncontrolled external callbacks, privileged Docker access, or host filesystem dependencies.",
            "- Prefer realistic bounded service behavior over static fake response text.",
            "",
            "## Output Contract",
            "",
            "Write a LabForge agent result YAML containing summary, findings, artifacts, and open questions.",
            "",
        ]
    )


def render_service_builder_task_prompt(artifact: Any, tasks: list[ServiceImplementationTask]) -> str:
    lines = [
        "## Task",
        "",
        f"Implement service `{artifact.service}`.",
        "",
        "## Service Contract",
        "",
        f"- Source path: `{artifact.source_path}`",
        f"- Runtime: `{artifact.runtime}`",
        f"- Purpose: {artifact.purpose}",
        "",
        "## Implementation Tasks",
        "",
    ]
    for task in tasks:
        lines += [
            f"### `{task.task_id}`",
            "",
            f"- Category: `{task.category}`",
            f"- Title: {task.title}",
            "- Details:",
        ]
        lines.extend(f"  - {item}" for item in task.details)
        lines.append("- Done criteria:")
        lines.extend(f"  - {item}" for item in task.done_criteria)
        lines.append("")
    lines += [
        "## Done Criteria",
        "",
        "- The service starts from provider-generated output.",
        "- Healthcheck and reset scripts reflect the actual implementation.",
        "- Seed, noise, evidence logs, and tests match the contract.",
        "- Safety boundaries are enforced by code, config, or provider controls where feasible.",
        "",
    ]
    return "\n".join(lines)


def render_service_agent_manual_invocation(package: AgentExecutionPackageSpec, package_path: Path) -> str:
    return "\n".join(
        [
            f"# Manual Service Builder Invocation - {package.task_id}",
            "",
            "## Adapter",
            "",
            "- Name: `manual`",
            "- Live LLM call: no",
            f"- Package file: `{package_path.as_posix()}`",
            "",
            "## How To Use",
            "",
            "1. Start the target LLM or developer agent manually.",
            "2. Paste the system prompt below as the agent's system/developer instruction.",
            "3. Paste the task prompt and task manifest below as the user task context.",
            f"4. Implement or review only the service described by `{package.task_id}`.",
            f"5. Write the result summary to `{package.output_file}` using the LabForge agent result schema.",
            "6. Run service checks and QA smoke after implementation changes are applied.",
            "",
            "## Context Status",
            "",
            f"- Context root: `{package.context_root}`",
            f"- Missing context files: {', '.join(package.missing_context_files) if package.missing_context_files else 'none'}",
            "",
            "## System Prompt",
            "",
            "```markdown",
            package.system_prompt.rstrip(),
            "```",
            "",
            "## Task Prompt",
            "",
            "```markdown",
            package.task_prompt.rstrip(),
            "```",
            "",
            "## Task Manifest",
            "",
            "```yaml",
            dump_yaml(package.task_manifest).rstrip(),
            "```",
            "",
        ]
    )


def normalize_task_prefix(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value.lower()).strip("-")


def list_or_default(values: list[str], default: str) -> list[str]:
    return list(values) if values else [default]


def implementation_plan_to_json(plan: ServiceImplementationPlan) -> str:
    return json.dumps(plan.model_dump(), ensure_ascii=False, indent=2) + "\n"


def implementation_plan_to_markdown(plan: ServiceImplementationPlan) -> str:
    lines = [
        f"# Service Implementation Plan - {plan.title}",
        "",
        f"- Lab ID: `{plan.lab_id}`",
        f"- Service count: `{plan.service_count}`",
        f"- Task count: `{len(plan.tasks)}`",
        "",
        "## Task Matrix",
        "",
        "| Task ID | Service | Category | Title |",
        "|---|---|---|---|",
    ]
    for task in plan.tasks:
        lines.append(f"| `{task.task_id}` | `{task.service}` | `{task.category}` | {task.title} |")
    lines.append("")

    current_service = ""
    for task in plan.tasks:
        if task.service != current_service:
            current_service = task.service
            lines += [f"## `{current_service}`", ""]
        lines += [
            f"### `{task.task_id}` - {task.title}",
            "",
            "Details:",
            "",
        ]
        lines.extend(f"- {item}" for item in task.details)
        lines += ["", "Expected files:", ""]
        lines.extend(f"- `{item}`" for item in task.expected_files)
        lines += ["", "Done criteria:", ""]
        lines.extend(f"- {item}" for item in task.done_criteria)
        lines.append("")
    return "\n".join(lines)


IMPLEMENTATION_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "service-implementation-plan.schema.json": ServiceImplementationPlan,
}
