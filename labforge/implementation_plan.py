from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .agent_orchestration import AgentExecutionPackageSpec
from .io import dump_yaml, write_text
from .model import LabSpec
from .service_blueprints import create_service_blueprints
from .service_artifacts import declared_service_artifacts
from .vulnerability_plugins import declared_vulnerability_plugins, get_vulnerability_plugin, normalize_template_id


class ImplementationModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class ServiceImplementationTask(ImplementationModel):
    task_id: str
    service: str
    category: Literal["blueprint", "runtime", "api", "workflow", "data", "vulnerability", "seed", "noise", "healthcheck", "reset", "evidence", "safety", "tests"]
    title: str
    details: list[str] = Field(default_factory=list)
    expected_files: list[str] = Field(default_factory=list)
    done_criteria: list[str] = Field(default_factory=list)


class ServiceImplementationPlan(ImplementationModel):
    lab_id: str
    title: str
    service_count: int
    tasks: list[ServiceImplementationTask] = Field(default_factory=list)


def vulnerability_plugin_contract_paths(artifact: Any) -> list[str]:
    paths: list[str] = []
    for item in declared_vulnerability_plugins(artifact):
        plugin_id = str(item.get("id", "")).strip()
        if plugin_id:
            paths.append(f"{artifact.source_path}/plugins/{normalize_template_id(plugin_id)}.contract.yaml")
    return paths


def vulnerability_plugin_context(artifact: Any) -> list[dict[str, Any]]:
    context: list[dict[str, Any]] = []
    for item in declared_vulnerability_plugins(artifact):
        plugin_id = str(item.get("id", "")).strip()
        plugin = get_vulnerability_plugin(plugin_id) if plugin_id else None
        if plugin:
            context.append(
                {
                    "id": plugin.plugin_id,
                    "description": plugin.description,
                    "mitre_tactics": list(plugin.mitre_tactics),
                    "mitre_techniques": list(plugin.mitre_techniques),
                    "scenario_must_define": list(plugin.scenario_must_define),
                    "safety_boundaries": list(plugin.safety_boundaries),
                    "required_config_keys": list(plugin.required_config_keys),
                    "implementation_requirements": list(plugin.implementation_requirements),
                    "verification_hints": list(plugin.verification_hints),
                    "configured_by_scenario": item,
                }
            )
        elif plugin_id:
            context.append(
                {
                    "id": plugin_id,
                    "description": "Unknown vulnerability plugin. Supervisor review required.",
                    "configured_by_scenario": item,
                    "review_required": True,
                }
            )
    return context


def create_service_implementation_plan(spec: LabSpec, out: Path | None = None) -> ServiceImplementationPlan:
    tasks: list[ServiceImplementationTask] = []
    services_by_name = {str(service.get("name")): service for service in spec.services}
    blueprints_by_service = {blueprint.service: blueprint for blueprint in create_service_blueprints(spec).blueprints}

    for artifact in declared_service_artifacts(spec):
        service = services_by_name.get(artifact.service, {})
        blueprint = blueprints_by_service.get(artifact.service)
        base = artifact.source_path
        task_prefix = normalize_task_prefix(artifact.service)
        tasks.extend(
            [
                ServiceImplementationTask(
                    task_id=f"{task_prefix}-blueprint",
                    service=artifact.service,
                    category="blueprint",
                    title="Review service blueprint",
                    details=[
                        f"Blueprint role: {blueprint.role if blueprint else 'not generated'}",
                        f"Template: {blueprint.template if blueprint else 'not generated'}",
                        f"Normal workflows: {len(blueprint.normal_workflows) if blueprint else 0}",
                    ],
                    expected_files=[f"{base}/blueprint.yaml"],
                    done_criteria=[
                        "Blueprint explains the business role, API surface, data stores, normal workflows, and safety boundaries.",
                        "Implementation follows the blueprint unless the supervisor explicitly approves a change.",
                    ],
                ),
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
                    task_id=f"{task_prefix}-api",
                    service=artifact.service,
                    category="api",
                    title="Implement realistic API and UI routes",
                    details=[f"{route.method} {route.path}: {route.purpose} (auth: {route.auth})" for route in (blueprint.routes if blueprint else [])]
                    or ["No blueprint routes were generated. Define service-specific routes before implementation."],
                    expected_files=[f"{base}/app.py", f"{base}/tests/"],
                    done_criteria=[
                        "Routes reflect normal business or operator workflows.",
                        "Routes avoid solver-facing names such as flag, exploit, foothold, or stage.",
                        "Authentication and authorization assumptions are explicit, even when intentionally weak for the lab.",
                    ],
                ),
                ServiceImplementationTask(
                    task_id=f"{task_prefix}-workflow",
                    service=artifact.service,
                    category="workflow",
                    title="Implement normal user workflow",
                    details=[f"{workflow.name}: {' -> '.join(workflow.steps)}" for workflow in (blueprint.normal_workflows if blueprint else [])]
                    or ["No normal workflow was generated. Define at least one ordinary business workflow."],
                    expected_files=[f"{base}/app.py", f"{base}/seed/", f"{base}/noise/"],
                    done_criteria=[
                        "A user can perform a normal non-attack workflow against the service.",
                        "Business data changes are logged or reflected in state where appropriate.",
                    ],
                ),
                ServiceImplementationTask(
                    task_id=f"{task_prefix}-data",
                    service=artifact.service,
                    category="data",
                    title="Implement data model and storage",
                    details=[f"{store.name} ({store.kind}): {store.purpose}" for store in (blueprint.data_stores if blueprint else [])]
                    or ["No data store blueprint was generated. Define files, database tables, or in-memory state."],
                    expected_files=[f"{base}/seed/", f"{base}/noise/", f"{base}/app.py"],
                    done_criteria=[
                        "Data model supports the normal workflow and the intended lab chain.",
                        "Seed and noise data are deterministic, synthetic, and realistic for the service role.",
                    ],
                ),
                *vulnerability_plugin_tasks(artifact, base, task_prefix),
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


def vulnerability_plugin_tasks(artifact: Any, base: str, task_prefix: str) -> list[ServiceImplementationTask]:
    tasks: list[ServiceImplementationTask] = []
    for declared in declared_vulnerability_plugins(artifact):
        plugin_id = str(declared.get("id", "")).strip()
        plugin = get_vulnerability_plugin(plugin_id) if plugin_id else None
        normalized = normalize_template_id(plugin_id or "unknown-plugin")
        if plugin:
            details = [
                f"Plugin: {plugin.plugin_id}",
                f"MITRE techniques: {', '.join(plugin.mitre_techniques)}",
                "Required scenario config:",
                *[f"{key}: {declared.get(key, '<missing>')}" for key in plugin.required_config_keys],
                "Implementation requirements:",
                *plugin.implementation_requirements,
            ]
            done_criteria = [
                "Normal business workflow exists before the vulnerable behavior is useful.",
                "Vulnerable behavior is scenario-specific and bounded by the plugin safety contract.",
                "Evidence logs capture normal, denied, and vulnerable-path activity where relevant.",
                "Tests cover at least one normal case and one plugin-specific scenario case.",
            ]
        else:
            details = [f"Unknown plugin: {plugin_id or '<missing>'}", "Supervisor review is required before implementation."]
            done_criteria = ["Do not implement unknown vulnerability behavior until the supervisor approves the contract."]
        tasks.append(
            ServiceImplementationTask(
                task_id=f"{task_prefix}-vuln-{normalized}",
                service=artifact.service,
                category="vulnerability",
                title=f"Implement vulnerability plugin contract `{plugin_id or 'unknown'}`",
                details=details,
                expected_files=[
                    f"{base}/plugins/{normalized}.contract.yaml",
                    f"{base}/app.py",
                    f"{base}/tests/",
                ],
                done_criteria=done_criteria,
            )
        )
    return tasks


def create_service_agent_packages(spec: LabSpec, out: Path, *, adapter: str = "manual", baseline_from_runtime: bool = False) -> list[Path]:
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
        plugin_contracts = vulnerability_plugin_contract_paths(artifact)
        blueprint_context = f"{artifact.source_path}/blueprint.yaml"
        missing_context_files = [
            item
            for item in [*context_files, artifact.source_path, blueprint_context, *plugin_contracts]
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
            "context_files": [*context_files, artifact.source_path, blueprint_context, *plugin_contracts],
            "inputs": [
                "service artifact contract",
                "service blueprint",
                "vulnerability plugin contracts",
                "stage requirements",
                "seed and noise requirements",
                "safety boundaries",
            ],
            "expected_outputs": [
                "implemented routes/API surface",
                "normal workflow behavior",
                "data model and seed records",
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
            "blueprint_file": blueprint_context,
            "vulnerability_plugins": vulnerability_plugin_context(artifact),
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
            task_prompt=render_service_builder_task_prompt(
                artifact,
                tasks_by_service.get(artifact.service, []),
                vulnerability_plugin_context(artifact),
            ),
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
        result_payload = service_agent_result_stub(task_id, artifact)
        if baseline_from_runtime:
            result_payload = baseline_service_result_from_runtime(spec, task_id, artifact)
        write_text(output_path, dump_yaml(result_payload))
        written.append(output_path)
    return written


def service_agent_result_stub(task_id: str, artifact: Any) -> dict:
    return {
        "task_id": task_id,
        "status": "needs-review",
        "service": artifact.service,
        "summary": "",
        "implemented_routes": [],
        "data_model": [],
        "normal_workflows": [],
        "vulnerable_paths": [],
        "detection_evidence": [],
        "healthcheck_behavior": "",
        "reset_behavior": "",
        "service_changes": [],
        "findings": [],
        "open_questions": [],
    }


def baseline_service_result_from_runtime(spec: LabSpec, task_id: str, artifact: Any) -> dict:
    service_root = spec.root / artifact.source_path
    runtime_files = [name for name in ("Dockerfile", "app.py", "healthcheck.sh", "reset.sh") if (service_root / name).exists()]
    if not runtime_files:
        result = service_agent_result_stub(task_id, artifact)
        result["summary"] = "Runtime baseline could not be generated because no materialized runtime files were found."
        return result

    return {
        "task_id": task_id,
        "status": "complete",
        "service": artifact.service,
        "summary": (
            "Baseline MVP implementation generated by LabForge runtime materialization. "
            "Specialist agents may replace or deepen this result before release."
        ),
        "implemented_routes": [
            {"method": "GET", "path": "/healthz", "purpose": "Container readiness check"},
            {"method": "GET", "path": "/", "purpose": "Service landing or metadata surface"},
            {"method": "GET", "path": "/metadata", "purpose": "Seed-backed service metadata"},
            {"method": "GET", "path": "/api/routes", "purpose": "Expose scaffolded API route inventory"},
            {"method": "GET", "path": "/workflow", "purpose": "Expose scaffolded workflow metadata"},
            {"method": "GET", "path": "/api/records", "purpose": "Read seed-backed records"},
            {"method": "POST", "path": "/api/actions", "purpose": "Accept deterministic lab actions"},
        ],
        "data_model": [
            "seed/metadata.json",
            "seed/workflow.json",
            "seed/records.json",
            "noise/events.jsonl",
        ],
        "normal_workflows": [
            "Load service metadata and workflow context.",
            "Query seed-backed records.",
            "Submit deterministic lab actions that emit evidence logs.",
        ],
        "vulnerable_paths": [item.get("id", "unknown") for item in vulnerability_plugin_context(artifact)],
        "detection_evidence": list(artifact.evidence_logs or ["logs/app.log"]),
        "healthcheck_behavior": artifact.healthcheck,
        "reset_behavior": artifact.reset,
        "service_changes": [
            {
                "target_path": name,
                "content": (service_root / name).read_text(encoding="utf-8"),
                "executable": name.endswith(".sh"),
            }
            for name in runtime_files
        ],
        "findings": [
            "This is an automatically generated baseline MVP result from the current runtime scaffold, not a final human-approved service implementation."
        ],
        "open_questions": [],
    }


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
            "- Implement normal business routes, data, and workflows before lab-specific attack behavior.",
            "- Treat `blueprint.yaml` as the service contract for UI/API shape, data stores, and normal workflows.",
            "",
            "## Output Contract",
            "",
            "Write a LabForge service result YAML containing task_id, status, service, summary, implemented_routes, data_model, normal_workflows, vulnerable_paths, detection_evidence, healthcheck_behavior, reset_behavior, service_changes, findings, and open_questions.",
            "",
        ]
    )


def render_service_builder_task_prompt(
    artifact: Any,
    tasks: list[ServiceImplementationTask],
    vulnerability_plugins: list[dict[str, Any]] | None = None,
) -> str:
    vulnerability_plugins = vulnerability_plugins or []
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
        f"- Blueprint file: `{artifact.source_path}/blueprint.yaml`",
        "",
        "## Required Implementation Shape",
        "",
        "- Implement real routes or handlers for the blueprint API surface.",
        "- Implement at least one normal non-attack workflow for the service role.",
        "- Implement deterministic seed data, realistic noise data, and evidence logs.",
        "- Implement healthcheck and reset scripts that verify the actual service behavior.",
        "- Keep exact answer keys, final objects, and solver-only payloads out of reusable template metadata.",
        "",
        "## Vulnerability Plugin Contracts",
        "",
    ]
    if vulnerability_plugins:
        for plugin in vulnerability_plugins:
            lines += [
                f"### `{plugin.get('id')}`",
                "",
                plugin.get("description", ""),
                "",
                "MITRE mapping:",
                "",
            ]
            lines.extend(f"- {item}" for item in plugin.get("mitre_techniques", []) or ["Review required."])
            lines += [
                "",
                "Scenario must define:",
                "",
            ]
            lines.extend(f"- {item}" for item in plugin.get("scenario_must_define", []) or ["Review required."])
            lines += [
                "",
                "Required config keys:",
                "",
            ]
            lines.extend(f"- {item}" for item in plugin.get("required_config_keys", []) or ["Review required."])
            lines += [
                "",
                "Implementation requirements:",
                "",
            ]
            lines.extend(f"- {item}" for item in plugin.get("implementation_requirements", []) or ["Review required."])
            lines += [
                "",
                "Verification hints:",
                "",
            ]
            lines.extend(f"- {item}" for item in plugin.get("verification_hints", []) or ["Review required."])
            lines += [
                "",
                "Safety boundaries:",
                "",
            ]
            lines.extend(f"- {item}" for item in plugin.get("safety_boundaries", []) or ["Review required."])
            if plugin.get("configured_by_scenario"):
                lines += [
                    "",
                    "Configured by scenario:",
                    "",
                    "```yaml",
                    dump_yaml(plugin["configured_by_scenario"]).rstrip(),
                    "```",
                    "",
                ]
    else:
        lines += [
            "No vulnerability plugin contracts were declared for this service.",
            "",
        ]
    lines += [
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
        "- Blueprint routes, workflows, and data stores are represented in code or documented as intentionally deferred.",
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
            f"5. Write the result summary and service_changes to `{package.output_file}` using the LabForge service result schema.",
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
