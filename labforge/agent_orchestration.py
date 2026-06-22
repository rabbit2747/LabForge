from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .io import dump_yaml, write_text
from .model import LabSpec


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
            "tasks_dir": ".ai/tasks",
            "outputs_dir": ".ai/outputs",
            "decisions_dir": ".ai/decisions",
            "llm_runtime": "not-configured",
            "rule": "Dry-run scaffolds tasks only. LLM adapters must be explicitly configured later.",
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
    tasks = base / "tasks"
    outputs = base / "outputs"
    decisions = base / "decisions"

    manifest_path = base / "orchestration-plan.yaml"
    write_text(manifest_path, dump_yaml(orchestration_manifest(spec)))
    written.append(manifest_path)

    readme_path = base / "README.md"
    write_text(readme_path, render_agent_workspace_readme(spec))
    written.append(readme_path)

    for order, role in enumerate(DEFAULT_AGENT_ROLES, start=1):
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
