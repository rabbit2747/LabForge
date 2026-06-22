from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, load_yaml, write_text
from .starter import starter_security_controls, starter_supervisor_selection


class IntakeModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class IntakeStage(IntakeModel):
    stage_id: str
    learner_goal: str
    expected_action: str
    evidence: list[str] = Field(default_factory=list)
    mitre_tactic: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    infrastructure_touched: list[str] = Field(default_factory=list)


class ScenarioIntake(IntakeModel):
    lab_id: str
    title: str
    audience: str = "junior red-team learner"
    summary: str = "Describe the scenario in one paragraph."
    inspiration: list[str] = Field(default_factory=list)
    final_objective: str = "Describe the final object, proof, or business impact."
    learner_entrypoint: str = "Describe what the learner can access at the beginning."
    safety_boundaries: list[str] = Field(default_factory=list)
    attacker_infrastructure: list[str] = Field(default_factory=list)
    target_infrastructure: list[str] = Field(default_factory=list)
    security_controls: list[str] = Field(default_factory=list)
    stages: list[IntakeStage] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)


def create_intake_template(out: Path, *, lab_id: str, title: str, force: bool = False) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    intake = default_intake(lab_id, title)
    files = {
        out / "scenario-intake.md": render_intake_markdown(intake),
        out / "scenario-intake.yaml": dump_yaml(intake.model_dump()),
        out / "llm-transformation-brief.md": render_llm_transformation_brief(intake),
    }
    written: list[Path] = []
    for path, content in files.items():
        if path.exists() and not force:
            continue
        write_text(path, content)
        written.append(path)
    return written


def scaffold_lab_from_intake(intake_path: Path, out: Path, *, force: bool = False) -> list[Path]:
    intake = ScenarioIntake.model_validate(load_yaml(intake_path))
    files = lab_files_from_intake(intake)
    written: list[Path] = []
    for filename, content in files.items():
        path = out / filename
        if path.exists() and not force:
            continue
        write_text(path, content)
        written.append(path)
    return written


def lab_files_from_intake(intake: ScenarioIntake) -> dict[str, str]:
    return {
        "lab.yaml": dump_yaml(
            {
                "id": intake.lab_id,
                "title": intake.title,
                "version": "0.2",
                "difficulty": "draft",
                "mode": "red-team",
                "default_provider": "docker-compose",
                "supported_providers": ["docker-compose", "hybrid", "ansible", "terraform", "ludus"],
            }
        ),
        "scenario.yaml": dump_yaml(
            {
                "id": intake.lab_id,
                "title": intake.title,
                "summary": intake.summary,
                "final_objective": intake.final_objective,
                "learner_entrypoint": intake.learner_entrypoint,
                "motivation": intake.inspiration,
                "safety": {"boundaries": intake.safety_boundaries},
            }
        ),
        "topology.yaml": dump_yaml(topology_from_intake(intake)),
        "stages.yaml": dump_yaml(stages_from_intake(intake)),
        "environment.yaml": dump_yaml(environment_from_intake(intake)),
        "artifacts.yaml": dump_yaml(artifacts_from_intake(intake)),
        "security-controls.yaml": dump_yaml(starter_security_controls()),
        "supervisor-selection.yaml": dump_yaml(starter_supervisor_selection()),
        "providers/docker-compose.yaml": dump_yaml(
            {
                "provider": "docker-compose",
                "profile_support": ["unprotected", "protected"],
                "purpose": "Prototype the scenario with bounded local services.",
                "limitations": [
                    "Replace generated placeholders with real lab-scoped service implementations.",
                    "Use hybrid or VM provider when the intake requires Windows, AD, ICS, or endpoint realism.",
                ],
            }
        ),
        "providers/hybrid.yaml": dump_yaml(
            {
                "provider": "hybrid",
                "status": "planned",
                "purpose": "Split services across Docker and VM-backed enterprise assets when realism requires it.",
            }
        ),
        "services/README.md": "\n".join(
            [
                "# Services",
                "",
                "This lab was scaffolded from a scenario intake file.",
                "Run `python -m labforge services scaffold <lab-root>` to create service artifact directories.",
                "Replace generated placeholders with real bounded lab implementations before production use.",
                "",
            ]
        ),
    }


def topology_from_intake(intake: ScenarioIntake) -> dict:
    service_names = service_names_from_intake(intake)
    services = []
    exposed_index = 0
    for name in service_names:
        exposed = name in {"attacker-workstation", "controlled-drop"} or "entry" in name or "portal" in name
        networks = ["public_net"] if exposed else ["internal_net"]
        if name == "attacker-workstation":
            networks = ["public_net", "internal_net", "control_net"]
        if name == "controlled-drop":
            networks = ["control_net"]
        ports: list[str] = []
        if exposed:
            host_port = 8080 if "entry" in name or "portal" in name else 18080 + exposed_index
            exposed_index += 1
            ports = [f"{host_port}:8080"]
        services.append(
            {
                "name": name,
                "role": role_for_service(name),
                "exposed": exposed,
                "networks": networks,
                "ports": ports,
                "expose": ["8080"] if not exposed else [],
                "healthcheck": {
                    "test": ["CMD", "sh", "-lc", "true"],
                    "interval": "10s",
                    "timeout": "3s",
                    "retries": 10,
                },
            }
        )
    return {
        "networks": [
            {"name": "public_net"},
            {"name": "internal_net", "internal": True},
            {"name": "control_net", "internal": True},
        ],
        "security_controls": {"recommended": intake.security_controls or ["Firewall / Segmentation", "Central Log Collection"]},
        "deployment": {
            "recommended_model": "docker-compose",
            "docker_only_supported": True,
            "docker_only_notes": "Review this generated assumption. Switch to hybrid when the scenario requires Windows, AD, endpoint, cloud, ICS, or hypervisor realism.",
            "minimum_environment": {
                "description": "Single training PC for generated prototype mode.",
                "hosts": [
                    {
                        "role": "training-host",
                        "count": 1,
                        "os": "Windows, Linux, or macOS with a Docker-capable runtime",
                        "cpu": "8 cores recommended",
                        "memory": "16 GB minimum",
                        "storage": "80 GB free",
                        "software": ["Docker-compatible runtime", "Python 3.11+", "Git"],
                    }
                ],
            },
        },
        "services": services,
    }


def stages_from_intake(intake: ScenarioIntake) -> dict:
    stages = []
    for index, stage in enumerate(intake.stages, start=1):
        techniques = [parse_technique(item) for item in stage.mitre_techniques] or [
            {"id": "T0000", "name": "Replace with MITRE ATT&CK technique"}
        ]
        stages.append(
            {
                "id": stage.stage_id or f"stage-{index:02d}",
                "title": stage.learner_goal,
                "procedure": stage.expected_action,
                "evidence": stage.evidence,
                "mitre": {
                    "tactic": stage.mitre_tactic or "Discovery",
                    "techniques": techniques,
                },
                "required_findings": stage.infrastructure_touched,
                "next_stage": intake.stages[index].stage_id if index < len(intake.stages) else None,
            }
        )
    return {"stages": stages}


def environment_from_intake(intake: ScenarioIntake) -> dict:
    assets = []
    for item in [*intake.attacker_infrastructure, *intake.target_infrastructure]:
        name = normalize_service_name(item)
        assets.append(
            {
                "id": name,
                "type": "attacker" if "attacker" in name else "service",
                "zone": "attacker" if "attacker" in name else "target",
                "os": "linux",
                "exposure": "public" if name in {"attacker-workstation", "controlled-drop"} else "internal",
            }
        )
    return {
        "zones": [
            {"name": "attacker", "description": "Learner-controlled infrastructure."},
            {"name": "target", "description": "Target enterprise lab infrastructure."},
        ],
        "assets": assets,
    }


def artifacts_from_intake(intake: ScenarioIntake) -> dict:
    service_artifacts = []
    for name in service_names_from_intake(intake):
        service_artifacts.append(
            {
                "service": name,
                "source_path": f"services/{name}",
                "runtime": "generated-placeholder",
                "purpose": f"Implement the `{name}` behavior described in the scenario intake.",
                "attack_surface": ["Replace with learner-visible endpoints, shell access, or protocol behavior."],
                "seed_inputs": ["seed/metadata.json"],
                "noise_inputs": ["noise/"],
                "healthcheck": "healthcheck.sh exits 0 when the service is ready.",
                "reset": "reset.sh restores deterministic lab state.",
                "evidence_logs": ["logs/app.log"],
                "safety_boundaries": intake.safety_boundaries or ["Lab-internal behavior only."],
            }
        )
    return {
        "seed": [],
        "noise": [],
        "learner_handouts": [],
        "instructor_only": [{"name": "scenario-intake-source", "path": "scenario-intake.yaml"}],
        "service_artifacts": service_artifacts,
    }


def service_names_from_intake(intake: ScenarioIntake) -> list[str]:
    values = [*intake.attacker_infrastructure, *intake.target_infrastructure]
    names = [normalize_service_name(value) for value in values]
    if not names:
        names = ["attacker-workstation", "entry-service", "controlled-drop"]
    return sorted(set(names), key=names.index)


def normalize_service_name(value: str) -> str:
    raw = value.split(":", 1)[0].strip().lower()
    raw = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    return raw or "service"


def role_for_service(name: str) -> str:
    if "attacker" in name:
        return "learner attack workstation"
    if "drop" in name:
        return "controlled final submission"
    if "entry" in name or "portal" in name:
        return "external entry service"
    if "data" in name or "sensitive" in name:
        return "sensitive data service"
    return "internal service"


def parse_technique(value: str) -> dict[str, str]:
    parts = value.strip().split(maxsplit=1)
    if parts and re.fullmatch(r"T\d{4}(?:\.\d{3})?", parts[0]):
        return {"id": parts[0], "name": parts[1] if len(parts) > 1 else "Technique name required"}
    return {"id": "T0000", "name": value or "Replace with MITRE ATT&CK technique"}


def default_intake(lab_id: str, title: str) -> ScenarioIntake:
    return ScenarioIntake(
        lab_id=lab_id,
        title=title,
        inspiration=[
            "Replace with incident, intrusion set, or enterprise attack pattern inspiration.",
        ],
        safety_boundaries=[
            "Lab-internal network only.",
            "No real external command-and-control.",
            "No destructive behavior outside resettable lab state.",
        ],
        attacker_infrastructure=[
            "attacker-workstation: learner-controlled shell host",
            "controlled-drop: final controlled submission service",
        ],
        target_infrastructure=[
            "public-entry-service: externally reachable business service",
            "internal-service-01: first internal discovery target",
            "sensitive-data-service: final collection target",
        ],
        security_controls=[
            "Firewall / segmentation",
            "IDS east-west sensor",
            "Central log collection",
        ],
        stages=[
            IntakeStage(
                stage_id="stage-01",
                learner_goal="Identify the initial externally reachable weakness.",
                expected_action="Capture traffic, inspect behavior, and confirm exploitability inside the lab.",
                evidence=["initial_weakness_confirmed"],
                mitre_tactic="Initial Access",
                mitre_techniques=["T1190 Exploit Public-Facing Application"],
                infrastructure_touched=["public-entry-service"],
            ),
            IntakeStage(
                stage_id="stage-02",
                learner_goal="Establish a limited foothold and enumerate the local host.",
                expected_action="Use the discovered weakness to run bounded discovery commands.",
                evidence=["foothold_confirmed", "host_context_collected"],
                mitre_tactic="Execution",
                mitre_techniques=["T1059 Command and Scripting Interpreter"],
                infrastructure_touched=["public-entry-service", "attacker-workstation"],
            ),
        ],
        open_questions=[
            "Which services must be real implementations rather than simulated responses?",
            "Which stages require browser UI, shell access, or both?",
            "Which safety controls must be enforced by infrastructure instead of only documented?",
        ],
    )


def render_intake_markdown(intake: ScenarioIntake) -> str:
    lines = [
        f"# Scenario Intake - {intake.title}",
        "",
        "Use this document to describe a lab idea before converting it into LabForge YAML.",
        "Write concrete learner-visible behavior, infrastructure assumptions, and safety boundaries.",
        "",
        "## Identity",
        "",
        f"- Lab ID: `{intake.lab_id}`",
        f"- Title: {intake.title}",
        f"- Audience: {intake.audience}",
        "",
        "## Scenario Summary",
        "",
        intake.summary,
        "",
        "## Inspiration",
        "",
    ]
    lines.extend(f"- {item}" for item in intake.inspiration)
    lines += [
        "",
        "## Final Objective",
        "",
        intake.final_objective,
        "",
        "## Learner Entrypoint",
        "",
        intake.learner_entrypoint,
        "",
        "## Safety Boundaries",
        "",
    ]
    lines.extend(f"- {item}" for item in intake.safety_boundaries)
    lines += ["", "## Attacker Infrastructure", ""]
    lines.extend(f"- {item}" for item in intake.attacker_infrastructure)
    lines += ["", "## Target Infrastructure", ""]
    lines.extend(f"- {item}" for item in intake.target_infrastructure)
    lines += ["", "## Security Controls to Consider", ""]
    lines.extend(f"- {item}" for item in intake.security_controls)
    lines += ["", "## Stage Draft", ""]
    for stage in intake.stages:
        lines += [
            f"### {stage.stage_id}",
            "",
            f"- Learner goal: {stage.learner_goal}",
            f"- Expected action: {stage.expected_action}",
            f"- Evidence: {', '.join(stage.evidence)}",
            f"- MITRE tactic: {stage.mitre_tactic}",
            f"- MITRE techniques: {', '.join(stage.mitre_techniques)}",
            f"- Infrastructure touched: {', '.join(stage.infrastructure_touched)}",
            "",
        ]
    lines += ["## Open Questions", ""]
    lines.extend(f"- {item}" for item in intake.open_questions)
    lines.append("")
    return "\n".join(lines)


def render_llm_transformation_brief(intake: ScenarioIntake) -> str:
    return "\n".join(
        [
            f"# LLM Transformation Brief - {intake.title}",
            "",
            "You are converting a human-written cyber range scenario intake into a LabForge lab specification.",
            "Produce LabForge-compatible YAML files, not runnable service code.",
            "",
            "Required outputs:",
            "",
            "- `lab.yaml` with metadata and supported providers.",
            "- `scenario.yaml` with summary, final objective, learner entrypoint, motivation, and safety notes.",
            "- `stages.yaml` with numbered stages, learner procedures, required findings, evidence, and MITRE ATT&CK Enterprise mapping.",
            "- `topology.yaml` with networks, services, security controls, and realistic deployment requirements.",
            "- `environment.yaml` with zones and assets.",
            "- `artifacts.yaml` with seed, noise, learner handouts, instructor-only notes, and service artifact contracts.",
            "- `security-controls.yaml` and `supervisor-selection.yaml` with selectable protected/unprotected controls.",
            "",
            "Transformation rules:",
            "",
            "- Keep all internal generated instructions in English.",
            "- Do not invent real-world victim names, credentials, or external command-and-control.",
            "- Prefer real bounded services over fake text-only simulators when feasible.",
            "- If a provider cannot realistically support a requirement, mark it as prototype-only and recommend a VM or hybrid provider.",
            "- Map every stage to one MITRE ATT&CK Matrix for Enterprise tactic.",
            "- Avoid magic strings that learners cannot discover from the lab environment.",
            "- Include safety boundaries for each service artifact.",
            "",
            "Source intake JSON:",
            "",
            "```json",
            json.dumps(intake.model_dump(), ensure_ascii=False, indent=2),
            "```",
            "",
        ]
    )


INTAKE_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "scenario-intake.schema.json": ScenarioIntake,
}
