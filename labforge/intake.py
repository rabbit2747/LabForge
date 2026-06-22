from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, write_text


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
