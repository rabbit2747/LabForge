from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, load_yaml, write_text
from .starter import starter_security_controls, starter_supervisor_selection


GENERIC_ASSET_NAMES = {
    "api",
    "agent",
    "bastion",
    "console",
    "database",
    "db",
    "gateway",
    "portal",
    "repo",
    "server",
    "service",
    "store",
    "wiki",
}

NON_SERVICE_ASSET_MARKERS = (
    "command-and-scripting",
    "credentials-in-files",
    "data-from",
    "exploit-public-facing",
    "exploitation-of",
    "file-and-directory",
    "network-service",
    "remote-system-discovery",
    "system-information",
)


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
    target_industry: str = "enterprise"
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


class NaturalLanguageScenarioRequest(IntakeModel):
    lab_id: str
    title: str
    prompt: str
    industry: str = "enterprise"
    difficulty: str = "intermediate"
    preferred_provider: str = "auto"
    audience: str = "junior red-team learner"


class PromptAnalysis(IntakeModel):
    detected_industry: str = "enterprise"
    industry_evidence: list[str] = Field(default_factory=list)
    provider_pressure: list[str] = Field(default_factory=list)
    likely_entrypoints: list[str] = Field(default_factory=list)
    likely_final_objectives: list[str] = Field(default_factory=list)
    named_assets: list[str] = Field(default_factory=list)
    requested_attack_themes: list[str] = Field(default_factory=list)
    security_control_hints: list[str] = Field(default_factory=list)
    realism_risks: list[str] = Field(default_factory=list)
    supervisor_questions: list[str] = Field(default_factory=list)


class NaturalLanguageIntakePackage(IntakeModel):
    request: NaturalLanguageScenarioRequest
    inferred_intake: ScenarioIntake
    prompt_analysis: PromptAnalysis
    assumptions: list[str] = Field(default_factory=list)
    next_commands: list[str] = Field(default_factory=list)
    generated_files: list[str] = Field(default_factory=list)


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


def create_intake_from_prompt(
    out: Path,
    *,
    prompt: str,
    lab_id: str | None = None,
    title: str | None = None,
    industry: str | None = None,
    difficulty: str = "intermediate",
    provider: str = "auto",
    force: bool = False,
) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    prompt = normalize_prompt_text(prompt)
    title = normalize_prompt_text(title) if title else None
    inferred_title = title or infer_title_from_prompt(prompt)
    inferred_lab_id = lab_id or slugify(inferred_title)
    inferred_industry = normalize_industry(industry or infer_industry_from_prompt(prompt))
    request = NaturalLanguageScenarioRequest(
        lab_id=inferred_lab_id,
        title=inferred_title,
        prompt=prompt,
        industry=inferred_industry,
        difficulty=difficulty,
        preferred_provider=provider,
    )
    intake = intake_from_natural_language_request(request)
    analysis = analyze_prompt(request)
    package = NaturalLanguageIntakePackage(
        request=request,
        inferred_intake=intake,
        prompt_analysis=analysis,
        assumptions=natural_language_assumptions(request),
        next_commands=[
            f"python -m labforge intake scaffold --from {out / 'scenario-intake.yaml'} --out output/{inferred_lab_id}-draft --force",
            f"python -m labforge agents scaffold output/{inferred_lab_id}-draft --out output/{inferred_lab_id}-agents",
            f"python -m labforge agents run output/{inferred_lab_id}-agents --adapter <manual|codex|claude-code|openai> --agent scenario-designer --context-root output/{inferred_lab_id}-draft --dry-run",
            f"python -m labforge realism check output/{inferred_lab_id}-draft --industry {inferred_industry}",
        ],
        generated_files=[
            "scenario-prompt.md",
            "scenario-intake.yaml",
            "scenario-intake.md",
            "prompt-analysis.yaml",
            "prompt-analysis.md",
            "natural-language-intake-package.yaml",
            "llm-transformation-brief.md",
        ],
    )
    files = {
        out / "scenario-prompt.md": render_source_prompt_markdown(request),
        out / "scenario-intake.yaml": dump_yaml(intake.model_dump()),
        out / "scenario-intake.md": render_intake_markdown(intake),
        out / "prompt-analysis.yaml": dump_yaml(analysis.model_dump()),
        out / "prompt-analysis.md": render_prompt_analysis_markdown(analysis),
        out / "natural-language-intake-package.yaml": dump_yaml(package.model_dump()),
        out / "llm-transformation-brief.md": render_natural_language_transformation_brief(package),
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


def intake_from_natural_language_request(request: NaturalLanguageScenarioRequest) -> ScenarioIntake:
    analysis = analyze_prompt(request)
    profile = apply_prompt_analysis_to_profile(scenario_profile_for_request(request), analysis)
    return ScenarioIntake(
        lab_id=request.lab_id,
        title=request.title,
        target_industry=request.industry,
        audience=request.audience,
        summary=(
            "Natural-language scenario draft. The source prompt must remain the authority until "
            "the scenario-designer agent and supervisor approve the final LabForge specification."
        ),
        inspiration=profile["inspiration"],
        final_objective=profile["final_objective"],
        learner_entrypoint=profile["learner_entrypoint"],
        safety_boundaries=[
            "Lab-internal network only.",
            "No real external command-and-control or third-party victim infrastructure.",
            "No destructive behavior outside resettable lab state.",
            "All offensive behavior must be bounded to approved training services.",
        ],
        attacker_infrastructure=profile["attacker_infrastructure"],
        target_infrastructure=profile["target_infrastructure"],
        security_controls=profile["security_controls"],
        stages=[IntakeStage(**stage) for stage in profile["stages"]],
        open_questions=[
            "Which real-world incident or intrusion pattern should be used as the primary inspiration?",
            "Which vulnerabilities should be implemented as real bounded services instead of documentation-only placeholders?",
            "Which provider is required for realism: Docker-only, hybrid VM, AD lab, or another target environment?",
            "Which safety controls should be mandatory in the protected architecture?",
            "Which learner-visible clues are acceptable, and which facts must remain instructor-only?",
        ],
    )


def apply_prompt_analysis_to_profile(profile: dict, analysis: PromptAnalysis) -> dict:
    merged = {**profile}
    inspiration = list(merged.get("inspiration", []))
    for theme in analysis.requested_attack_themes:
        item = f"attack-theme: {theme}"
        if item not in inspiration:
            inspiration.append(item)
    merged["inspiration"] = inspiration

    existing_names = {normalize_service_name(item) for item in merged.get("target_infrastructure", [])}
    target_infrastructure = list(merged.get("target_infrastructure", []))
    for asset in analysis.named_assets:
        normalized = normalize_service_name(asset)
        if (
            normalized in existing_names
            or normalized in {"attacker-workstation", "controlled-drop"}
            or not should_promote_asset_to_service(normalized)
            or has_overlapping_service_name(normalized, existing_names)
        ):
            continue
        target_infrastructure.append(f"{normalized}: inferred from source prompt")
        existing_names.add(normalized)
    merged["target_infrastructure"] = target_infrastructure

    if analysis.likely_entrypoints:
        entry = analysis.likely_entrypoints[0]
        if entry != "public-entry-service":
            merged["learner_entrypoint"] = f"Externally reachable `{entry}` identified from the source prompt."

    objective = first_specific_objective(analysis.likely_final_objectives)
    if objective:
        merged["final_objective"] = objective

    controls = list(merged.get("security_controls", []))
    for hint in analysis.security_control_hints:
        control = hint.split(":", 1)[0].replace("-", " ").title()
        if control not in controls:
            controls.append(control)
    merged["security_controls"] = controls
    return merged


def first_specific_objective(objectives: list[str]) -> str:
    generic_values = {
        "declared sensitive object or proof material",
        "controlled business export object",
        "controlled final proof object",
    }
    for objective in objectives:
        cleaned = clean_objective_text(objective)
        if cleaned and cleaned.lower() not in generic_values:
            return cleaned
    return ""


def should_promote_asset_to_service(asset: str) -> bool:
    if not asset or asset in GENERIC_ASSET_NAMES:
        return False
    if re.match(r"^t\d{4}(?:-\d{3})?", asset):
        return False
    if re.search(r"\d-\d", asset):
        return False
    if any(marker in asset for marker in NON_SERVICE_ASSET_MARKERS):
        return False
    if asset.endswith("agent") and not any(prefix in asset for prefix in ("attacker", "customer")):
        return False
    return True


def has_overlapping_service_name(asset: str, existing_names: set[str]) -> bool:
    for existing in existing_names:
        if existing.endswith(f"-{asset}") or asset.endswith(f"-{existing}"):
            return True
    return False


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
                "target_industry": intake.target_industry,
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
                    "Extend generated MVP runtimes with lab-scoped vulnerability behavior before production delivery.",
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
                "Extend generated MVP runtimes with real bounded lab implementations before production use.",
                "",
            ]
        ),
    }


def topology_from_intake(intake: ScenarioIntake) -> dict:
    service_names = service_names_from_intake(intake)
    industry = normalize_industry(intake.target_industry)
    zone_names = industry_zone_names(industry)
    network_names = [network_name_for_zone(zone) for zone in zone_names if zone != "attacker"]
    if "public_edge_net" not in network_names:
        network_names.insert(0, "public_edge_net")
    if "control_net" not in network_names:
        network_names.append("control_net")
    services = []
    exposed_index = 0
    for name in service_names:
        exposed = name in {"attacker-workstation", "controlled-drop"} or "entry" in name or "portal" in name
        zone = service_zone_for_name(name, industry)
        primary_network = network_name_for_zone(zone)
        networks = ["public_edge_net"] if exposed else [primary_network]
        if name == "attacker-workstation":
            networks = sorted(set(["public_edge_net", "control_net", *[item for item in network_names if item != "public_edge_net"]]))
        if name == "controlled-drop":
            networks = ["public_edge_net", "control_net"]
        ports: list[str] = []
        if exposed:
            if name == "attacker-workstation":
                ports = ["2222:22"]
            else:
                host_port = 18080 + exposed_index
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
        "networks": [{"name": name, **({"internal": True} if name != "public_edge_net" else {})} for name in network_names],
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
            {"id": "T0000", "name": "MITRE ATT&CK technique to be selected during review"}
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
    industry = normalize_industry(intake.target_industry)
    zones = industry_zone_names(industry)
    assets = []
    for item in [*intake.attacker_infrastructure, *intake.target_infrastructure]:
        name = normalize_service_name(item)
        zone = service_zone_for_name(name, industry)
        assets.append(
            {
                "id": name,
                "type": "attacker" if "attacker" in name else "service",
                "zone": "attacker" if "attacker" in name else zone,
                "os": "linux",
                "exposure": "public" if name in {"attacker-workstation", "controlled-drop"} else "internal",
            }
        )
    return {
        "zones": [{"name": zone, "description": zone_description(zone)} for zone in zones],
        "assets": assets,
    }


def industry_zone_names(industry: str) -> list[str]:
    zone_map = {
        "supply-chain": ["attacker", "public edge", "corporate", "development", "build", "release", "customer", "security monitoring"],
        "securities": ["attacker", "public or internet edge", "dmz", "application", "core trading", "data", "settlement", "compliance", "management", "security monitoring"],
        "banking": ["attacker", "public or internet edge", "dmz", "digital banking", "core banking", "loan operations", "payments", "data", "compliance", "management", "security monitoring"],
        "healthcare": ["attacker", "public edge", "dmz", "clinical", "administrative", "data", "security monitoring"],
        "manufacturing": ["attacker", "public edge", "corporate", "engineering", "ot", "data", "security monitoring"],
        "active-directory": ["attacker", "public edge", "workstation", "server", "domain services", "data", "management", "security monitoring"],
    }
    return zone_map.get(industry, ["attacker", "public or internet edge", "dmz", "corporate", "data", "management", "security monitoring"])


def network_name_for_zone(zone: str) -> str:
    normalized = zone.replace(" or ", " ").replace("/", " ")
    return f"{slugify(normalized).replace('-', '_')}_net"


def zone_description(zone: str) -> str:
    descriptions = {
        "attacker": "Learner-controlled infrastructure.",
        "public edge": "Externally reachable edge services and internet-facing entry points.",
        "public or internet edge": "Externally reachable edge services and internet-facing entry points.",
        "dmz": "Demilitarized service tier between public and internal networks.",
        "corporate": "Internal corporate applications, knowledge systems, and operations tooling.",
        "development": "Developer collaboration, source control, and engineering services.",
        "build": "CI, build, artifact, and package production services.",
        "release": "Release approval, signing, publishing, and update channel services.",
        "customer": "Customer-side integration, tenant, agent, and downstream application services.",
        "security monitoring": "Logging, detection, audit, and monitoring infrastructure.",
        "data": "Data stores, document stores, exports, and sensitive business records.",
    }
    return descriptions.get(zone, f"{zone.title()} lab zone.")


def service_zone_for_name(service_name: str, industry: str) -> str:
    name = service_name.lower()
    if "attacker" in name:
        return "attacker"
    if any(word in name for word in ["drop", "public", "edge", "support", "portal", "entry", "docs"]):
        return "public edge" if industry != "securities" else "public or internet edge"
    if industry == "supply-chain":
        if any(word in name for word in ["wiki", "ldap", "identity", "corp"]):
            return "corporate"
        if any(word in name for word in ["repo", "source", "code", "developer", "dev"]):
            return "development"
        if any(word in name for word in ["build", "ci", "artifact", "package"]):
            return "build"
        if any(word in name for word in ["release", "sign", "update", "bastion", "console"]):
            return "release"
        if any(word in name for word in ["customer", "object", "tenant", "agent"]):
            return "customer"
        if any(word in name for word in ["siem", "ids", "log", "audit", "monitor"]):
            return "security monitoring"
        return "corporate"
    if any(word in name for word in ["siem", "ids", "log", "audit", "monitor", "edr"]):
        return "security monitoring"
    if any(word in name for word in ["data", "store", "share", "object", "export", "file"]):
        return "data"
    if industry == "banking":
        if any(word in name for word in ["identity", "mfa", "device", "session", "gateway", "api"]):
            return "digital banking"
        if any(word in name for word in ["loan", "underwriting", "document", "case"]):
            return "loan operations"
        if any(word in name for word in ["core", "account", "deposit", "ledger", "customer-record"]):
            return "core banking"
        if any(word in name for word in ["payment", "payments", "wire", "ach", "card", "settlement", "reconciliation", "batch"]):
            return "payments"
        if any(word in name for word in ["fraud", "fds", "aml", "sar", "risk", "compliance", "regulatory"]):
            return "compliance"
        if any(word in name for word in ["portal", "public", "edge", "support"]):
            return "dmz"
        return "digital banking"
    if industry == "active-directory":
        if any(word in name for word in ["domain", "ldap", "kerberos", "dns"]):
            return "domain services"
        if "workstation" in name:
            return "workstation"
        if any(word in name for word in ["admin", "pam", "management"]):
            return "management"
        return "server"
    if industry == "manufacturing":
        if any(word in name for word in ["engineering", "plc", "recipe"]):
            return "engineering"
        if any(word in name for word in ["ot", "scada", "mes", "historian", "plant"]):
            return "ot"
        return "corporate"
    if industry == "healthcare":
        if any(word in name for word in ["ehr", "clinical", "patient"]):
            return "clinical"
        if any(word in name for word in ["billing", "claims", "admin"]):
            return "administrative"
        return "dmz"
    if industry == "securities":
        if any(word in name for word in ["trade", "order", "market", "risk"]):
            return "core trading"
        if any(word in name for word in ["settlement", "clearing"]):
            return "settlement"
        if any(word in name for word in ["compliance", "audit"]):
            return "compliance"
        if any(word in name for word in ["gateway", "api", "app"]):
            return "application"
        return "dmz"
    return "corporate"


def artifacts_from_intake(intake: ScenarioIntake) -> dict:
    service_artifacts = []
    for name in service_names_from_intake(intake):
        vulnerability_plugins = vulnerability_plugins_for_service(intake, name)
        service_artifacts.append(
            {
                "service": name,
                "source_path": f"services/{name}",
                "runtime": "scenario-derived-mvp-runtime",
                "purpose": f"Implement the `{name}` behavior described in the scenario intake.",
                "attack_surface": ["Learner-visible endpoints, shell access, or protocol behavior derived from the intake."],
                "seed_inputs": ["seed/metadata.json"],
                "noise_inputs": ["noise/"],
                "healthcheck": "healthcheck.sh exits 0 when the service is ready.",
                "reset": "reset.sh restores deterministic lab state.",
                "evidence_logs": ["logs/app.log"],
                "safety_boundaries": intake.safety_boundaries or ["Lab-internal behavior only."],
                "vulnerability_plugins": vulnerability_plugins,
            }
        )
    return {
        "seed": [],
        "noise": [],
        "learner_handouts": [],
        "instructor_only": [{"name": "scenario-intake-source", "path": "scenario-intake.yaml"}],
        "service_artifacts": service_artifacts,
    }


def vulnerability_plugins_for_service(intake: ScenarioIntake, service_name: str) -> list[dict]:
    scenario_text = scenario_search_text(intake)
    service_text = service_name.lower()
    plugins: list[dict] = []
    if service_text in {"attacker-workstation", "controlled-drop"}:
        return plugins

    if any(word in scenario_text for word in ["ssti", "server-side template", "template injection", "jinja", "preview", "render"]):
        if any(word in service_text for word in ["portal", "entry", "support", "hr", "public"]):
            plugins.append(
                {
                    "id": "ssti-preview",
                    "workflow": "business preview or response drafting",
                    "template_engine": "jinja2",
                    "execution_boundary": "isolated generated lab service",
                    "post_exploitation_objective": "obtain a bounded service foothold or internal clue for the next stage",
                }
            )

    if any(word in scenario_text for word in ["xss", "cross-site", "review", "bot", "manager", "approval"]) or any(
        word in service_text for word in ["review", "release-console", "manager-console"]
    ):
        if any(word in service_text for word in ["console", "review", "release", "manager", "portal", "internal"]):
            plugins.append(
                {
                    "id": "stored-xss-review",
                    "storage_location": "/state/review-items.json",
                    "reviewer_role": "privileged reviewer",
                    "review_surface": "internal review queue",
                    "callback_scope": "lab-internal learner callback",
                }
            )

    if any(word in scenario_text for word in ["ssrf", "server-side request", "internal fetch", "webhook", "url fetch", "metadata"]):
        if any(word in service_text for word in ["portal", "entry", "support", "wiki", "import", "webhook", "gateway"]):
            plugins.append(
                {
                    "id": "ssrf-internal-fetch",
                    "business_fetch_reason": "server-side document, webhook, or knowledge-base lookup",
                    "allowed_url_policy": "lab-internal HTTP targets only",
                    "internal_targets": ["http://metadata-service:8080/metadata", "http://internal-portal:8080/metadata"],
                    "blocked_targets": ["http://169.254.169.254/", "https://example.com/"],
                }
            )

    if any(word in scenario_text for word in ["idor", "object", "export", "sensitive data", "dataset", "file", "archive"]):
        if any(word in service_text for word in ["api", "object", "store", "file", "data", "sensitive", "customer", "export", "report", "compliance", "audit"]):
            plugins.append(
                {
                    "id": "idor-object-access",
                    "object_model": "synthetic business records and export objects",
                    "authorization_rule": "owner is checked on list views but not consistently checked on direct object reads",
                    "reference_discovery": "object identifiers are discoverable through normal metadata or logs",
                    "target_dataset": "scenario-defined synthetic final object",
                }
            )

    if any(word in scenario_text for word in ["path traversal", "directory traversal", "../", "file read", "download", "attachment", "document download"]):
        if any(word in service_text for word in ["portal", "document", "file", "object", "store", "data", "archive", "download", "case"]):
            plugins.append(
                {
                    "id": "path-traversal-download",
                    "document_workflow": "business document or attachment download",
                    "public_document_root": "/state/documents/public",
                    "restricted_document": "restricted/audit-export.txt",
                    "safe_file_boundary": "synthetic service document root only",
                }
            )

    if any(word in scenario_text for word in ["file upload", "upload", "attachment upload", "evidence upload", "document upload"]):
        if any(word in service_text for word in ["portal", "case", "document", "review", "console", "support", "intake"]):
            plugins.append(
                {
                    "id": "unsafe-file-upload",
                    "upload_workflow": "business attachment or evidence upload",
                    "accepted_extensions": [".txt", ".pdf", ".csv"],
                    "storage_scope": "/state/uploads",
                    "post_upload_effect": "uploaded file becomes available to the lab-scoped review or retrieval workflow",
                }
            )

    if any(word in scenario_text for word in ["command injection", "diagnostic", "shell", "foothold", "command execution", "rce"]):
        if any(word in service_text for word in ["portal", "ops", "admin", "console", "diagnostic", "bastion", "search", "jump-host"]):
            plugins.append(
                {
                    "id": "diagnostic-command-injection",
                    "operator_workflow": "operator diagnostic command execution",
                    "injection_field": "diagnostic target or argument",
                    "command_boundary": "isolated generated lab container",
                    "observable_outputs": ["stdout", "stderr", "service event log"],
                }
            )

    supply_chain_terms = [
        "supply chain",
        "trusted build",
        "build pipeline",
        "release pipeline",
        "release",
        "signing",
        "signed manifest",
        "update channel",
        "customer agent",
        "software update",
        "pipeline",
        "공급망",
        "빌드",
        "배포",
        "서명",
        "업데이트",
    ]
    if any(term in scenario_text for term in supply_chain_terms):
        if any(word in service_text for word in ["build", "pipeline", "release-console", "release", "ci", "cd"]):
            plugins.append(
                {
                    "id": "build-pipeline-abuse",
                    "repo": "example/product-agent",
                    "ref": "refs/heads/release/lab",
                    "channel": "training",
                    "patch_ref_field": "support_patch_ref",
                }
            )
        if any(word in service_text for word in ["sign", "update", "release-console", "release", "publish"]):
            plugins.append(
                {
                    "id": "signed-update-publish",
                    "channel": "training",
                    "signing_identity": "lab-release-signing",
                    "manifest_contract": ["product", "channel", "version", "build_id", "artifact", "signature"],
                }
            )
        if any(word in service_text for word in ["customer", "agent", "app", "api"]):
            plugins.append(
                {
                    "id": "customer-update-callback",
                    "channel": "training",
                    "final_dataset": "LABFORGE_SYNTHETIC_SUPPLY_CHAIN_EXPORT",
                    "callback_scope": "lab-internal learner callback",
                }
            )

    return plugins


def scenario_search_text(intake: ScenarioIntake) -> str:
    parts = [
        intake.title,
        intake.summary,
        intake.final_objective,
        intake.learner_entrypoint,
        " ".join(intake.inspiration),
        " ".join(intake.attacker_infrastructure),
        " ".join(intake.target_infrastructure),
    ]
    for stage in intake.stages:
        parts.extend(
            [
                stage.stage_id,
                stage.learner_goal,
                stage.expected_action,
                stage.mitre_tactic,
                " ".join(stage.mitre_techniques),
                " ".join(stage.infrastructure_touched),
            ]
        )
    return " ".join(parts).lower()


def service_names_from_intake(intake: ScenarioIntake) -> list[str]:
    values = [*intake.attacker_infrastructure, *intake.target_infrastructure]
    names = [normalize_service_name(value) for value in values]
    if not names:
        names = ["attacker-workstation", "entry-service", "controlled-drop"]
    return sorted(set(names), key=names.index)


def infer_title_from_prompt(prompt: str) -> str:
    text = " ".join(normalize_prompt_text(prompt).split())
    if not text:
        return "Untitled Lab Scenario"
    sentence = re.split(r"[.!?\n]", text, maxsplit=1)[0].strip()
    if len(sentence) > 72:
        sentence = sentence[:72].rsplit(" ", 1)[0].strip()
    return sentence or "Untitled Lab Scenario"


def normalize_prompt_text(value: str) -> str:
    text = str(value or "").strip()
    for marker in ("\ufeff", "ï»¿", "癤풠"):
        if text.startswith(marker):
            text = text[len(marker) :].lstrip()
    return text


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "lab-scenario"


def infer_industry_from_prompt(prompt: str) -> str:
    text = prompt.lower()
    keyword_map = {
        "banking": ["bank", "banking", "regional bank", "retail bank", "commercial bank", "loan", "deposit", "core banking", "payment", "payments", "wire", "ach", "fds", "aml", "suspicious activity"],
        "securities": ["securities", "brokerage", "trading", "market data", "stock", "증권", "거래소", "주식"],
        "healthcare": ["healthcare", "hospital", "clinic", "patient", "ehr", "emr", "의료", "병원", "환자"],
        "manufacturing": ["manufacturing", "factory", "plant", "ot", "ics", "scada", "mes", "제조", "공장"],
        "retail": ["retail", "commerce", "pos", "loyalty", "e-commerce", "커머스", "쇼핑", "pos"],
        "education": ["university", "school", "student", "lms", "교육", "대학교", "학생"],
        "public-sector": ["government", "municipal", "public sector", "agency", "공공", "정부", "지자체"],
        "supply-chain": ["supply chain", "ci/cd", "build pipeline", "release", "update channel", "공급망", "빌드", "배포"],
        "active-directory": ["active directory", "domain controller", "kerberos", "ldap", "windows domain", "ad ", "도메인"],
    }
    for industry, keywords in keyword_map.items():
        if any(keyword in text for keyword in keywords):
            return industry
    return "enterprise"


def analyze_prompt(request: NaturalLanguageScenarioRequest) -> PromptAnalysis:
    text = request.prompt.lower()
    detected_industry = normalize_industry(request.industry or infer_industry_from_prompt(request.prompt))
    industry_evidence = keyword_evidence(
        text,
        {
            "banking": ["bank", "banking", "regional bank", "retail bank", "commercial bank", "loan", "deposit", "core banking", "payment", "payments", "wire", "ach", "fds", "aml", "suspicious activity"],
            "securities": ["securities", "brokerage", "trading", "market data", "stock", "증권", "거래소", "주식"],
            "healthcare": ["healthcare", "hospital", "clinic", "patient", "ehr", "emr", "의료", "병원", "환자"],
            "manufacturing": ["manufacturing", "factory", "plant", "ot", "ics", "scada", "mes", "제조", "공장"],
            "active-directory": ["active directory", "domain controller", "kerberos", "ldap", "windows domain", "ad ", "도메인"],
            "supply-chain": ["supply chain", "ci/cd", "build pipeline", "release", "update channel", "공급망", "빌드", "배포"],
        },
    )
    provider_pressure = keyword_evidence(
        text,
        {
            "hybrid-or-vm": ["active directory", "domain controller", "windows", "kerberos", "gpo", "rdp", "edr", "endpoint"],
            "ot-or-ics": ["ot", "ics", "scada", "plc", "historian", "mes"],
            "container-friendly": ["web", "api", "portal", "wiki", "build", "object store", "docker"],
            "cloud-provider-needed": ["cloud", "iam", "s3", "kubernetes", "eks", "aks", "gke"],
        },
    )
    requested_attack_themes = keyword_evidence(
        text,
        {
            "initial-access": ["public", "external", "portal", "vpn", "internet-facing", "외부", "포털"],
            "web-exploitation": ["ssti", "xss", "ssrf", "idor", "rce", "upload", "웹", "취약점"],
            "ssti": ["ssti", "server-side template", "template injection", "jinja"],
            "stored-xss": ["stored xss", "xss", "cross-site", "review bot", "manager bot"],
            "ssrf": ["ssrf", "server-side request", "internal fetch", "webhook", "url fetch"],
            "idor": ["idor", "direct object", "object reference", "export object"],
            "diagnostic-command-execution": ["diagnostic", "command injection", "command execution", "rce", "shell"],
            "identity-abuse": ["ldap", "sso", "session", "cookie", "token", "credential", "계정", "세션", "토큰"],
            "lateral-movement": ["lateral", "pivot", "tunnel", "bastion", "jump", "내부망", "이동"],
            "collection": ["export", "object", "file", "database", "sensitive", "audit", "탈취", "수집"],
            "supply-chain": ["build", "release", "pipeline", "sign", "update", "agent", "공급망", "배포"],
        },
    )
    security_control_hints = keyword_evidence(
        text,
        {
            "firewall-segmentation": ["segmentation", "firewall", "dmz", "internal network", "망분리"],
            "ids-network-monitoring": ["ids", "suricata", "zeek", "network detection"],
            "siem-logging": ["siem", "log", "audit", "event", "logging"],
            "endpoint-telemetry": ["edr", "sysmon", "windows event", "endpoint"],
            "waf": ["waf", "reverse proxy", "nginx", "web firewall"],
        },
    )
    named_assets = extract_named_assets(request.prompt)
    likely_entrypoints = infer_likely_entrypoints(request.prompt, named_assets)
    likely_final_objectives = infer_likely_final_objectives(request.prompt)
    realism_risks = infer_realism_risks(provider_pressure, requested_attack_themes)
    supervisor_questions = [
        "Which inferred assets are real services that must be implemented, and which are documentation-only context?",
        "Which vulnerabilities must be implemented as bounded runnable services?",
        "Which provider should be used after realism review: Docker Compose, hybrid VM, Ansible, Terraform, or Ludus?",
        "Which security controls should be enforced in the protected profile rather than only shown in diagrams?",
    ]
    if any(item.startswith(("hybrid-or-vm", "ot-or-ics")) for item in provider_pressure):
        supervisor_questions.append("Which VM or hypervisor-backed assets are mandatory for realism?")
    return PromptAnalysis(
        detected_industry=detected_industry,
        industry_evidence=industry_evidence,
        provider_pressure=provider_pressure,
        likely_entrypoints=likely_entrypoints,
        likely_final_objectives=likely_final_objectives,
        named_assets=named_assets,
        requested_attack_themes=requested_attack_themes,
        security_control_hints=security_control_hints,
        realism_risks=realism_risks,
        supervisor_questions=supervisor_questions,
    )


def keyword_evidence(text: str, categories: dict[str, list[str]]) -> list[str]:
    evidence: list[str] = []
    for category, keywords in categories.items():
        hits = [keyword for keyword in keywords if keyword_matches(text, keyword)]
        if hits:
            evidence.append(f"{category}: {', '.join(hits[:5])}")
    return evidence


def keyword_matches(text: str, keyword: str) -> bool:
    lowered = keyword.lower()
    if re.fullmatch(r"[a-z0-9]{1,3}", lowered):
        return re.search(rf"(?<![a-z0-9]){re.escape(lowered)}(?![a-z0-9])", text) is not None
    return lowered in text


def extract_named_assets(prompt: str) -> list[str]:
    assets: list[str] = []
    for asset in extract_markdown_table_assets(prompt):
        append_asset(assets, asset)
    for asset in extract_backtick_assets(prompt):
        append_asset(assets, asset)
    patterns = (
        r"\b[a-zA-Z0-9_-]+(?:portal|api|console|server|service|gateway|wiki|db|database|agent|store|bastion|repo)\b",
        r"\b[a-zA-Z0-9_-]+\s+(?:portal|api|console|server|service|gateway|wiki|database|agent|store|bastion|repo)\b",
        r"\b(?:support|internal|ticket|build|signing|update|customer|object|source|release|dark web|controlled)\s+(?:portal|api|console|server|service|gateway|wiki|database|agent|store|bastion|repo|drop)\b",
    )
    for pattern in patterns:
        for match in re.findall(pattern, prompt, flags=re.IGNORECASE):
            append_asset(assets, match)
    return assets[:20]


def extract_markdown_table_assets(prompt: str) -> list[str]:
    assets: list[str] = []
    for line in prompt.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or "---" in stripped:
            continue
        cells = [cell.strip(" `") for cell in stripped.strip("|").split("|")]
        if len(cells) < 2:
            continue
        first = cells[0]
        if first.lower() in {"system", "service", "asset", "시스템", "서비스", "역할", "stage"}:
            continue
        if looks_like_asset_name(first):
            assets.append(first)
    return assets


def extract_backtick_assets(prompt: str) -> list[str]:
    assets: list[str] = []
    for value in re.findall(r"`([^`]{2,80})`", prompt):
        if looks_like_asset_name(value):
            assets.append(value)
    return assets


def append_asset(assets: list[str], value: str) -> None:
    asset = normalize_service_name(value)
    if not asset or asset in GENERIC_ASSET_NAMES:
        return
    if asset not in assets:
        assets.append(asset)


def looks_like_asset_name(value: str) -> bool:
    normalized = normalize_service_name(value)
    if not normalized or normalized in GENERIC_ASSET_NAMES:
        return False
    service_tokens = (
        "portal", "api", "console", "server", "service", "gateway", "wiki",
        "database", "db", "agent", "store", "bastion", "repo", "ldap",
        "gitea", "build", "signing", "update", "customer", "drop", "grader",
    )
    return any(token in normalized for token in service_tokens)


def infer_likely_entrypoints(prompt: str, named_assets: list[str]) -> list[str]:
    lowered = prompt.lower()
    entrypoints = [asset for asset in named_assets if any(token in asset for token in ("portal", "gateway", "vpn", "public", "entry"))]
    if "support" in lowered and "support-portal" not in entrypoints:
        entrypoints.append("support-portal")
    if "investor" in lowered and "investor-portal" not in entrypoints:
        entrypoints.append("investor-portal")
    if "patient" in lowered and "patient-portal" not in entrypoints:
        entrypoints.append("patient-portal")
    if not entrypoints:
        entrypoints.append("public-entry-service")
    return entrypoints[:8]


def infer_likely_final_objectives(prompt: str) -> list[str]:
    lowered = prompt.lower()
    objectives: list[str] = []
    heading_objectives = extract_objectives_after_heading(prompt)
    objectives.extend(heading_objectives)
    objective_patterns = (
        r"(?:final objective|final target|최종 목표|최종 대상)\s*[:：]\s*([^\n.]+)",
        r"(?:reach|obtain|retrieve|submit|exfiltrate|획득|제출|도달)[^\n.]{0,120}",
    )
    for pattern in objective_patterns:
        for match in re.findall(pattern, prompt, flags=re.IGNORECASE):
            value = clean_objective_text(str(match))
            if value and value not in objectives:
                objectives.append(value)
    if not objectives:
        if "export" in lowered:
            objectives.append("controlled business export object")
        elif "flag" in lowered:
            objectives.append("controlled final proof object")
        else:
            objectives.append("declared sensitive object or proof material")
    return objectives[:5]


def extract_objectives_after_heading(prompt: str) -> list[str]:
    objectives: list[str] = []
    lines = prompt.splitlines()
    collecting = False
    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered.rstrip(":：") in {"최종 목표", "final objective", "final objectives", "final target"}:
            collecting = True
            continue
        if collecting:
            if stripped.startswith("#") or (stripped and not stripped.startswith(("-", "*"))):
                break
            if stripped.startswith(("-", "*")):
                value = clean_objective_text(stripped)
                if value:
                    objectives.append(value)
    return objectives[:5]


def clean_objective_text(value: str) -> str:
    cleaned = re.sub(r"^[\s\-*|]+", "", value.strip())
    cleaned = re.sub(r"\s+", " ", cleaned)
    cleaned = cleaned.strip(" .|")
    return cleaned


def infer_realism_risks(provider_pressure: list[str], attack_themes: list[str]) -> list[str]:
    risks: list[str] = []
    if any(item.startswith("hybrid-or-vm") for item in provider_pressure):
        risks.append("Windows domain, endpoint, or AD behavior may not be realistic in Docker-only mode.")
    if any(item.startswith("ot-or-ics") for item in provider_pressure):
        risks.append("OT/ICS behavior requires careful simulation boundaries and may need VM or specialized protocol emulation.")
    if any(item.startswith("cloud-provider-needed") for item in provider_pressure):
        risks.append("Cloud identity and storage behavior may require a dedicated provider model or local emulator.")
    if not attack_themes:
        risks.append("The prompt does not clearly identify the attack path; scenario-designer must define stages before implementation.")
    return risks


def normalize_industry(value: str) -> str:
    normalized = slugify(value)
    aliases = {
        "bank": "banking",
        "banking": "banking",
        "regional-bank": "banking",
        "retail-bank": "banking",
        "commercial-bank": "banking",
        "core-banking": "banking",
        "finance": "banking",
        "financial": "banking",
        "financial-services": "banking",
        "brokerage": "securities",
        "stock-brokerage": "securities",
        "medical": "healthcare",
        "hospital": "healthcare",
        "ad": "active-directory",
        "windows-domain": "active-directory",
    }
    return aliases.get(normalized, normalized or "enterprise")


def natural_language_assumptions(request: NaturalLanguageScenarioRequest) -> list[str]:
    provider_note = {
        "auto": "Provider is unresolved. LabForge will start with a conservative draft and ask provider agents to decide whether Docker-only is realistic.",
        "docker-compose": "Docker Compose is preferred, but the provider agent must flag any Windows, AD, endpoint, OT, or hypervisor realism gaps.",
        "hybrid": "Hybrid deployment is preferred, so VM-backed assets may be required for realistic enterprise behavior.",
        "ansible": "Ansible is preferred, so generated implementation should target host provisioning rather than only containers.",
        "terraform": "Terraform is preferred, so generated implementation should include infrastructure resources and lifecycle boundaries.",
        "ludus": "Ludus-style range deployment is preferred for VM-heavy cyber range assets.",
    }.get(request.preferred_provider, "Provider preference is custom and must be reviewed.")
    return [
        "The user prompt is treated as intent, not as a complete or trusted technical specification.",
        "The inferred scenario intake is a draft for LLM and supervisor review.",
        "Industry realism must be reviewed by a dedicated industry-realism-reviewer agent before implementation.",
        provider_note,
    ]


def scenario_profile_for_request(request: NaturalLanguageScenarioRequest) -> dict:
    if request.industry == "supply-chain":
        return supply_chain_profile(request)
    if request.industry == "active-directory":
        return active_directory_profile(request)
    if request.industry == "securities":
        return securities_profile(request)
    if request.industry == "banking":
        return banking_profile(request)
    if request.industry == "healthcare":
        return healthcare_profile(request)
    if request.industry == "manufacturing":
        return manufacturing_profile(request)
    return enterprise_profile(request)


def common_attacker_infrastructure() -> list[str]:
    return [
        "attacker-workstation: learner-controlled Linux shell host with browser-accessible tunnel support",
        "controlled-drop: final controlled submission service",
    ]


def common_security_controls() -> list[str]:
    return [
        "Firewall / segmentation",
        "IDS east-west sensor",
        "Central log collection",
        "Application access logs",
        "Supervisor-selectable protected/unprotected profile",
    ]


def enterprise_profile(request: NaturalLanguageScenarioRequest) -> dict:
    return {
        "inspiration": ["General enterprise intrusion chain derived from the natural-language scenario prompt."],
        "final_objective": "Reach the declared sensitive business object and submit it to the controlled drop service.",
        "learner_entrypoint": "Externally reachable business web service identified from the scenario prompt.",
        "attacker_infrastructure": common_attacker_infrastructure(),
        "target_infrastructure": [
            "public-entry-service: external business application",
            "internal-portal: intranet service containing operational clues",
            "identity-service: directory or SSO-like identity service",
            "file-service: internal document and evidence store",
            "sensitive-data-service: final collection target",
        ],
        "security_controls": common_security_controls(),
        "stages": generic_stage_chain("public-entry-service", "internal-portal", "sensitive-data-service"),
    }


def supply_chain_profile(request: NaturalLanguageScenarioRequest) -> dict:
    return {
        "inspiration": ["Supply-chain intrusion pattern involving support, release, trusted build, and customer environments."],
        "final_objective": "Compromise a trusted release path and reach a customer-side controlled sensitive object.",
        "learner_entrypoint": "Public support or partner-facing portal.",
        "attacker_infrastructure": common_attacker_infrastructure(),
        "target_infrastructure": [
            "support-portal: externally reachable support application",
            "internal-wiki: internal knowledge base",
            "release-bastion: release network jump host",
            "release-console: release operations application",
            "build-server: trusted build pipeline",
            "update-server: signed update channel",
            "customer-agent: customer-side update consumer",
            "customer-api: customer business API",
            "object-store: customer export object store",
        ],
        "security_controls": common_security_controls() + ["Build provenance logging", "Release approval workflow"],
        "stages": [
            stage("stage-01", "Identify the support portal weakness.", "Inspect normal portal behavior and confirm the initial public-facing exploit path.", "Initial Access", ["T1190 Exploit Public-Facing Application"], ["support-portal"]),
            stage("stage-02", "Obtain a bounded foothold on the support host.", "Use the initial weakness to establish lab-scoped shell or command execution and collect local context.", "Execution", ["T1059 Command and Scripting Interpreter"], ["support-portal", "attacker-workstation"]),
            stage("stage-03", "Pivot to internal knowledge resources.", "Use standard tunneling or proxying to reach the internal wiki from the foothold path.", "Command and Control", ["T1090 Proxy"], ["support-portal", "internal-wiki"]),
            stage("stage-04", "Discover release operations clues.", "Read realistic internal documentation and separate useful release topology from operational noise.", "Discovery", ["T1083 File and Directory Discovery"], ["internal-wiki"]),
            stage("stage-05", "Move into the release network.", "Exploit a bounded internal service weakness and establish access to the release-side host.", "Lateral Movement", ["T1210 Exploitation of Remote Services"], ["release-bastion"]),
            stage("stage-06", "Abuse release operator trust.", "Use an application-layer weakness such as stored XSS or workflow abuse to obtain build context.", "Credential Access", ["T1539 Steal Web Session Cookie"], ["release-console"]),
            stage("stage-07", "Create a trusted modified build.", "Submit the approved patch artifact through the build workflow and verify signed build metadata.", "Defense Evasion", ["T1553 Subvert Trust Controls"], ["build-server"]),
            stage("stage-08", "Publish to the customer update channel.", "Publish the signed manifest to the target customer channel through the release workflow.", "Impact", ["T1484 Domain or Tenant Policy Modification"], ["update-server"]),
            stage("stage-09", "Observe customer-side callback or update effects.", "Wait for or trigger the lab-scoped customer agent update behavior and collect allowed diagnostics.", "Command and Control", ["T1105 Ingress Tool Transfer"], ["customer-agent"]),
            stage("stage-10", "Collect and submit the final customer object.", "Use discovered customer API metadata to retrieve the controlled object and submit proof.", "Collection", ["T1005 Data from Local System"], ["customer-api", "object-store", "controlled-drop"]),
        ],
    }


def active_directory_profile(request: NaturalLanguageScenarioRequest) -> dict:
    return {
        "inspiration": ["Enterprise Windows domain compromise pattern with identity abuse and internal collection."],
        "final_objective": "Compromise the domain-backed path to a sensitive internal file or application object.",
        "learner_entrypoint": "Externally reachable employee service or VPN-like access broker.",
        "attacker_infrastructure": common_attacker_infrastructure(),
        "target_infrastructure": [
            "employee-portal: externally reachable employee application",
            "windows-workstation: domain-joined workstation",
            "domain-controller: Windows Server Active Directory domain controller",
            "file-share: domain file server",
            "admin-workstation: privileged operator workstation",
            "sensitive-share: final controlled data location",
        ],
        "security_controls": common_security_controls() + ["Windows event forwarding", "Endpoint telemetry", "AD audit policy"],
        "stages": [
            stage("stage-01", "Identify the employee-facing initial access path.", "Inspect the public service and establish a bounded first foothold.", "Initial Access", ["T1190 Exploit Public-Facing Application"], ["employee-portal"]),
            stage("stage-02", "Enumerate domain context.", "Collect hostname, user, domain, group, and network context from the foothold.", "Discovery", ["T1087 Account Discovery"], ["windows-workstation", "domain-controller"]),
            stage("stage-03", "Find reachable internal shares and services.", "Map internal SMB, LDAP, Kerberos, and application services available to the current identity.", "Discovery", ["T1046 Network Service Discovery"], ["domain-controller", "file-share"]),
            stage("stage-04", "Acquire or abuse a domain credential path.", "Use the scenario-approved identity weakness to gain a more useful domain context.", "Credential Access", ["T1555 Credentials from Password Stores"], ["windows-workstation"]),
            stage("stage-05", "Move laterally to a domain host.", "Use an approved remote service path to access a second host.", "Lateral Movement", ["T1021 Remote Services"], ["admin-workstation"]),
            stage("stage-06", "Reach the sensitive share and collect proof.", "Use discovered ACLs and domain context to retrieve the final controlled file.", "Collection", ["T1039 Data from Network Shared Drive"], ["sensitive-share", "controlled-drop"]),
        ],
    }


def securities_profile(request: NaturalLanguageScenarioRequest) -> dict:
    return {
        "inspiration": ["Financial-sector intrusion pattern involving public investor services and internal trade operations systems."],
        "final_objective": "Reach a controlled trade, settlement, or compliance export object and submit proof.",
        "learner_entrypoint": "Public investor or customer support portal.",
        "attacker_infrastructure": common_attacker_infrastructure(),
        "target_infrastructure": [
            "investor-portal: public account and support surface",
            "customer-identity-gateway: customer login, MFA, and session service",
            "api-gateway: customer and partner API gateway",
            "market-data-service: internal market data service",
            "trade-ops-console: operations console for trade exceptions",
            "settlement-db: settlement and reconciliation data store",
            "trade-data-warehouse: trade records and compliance data warehouse",
            "compliance-export: controlled final export service",
        ],
        "security_controls": common_security_controls() + ["Fraud monitoring feed", "Transaction anomaly logging"],
        "stages": [
            stage("stage-01", "Identify the investor portal rendering or request-routing weakness.", "Inspect normal investor support workflows and confirm a bounded public-facing application exploit path such as template preview abuse or internal URL fetch behavior.", "Initial Access", ["T1190 Exploit Public-Facing Application"], ["investor-portal"]),
            stage("stage-02", "Establish a bounded foothold in the application tier.", "Use the entry weakness to collect service identity, environment, and internal routing context without touching real financial systems.", "Execution", ["T1059 Command and Scripting Interpreter"], ["investor-portal", "attacker-workstation"]),
            stage("stage-03", "Discover trading application services.", "Enumerate application-tier service names and distinguish market data, trade operations, settlement, and compliance systems from operational noise.", "Discovery", ["T1046 Network Service Discovery"], ["api-gateway", "market-data-service"]),
            stage("stage-04", "Access trade operations context.", "Use internal documentation or gateway metadata to learn how trade exception reviews and approval queues are handled.", "Discovery", ["T1083 File and Directory Discovery"], ["trade-ops-console"]),
            stage("stage-05", "Abuse a trade exception review workflow.", "Submit controlled content or metadata that is reviewed by a privileged trade operations role and collect lab-scoped context exposed by that review.", "Credential Access", ["T1539 Steal Web Session Cookie"], ["trade-ops-console"]),
            stage("stage-06", "Reach settlement metadata.", "Use the discovered operations context to query settlement or reconciliation records and identify the relevant controlled export identifier.", "Collection", ["T1005 Data from Local System"], ["settlement-db"]),
            stage("stage-07", "Retrieve the compliance export object.", "Use the export identifier and discovered proof material to access the synthetic compliance export through the intended lab path.", "Collection", ["T1020 Automated Exfiltration"], ["compliance-export"]),
            stage("stage-08", "Submit final proof.", "Submit the controlled compliance export proof to the drop service and verify completion evidence.", "Exfiltration", ["T1041 Exfiltration Over C2 Channel"], ["controlled-drop"]),
        ],
    }


def banking_profile(request: NaturalLanguageScenarioRequest) -> dict:
    return {
        "inspiration": ["Retail and commercial banking intrusion pattern involving digital banking, loan operations, core account services, fraud monitoring, and compliance exports."],
        "final_objective": "Reach a controlled banking compliance, fraud, or suspicious-activity export object and submit proof.",
        "learner_entrypoint": "Public online banking, loan application, or customer support portal.",
        "attacker_infrastructure": common_attacker_infrastructure(),
        "target_infrastructure": [
            "loan-application-portal: public digital banking and loan intake surface",
            "customer-identity-gateway: customer login, MFA, device trust, and session service",
            "document-intake-service: uploaded evidence and loan document processing service",
            "loan-ops-console: internal underwriting and exception review console",
            "core-account-service: synthetic account and deposit profile service",
            "payments-batch-service: payment, wire, ACH, and reconciliation batch context",
            "fraud-monitoring-service: FDS, transaction risk, and AML case context",
            "compliance-export-service: controlled regulatory or suspicious-activity export service",
        ],
        "security_controls": common_security_controls()
        + [
            "Digital banking access logs",
            "Fraud detection feed",
            "AML case review audit trail",
            "Payments batch reconciliation logging",
        ],
        "stages": [
            stage("stage-01", "Identify the public banking workflow weakness.", "Inspect normal online banking, loan application, or support workflows and confirm a bounded public-facing application exploit path.", "Initial Access", ["T1190 Exploit Public-Facing Application"], ["loan-application-portal"]),
            stage("stage-02", "Establish a bounded foothold in the digital banking tier.", "Use the entry weakness to collect service identity, environment, and internal routing context without touching real banking systems.", "Execution", ["T1059 Command and Scripting Interpreter"], ["loan-application-portal", "attacker-workstation"]),
            stage("stage-03", "Discover internal banking services.", "Enumerate service names and separate identity, document intake, loan operations, core account, payments, fraud, and compliance systems from operational noise.", "Discovery", ["T1046 Network Service Discovery"], ["customer-identity-gateway", "document-intake-service"]),
            stage("stage-04", "Reach loan operations context.", "Use internal documentation, metadata, or workflow clues to learn how underwriting, evidence review, and loan exceptions are handled.", "Discovery", ["T1083 File and Directory Discovery"], ["loan-ops-console"]),
            stage("stage-05", "Abuse an operations review workflow.", "Submit controlled content or metadata reviewed by a privileged loan operations role and collect lab-scoped context exposed by that review.", "Credential Access", ["T1539 Steal Web Session Cookie"], ["loan-ops-console"]),
            stage("stage-06", "Correlate account, payment, and fraud metadata.", "Use the discovered operations context to identify the relevant synthetic account, payment batch, fraud case, or AML export identifier.", "Collection", ["T1005 Data from Local System"], ["core-account-service", "payments-batch-service", "fraud-monitoring-service"]),
            stage("stage-07", "Retrieve the controlled compliance export.", "Use the export identifier and proof material to access the intended synthetic regulatory or suspicious-activity export.", "Collection", ["T1020 Automated Exfiltration"], ["compliance-export-service"]),
            stage("stage-08", "Submit final proof.", "Submit the controlled banking export proof to the drop service and verify completion evidence.", "Exfiltration", ["T1041 Exfiltration Over C2 Channel"], ["controlled-drop"]),
        ],
    }


def healthcare_profile(request: NaturalLanguageScenarioRequest) -> dict:
    return {
        "inspiration": ["Healthcare provider intrusion pattern involving patient portal, clinical systems, and audit exports."],
        "final_objective": "Reach a controlled patient or clinical audit export without using real patient data.",
        "learner_entrypoint": "Public patient portal or appointment service.",
        "attacker_infrastructure": common_attacker_infrastructure(),
        "target_infrastructure": [
            "patient-portal: public appointment and message service",
            "identity-gateway: staff and patient identity gateway",
            "ehr-api: electronic health record API",
            "billing-claims-adapter: synthetic billing and insurance integration",
            "clinical-workstation: internal clinical workstation",
            "audit-export-service: final controlled export service",
        ],
        "security_controls": common_security_controls() + ["PHI-safe synthetic data boundary", "Clinical audit logging"],
        "stages": [
            stage("stage-01", "Identify the patient portal weakness.", "Inspect appointment, message, or document-preview workflows and confirm a bounded public-facing exploit condition.", "Initial Access", ["T1190 Exploit Public-Facing Application"], ["patient-portal"]),
            stage("stage-02", "Establish a bounded portal foothold.", "Collect runtime identity, route metadata, and clinical network clues from the portal context while staying inside synthetic lab data.", "Execution", ["T1059 Command and Scripting Interpreter"], ["patient-portal", "attacker-workstation"]),
            stage("stage-03", "Discover identity and clinical APIs.", "Enumerate internal identity gateway and EHR API surfaces reachable from the application tier.", "Discovery", ["T1046 Network Service Discovery"], ["identity-gateway", "ehr-api"]),
            stage("stage-04", "Correlate synthetic patient and staff context.", "Use normal metadata and audit views to identify which synthetic records or staff workflow unlock the next stage.", "Discovery", ["T1087 Account Discovery"], ["identity-gateway", "ehr-api"]),
            stage("stage-05", "Abuse a clinical review or workstation workflow.", "Use a lab-scoped review, diagnostic, or session workflow to expose privileged clinical context.", "Credential Access", ["T1539 Steal Web Session Cookie"], ["clinical-workstation"]),
            stage("stage-06", "Access the audit export service.", "Use discovered authorization gaps or export metadata to request the controlled clinical audit export.", "Collection", ["T1005 Data from Local System"], ["audit-export-service"]),
            stage("stage-07", "Verify synthetic data boundaries.", "Confirm the retrieved object is synthetic training data and contains no real protected health information.", "Collection", ["T1119 Automated Collection"], ["audit-export-service"]),
            stage("stage-08", "Submit final proof.", "Submit the controlled audit export proof to the drop service.", "Exfiltration", ["T1041 Exfiltration Over C2 Channel"], ["controlled-drop"]),
        ],
    }


def manufacturing_profile(request: NaturalLanguageScenarioRequest) -> dict:
    return {
        "inspiration": ["Manufacturing enterprise intrusion pattern crossing IT services into bounded OT-style visibility."],
        "final_objective": "Reach a controlled production report or engineering export without affecting real industrial systems.",
        "learner_entrypoint": "Public supplier or maintenance portal.",
        "attacker_infrastructure": common_attacker_infrastructure(),
        "target_infrastructure": [
            "supplier-portal: public supplier access application",
            "engineering-wiki: internal engineering documentation",
            "mes-api: manufacturing execution API",
            "historian: bounded process-history data service",
            "ot-jump-host: simulated operations jump host",
            "production-report-store: final controlled export service",
        ],
        "security_controls": common_security_controls() + ["IT/OT segmentation", "Passive OT monitoring"],
        "stages": [
            stage("stage-01", "Identify the supplier portal weakness.", "Inspect supplier document, maintenance request, or quote-preview workflows and confirm a bounded public-facing application exploit path.", "Initial Access", ["T1190 Exploit Public-Facing Application"], ["supplier-portal"]),
            stage("stage-02", "Establish a bounded IT foothold.", "Use the entry weakness to collect host, route, and service context from the supplier portal tier.", "Execution", ["T1059 Command and Scripting Interpreter"], ["supplier-portal", "attacker-workstation"]),
            stage("stage-03", "Reach engineering knowledge systems.", "Use standard tunneling or internal service discovery to access engineering documentation without direct OT manipulation.", "Command and Control", ["T1090 Proxy"], ["engineering-wiki"]),
            stage("stage-04", "Separate useful engineering clues from noise.", "Review realistic maintenance notes, recipe documentation, and production change records to find MES and historian paths.", "Discovery", ["T1083 File and Directory Discovery"], ["engineering-wiki"]),
            stage("stage-05", "Discover bounded production services.", "Enumerate MES, historian, and jump-host surfaces that are intentionally simulated for the lab.", "Discovery", ["T1046 Network Service Discovery"], ["mes-api", "historian", "ot-jump-host"]),
            stage("stage-06", "Abuse an operations diagnostic or trust workflow.", "Use a scenario-approved internal workflow to reach production report metadata while avoiding any destructive control action.", "Lateral Movement", ["T1210 Exploitation of Remote Services"], ["ot-jump-host", "mes-api"]),
            stage("stage-07", "Retrieve the production report object.", "Use discovered historian or MES metadata to access the controlled production report export.", "Collection", ["T1005 Data from Local System"], ["historian", "production-report-store"]),
            stage("stage-08", "Submit final proof.", "Submit the controlled production report proof to the drop service.", "Exfiltration", ["T1041 Exfiltration Over C2 Channel"], ["controlled-drop"]),
        ],
    }


def generic_stage_chain(entry: str, internal: str, final: str) -> list[dict]:
    return [
        stage("stage-01", "Identify the external entry weakness.", "Inspect normal business behavior and confirm the initial access condition.", "Initial Access", ["T1190 Exploit Public-Facing Application"], [entry]),
        stage("stage-02", "Establish a bounded foothold.", "Use the entry weakness to obtain lab-scoped execution or session access.", "Execution", ["T1059 Command and Scripting Interpreter"], [entry, "attacker-workstation"]),
        stage("stage-03", "Discover internal services.", "Enumerate reachable hosts, names, and application surfaces from the foothold.", "Discovery", ["T1046 Network Service Discovery"], [entry, internal]),
        stage("stage-04", "Access internal operational context.", "Reach internal documentation or an operations application and identify the next trust boundary.", "Discovery", ["T1083 File and Directory Discovery"], [internal]),
        stage("stage-05", "Move laterally or abuse trust.", "Use a scenario-approved internal weakness or trust relationship to access the next system.", "Lateral Movement", ["T1210 Exploitation of Remote Services"], [internal]),
        stage("stage-06", "Collect the final controlled object.", "Use discovered metadata and authorized lab paths to retrieve and submit the final object.", "Collection", ["T1005 Data from Local System"], [final, "controlled-drop"]),
    ]


def stage(
    stage_id: str,
    learner_goal: str,
    expected_action: str,
    mitre_tactic: str,
    mitre_techniques: list[str],
    infrastructure_touched: list[str],
) -> dict:
    return {
        "stage_id": stage_id,
        "learner_goal": learner_goal,
        "expected_action": expected_action,
        "evidence": [f"{stage_id}_completed"],
        "mitre_tactic": mitre_tactic,
        "mitre_techniques": mitre_techniques,
        "infrastructure_touched": infrastructure_touched,
    }


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
        f"- Target industry: `{intake.target_industry}`",
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


def render_source_prompt_markdown(request: NaturalLanguageScenarioRequest) -> str:
    return "\n".join(
        [
            f"# Source Scenario Prompt - {request.title}",
            "",
            "This file preserves the original natural-language scenario intent.",
            "Treat this prompt as the source of user intent. The generated YAML files are draft interpretations.",
            "",
            "## Metadata",
            "",
            f"- Lab ID: `{request.lab_id}`",
            f"- Industry: `{request.industry}`",
            f"- Difficulty: `{request.difficulty}`",
            f"- Preferred provider: `{request.preferred_provider}`",
            f"- Audience: `{request.audience}`",
            "",
            "## Prompt",
            "",
            request.prompt,
            "",
        ]
    )


def render_prompt_analysis_markdown(analysis: PromptAnalysis) -> str:
    sections = [
        ("Industry Evidence", analysis.industry_evidence),
        ("Provider Pressure", analysis.provider_pressure),
        ("Likely Entrypoints", analysis.likely_entrypoints),
        ("Likely Final Objectives", analysis.likely_final_objectives),
        ("Named Assets", analysis.named_assets),
        ("Requested Attack Themes", analysis.requested_attack_themes),
        ("Security Control Hints", analysis.security_control_hints),
        ("Realism Risks", analysis.realism_risks),
        ("Supervisor Questions", analysis.supervisor_questions),
    ]
    lines = [
        "# Prompt Analysis",
        "",
        f"- Detected industry: `{analysis.detected_industry}`",
        "",
    ]
    for title, values in sections:
        lines += [f"## {title}", ""]
        if values:
            lines.extend(f"- {item}" for item in values)
        else:
            lines.append("- None detected.")
        lines.append("")
    return "\n".join(lines)


def render_natural_language_transformation_brief(package: NaturalLanguageIntakePackage) -> str:
    intake = package.inferred_intake
    request = package.request
    lines = [
        f"# Natural-Language Scenario Transformation Brief - {request.title}",
        "",
        "You are turning a natural-language cyber range idea into a LabForge scenario package.",
        "The user did not provide a complete LabForge specification. You must design one, document assumptions, and preserve safety boundaries.",
        "",
        "## Source Prompt",
        "",
        request.prompt,
        "",
        "## Draft Inference",
        "",
        f"- Lab ID: `{request.lab_id}`",
        f"- Industry: `{request.industry}`",
        f"- Difficulty: `{request.difficulty}`",
        f"- Preferred provider: `{request.preferred_provider}`",
        "",
        "## Required Agent Work",
        "",
        "1. `scenario-designer`: convert the prompt into a coherent stage-by-stage red-team lab, selecting realistic vulnerabilities and business services.",
        "2. `mitre-mapper`: map every stage to MITRE ATT&CK Matrix for Enterprise tactics and techniques.",
        "3. `infrastructure-architect`: produce unprotected and protected architecture, provider requirements, network boundaries, and host requirements.",
        "4. `industry-realism-reviewer`: verify that UI, services, data, architecture, and workflows match the declared industry.",
        "5. `safety-reviewer`: reject external C2, real victim data, destructive payloads, or uncontrolled exploit behavior.",
        "6. `provider-engineer` and `service-builder`: implement only after the design is accepted by a supervisor.",
        "",
        "## Transformation Rules",
        "",
        "- Keep generated internal contracts, code, and prompts in English.",
        "- Do not treat the heuristic intake as final truth.",
        "- Prefer realistic bounded services over fake text-only simulators.",
        "- If Docker-only cannot represent the scenario realistically, recommend a hybrid or VM provider.",
        "- Produce both unprotected and protected architecture views.",
        "- Avoid magic strings, hidden endpoints, or solver-only knowledge that learners cannot discover from the lab.",
        "- Keep all callback, exploit, and collection behavior inside lab-controlled infrastructure.",
        "",
        "## Assumptions to Review",
        "",
    ]
    lines.extend(f"- {item}" for item in package.assumptions)
    lines += [
        "",
        "## Prompt Analysis",
        "",
        f"- Detected industry: `{package.prompt_analysis.detected_industry}`",
    ]
    for value in package.prompt_analysis.realism_risks:
        lines.append(f"- Realism risk: {value}")
    lines += [
        "",
        "## Draft Scenario Intake",
        "",
        "```json",
        json.dumps(intake.model_dump(), ensure_ascii=False, indent=2),
        "```",
        "",
        "## Suggested Next Commands",
        "",
        "```powershell",
    ]
    lines.extend(package.next_commands)
    lines += ["```", ""]
    return "\n".join(lines)


INTAKE_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "scenario-intake.schema.json": ScenarioIntake,
    "natural-language-scenario-request.schema.json": NaturalLanguageScenarioRequest,
    "natural-language-intake-package.schema.json": NaturalLanguageIntakePackage,
    "prompt-analysis.schema.json": PromptAnalysis,
}
