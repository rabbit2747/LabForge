from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, write_text
from .model import LabSpec
from .service_templates import get_service_template_by_id, template_id_for_artifact


class ServiceBlueprintModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class ServiceRouteBlueprint(ServiceBlueprintModel):
    method: str = "GET"
    path: str
    purpose: str
    auth: str = "none"
    learner_visible: bool = True


class ServiceDataStoreBlueprint(ServiceBlueprintModel):
    name: str
    kind: str = "file"
    purpose: str
    seed_files: list[str] = Field(default_factory=list)


class ServiceWorkflowBlueprint(ServiceBlueprintModel):
    name: str
    actor: str
    steps: list[str] = Field(default_factory=list)
    normal_outcome: str = ""


class ServiceBuilderBlueprint(ServiceBlueprintModel):
    service: str
    template: str
    runtime: str
    purpose: str
    role: Literal[
        "business-portal",
        "internal-admin-console",
        "identity-gateway",
        "data-api",
        "audit-log-service",
        "message-broker-stub",
        "object-store",
        "siem-log-viewer",
        "attacker-workstation",
        "controlled-drop",
        "generic-service",
    ] = "generic-service"
    exposed: bool = False
    routes: list[ServiceRouteBlueprint] = Field(default_factory=list)
    data_stores: list[ServiceDataStoreBlueprint] = Field(default_factory=list)
    normal_workflows: list[ServiceWorkflowBlueprint] = Field(default_factory=list)
    seed_data: list[str] = Field(default_factory=list)
    noise_data: list[str] = Field(default_factory=list)
    evidence_logs: list[str] = Field(default_factory=list)
    healthcheck: str
    reset: str
    safety_boundaries: list[str] = Field(default_factory=list)
    implementation_notes: list[str] = Field(default_factory=list)


class ServiceBlueprintReport(ServiceBlueprintModel):
    lab_id: str
    service_count: int
    blueprints: list[ServiceBuilderBlueprint] = Field(default_factory=list)


class ServiceImplementationStatusItem(ServiceBlueprintModel):
    service: str
    role: str = "generic-service"
    source_path: str
    status: Literal["missing", "scaffolded", "blueprinted", "runtime", "tested"] = "missing"
    blueprint: bool = False
    scaffold: bool = False
    runtime: bool = False
    tests: bool = False
    healthcheck: bool = False
    reset: bool = False
    findings: list[str] = Field(default_factory=list)


class ServiceImplementationStatusReport(ServiceBlueprintModel):
    lab_id: str
    service_count: int
    ready_count: int = 0
    items: list[ServiceImplementationStatusItem] = Field(default_factory=list)


def create_service_blueprints(spec: LabSpec, out: Path | None = None) -> ServiceBlueprintReport:
    services_by_name = {str(service.get("name")): service for service in spec.services}
    blueprints: list[ServiceBuilderBlueprint] = []
    for artifact in blueprint_service_artifacts(spec):
        service = services_by_name.get(artifact.service, {})
        template = choose_blueprint_template(artifact)
        role = infer_service_role(artifact.service, artifact.purpose, template)
        blueprint = ServiceBuilderBlueprint(
            service=artifact.service,
            template=template or "python-flask-web",
            runtime=artifact.runtime,
            purpose=artifact.purpose,
            role=role,
            exposed=bool(service.get("exposed") or service.get("ports")),
            routes=default_routes_for_role(role),
            data_stores=default_data_stores_for_role(role, artifact),
            normal_workflows=default_workflows_for_role(role, artifact),
            seed_data=list(artifact.seed_inputs),
            noise_data=list(artifact.noise_inputs),
            evidence_logs=list(artifact.evidence_logs),
            healthcheck=artifact.healthcheck,
            reset=artifact.reset,
            safety_boundaries=list(artifact.safety_boundaries),
            implementation_notes=implementation_notes_for_role(role),
        )
        blueprints.append(blueprint)

    report = ServiceBlueprintReport(lab_id=spec.lab_id, service_count=len(blueprints), blueprints=blueprints)
    if out:
        out.mkdir(parents=True, exist_ok=True)
        write_text(out / "service-blueprints.yaml", dump_yaml(report.model_dump()))
        write_text(out / "service-blueprints.json", json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + "\n")
        write_text(out / "service-blueprints.md", service_blueprints_to_markdown(report))
    return report


def write_service_blueprint_files(spec: LabSpec, force: bool = False) -> list[Path]:
    written: list[Path] = []
    report = create_service_blueprints(spec)
    for blueprint in report.blueprints:
        service_root = spec.root / service_source_path(spec, blueprint.service)
        if not service_root:
            continue
        target = service_root / "blueprint.yaml"
        if target.exists() and not force:
            continue
        write_text(target, dump_yaml(blueprint.model_dump()))
        written.append(target)
    return written


def inspect_service_implementation_status(spec: LabSpec, out: Path | None = None) -> ServiceImplementationStatusReport:
    blueprint_by_service = {blueprint.service: blueprint for blueprint in create_service_blueprints(spec).blueprints}
    items: list[ServiceImplementationStatusItem] = []
    ready = 0
    for artifact in blueprint_service_artifacts(spec):
        service_root = spec.root / artifact.source_path
        blueprint = service_root / "blueprint.yaml"
        scaffold_files = [service_root / "README.md", service_root / "labforge-service.yaml", service_root / "healthcheck.sh", service_root / "reset.sh"]
        runtime_files = [service_root / "Dockerfile", service_root / "app.py"]
        tests_dir = service_root / "tests"
        findings: list[str] = []
        root_exists = service_root.exists() and service_root.is_dir()
        scaffold = root_exists and all(path.exists() for path in scaffold_files)
        runtime = root_exists and all(path.exists() for path in runtime_files)
        tests = tests_dir.exists() and any(path.is_file() and path.name != ".gitkeep" for path in tests_dir.rglob("*"))
        healthcheck = (service_root / "healthcheck.sh").exists()
        reset = (service_root / "reset.sh").exists()
        if not root_exists:
            findings.append("service source directory is missing")
        if not blueprint.exists():
            findings.append("blueprint.yaml is missing")
        if not scaffold:
            findings.append("scaffold contract files are incomplete")
        if not runtime:
            findings.append("runtime files are incomplete")
        if not tests:
            findings.append("service tests are missing")
        status = "missing"
        if scaffold:
            status = "scaffolded"
        if blueprint.exists():
            status = "blueprinted"
        if runtime:
            status = "runtime"
        if runtime and tests:
            status = "tested"
            ready += 1
        items.append(
            ServiceImplementationStatusItem(
                service=artifact.service,
                role=blueprint_by_service.get(artifact.service).role if blueprint_by_service.get(artifact.service) else "generic-service",
                source_path=artifact.source_path,
                status=status,
                blueprint=blueprint.exists(),
                scaffold=scaffold,
                runtime=runtime,
                tests=tests,
                healthcheck=healthcheck,
                reset=reset,
                findings=findings,
            )
        )
    report = ServiceImplementationStatusReport(lab_id=spec.lab_id, service_count=len(items), ready_count=ready, items=items)
    if out:
        out.mkdir(parents=True, exist_ok=True)
        write_text(out / "service-status.yaml", dump_yaml(report.model_dump()))
        write_text(out / "service-status.json", json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + "\n")
        write_text(out / "service-status.md", service_status_to_markdown(report))
    return report


def service_source_path(spec: LabSpec, service_name: str) -> str:
    for artifact in blueprint_service_artifacts(spec):
        if artifact.service == service_name:
            return artifact.source_path
    return ""


def blueprint_service_artifacts(spec: LabSpec):
    if not spec.artifacts_model:
        return []
    return spec.artifacts_model.service_artifacts


def infer_template_from_artifact(artifact: Any) -> str:
    text = f"{artifact.service} {artifact.runtime} {artifact.purpose}".lower()
    if "drop" in text or "submit" in text:
        return "controlled-drop"
    if "attacker" in text or "workstation" in text:
        return "attacker-workstation-ssh"
    if "portal" in text or "public" in text or "support" in text or "wiki" in text or "docs" in text:
        return "business-portal"
    if "admin" in text or "console" in text or "jump-host" in text or "jumpbox" in text:
        return "internal-admin-console"
    if "review" in text or "approval" in text or "ops" in text:
        return "internal-admin-console"
    if "identity" in text or "auth" in text or "sso" in text:
        return "identity-gateway"
    if "siem" in text or "audit" in text or "log" in text:
        return "audit-log-service"
    if "object" in text or "store" in text or "archive" in text:
        return "object-store"
    if "data" in text or "api" in text:
        return "data-api"
    if "message broker" in text or "event bus" in text or " queue" in text or "-queue" in text:
        return "message-broker-stub"
    return "business-portal" if "portal" in text else "python-flask-web"


def choose_blueprint_template(artifact: Any) -> str:
    explicit = template_id_for_artifact(artifact)
    inferred = infer_template_from_artifact(artifact)
    generic = {"python-web-application", "python-flask-web", "python-flask", "flask", "unspecified"}
    if not explicit or explicit in generic:
        return inferred
    if not get_service_template_by_id(explicit):
        return inferred
    return explicit


def infer_service_role(service: str, purpose: str, template: str) -> str:
    text = f"{service} {purpose} {template}".lower()
    if "attacker" in text:
        return "attacker-workstation"
    if "drop" in text or "submit" in text:
        return "controlled-drop"
    if "portal" in text or "public" in text or "support" in text or "wiki" in text or "docs" in text:
        return "business-portal"
    if "admin" in text or "console" in text or "ops" in text or "jump-host" in text or "jumpbox" in text:
        return "internal-admin-console"
    if "review" in text or "approval" in text:
        return "internal-admin-console"
    if "identity" in text or "auth" in text or "sso" in text or "mfa" in text:
        return "identity-gateway"
    if "siem" in text or "audit" in text or "log" in text or "security" in text:
        return "audit-log-service" if "siem" not in text else "siem-log-viewer"
    if "object" in text or "archive" in text:
        return "object-store"
    if "data" in text or "api" in text or "warehouse" in text:
        return "data-api"
    if "message broker" in text or "event bus" in text or " queue" in text or "-queue" in text:
        return "message-broker-stub"
    return "generic-service"


def default_routes_for_role(role: str) -> list[ServiceRouteBlueprint]:
    routes = {
        "business-portal": [
            ("GET", "/", "Render business landing or dashboard", "none"),
            ("GET", "/healthz", "Readiness check", "none"),
            ("GET", "/api/profile", "Return current customer/operator profile", "session"),
            ("POST", "/api/requests", "Create normal business request", "session"),
        ],
        "internal-admin-console": [
            ("GET", "/", "Render operator console", "staff-session"),
            ("GET", "/api/tasks", "List operational tasks", "staff-session"),
            ("POST", "/api/actions", "Submit approved action", "staff-session"),
        ],
        "identity-gateway": [
            ("GET", "/healthz", "Readiness check", "none"),
            ("POST", "/api/login", "Start login flow", "none"),
            ("POST", "/api/mfa/verify", "Verify MFA challenge", "pending-session"),
            ("GET", "/api/session", "Inspect current session", "session"),
        ],
        "data-api": [
            ("GET", "/metadata", "Describe available datasets", "service-token"),
            ("GET", "/records", "Query business records", "service-token"),
            ("GET", "/exports", "List export objects", "service-token"),
        ],
        "audit-log-service": [
            ("GET", "/healthz", "Readiness check", "none"),
            ("POST", "/events", "Ingest audit event", "service-token"),
            ("GET", "/events", "Query audit events", "analyst-session"),
        ],
        "message-broker-stub": [
            ("POST", "/topics/<topic>/publish", "Publish lab-scoped message", "service-token"),
            ("GET", "/topics/<topic>/messages", "Read queued messages", "service-token"),
        ],
        "object-store": [
            ("GET", "/objects", "List visible object metadata", "service-token"),
            ("GET", "/objects/<key>", "Retrieve object with proof", "service-token"),
        ],
        "siem-log-viewer": [
            ("GET", "/", "Render analyst log viewer", "analyst-session"),
            ("GET", "/api/alerts", "List alerts", "analyst-session"),
            ("GET", "/api/events", "Search events", "analyst-session"),
        ],
    }
    selected = routes.get(role, [("GET", "/", "Service metadata endpoint", "none"), ("GET", "/healthz", "Readiness check", "none")])
    return [ServiceRouteBlueprint(method=method, path=path, purpose=purpose, auth=auth) for method, path, purpose, auth in selected]


def default_data_stores_for_role(role: str, artifact: Any) -> list[ServiceDataStoreBlueprint]:
    seeds = list(artifact.seed_inputs)
    noise = list(artifact.noise_inputs)
    if role in {"data-api", "object-store"}:
        return [ServiceDataStoreBlueprint(name="business-records", kind="json", purpose="Synthetic business objects", seed_files=seeds)]
    if role in {"audit-log-service", "siem-log-viewer"}:
        return [ServiceDataStoreBlueprint(name="events", kind="jsonl", purpose="Synthetic audit and detection events", seed_files=[*seeds, *noise])]
    if role == "identity-gateway":
        return [ServiceDataStoreBlueprint(name="identity-directory", kind="json", purpose="Synthetic users, sessions, roles, and MFA events", seed_files=seeds)]
    return [ServiceDataStoreBlueprint(name="metadata", kind="json", purpose="Service seed and operational metadata", seed_files=[*seeds, *noise])]


def default_workflows_for_role(role: str, artifact: Any) -> list[ServiceWorkflowBlueprint]:
    if role == "identity-gateway":
        return [ServiceWorkflowBlueprint(name="normal-login", actor="user", steps=["submit username", "verify MFA", "receive session"], normal_outcome="session issued")]
    if role == "business-portal":
        return [ServiceWorkflowBlueprint(name="business-request", actor="customer or employee", steps=["open portal", "review records", "submit request"], normal_outcome="request recorded")]
    if role in {"audit-log-service", "siem-log-viewer"}:
        return [ServiceWorkflowBlueprint(name="alert-review", actor="security analyst", steps=["search events", "open alert", "mark disposition"], normal_outcome="audit trail updated")]
    if role in {"data-api", "object-store"}:
        return [ServiceWorkflowBlueprint(name="authorized-data-read", actor="internal service", steps=["present token", "query metadata", "retrieve dataset"], normal_outcome="business data returned")]
    return [ServiceWorkflowBlueprint(name="service-health", actor="operator", steps=["open health endpoint", "review metadata"], normal_outcome="service ready")]


def implementation_notes_for_role(role: str) -> list[str]:
    notes = [
        "Implement normal business behavior first; scenario-specific vulnerability logic belongs in service code or plugin contracts, not reusable template metadata.",
        "Seed data must be synthetic and deterministic.",
        "Expose healthcheck and reset behavior through real files.",
    ]
    if role in {"business-portal", "internal-admin-console"}:
        notes.append("UI labels should use business language, not solver-facing stage names.")
    if role in {"identity-gateway", "data-api", "object-store"}:
        notes.append("Authorization decisions should be explicit and testable, even when deliberately weak for the lab.")
    return notes


def service_blueprints_to_markdown(report: ServiceBlueprintReport) -> str:
    lines = [
        f"# Service Blueprints - {report.lab_id}",
        "",
        f"- Service count: `{report.service_count}`",
        "",
        "| Service | Role | Template | Routes | Data Stores | Workflows |",
        "|---|---|---|---:|---:|---:|",
    ]
    for blueprint in report.blueprints:
        lines.append(
            f"| `{blueprint.service}` | `{blueprint.role}` | `{blueprint.template}` | "
            f"`{len(blueprint.routes)}` | `{len(blueprint.data_stores)}` | `{len(blueprint.normal_workflows)}` |"
        )
    for blueprint in report.blueprints:
        lines += [
            "",
            f"## {blueprint.service}",
            "",
            f"- Role: `{blueprint.role}`",
            f"- Template: `{blueprint.template}`",
            f"- Purpose: {blueprint.purpose}",
            "",
            "### Routes",
            "",
        ]
        lines.extend(f"- `{route.method} {route.path}`: {route.purpose} (auth: `{route.auth}`)" for route in blueprint.routes)
        lines += ["", "### Workflows", ""]
        for workflow in blueprint.normal_workflows:
            lines.append(f"- `{workflow.name}` ({workflow.actor}): {' -> '.join(workflow.steps)}")
        lines += ["", "### Implementation Notes", ""]
        lines.extend(f"- {note}" for note in blueprint.implementation_notes)
    lines.append("")
    return "\n".join(lines)


def service_status_to_markdown(report: ServiceImplementationStatusReport) -> str:
    lines = [
        f"# Service Implementation Status - {report.lab_id}",
        "",
        f"- Service count: `{report.service_count}`",
        f"- Ready count: `{report.ready_count}`",
        "",
        "| Service | Role | Status | Blueprint | Scaffold | Runtime | Tests | Findings |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ]
    for item in report.items:
        lines.append(
            f"| `{item.service}` | `{item.role}` | `{item.status}` | `{item.blueprint}` | `{item.scaffold}` | "
            f"`{item.runtime}` | `{item.tests}` | {'; '.join(item.findings) or '-'} |"
        )
    lines.append("")
    return "\n".join(lines)


SERVICE_BLUEPRINT_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "service-blueprint.schema.json": ServiceBuilderBlueprint,
    "service-blueprint-report.schema.json": ServiceBlueprintReport,
    "service-status-report.schema.json": ServiceImplementationStatusReport,
}
