from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
import yaml

from .model import LabSpec
from .service_artifacts import REQUIRED_FILES, RUNTIME_FILES, declared_service_artifacts, service_check
from .service_blueprints import ServiceBuilderBlueprint
from .service_templates import normalize_template_id, template_id_for_artifact
from .vulnerability_plugins import declared_vulnerability_plugins, get_vulnerability_plugin
from .vulnerability_scaffolds import SUPPORTED_VULNERABILITY_SCAFFOLDS


class ServiceVerificationModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class ServiceVerificationFinding(ServiceVerificationModel):
    severity: Literal["info", "warning", "error"]
    service: str
    category: str
    path: str = ""
    message: str


class ServiceVerificationReport(ServiceVerificationModel):
    lab_id: str
    status: Literal["passed", "warning", "failed"]
    findings: list[ServiceVerificationFinding] = Field(default_factory=list)


PLACEHOLDER_MARKERS = (
    "[labforge] replace this",
    "placeholder-runtime",
    "placeholder for",
    "replace with",
    "replace this",
    "generated-placeholder",
)

TEMPLATE_PUZZLE_MARKERS = (
    "answer_key",
    "ctf_flag",
    "exploit_command",
    "final_flag",
    "hardcoded_payload",
    "magic_string",
    "solution_path",
)

LEARNER_VISIBLE_SOLVER_MARKERS: dict[str, str] = {
    "foothold shell": "Realistic portals should call this a diagnostic console, maintenance shell, or approved jump host.",
    "support foothold": "Learner-facing copy should not describe the attacker's achieved position.",
    "exploit here": "The service should expose normal business behavior and let the learner infer the weakness.",
    "submit flag": "Use controlled evidence submission language instead of game terminology.",
    "ctf": "The lab should read like an enterprise environment, not a capture-the-flag challenge.",
    "answer key": "Do not expose walkthrough language in learner-visible service content.",
    "solution path": "Do not expose solver route labels in normal service content.",
    "pwn": "Use business, operations, or incident-response language.",
    "admin password": "Credentials should be discoverable through realistic configuration, logs, tickets, or secret references.",
    "password is": "Avoid direct answer-style credential disclosure in business content.",
    "cve-": "Learner-facing internal content should usually expose version and behavior clues, not the exact CVE label.",
}

LEARNER_VISIBLE_SCAN_DIRS = ("templates", "seed", "noise", "static")
LEARNER_VISIBLE_SCAN_FILES = ("blueprint.yaml",)
LEARNER_VISIBLE_SUFFIXES = {".html", ".htm", ".jinja", ".j2", ".json", ".jsonl", ".yaml", ".yml", ".md", ".txt", ".csv"}


def verify_services(spec: LabSpec) -> ServiceVerificationReport:
    findings: list[ServiceVerificationFinding] = []
    structure = service_check(spec)
    for error in structure.errors:
        findings.append(
            ServiceVerificationFinding(
                severity="error",
                service=parse_service_name(error),
                category="structure",
                message=error,
            )
        )
    for warning in structure.warnings:
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=parse_service_name(warning),
                category="structure",
                message=warning,
            )
        )

    for artifact in declared_service_artifacts(spec):
        service_root = spec.root / artifact.source_path
        if not service_root.exists() or not service_root.is_dir():
            continue
        verify_required_file_content(findings, artifact.service, service_root, artifact.source_path)
        verify_runtime_files(findings, artifact.service, service_root, artifact.source_path)
        verify_blueprint(findings, artifact, service_root, artifact.source_path)
        verify_seed_noise_tests(findings, artifact, service_root, artifact.source_path)
        verify_contract_depth(findings, artifact, service_root, artifact.source_path)
        verify_template_boundaries(findings, artifact, service_root, artifact.source_path)
        verify_learner_visible_language(findings, artifact.service, service_root, artifact.source_path)
        verify_vulnerability_plugins(findings, artifact, service_root, artifact.source_path)

    status: Literal["passed", "warning", "failed"]
    if any(item.severity == "error" for item in findings):
        status = "failed"
    elif any(item.severity == "warning" for item in findings):
        status = "warning"
    else:
        status = "passed"
    return ServiceVerificationReport(lab_id=spec.lab_id, status=status, findings=findings)


def verify_required_file_content(
    findings: list[ServiceVerificationFinding],
    service: str,
    service_root: Path,
    source_path: str,
) -> None:
    for filename in REQUIRED_FILES:
        path = service_root / filename
        if not path.exists():
            continue
        text = read_text(path)
        marker = first_placeholder_marker(text)
        if marker:
            findings.append(
                ServiceVerificationFinding(
                    severity="warning",
                    service=service,
                    category="placeholder",
                    path=f"{source_path}/{filename}",
                    message=f"Placeholder marker `{marker}` remains.",
                )
            )


def verify_runtime_files(
    findings: list[ServiceVerificationFinding],
    service: str,
    service_root: Path,
    source_path: str,
) -> None:
    for filename in RUNTIME_FILES:
        path = service_root / filename
        if not path.exists():
            findings.append(
                ServiceVerificationFinding(
                    severity="warning",
                    service=service,
                    category="runtime",
                    path=f"{source_path}/{filename}",
                    message="Runtime file is missing. This may be acceptable for non-Docker providers, but Docker prototype builds need a real implementation.",
                )
            )
            continue
        text = read_text(path)
        marker = first_placeholder_marker(text)
        if marker:
            findings.append(
                ServiceVerificationFinding(
                    severity="warning",
                    service=service,
                    category="runtime",
                    path=f"{source_path}/{filename}",
                    message=f"Runtime file still contains placeholder marker `{marker}`.",
                )
            )


def verify_seed_noise_tests(findings: list[ServiceVerificationFinding], artifact, service_root: Path, source_path: str) -> None:
    if artifact.seed_inputs and not directory_has_substantive_files(service_root / "seed"):
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=artifact.service,
                category="seed",
                path=f"{source_path}/seed",
                message="Seed inputs are declared but the seed directory has no substantive files.",
            )
        )


def verify_blueprint(findings: list[ServiceVerificationFinding], artifact, service_root: Path, source_path: str) -> None:
    blueprint_path = service_root / "blueprint.yaml"
    if not blueprint_path.exists():
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=artifact.service,
                category="blueprint",
                path=f"{source_path}/blueprint.yaml",
                message="Service blueprint is missing. Run `labforge services blueprints` or `labforge services scaffold`.",
            )
        )
        return
    try:
        import yaml

        blueprint = ServiceBuilderBlueprint.model_validate(yaml.safe_load(blueprint_path.read_text(encoding="utf-8")) or {})
    except Exception as exc:  # noqa: BLE001 - report blueprint parse errors.
        findings.append(
            ServiceVerificationFinding(
                severity="error",
                service=artifact.service,
                category="blueprint",
                path=f"{source_path}/blueprint.yaml",
                message=f"Service blueprint is invalid: {exc}",
            )
        )
        return
    if not blueprint.routes:
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=artifact.service,
                category="blueprint",
                path=f"{source_path}/blueprint.yaml",
                message="Blueprint declares no service routes.",
            )
        )
    if not blueprint.normal_workflows:
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=artifact.service,
                category="blueprint",
                path=f"{source_path}/blueprint.yaml",
                message="Blueprint declares no normal business workflow.",
            )
        )
    if not blueprint.data_stores:
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=artifact.service,
                category="blueprint",
                path=f"{source_path}/blueprint.yaml",
                message="Blueprint declares no data store.",
            )
        )
    if artifact.noise_inputs and not directory_has_substantive_files(service_root / "noise"):
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=artifact.service,
                category="noise",
                path=f"{source_path}/noise",
                message="Noise inputs are declared but the noise directory has no substantive files.",
            )
        )
    if not directory_has_substantive_files(service_root / "tests"):
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=artifact.service,
                category="tests",
                path=f"{source_path}/tests",
                message="No substantive service tests were found.",
            )
        )


def verify_contract_depth(findings: list[ServiceVerificationFinding], artifact, service_root: Path, source_path: str) -> None:
    if not artifact.safety_boundaries:
        findings.append(
            ServiceVerificationFinding(
                severity="error",
                service=artifact.service,
                category="safety",
                path=f"{source_path}/labforge-service.yaml",
                message="Service artifact has no safety boundaries.",
            )
        )


def verify_template_boundaries(findings: list[ServiceVerificationFinding], artifact, service_root: Path, source_path: str) -> None:
    extra = getattr(artifact, "model_extra", None) or {}
    template_fields = {
        key: value
        for key, value in extra.items()
        if "template" in str(key).lower() or "solution" in str(key).lower() or "answer" in str(key).lower()
    }
    serialized = json.dumps(template_fields, ensure_ascii=False).lower()
    marker = first_template_puzzle_marker(serialized)
    if marker:
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=artifact.service,
                category="template-boundary",
                path=f"{source_path}/labforge-service.yaml",
                message=(
                    f"Template metadata contains puzzle-like marker `{marker}`. "
                    "Templates should generate reusable infrastructure parts, not fixed solution paths."
                ),
            )
        )

    contract_path = service_root / "labforge-service.yaml"
    if not contract_path.exists():
        return
    text = read_text(contract_path).lower()
    marker = first_template_puzzle_marker(text)
    if marker:
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=artifact.service,
                category="template-boundary",
                path=f"{source_path}/labforge-service.yaml",
                message=(
                    f"Service contract contains puzzle-like marker `{marker}`. "
                    "Move answer keys, exact exploit commands, and final-object values to instructor-only artifacts."
                ),
            )
        )
    if not artifact.evidence_logs:
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=artifact.service,
                category="evidence",
                path=f"{source_path}/labforge-service.yaml",
                message="No evidence logs are declared for instructor review.",
            )
        )


def verify_learner_visible_language(
    findings: list[ServiceVerificationFinding],
    service: str,
    service_root: Path,
    source_path: str,
) -> None:
    reported: set[tuple[str, str]] = set()
    for path in learner_visible_files(service_root):
        text = read_text(path).lower()
        if not text:
            continue
        for marker, reason in LEARNER_VISIBLE_SOLVER_MARKERS.items():
            if marker not in text:
                continue
            rel = path.relative_to(service_root).as_posix()
            key = (rel, marker)
            if key in reported:
                continue
            reported.add(key)
            findings.append(
                ServiceVerificationFinding(
                    severity="warning",
                    service=service,
                    category="learner-facing-language",
                    path=f"{source_path}/{rel}",
                    message=(
                        f"Learner-visible content contains solver-facing marker `{marker}`. "
                        f"{reason}"
                    ),
                )
            )


def verify_vulnerability_plugins(findings: list[ServiceVerificationFinding], artifact, service_root: Path, source_path: str) -> None:
    template_ids = vulnerability_template_ids(artifact, service_root)
    for declared in declared_vulnerability_plugins(artifact):
        plugin_id = str(declared.get("id", "")).strip()
        if not plugin_id:
            findings.append(
                ServiceVerificationFinding(
                    severity="warning",
                    service=artifact.service,
                    category="vulnerability-plugin",
                    path=f"{source_path}/labforge-service.yaml",
                    message="Vulnerability plugin declaration is missing an id.",
                )
            )
            continue
        plugin = get_vulnerability_plugin(plugin_id)
        contract_path = service_root / "plugins" / f"{normalize_plugin_filename(plugin_id)}.contract.yaml"
        if not contract_path.exists():
            findings.append(
                ServiceVerificationFinding(
                    severity="warning",
                    service=artifact.service,
                    category="vulnerability-plugin",
                    path=f"{source_path}/plugins/{normalize_plugin_filename(plugin_id)}.contract.yaml",
                    message=f"Vulnerability plugin contract file for `{plugin_id}` is missing. Run `labforge services scaffold`.",
                )
            )
        if not plugin:
            findings.append(
                ServiceVerificationFinding(
                    severity="warning",
                    service=artifact.service,
                    category="vulnerability-plugin",
                    path=f"{source_path}/labforge-service.yaml",
                    message=f"Unknown vulnerability plugin `{plugin_id}` requires supervisor review.",
                )
            )
            continue
        if normalize_template_id(plugin.plugin_id) in SUPPORTED_VULNERABILITY_SCAFFOLDS:
            verify_vulnerability_scaffold_files(findings, artifact.service, plugin.plugin_id, service_root, source_path)
        if contract_path.exists():
            verify_vulnerability_contract_file(findings, artifact.service, plugin, contract_path, source_path)
        compatible = {normalize_template_id(item) for item in plugin.compatible_templates}
        if template_ids and not (template_ids & compatible):
            findings.append(
                ServiceVerificationFinding(
                    severity="warning",
                    service=artifact.service,
                    category="vulnerability-plugin",
                    path=f"{source_path}/labforge-service.yaml",
                    message=(
                        f"Plugin `{plugin.plugin_id}` is not declared compatible with "
                        f"template/runtime `{', '.join(sorted(template_ids))}`."
                    ),
                )
            )
        for key in plugin.required_config_keys:
            if key not in declared or declared.get(key) in (None, "", [], {}):
                findings.append(
                    ServiceVerificationFinding(
                        severity="warning",
                        service=artifact.service,
                        category="vulnerability-plugin",
                        path=f"{source_path}/labforge-service.yaml",
                        message=f"Plugin `{plugin.plugin_id}` is missing required scenario config key `{key}`.",
                    )
                )
        serialized = json.dumps(declared, ensure_ascii=False).lower()
        marker = first_template_puzzle_marker(serialized)
        if marker:
            findings.append(
                ServiceVerificationFinding(
                    severity="warning",
                    service=artifact.service,
                    category="vulnerability-plugin",
                    path=f"{source_path}/labforge-service.yaml",
                    message=(
                        f"Vulnerability plugin configuration contains puzzle-like marker `{marker}`. "
                        "Keep answer keys and exact payloads in instructor-only artifacts."
                    ),
                )
            )


def verify_vulnerability_contract_file(
    findings: list[ServiceVerificationFinding],
    service: str,
    plugin,
    contract_path: Path,
    source_path: str,
) -> None:
    rel = f"{source_path}/plugins/{contract_path.name}"
    try:
        contract = yaml.safe_load(contract_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001 - verification should report contract parse failures.
        findings.append(
            ServiceVerificationFinding(
                severity="error",
                service=service,
                category="vulnerability-plugin-contract",
                path=rel,
                message=f"Plugin contract file is invalid YAML: {exc}",
            )
        )
        return
    if contract.get("plugin") != plugin.plugin_id:
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=service,
                category="vulnerability-plugin-contract",
                path=rel,
                message=f"Plugin contract declares `{contract.get('plugin')}` but expected `{plugin.plugin_id}`.",
            )
        )
    for field in ("scenario_must_define", "safety_boundaries", "implementation_requirements", "verification_hints"):
        value = contract.get(field)
        if not isinstance(value, list) or not value:
            findings.append(
                ServiceVerificationFinding(
                    severity="warning",
                    service=service,
                    category="vulnerability-plugin-contract",
                    path=rel,
                    message=f"Plugin contract does not include non-empty `{field}`.",
                )
            )


def verify_vulnerability_scaffold_files(
    findings: list[ServiceVerificationFinding],
    service: str,
    plugin_id: str,
    service_root: Path,
    source_path: str,
) -> None:
    normalized = normalize_template_id(plugin_id)
    app_path = service_root / "app.py"
    marker = f"LabForge vulnerability scaffold: {normalized}"
    if not app_path.exists():
        return
    app_text = read_text(app_path)
    if marker not in app_text:
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=service,
                category="vulnerability-scaffold",
                path=f"{source_path}/app.py",
                message=f"Supported plugin `{plugin_id}` is declared but its runnable scaffold marker is missing from app.py.",
            )
        )
    test_path = service_root / "tests" / f"test_{normalized.replace('-', '_')}_scaffold.py"
    if not test_path.exists():
        findings.append(
            ServiceVerificationFinding(
                severity="warning",
                service=service,
                category="vulnerability-scaffold",
                path=f"{source_path}/tests/{test_path.name}",
                message=f"Supported plugin `{plugin_id}` is declared but its scaffold smoke test is missing.",
            )
        )


def normalize_plugin_filename(plugin_id: str) -> str:
    return normalize_template_id(plugin_id)


def vulnerability_template_ids(artifact, service_root: Path) -> set[str]:
    ids = {normalize_template_id(template_id_for_artifact(artifact))}
    blueprint_path = service_root / "blueprint.yaml"
    if blueprint_path.exists():
        try:
            blueprint = yaml.safe_load(blueprint_path.read_text(encoding="utf-8")) or {}
            template = blueprint.get("template")
            if template:
                ids.add(normalize_template_id(str(template)))
        except yaml.YAMLError:
            pass
    return {item for item in ids if item}


def parse_service_name(message: str) -> str:
    if "`" in message:
        parts = message.split("`")
        if len(parts) >= 2:
            return parts[1]
    return "unknown"


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def first_placeholder_marker(text: str) -> str:
    lowered = text.lower()
    for marker in PLACEHOLDER_MARKERS:
        if marker in lowered:
            return marker
    return ""


def first_template_puzzle_marker(text: str) -> str:
    for marker in TEMPLATE_PUZZLE_MARKERS:
        if marker in text:
            return marker
    return ""


def learner_visible_files(service_root: Path) -> list[Path]:
    paths: list[Path] = []
    for filename in LEARNER_VISIBLE_SCAN_FILES:
        path = service_root / filename
        if path.exists() and path.is_file():
            paths.append(path)
    for dirname in LEARNER_VISIBLE_SCAN_DIRS:
        root = service_root / dirname
        if not root.exists() or not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in LEARNER_VISIBLE_SUFFIXES:
                paths.append(path)
    return sorted(set(paths))


def directory_has_substantive_files(path: Path) -> bool:
    if not path.exists() or not path.is_dir():
        return False
    for item in path.rglob("*"):
        if item.is_file() and item.name != ".gitkeep":
            return True
    return False


def service_verification_to_json(report: ServiceVerificationReport) -> str:
    return json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + "\n"


def service_verification_to_markdown(report: ServiceVerificationReport) -> str:
    lines = [
        f"# Service Verification Report - {report.lab_id}",
        "",
        f"- Status: `{report.status}`",
        f"- Finding count: `{len(report.findings)}`",
        "",
        "| Severity | Service | Category | Path | Message |",
        "|---|---|---|---|---|",
    ]
    if not report.findings:
        lines.append("| info | - | - | - | No service verification findings. |")
    for finding in report.findings:
        lines.append(
            f"| {finding.severity} | `{finding.service}` | `{finding.category}` | `{finding.path}` | {finding.message} |"
        )
    lines.append("")
    return "\n".join(lines)


SERVICE_VERIFICATION_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "service-verification-report.schema.json": ServiceVerificationReport,
}
