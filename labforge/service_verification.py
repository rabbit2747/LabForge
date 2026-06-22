from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .model import LabSpec
from .service_artifacts import REQUIRED_FILES, RUNTIME_FILES, declared_service_artifacts, service_check


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
        verify_seed_noise_tests(findings, artifact, service_root, artifact.source_path)
        verify_contract_depth(findings, artifact, service_root, artifact.source_path)
        verify_template_boundaries(findings, artifact, service_root, artifact.source_path)

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
