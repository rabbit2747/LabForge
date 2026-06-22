from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .model import LabSpec


class LintModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class LintFinding(LintModel):
    severity: Literal["info", "warning", "error"]
    location: str
    message: str


class LintReport(LintModel):
    lab_id: str
    status: Literal["passed", "warning", "failed"]
    findings: list[LintFinding] = Field(default_factory=list)


PLACEHOLDER_MARKERS = (
    "replace this",
    "replace with",
    "todo",
    "tbd",
    "t0000",
)


def lint_lab(root: Path) -> LintReport:
    spec = LabSpec.load(root)
    findings: list[LintFinding] = []
    check_text(findings, "scenario.summary", spec.scenario.get("summary", ""))
    check_text(findings, "scenario.final_objective", spec.scenario.get("final_objective", ""))
    check_text(findings, "scenario.learner_entrypoint", spec.scenario.get("learner_entrypoint", ""))

    if not any(service.get("exposed") for service in spec.services):
        findings.append(
            LintFinding(
                severity="warning",
                location="topology.services",
                message="No exposed service is declared. Learners may not have a clear starting point.",
            )
        )

    for index, service in enumerate(spec.services):
        name = service.get("name", f"service[{index}]")
        check_text(findings, f"topology.services.{name}.role", service.get("role", ""))
        if not service.get("healthcheck"):
            findings.append(
                LintFinding(
                    severity="warning",
                    location=f"topology.services.{name}.healthcheck",
                    message="Service has no healthcheck.",
                )
            )

    for index, stage in enumerate(spec.stage_list):
        stage_id = stage.get("id", f"stage[{index}]")
        check_text(findings, f"stages.{stage_id}.title", stage.get("title", ""))
        check_text(findings, f"stages.{stage_id}.procedure", stage.get("procedure", ""))
        mitre = stage.get("mitre", {})
        for technique in mitre.get("techniques", []) if isinstance(mitre, dict) else []:
            check_text(findings, f"stages.{stage_id}.mitre.technique", technique.get("id", ""))
            check_text(findings, f"stages.{stage_id}.mitre.technique", technique.get("name", ""))

    if spec.artifacts_model:
        for artifact in spec.artifacts_model.service_artifacts:
            check_text(findings, f"artifacts.service_artifacts.{artifact.service}.purpose", artifact.purpose)
            check_text(findings, f"artifacts.service_artifacts.{artifact.service}.runtime", artifact.runtime)
            if not artifact.safety_boundaries:
                findings.append(
                    LintFinding(
                        severity="warning",
                        location=f"artifacts.service_artifacts.{artifact.service}.safety_boundaries",
                        message="Service artifact has no safety boundaries.",
                    )
                )

    status: Literal["passed", "warning", "failed"]
    if any(item.severity == "error" for item in findings):
        status = "failed"
    elif findings:
        status = "warning"
    else:
        status = "passed"
    return LintReport(lab_id=spec.lab_id, status=status, findings=findings)


def check_text(findings: list[LintFinding], location: str, value: object) -> None:
    text = str(value or "")
    lowered = text.lower()
    for marker in PLACEHOLDER_MARKERS:
        if marker in lowered:
            findings.append(
                LintFinding(
                    severity="warning",
                    location=location,
                    message=f"Placeholder marker `{marker}` remains in text.",
                )
            )
            return


def lint_report_to_json(report: LintReport) -> str:
    return json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + "\n"


def lint_report_to_markdown(report: LintReport) -> str:
    lines = [
        f"# LabForge Lint Report - {report.lab_id}",
        "",
        f"- Status: `{report.status}`",
        "",
        "| Severity | Location | Message |",
        "|---|---|---|",
    ]
    if not report.findings:
        lines.append("| info | - | No lint findings. |")
    for finding in report.findings:
        lines.append(f"| {finding.severity} | `{finding.location}` | {finding.message} |")
    lines.append("")
    return "\n".join(lines)


LINT_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "lint-report.schema.json": LintReport,
}
