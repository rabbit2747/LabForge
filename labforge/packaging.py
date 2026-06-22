from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .doctor import inspect_host, report_to_json, report_to_markdown
from .execution_plan import create_execution_plan, plan_to_json, plan_to_markdown
from .io import write_text
from .linting import lint_lab, lint_report_to_json, lint_report_to_markdown
from .model import LabSpec
from .qa import run_qa_smoke
from .render import build_lab
from .validate import validate_lab


class PackageModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class PackageArtifact(PackageModel):
    name: str
    path: str
    purpose: str


class PackageReport(PackageModel):
    lab_id: str
    title: str
    provider: str
    profile: Literal["unprotected", "protected"]
    status: Literal["passed", "warning", "failed"]
    output_dir: str
    artifacts: list[PackageArtifact] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def create_supervisor_package(
    lab_root: Path,
    out: Path,
    *,
    provider: str,
    profile: Literal["unprotected", "protected"],
    materialize: bool = False,
    force: bool = False,
) -> PackageReport:
    lab_root = lab_root.resolve()
    if out.exists() and force:
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    spec = LabSpec.load(lab_root)
    validation_errors = validate_lab(lab_root)
    lint_report = lint_lab(lab_root)
    host_report = inspect_host(lab_root)

    generated_dir = out / "generated"
    reports_dir = out / "reports"
    qa_dir = out / "qa"

    build_status: Literal["passed", "failed"] = "passed"
    build_warnings: list[str] = []
    try:
        build_lab(spec, generated_dir, provider_name=provider, profile=profile)
    except Exception as exc:  # noqa: BLE001 - package report should preserve generation failures.
        build_status = "failed"
        build_warnings.append(f"Provider generation failed: {exc}")

    plan = create_execution_plan(spec, lab_root, generated_dir, provider=provider, profile=profile)
    qa_report = run_qa_smoke(
        lab_root,
        qa_dir,
        provider=provider,
        profile=profile,
        materialize=materialize,
        force=force,
    )

    write_text(reports_dir / "host-doctor.md", report_to_markdown(host_report))
    write_text(reports_dir / "host-doctor.json", report_to_json(host_report))
    write_text(reports_dir / "execution-plan.md", plan_to_markdown(plan))
    write_text(reports_dir / "execution-plan.json", plan_to_json(plan))
    write_text(reports_dir / "lint-report.md", lint_report_to_markdown(lint_report))
    write_text(reports_dir / "lint-report.json", lint_report_to_json(lint_report))

    warnings = [
        *validation_errors,
        *[f"{finding.location}: {finding.message}" for finding in lint_report.findings],
        *host_report.warnings,
        *build_warnings,
    ]
    status = aggregate_package_status(
        validation_errors=validation_errors,
        lint_status=lint_report.status,
        qa_status=qa_report.status,
        build_status=build_status,
    )
    report = PackageReport(
        lab_id=spec.lab_id,
        title=spec.title,
        provider=provider,
        profile=profile,
        status=status,
        output_dir=str(out.resolve()),
        artifacts=[
            PackageArtifact(
                name="generated-lab",
                path=str(generated_dir.resolve()),
                purpose="Provider output, rendered documentation, and diagrams.",
            ),
            PackageArtifact(
                name="host-doctor",
                path=str((reports_dir / "host-doctor.md").resolve()),
                purpose="Host operating system, WSL, Docker, and readiness assessment.",
            ),
            PackageArtifact(
                name="execution-plan",
                path=str((reports_dir / "execution-plan.md").resolve()),
                purpose="Host-aware build and runtime plan for supervisors.",
            ),
            PackageArtifact(
                name="lint-report",
                path=str((reports_dir / "lint-report.md").resolve()),
                purpose="Scenario quality warnings and placeholder checks.",
            ),
            PackageArtifact(
                name="qa-smoke-report",
                path=str((qa_dir / "qa-smoke-report.md").resolve()),
                purpose="Schema, lint, service artifact, and provider smoke checks.",
            ),
        ],
        warnings=warnings,
    )
    write_text(out / "package-report.json", package_report_to_json(report))
    write_text(out / "package-report.md", package_report_to_markdown(report))
    return report


def aggregate_package_status(
    *,
    validation_errors: list[str],
    lint_status: str,
    qa_status: str,
    build_status: str,
) -> Literal["passed", "warning", "failed"]:
    if validation_errors or qa_status == "failed" or build_status == "failed":
        return "failed"
    if lint_status == "warning" or qa_status == "warning":
        return "warning"
    return "passed"


def package_report_to_json(report: PackageReport) -> str:
    return json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + "\n"


def package_report_to_markdown(report: PackageReport) -> str:
    lines = [
        f"# LabForge Package Report - {report.title}",
        "",
        "## Summary",
        "",
        f"- Lab ID: `{report.lab_id}`",
        f"- Provider: `{report.provider}`",
        f"- Profile: `{report.profile}`",
        f"- Status: `{report.status}`",
        f"- Output directory: `{report.output_dir}`",
        "",
        "## Artifacts",
        "",
        "| Name | Path | Purpose |",
        "|---|---|---|",
    ]
    for artifact in report.artifacts:
        lines.append(f"| `{artifact.name}` | `{artifact.path}` | {artifact.purpose} |")
    lines += ["", "## Warnings", ""]
    lines.extend(f"- {warning}" for warning in report.warnings or ["No warnings."])
    lines.append("")
    return "\n".join(lines)


PACKAGE_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "package-report.schema.json": PackageReport,
}
