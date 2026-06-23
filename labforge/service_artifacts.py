from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .io import dump_yaml, load_yaml, write_text
from .model import LabSpec
from .service_blueprints import create_service_blueprints, write_service_blueprint_files
from .service_templates import render_template_files
from .vulnerability_plugins import render_vulnerability_plugin_contracts


RECOMMENDED_DIRECTORIES = ("seed", "noise", "tests")
REQUIRED_FILES = ("README.md", "labforge-service.yaml", "healthcheck.sh", "reset.sh")
RUNTIME_FILES = ("Dockerfile", "app.py")


@dataclass(frozen=True)
class ServiceCheckResult:
    errors: list[str]
    warnings: list[str]


@dataclass(frozen=True)
class ServiceHookRun:
    service: str
    hook: str
    path: Path
    returncode: int
    stdout: str
    stderr: str


class ServiceArtifactModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class ServiceChangeSpec(ServiceArtifactModel):
    target_path: str
    content: str | None = None
    source_path: str | None = None
    executable: bool = False

    @model_validator(mode="after")
    def validate_change_source(self) -> "ServiceChangeSpec":
        if bool(self.content is not None) == bool(self.source_path):
            raise ValueError("exactly one of content or source_path is required")
        return self


class ServiceResultSpec(ServiceArtifactModel):
    task_id: str
    status: Literal["complete", "needs-review"]
    service: str
    summary: str = ""
    implemented_routes: list[dict | str] = Field(default_factory=list)
    data_model: list[dict | str] = Field(default_factory=list)
    normal_workflows: list[dict | str] = Field(default_factory=list)
    vulnerable_paths: list[dict | str] = Field(default_factory=list)
    detection_evidence: list[dict | str] = Field(default_factory=list)
    healthcheck_behavior: str = ""
    reset_behavior: str = ""
    service_changes: list[ServiceChangeSpec] = Field(default_factory=list)
    findings: list[dict | str] = Field(default_factory=list)
    open_questions: list[dict | str] = Field(default_factory=list)


class ServiceResultApplyItem(ServiceArtifactModel):
    target_path: str
    action: Literal["would-write", "written", "skipped", "failed"]
    message: str = ""


class ServiceResultApplyReport(ServiceArtifactModel):
    lab_id: str
    service: str
    result_file: str
    status: Literal["passed", "failed"]
    dry_run: bool = False
    applied: list[ServiceResultApplyItem] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ServiceResultReviewItem(ServiceArtifactModel):
    target_path: str
    status: Literal["ok", "warning", "error"]
    message: str


class ServiceResultReviewReport(ServiceArtifactModel):
    lab_id: str
    service: str = ""
    result_file: str
    status: Literal["ready", "needs-review", "failed"]
    ready_to_apply: bool = False
    items: list[ServiceResultReviewItem] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    open_questions: list[dict | str] = Field(default_factory=list)


class ServiceResultBatchReviewReport(ServiceArtifactModel):
    lab_id: str
    result_dir: str
    status: Literal["ready", "needs-review", "failed"]
    ready_count: int = 0
    needs_review_count: int = 0
    failed_count: int = 0
    missing_service_results: list[str] = Field(default_factory=list)
    reviews: list[ServiceResultReviewReport] = Field(default_factory=list)


class ServiceResultBatchApplyItem(ServiceArtifactModel):
    service: str = ""
    result_file: str = ""
    status: Literal["applied", "skipped", "failed"]
    reason: str = ""
    applied: list[ServiceResultApplyItem] = Field(default_factory=list)


class ServiceResultBatchApplyReport(ServiceArtifactModel):
    lab_id: str
    result_dir: str
    status: Literal["passed", "warning", "failed"]
    dry_run: bool = True
    applied_count: int = 0
    skipped_count: int = 0
    failed_count: int = 0
    items: list[ServiceResultBatchApplyItem] = Field(default_factory=list)


def declared_service_artifacts(spec: LabSpec):
    if not spec.artifacts_model:
        return []
    return spec.artifacts_model.service_artifacts


def service_check(spec: LabSpec) -> ServiceCheckResult:
    errors: list[str] = []
    warnings: list[str] = []
    service_names = {str(service["name"]) for service in spec.services}
    artifacts = declared_service_artifacts(spec)
    artifact_names = {artifact.service for artifact in artifacts}

    for missing in sorted(service_names - artifact_names):
        errors.append(f"service `{missing}` is missing a service_artifacts contract")
    for unknown in sorted(artifact_names - service_names):
        errors.append(f"service_artifacts references unknown service `{unknown}`")

    for artifact in artifacts:
        service_root = spec.root / artifact.source_path
        if not service_root.exists():
            errors.append(f"`{artifact.service}` source_path does not exist: {artifact.source_path}")
            continue
        if not service_root.is_dir():
            errors.append(f"`{artifact.service}` source_path is not a directory: {artifact.source_path}")
            continue

        for filename in REQUIRED_FILES:
            if not (service_root / filename).exists():
                errors.append(f"`{artifact.service}` missing required file: {artifact.source_path}/{filename}")
        for dirname in RECOMMENDED_DIRECTORIES:
            if not (service_root / dirname).exists():
                warnings.append(f"`{artifact.service}` missing recommended directory: {artifact.source_path}/{dirname}")

    return ServiceCheckResult(errors=errors, warnings=warnings)


def scaffold_service_artifacts(spec: LabSpec, force: bool = False) -> list[Path]:
    written: list[Path] = []
    for artifact in declared_service_artifacts(spec):
        service_root = spec.root / artifact.source_path
        service_root.mkdir(parents=True, exist_ok=True)

        for dirname in RECOMMENDED_DIRECTORIES:
            directory = service_root / dirname
            directory.mkdir(parents=True, exist_ok=True)
            keep = directory / ".gitkeep"
            if not keep.exists():
                write_text(keep, "")
                written.append(keep)

        files = {
            "README.md": render_service_readme(artifact),
            "labforge-service.yaml": render_labforge_service_yaml(artifact),
            "healthcheck.sh": render_healthcheck_script(artifact),
            "reset.sh": render_reset_script(artifact),
        }
        for filename, content in files.items():
            path = service_root / filename
            if path.exists() and not force:
                continue
            write_text(path, content)
            written.append(path)
    written.extend(write_service_blueprint_files(spec, force=force))
    return written


def materialize_service_runtimes(spec: LabSpec, force: bool = False) -> list[Path]:
    written: list[Path] = []
    written.extend(write_service_blueprint_files(spec, force=force))
    blueprint_by_service = {blueprint.service: blueprint for blueprint in create_service_blueprints(spec).blueprints}
    services_by_name = {str(service.get("name")): service for service in spec.services}
    for artifact in declared_service_artifacts(spec):
        service_root = spec.root / artifact.source_path
        service_root.mkdir(parents=True, exist_ok=True)
        service = services_by_name.get(artifact.service, {})
        port = service_runtime_port(service)
        files = render_template_files(artifact, port, blueprint=blueprint_by_service.get(artifact.service)) or {
            "Dockerfile": render_runtime_dockerfile(artifact, port),
            "app.py": render_runtime_app(artifact, port),
            "seed/metadata.json": render_runtime_metadata(artifact, port),
            "seed/blueprint.json": (
                json.dumps(blueprint_by_service[artifact.service].model_dump(), ensure_ascii=False, indent=2) + "\n"
                if artifact.service in blueprint_by_service
                else "{}\n"
            ),
            "tests/test_smoke.py": render_runtime_smoke_test(),
        }
        files.update(render_vulnerability_plugin_contracts(artifact))
        for filename, content in files.items():
            path = service_root / filename
            if path.exists() and not force:
                continue
            write_text(path, content)
            written.append(path)
    return written


def service_runtime_port(service: dict) -> int:
    exposed = service.get("expose") or []
    if exposed:
        return int(str(exposed[0]).split(":", maxsplit=1)[-1])
    ports = service.get("ports") or []
    if ports:
        return int(str(ports[0]).split(":")[-1])
    return 8080


def run_service_hooks(
    spec: LabSpec,
    hook: str,
    service: str | None = None,
    dry_run: bool = False,
) -> tuple[list[ServiceHookRun], list[str]]:
    if hook not in {"healthcheck", "reset"}:
        raise ValueError(f"unsupported service hook: {hook}")

    selected = []
    for artifact in declared_service_artifacts(spec):
        if service and artifact.service != service:
            continue
        selected.append(artifact)

    if service and not selected:
        return [], [f"unknown service or missing service_artifacts contract: {service}"]

    errors: list[str] = []
    runs: list[ServiceHookRun] = []
    for artifact in selected:
        script = spec.root / artifact.source_path / f"{hook}.sh"
        if not script.exists():
            errors.append(f"`{artifact.service}` missing hook: {script}")
            continue
        if dry_run:
            runs.append(ServiceHookRun(artifact.service, hook, script, 0, f"DRY RUN: {script}", ""))
            continue
        command = shell_command_for_script(script)
        if command is None:
            errors.append(
                f"`{artifact.service}` cannot run {hook}.sh: no POSIX shell found. "
                "Install sh/Git Bash/WSL or run the hook inside a Linux-capable provider."
            )
            continue
        completed = subprocess.run(
            command,
            cwd=script.parent,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        runs.append(
            ServiceHookRun(
                artifact.service,
                hook,
                script,
                completed.returncode,
                completed.stdout.strip(),
                completed.stderr.strip(),
            )
        )
    return runs, errors


def apply_service_result(
    spec: LabSpec,
    result_file: Path,
    *,
    force: bool = False,
    dry_run: bool = False,
) -> ServiceResultApplyReport:
    result_path = result_file.resolve()
    result = ServiceResultSpec.model_validate(load_yaml(result_path))
    artifacts = {artifact.service: artifact for artifact in declared_service_artifacts(spec)}
    artifact = artifacts.get(result.service)
    if not artifact:
        return ServiceResultApplyReport(
            lab_id=spec.lab_id,
            service=result.service,
            result_file=str(result_path),
            status="failed",
            dry_run=dry_run,
            errors=[f"result references unknown service or missing service_artifacts contract: {result.service}"],
        )
    if result.status != "complete":
        return ServiceResultApplyReport(
            lab_id=spec.lab_id,
            service=result.service,
            result_file=str(result_path),
            status="failed",
            dry_run=dry_run,
            errors=[f"result status must be complete before apply, got: {result.status}"],
        )

    service_root = (spec.root / artifact.source_path).resolve()
    if not service_root.exists() or not service_root.is_dir():
        return ServiceResultApplyReport(
            lab_id=spec.lab_id,
            service=result.service,
            result_file=str(result_path),
            status="failed",
            dry_run=dry_run,
            errors=[f"service source_path does not exist: {artifact.source_path}"],
        )

    applied: list[ServiceResultApplyItem] = []
    errors: list[str] = []
    if not result.service_changes:
        errors.append("result contains no service_changes")

    for change in result.service_changes:
        target, target_error = resolve_service_target(service_root, change.target_path)
        if target_error:
            errors.append(target_error)
            applied.append(ServiceResultApplyItem(target_path=change.target_path, action="failed", message=target_error))
            continue

        assert target is not None
        if target.exists() and not force:
            message = "target exists; rerun with --force to overwrite"
            errors.append(f"{change.target_path}: {message}")
            applied.append(ServiceResultApplyItem(target_path=change.target_path, action="failed", message=message))
            continue

        content, content_error = service_change_content(change, result_path.parent)
        if content_error:
            errors.append(f"{change.target_path}: {content_error}")
            applied.append(ServiceResultApplyItem(target_path=change.target_path, action="failed", message=content_error))
            continue

        if dry_run:
            applied.append(ServiceResultApplyItem(target_path=change.target_path, action="would-write"))
            continue

        assert content is not None
        write_text(target, content)
        if change.executable:
            make_executable(target)
        applied.append(ServiceResultApplyItem(target_path=change.target_path, action="written"))

    status: Literal["passed", "failed"] = "failed" if errors else "passed"
    return ServiceResultApplyReport(
        lab_id=spec.lab_id,
        service=result.service,
        result_file=str(result_path),
        status=status,
        dry_run=dry_run,
        applied=applied,
        errors=errors,
    )


def review_service_result(spec: LabSpec, result_file: Path, *, force: bool = False) -> ServiceResultReviewReport:
    result_path = result_file.resolve()
    try:
        raw = load_yaml(result_path)
        result = ServiceResultSpec.model_validate(raw)
    except (OSError, ValueError, ValidationError) as exc:
        return ServiceResultReviewReport(
            lab_id=spec.lab_id,
            result_file=str(result_path),
            status="failed",
            ready_to_apply=False,
            errors=[f"invalid service result file: {exc}"],
        )

    artifacts = {artifact.service: artifact for artifact in declared_service_artifacts(spec)}
    artifact = artifacts.get(result.service)
    errors: list[str] = []
    items: list[ServiceResultReviewItem] = []

    if not artifact:
        errors.append(f"result references unknown service or missing service_artifacts contract: {result.service}")
        return ServiceResultReviewReport(
            lab_id=spec.lab_id,
            service=result.service,
            result_file=str(result_path),
            status="failed",
            ready_to_apply=False,
            errors=errors,
            open_questions=result.open_questions,
        )

    if result.status != "complete":
        items.append(
            ServiceResultReviewItem(
                target_path="-",
                status="warning",
                message=f"result status must be complete before apply, got: {result.status}",
            )
        )

    if result.open_questions:
        items.append(
            ServiceResultReviewItem(
                target_path="-",
                status="warning",
                message=f"result has {len(result.open_questions)} open question(s) for supervisor review",
            )
        )
    if result.status == "complete":
        if not result.implemented_routes:
            items.append(
                ServiceResultReviewItem(
                    target_path="-",
                    status="warning",
                    message="result does not describe implemented_routes; supervisor cannot compare implementation to blueprint API surface",
                )
            )
        if not result.normal_workflows:
            items.append(
                ServiceResultReviewItem(
                    target_path="-",
                    status="warning",
                    message="result does not describe normal_workflows; service may still be puzzle-only",
                )
            )
        if not result.data_model:
            items.append(
                ServiceResultReviewItem(
                    target_path="-",
                    status="warning",
                    message="result does not describe data_model; seed/noise realism is hard to review",
                )
            )

    service_root = (spec.root / artifact.source_path).resolve()
    if not service_root.exists() or not service_root.is_dir():
        errors.append(f"service source_path does not exist: {artifact.source_path}")
    if not result.service_changes:
        if result.status == "complete":
            errors.append("result contains no service_changes")
        else:
            items.append(
                ServiceResultReviewItem(
                    target_path="-",
                    status="warning",
                    message="result contains no service_changes yet",
                )
            )

    for change in result.service_changes:
        target, target_error = resolve_service_target(service_root, change.target_path)
        if target_error:
            errors.append(target_error)
            items.append(ServiceResultReviewItem(target_path=change.target_path, status="error", message=target_error))
            continue

        assert target is not None
        _, content_error = service_change_content(change, result_path.parent)
        if content_error:
            errors.append(f"{change.target_path}: {content_error}")
            items.append(ServiceResultReviewItem(target_path=change.target_path, status="error", message=content_error))
            continue

        if target.exists() and not force:
            items.append(
                ServiceResultReviewItem(
                    target_path=change.target_path,
                    status="warning",
                    message="target exists and would require --force to overwrite",
                )
            )
            continue

        items.append(ServiceResultReviewItem(target_path=change.target_path, status="ok", message="ready to write"))

    status: Literal["ready", "needs-review", "failed"]
    if errors:
        status = "failed"
    elif any(item.status == "warning" for item in items):
        status = "needs-review"
    else:
        status = "ready"
    return ServiceResultReviewReport(
        lab_id=spec.lab_id,
        service=result.service,
        result_file=str(result_path),
        status=status,
        ready_to_apply=status == "ready",
        items=items,
        errors=errors,
        open_questions=result.open_questions,
    )


def review_service_results(
    spec: LabSpec,
    result_dir: Path,
    *,
    force: bool = False,
) -> ServiceResultBatchReviewReport:
    resolved = result_dir.resolve()
    reviews: list[ServiceResultReviewReport] = []
    for result_file in sorted(resolved.glob("*.result.yaml")):
        reviews.append(review_service_result(spec, result_file, force=force))

    reviewed_services = {review.service for review in reviews if review.service}
    declared_services = {artifact.service for artifact in declared_service_artifacts(spec)}
    missing = sorted(declared_services - reviewed_services)
    ready_count = sum(1 for review in reviews if review.status == "ready")
    needs_review_count = sum(1 for review in reviews if review.status == "needs-review")
    failed_count = sum(1 for review in reviews if review.status == "failed") + len(missing)
    if failed_count:
        status: Literal["ready", "needs-review", "failed"] = "failed"
    elif needs_review_count:
        status = "needs-review"
    else:
        status = "ready"
    return ServiceResultBatchReviewReport(
        lab_id=spec.lab_id,
        result_dir=str(resolved),
        status=status,
        ready_count=ready_count,
        needs_review_count=needs_review_count,
        failed_count=failed_count,
        missing_service_results=missing,
        reviews=reviews,
    )


def apply_service_results(
    spec: LabSpec,
    result_dir: Path,
    *,
    force: bool = False,
    dry_run: bool = True,
) -> ServiceResultBatchApplyReport:
    resolved = result_dir.resolve()
    items: list[ServiceResultBatchApplyItem] = []

    result_files = sorted(resolved.glob("*.result.yaml"))
    if not result_files:
        return ServiceResultBatchApplyReport(
            lab_id=spec.lab_id,
            result_dir=str(resolved),
            status="failed",
            dry_run=dry_run,
            failed_count=1,
            items=[
                ServiceResultBatchApplyItem(
                    status="failed",
                    reason="result directory contains no *.result.yaml files",
                )
            ],
        )

    for result_file in result_files:
        review = review_service_result(spec, result_file, force=force)
        if review.status != "ready":
            reason = "; ".join(review.errors) if review.errors else f"review status is {review.status}"
            items.append(
                ServiceResultBatchApplyItem(
                    service=review.service,
                    result_file=review.result_file,
                    status="skipped",
                    reason=reason,
                )
            )
            continue

        apply_report = apply_service_result(spec, result_file, force=force, dry_run=dry_run)
        if apply_report.status == "passed":
            items.append(
                ServiceResultBatchApplyItem(
                    service=apply_report.service,
                    result_file=apply_report.result_file,
                    status="applied",
                    applied=apply_report.applied,
                )
            )
        else:
            items.append(
                ServiceResultBatchApplyItem(
                    service=apply_report.service,
                    result_file=apply_report.result_file,
                    status="failed",
                    reason="; ".join(apply_report.errors) or "apply failed",
                    applied=apply_report.applied,
                )
            )

    applied_count = sum(1 for item in items if item.status == "applied")
    skipped_count = sum(1 for item in items if item.status == "skipped")
    failed_count = sum(1 for item in items if item.status == "failed")
    if failed_count:
        status: Literal["passed", "warning", "failed"] = "failed"
    elif skipped_count:
        status = "warning"
    else:
        status = "passed"

    return ServiceResultBatchApplyReport(
        lab_id=spec.lab_id,
        result_dir=str(resolved),
        status=status,
        dry_run=dry_run,
        applied_count=applied_count,
        skipped_count=skipped_count,
        failed_count=failed_count,
        items=items,
    )


def resolve_service_target(service_root: Path, target_path: str) -> tuple[Path | None, str | None]:
    raw = Path(target_path)
    if raw.is_absolute():
        return None, f"target_path must be relative to the service root: {target_path}"
    if any(part == ".." for part in raw.parts):
        return None, f"target_path may not contain parent traversal: {target_path}"
    resolved = (service_root / raw).resolve()
    try:
        resolved.relative_to(service_root)
    except ValueError:
        return None, f"target_path escapes the service root: {target_path}"
    return resolved, None


def service_change_content(change: ServiceChangeSpec, result_dir: Path) -> tuple[str | None, str | None]:
    if change.content is not None:
        return change.content, None
    assert change.source_path is not None
    source = Path(change.source_path)
    if source.is_absolute():
        return None, f"source_path must be relative to the result file directory: {change.source_path}"
    if any(part == ".." for part in source.parts):
        return None, f"source_path may not contain parent traversal: {change.source_path}"
    source_path = (result_dir / source).resolve()
    try:
        source_path.relative_to(result_dir.resolve())
    except ValueError:
        return None, f"source_path escapes the result file directory: {change.source_path}"
    if not source_path.exists() or not source_path.is_file():
        return None, f"source_path does not exist: {change.source_path}"
    return source_path.read_text(encoding="utf-8"), None


def make_executable(path: Path) -> None:
    try:
        current = path.stat().st_mode
        path.chmod(current | 0o111)
    except OSError:
        pass


def service_result_apply_to_markdown(report: ServiceResultApplyReport) -> str:
    lines = [
        f"# Service Result Apply Report - {report.service}",
        "",
        f"- Lab ID: `{report.lab_id}`",
        f"- Result file: `{report.result_file}`",
        f"- Status: `{report.status}`",
        f"- Dry run: `{str(report.dry_run).lower()}`",
        "",
        "| Target | Action | Message |",
        "|---|---|---|",
    ]
    if not report.applied:
        lines.append("| - | - | No service changes were applied. |")
    for item in report.applied:
        lines.append(f"| `{item.target_path}` | `{item.action}` | {item.message or '-'} |")
    if report.errors:
        lines += [
            "",
            "## Errors",
            "",
        ]
        lines.extend(f"- {error}" for error in report.errors)
    lines.append("")
    return "\n".join(lines)


def service_result_review_to_markdown(report: ServiceResultReviewReport) -> str:
    lines = [
        f"# Service Result Review Report - {report.service or 'unknown'}",
        "",
        f"- Lab ID: `{report.lab_id}`",
        f"- Result file: `{report.result_file}`",
        f"- Status: `{report.status}`",
        f"- Ready to apply: `{str(report.ready_to_apply).lower()}`",
        "",
        "| Target | Status | Message |",
        "|---|---|---|",
    ]
    if not report.items:
        lines.append("| - | - | No review items were produced. |")
    for item in report.items:
        lines.append(f"| `{item.target_path}` | `{item.status}` | {item.message} |")
    if report.errors:
        lines += [
            "",
            "## Errors",
            "",
        ]
        lines.extend(f"- {error}" for error in report.errors)
    if report.open_questions:
        lines += [
            "",
            "## Open Questions",
            "",
        ]
        lines.extend(f"- {question}" for question in report.open_questions)
    lines.append("")
    return "\n".join(lines)


def service_result_batch_review_to_markdown(report: ServiceResultBatchReviewReport) -> str:
    lines = [
        f"# Service Result Batch Review - {report.lab_id}",
        "",
        f"- Result directory: `{report.result_dir}`",
        f"- Status: `{report.status}`",
        f"- Ready: `{report.ready_count}`",
        f"- Needs review: `{report.needs_review_count}`",
        f"- Failed: `{report.failed_count}`",
        "",
        "| Service | Status | Ready To Apply | Result File | Errors | Open Questions |",
        "|---|---|---|---|---:|---:|",
    ]
    if not report.reviews:
        lines.append("| - | failed | false | - | 1 | 0 |")
    for review in report.reviews:
        lines.append(
            f"| `{review.service or 'unknown'}` | `{review.status}` | `{str(review.ready_to_apply).lower()}` | "
            f"`{review.result_file}` | {len(review.errors)} | {len(review.open_questions)} |"
        )
    if report.missing_service_results:
        lines += [
            "",
            "## Missing Service Results",
            "",
        ]
        lines.extend(f"- `{service}`" for service in report.missing_service_results)
    failed_reviews = [review for review in report.reviews if review.errors]
    if failed_reviews:
        lines += [
            "",
            "## Errors",
            "",
        ]
        for review in failed_reviews:
            lines.append(f"### `{review.service or 'unknown'}`")
            lines.append("")
            lines.extend(f"- {error}" for error in review.errors)
            lines.append("")
    open_question_reviews = [review for review in report.reviews if review.open_questions]
    if open_question_reviews:
        lines += [
            "",
            "## Open Questions",
            "",
        ]
        for review in open_question_reviews:
            lines.append(f"### `{review.service or 'unknown'}`")
            lines.append("")
            lines.extend(f"- {question}" for question in review.open_questions)
            lines.append("")
    lines.append("")
    return "\n".join(lines)


def service_result_batch_apply_to_markdown(report: ServiceResultBatchApplyReport) -> str:
    lines = [
        f"# Service Result Batch Apply - {report.lab_id}",
        "",
        f"- Result directory: `{report.result_dir}`",
        f"- Status: `{report.status}`",
        f"- Dry run: `{str(report.dry_run).lower()}`",
        f"- Applied: `{report.applied_count}`",
        f"- Skipped: `{report.skipped_count}`",
        f"- Failed: `{report.failed_count}`",
        "",
        "| Service | Status | Result File | Files | Reason |",
        "|---|---|---|---:|---|",
    ]
    for item in report.items:
        lines.append(
            f"| `{item.service or '-'}` | `{item.status}` | `{item.result_file or '-'}` | "
            f"{len(item.applied)} | {item.reason or '-'} |"
        )
    if not report.items:
        lines.append("| - | failed | - | 0 | No service results were found. |")

    applied_items = [item for item in report.items if item.applied]
    if applied_items:
        lines += [
            "",
            "## File Actions",
            "",
        ]
        for item in applied_items:
            lines.append(f"### `{item.service or 'unknown'}`")
            lines.append("")
            lines.append("| Target | Action | Message |")
            lines.append("|---|---|---|")
            for applied in item.applied:
                lines.append(f"| `{applied.target_path}` | `{applied.action}` | {applied.message or '-'} |")
            lines.append("")
    lines.append("")
    return "\n".join(lines)


def shell_command_for_script(script: Path) -> list[str] | None:
    sh = shutil.which("sh")
    if sh:
        return [sh, str(script)]
    if platform.system().lower() == "windows" and shutil.which("wsl.exe"):
        distro = []
        distro_name = os.environ.get("LABFORGE_WSL_DISTRO")
        if distro_name:
            distro = ["-d", distro_name]
        return ["wsl.exe", *distro, "--", "sh", windows_to_wsl_path(script)]
    return None


def windows_to_wsl_path(path: Path) -> str:
    resolved = str(path.resolve())
    if len(resolved) >= 3 and resolved[1:3] == ":\\":
        drive = resolved[0].lower()
        rest = resolved[3:].replace("\\", "/")
        return f"/mnt/{drive}/{rest}"
    return resolved.replace("\\", "/")


def render_service_readme(artifact) -> str:
    lines = [
        f"# {artifact.service}",
        "",
        artifact.purpose,
        "",
        "## Runtime",
        "",
        f"- {artifact.runtime}",
        "",
        "## Attack Surface",
        "",
    ]
    lines.extend(f"- {item}" for item in artifact.attack_surface or ["No attack surface declared."])
    lines += [
        "",
        "## Healthcheck Contract",
        "",
        artifact.healthcheck,
        "",
        "## Reset Contract",
        "",
        artifact.reset,
        "",
        "## Evidence Logs",
        "",
    ]
    lines.extend(f"- `{item}`" for item in artifact.evidence_logs or ["No evidence logs declared."])
    lines += [
        "",
        "## Safety Boundaries",
        "",
    ]
    lines.extend(f"- {item}" for item in artifact.safety_boundaries or ["No safety boundaries declared."])
    lines.append("")
    return "\n".join(lines)


def render_labforge_service_yaml(artifact) -> str:
    data = {
        "service": artifact.service,
        "runtime": artifact.runtime,
        "purpose": artifact.purpose,
        "template_policy": {
            "role": "infrastructure-part",
            "puzzle_logic": "scenario-specific",
            "rule": "Reusable templates may provide runtime structure, healthcheck, reset, logging, and seed/noise loaders, but must not hard-code the learner solution path.",
        },
        "attack_surface": artifact.attack_surface,
        "seed_inputs": artifact.seed_inputs,
        "noise_inputs": artifact.noise_inputs,
        "healthcheck": artifact.healthcheck,
        "reset": artifact.reset,
        "evidence_logs": artifact.evidence_logs,
        "safety_boundaries": artifact.safety_boundaries,
    }
    return dump_yaml(data)


def render_healthcheck_script(artifact) -> str:
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            "set -eu",
            f"echo '[labforge] healthcheck placeholder for {artifact.service}'",
            "echo '[labforge] replace this with the service-specific healthcheck implementation'",
            "exit 0",
            "",
        ]
    )


def render_reset_script(artifact) -> str:
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            "set -eu",
            f"echo '[labforge] reset placeholder for {artifact.service}'",
            "echo '[labforge] replace this with deterministic service reset logic'",
            "exit 0",
            "",
        ]
    )


def render_runtime_dockerfile(artifact, port: int) -> str:
    return "\n".join(
        [
            "FROM python:3.12-alpine",
            "",
            "WORKDIR /app",
            f"ENV LABFORGE_SERVICE={artifact.service}",
            f"ENV PORT={port}",
            "COPY app.py /app/app.py",
            "COPY seed /app/seed",
            "RUN mkdir -p /home/attacker /var/log/labforge && chmod -R 755 /app /home/attacker /var/log/labforge",
            f"EXPOSE {port}",
            "CMD [\"python\", \"/app/app.py\"]",
            "",
        ]
    )


def render_runtime_app(artifact, port: int) -> str:
    service = str(artifact.service)
    purpose = str(artifact.purpose).replace("\\", "\\\\").replace('"', '\\"')
    runtime = str(artifact.runtime).replace("\\", "\\\\").replace('"', '\\"')
    return "\n".join(
        [
            "from __future__ import annotations",
            "",
            "import json",
            "import os",
            "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer",
            "",
            f"SERVICE = {service!r}",
            f"PURPOSE = \"{purpose}\"",
            f"RUNTIME = \"{runtime}\"",
            f"DEFAULT_PORT = {port}",
            "",
            "",
            "class Handler(BaseHTTPRequestHandler):",
            "    def do_GET(self):",
            "        if self.path in {'/', '/metadata'}:",
            "            self.write_json({",
            "                'service': SERVICE,",
            "                'purpose': PURPOSE,",
            "                'runtime': RUNTIME,",
            "                'status': 'placeholder-runtime',",
            "                'endpoints': ['/', '/metadata', '/healthz'],",
            "            })",
            "            return",
            "        if self.path == '/healthz':",
            "            self.send_response(200)",
            "            self.end_headers()",
            "            self.wfile.write(b'ok\\n')",
            "            return",
            "        self.send_response(404)",
            "        self.end_headers()",
            "",
            "    def log_message(self, fmt, *args):",
            "        return",
            "",
            "    def write_json(self, value):",
            "        data = json.dumps(value, indent=2).encode('utf-8')",
            "        self.send_response(200)",
            "        self.send_header('Content-Type', 'application/json')",
            "        self.send_header('Content-Length', str(len(data)))",
            "        self.end_headers()",
            "        self.wfile.write(data)",
            "",
            "",
            "def main():",
            "    port = int(os.environ.get('PORT', DEFAULT_PORT))",
            "    ThreadingHTTPServer(('0.0.0.0', port), Handler).serve_forever()",
            "",
            "",
            "if __name__ == '__main__':",
            "    main()",
            "",
        ]
    )


def render_runtime_metadata(artifact, port: int) -> str:
    import json

    data = {
        "service": artifact.service,
        "runtime": artifact.runtime,
        "purpose": artifact.purpose,
        "port": port,
        "status": "placeholder-runtime",
        "safety_boundaries": artifact.safety_boundaries,
    }
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def render_runtime_smoke_test() -> str:
    return "\n".join(
        [
            "from pathlib import Path",
            "",
            "",
            "def test_runtime_contract_files_exist():",
            "    root = Path(__file__).resolve().parents[1]",
            "    assert (root / 'Dockerfile').exists()",
            "    assert (root / 'app.py').exists()",
            "    assert (root / 'healthcheck.sh').exists()",
            "    assert (root / 'reset.sh').exists()",
            "    assert (root / 'blueprint.yaml').exists()",
            "",
        ]
    )


SERVICE_ARTIFACT_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "service-result.schema.json": ServiceResultSpec,
    "service-result-apply-report.schema.json": ServiceResultApplyReport,
    "service-result-review-report.schema.json": ServiceResultReviewReport,
    "service-result-batch-review-report.schema.json": ServiceResultBatchReviewReport,
    "service-result-batch-apply-report.schema.json": ServiceResultBatchApplyReport,
}
