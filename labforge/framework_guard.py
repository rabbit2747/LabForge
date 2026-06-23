from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class FrameworkGuardModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class FrameworkGuardFinding(FrameworkGuardModel):
    severity: Literal["warning", "error"]
    location: str
    message: str


class FrameworkGuardReport(FrameworkGuardModel):
    status: Literal["passed", "failed"]
    scanned_files: int
    findings: list[FrameworkGuardFinding] = Field(default_factory=list)


FORBIDDEN_SCENARIO_MARKER_PARTS = (
    ("orion", " ", "echo"),
    ("orion", "echo"),
    ("echo", "agent"),
    ("an", "rc"),
    ("solar", "winds"),
    ("solar", " ", "winds"),
)

SCANNED_DIRS = (
    "labforge",
    "schemas",
    "templates",
)

SCANNED_SUFFIXES = (
    ".py",
    ".j2",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
)


def guard_framework_hooks(root: Path) -> FrameworkGuardReport:
    root = root.resolve()
    findings: list[FrameworkGuardFinding] = []
    scanned_files = 0

    for path in iter_framework_files(root):
        scanned_files += 1
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lowered = text.lower()
        rel = path.relative_to(root).as_posix()
        for marker in forbidden_scenario_markers():
            if marker in lowered:
                findings.append(
                    FrameworkGuardFinding(
                        severity="error",
                        location=rel,
                        message=(
                            f"Framework code contains scenario-specific marker `{marker}`. "
                            "Move named-scenario behavior into scenario input, fixtures, plugin "
                            "contracts, provider capabilities, or tests instead of adding a core hook."
                        ),
                    )
                )

    status: Literal["passed", "failed"] = "failed" if findings else "passed"
    return FrameworkGuardReport(status=status, scanned_files=scanned_files, findings=findings)


def iter_framework_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for directory in SCANNED_DIRS:
        base = root / directory
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in SCANNED_SUFFIXES:
                files.append(path)
    return sorted(files)


def forbidden_scenario_markers() -> list[str]:
    return ["".join(parts) for parts in FORBIDDEN_SCENARIO_MARKER_PARTS]


def framework_guard_to_json(report: FrameworkGuardReport) -> str:
    return json.dumps(report.model_dump(), ensure_ascii=False, indent=2) + "\n"


def framework_guard_to_markdown(report: FrameworkGuardReport) -> str:
    lines = [
        "# LabForge Framework Guard Report",
        "",
        f"- Status: `{report.status}`",
        f"- Scanned files: `{report.scanned_files}`",
        "",
        "| Severity | Location | Message |",
        "|---|---|---|",
    ]
    if not report.findings:
        lines.append("| warning | - | No scenario-specific framework hooks detected. |")
    for finding in report.findings:
        lines.append(f"| {finding.severity} | `{finding.location}` | {finding.message} |")
    lines.append("")
    return "\n".join(lines)


FRAMEWORK_GUARD_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "framework-guard-report.schema.json": FrameworkGuardReport,
}
