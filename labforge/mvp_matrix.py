from __future__ import annotations

import shutil
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, write_text
from .pipeline import create_lab_pipeline, evaluate_pipeline_gate
from .qa import run_release_gate


class MvpMatrixModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class MvpMatrixCase(MvpMatrixModel):
    case_id: str
    industry: str
    prompt: str


class MvpMatrixResult(MvpMatrixModel):
    case_id: str
    industry: str
    status: Literal["passed", "failed"]
    workspace: str
    pipeline_status: str = ""
    pipeline_decision: str = ""
    release_gate_status: str = ""
    release_ready: bool = False
    messages: list[str] = Field(default_factory=list)


class MvpMatrixReport(MvpMatrixModel):
    status: Literal["passed", "failed"]
    provider: str
    profile: str
    cases: list[MvpMatrixResult] = Field(default_factory=list)
    output_dir: str


DEFAULT_MVP_MATRIX_CASES: tuple[MvpMatrixCase, ...] = (
    MvpMatrixCase(
        case_id="supply-chain",
        industry="supply-chain",
        prompt=(
            "Create a realistic enterprise supply chain red-team lab where a learner starts from "
            "an external support portal, reaches an internal wiki, abuses a release workflow, "
            "publishes a trusted update, and retrieves a controlled customer export object."
        ),
    ),
    MvpMatrixCase(
        case_id="securities",
        industry="securities",
        prompt=(
            "Create a realistic brokerage red-team lab where a learner starts from a public "
            "investor portal, reaches internal trade operations, abuses a review workflow, "
            "and retrieves a controlled compliance export."
        ),
    ),
    MvpMatrixCase(
        case_id="healthcare",
        industry="healthcare",
        prompt=(
            "Create a realistic hospital red-team lab where a learner starts from a patient "
            "portal, discovers identity and EHR systems, abuses a clinical workflow, and "
            "retrieves a controlled synthetic audit export."
        ),
    ),
    MvpMatrixCase(
        case_id="manufacturing",
        industry="manufacturing",
        prompt=(
            "Create a realistic manufacturing red-team lab where a learner starts from a "
            "supplier portal, reaches engineering documentation, discovers MES and historian "
            "services, and retrieves a controlled production report."
        ),
    ),
)


def run_mvp_matrix(
    out: Path,
    *,
    provider: str = "docker-compose",
    profile: str = "protected",
    adapter: str = "manual",
    force: bool = False,
    cases: list[MvpMatrixCase] | None = None,
) -> MvpMatrixReport:
    out = out.resolve()
    if out.exists() and force:
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    results: list[MvpMatrixResult] = []
    for case in cases or list(DEFAULT_MVP_MATRIX_CASES):
        workspace = out / case.case_id
        messages: list[str] = []
        try:
            pipeline_result = create_lab_pipeline(
                workspace,
                prompt=case.prompt,
                industry=case.industry,
                provider=provider,
                profile=profile,
                adapter=adapter,
                force=True,
                materialize=True,
                package_service_agents=True,
            )
            gate = evaluate_pipeline_gate(workspace)
            release_gate = run_release_gate(
                Path(pipeline_result.lab_dir),
                workspace / "release-gate",
                provider=provider if provider != "auto" else "docker-compose",
                profile=profile,
                materialize=True,
                force=True,
                agent_result_dir=workspace / "agents" / ".ai" / "outputs",
            )
            status: Literal["passed", "failed"] = (
                "passed"
                if pipeline_result.status in {"complete", "warning"}
                and gate.ready_for_release_gate
                and release_gate.status == "passed"
                and release_gate.release_ready
                else "failed"
            )
            if pipeline_result.status not in {"complete", "warning"}:
                messages.append(f"pipeline status is {pipeline_result.status}")
            if not gate.ready_for_release_gate:
                messages.append(f"pipeline gate decision is {gate.decision}")
            if release_gate.status != "passed":
                messages.append(f"release gate status is {release_gate.status}")
            results.append(
                MvpMatrixResult(
                    case_id=case.case_id,
                    industry=case.industry,
                    status=status,
                    workspace=str(workspace),
                    pipeline_status=pipeline_result.status,
                    pipeline_decision=gate.decision,
                    release_gate_status=release_gate.status,
                    release_ready=release_gate.release_ready,
                    messages=messages,
                )
            )
        except Exception as exc:  # noqa: BLE001 - matrix report should preserve case failures.
            results.append(
                MvpMatrixResult(
                    case_id=case.case_id,
                    industry=case.industry,
                    status="failed",
                    workspace=str(workspace),
                    messages=[str(exc)],
                )
            )

    report = MvpMatrixReport(
        status="failed" if any(result.status == "failed" for result in results) else "passed",
        provider=provider,
        profile=profile,
        cases=results,
        output_dir=str(out),
    )
    write_text(out / "mvp-matrix-report.yaml", dump_yaml(report.model_dump()))
    write_text(out / "mvp-matrix-report.md", render_mvp_matrix_markdown(report))
    return report


def render_mvp_matrix_markdown(report: MvpMatrixReport) -> str:
    lines = [
        "# LabForge MVP Matrix Report",
        "",
        f"- Status: `{report.status}`",
        f"- Provider: `{report.provider}`",
        f"- Profile: `{report.profile}`",
        f"- Output directory: `{report.output_dir}`",
        "",
        "| Case | Industry | Status | Pipeline Gate | Release Gate | Release Ready | Messages |",
        "|---|---|---|---|---|---:|---|",
    ]
    for result in report.cases:
        messages = "<br>".join(result.messages) if result.messages else "-"
        lines.append(
            f"| `{result.case_id}` | `{result.industry}` | {result.status} | "
            f"`{result.pipeline_decision or '-'}` | `{result.release_gate_status or '-'}` | "
            f"{str(result.release_ready).lower()} | {messages} |"
        )
    lines.append("")
    return "\n".join(lines)
