from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .access_playtest import run_access_playtest
from .chain import build_chain_manifest, write_chain_manifest
from .io import dump_yaml, write_text
from .model import LabSpec
from .plugin_runtime_smoke import run_plugin_runtime_smoke
from .realism import check_industry_context
from .render import build_lab
from .service_artifacts import declared_service_artifacts, materialize_service_runtimes
from .solver_runner import run_solver_plan
from .vulnerability_plugins import declared_vulnerability_plugins


PlaytestStatus = Literal["passed", "warning", "failed"]


TRUSTED_UPDATE_CHAIN = [
    "build-pipeline-abuse",
    "signed-update-publish",
    "customer-update-callback",
]


class PlaytestModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class PlaytestEndpoint(PlaytestModel):
    service: str
    role: str = ""
    protocol: str = ""
    connect: str = ""
    health_url: str = ""
    host: str = ""
    default_host_port: int | None = None
    container_port: str = ""
    override_env: str = ""
    networks: list[str] = Field(default_factory=list)
    expected_texts: list[str] = Field(default_factory=list)
    expected_selectors: list[str] = Field(default_factory=list)


class InternalAccessTarget(PlaytestModel):
    service: str
    role: str = ""
    dns: str = ""
    networks: list[str] = Field(default_factory=list)
    expose: list[str] = Field(default_factory=list)
    access_scope: str = "internal-only"
    access_note: str = ""


class PlaytestStep(PlaytestModel):
    step_id: str
    title: str
    status: PlaytestStatus
    evidence: list[str] = Field(default_factory=list)
    learner_action: str = ""
    expected_result: str = ""
    discovery_cues: list[str] = Field(default_factory=list)
    next_step_condition: str = ""


class PlaytestReport(PlaytestModel):
    lab_id: str
    title: str
    provider: str
    profile: str
    status: PlaytestStatus
    output_dir: str
    learner_entrypoints: list[PlaytestEndpoint] = Field(default_factory=list)
    attacker_entrypoints: list[PlaytestEndpoint] = Field(default_factory=list)
    final_submission_endpoints: list[PlaytestEndpoint] = Field(default_factory=list)
    steps: list[PlaytestStep] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)


class LearnerAccessCommand(PlaytestModel):
    label: str
    shell: str
    command: str


class LearnerAccessCheck(PlaytestModel):
    service: str
    kind: str
    command: str
    expected: str


class LearnerTerminalSequence(PlaytestModel):
    service: str
    kind: str = "ssh-command-sequence"
    connect: str
    commands: list[str] = Field(default_factory=list)
    expected_texts: list[str] = Field(default_factory=list)
    expected: str = "Remote command sequence completes."


class LearnerTunnelCommand(PlaytestModel):
    service: str
    dns: str
    internal_port: str
    local_host: str = "127.0.0.1"
    local_port: int
    via: str
    command: str
    url: str = ""
    access_note: str = ""


class LearnerAccessManifest(PlaytestModel):
    lab_id: str
    title: str
    provider: str
    profile: str
    provider_output_dir: str
    start_commands: list[LearnerAccessCommand] = Field(default_factory=list)
    status_commands: list[LearnerAccessCommand] = Field(default_factory=list)
    stop_commands: list[LearnerAccessCommand] = Field(default_factory=list)
    learner_entrypoints: list[PlaytestEndpoint] = Field(default_factory=list)
    attacker_entrypoints: list[PlaytestEndpoint] = Field(default_factory=list)
    final_submission_endpoints: list[PlaytestEndpoint] = Field(default_factory=list)
    internal_targets: list[InternalAccessTarget] = Field(default_factory=list)
    tunnel_commands: list[LearnerTunnelCommand] = Field(default_factory=list)
    health_checks: list[LearnerAccessCheck] = Field(default_factory=list)
    terminal_checks: list[LearnerAccessCheck] = Field(default_factory=list)
    terminal_sequences: list[LearnerTerminalSequence] = Field(default_factory=list)
    plugin_checks: list[dict[str, Any]] = Field(default_factory=list)
    stage_chain_checks: list[dict[str, Any]] = Field(default_factory=list)
    first_action: str = ""
    notes: list[str] = Field(default_factory=list)


class SolverPlanStep(PlaytestModel):
    order: int
    step_id: str
    title: str
    service: str = ""
    plugin: str = ""
    action_type: str
    learner_action: str
    expected_result: str
    evidence: list[str] = Field(default_factory=list)
    automation_hint: str = ""
    discovery_cues: list[str] = Field(default_factory=list)
    next_step_condition: str = ""
    terminal: str = ""
    commands: list[str] = Field(default_factory=list)
    expected_texts: list[str] = Field(default_factory=list)


class SolverPlan(PlaytestModel):
    lab_id: str
    title: str
    provider: str
    profile: str
    status: Literal["planned", "warning", "failed"]
    learner_start: str = ""
    attacker_shell: str = ""
    final_submission: str = ""
    steps: list[SolverPlanStep] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class LabAccessBundle(PlaytestModel):
    lab_id: str
    title: str
    provider: str
    profile: str
    provider_output_dir: str
    learner_urls: list[str] = Field(default_factory=list)
    attacker_ssh: list[str] = Field(default_factory=list)
    final_submission_urls: list[str] = Field(default_factory=list)
    published_endpoints: list[dict[str, Any]] = Field(default_factory=list)
    internal_targets: list[dict[str, Any]] = Field(default_factory=list)
    tunnel_commands: list[dict[str, Any]] = Field(default_factory=list)
    health_commands: list[str] = Field(default_factory=list)
    terminal_sequences: list[dict[str, Any]] = Field(default_factory=list)
    plugin_checks: list[dict[str, Any]] = Field(default_factory=list)
    stage_chain_checks: list[dict[str, Any]] = Field(default_factory=list)
    stage_handoffs: list[dict[str, Any]] = Field(default_factory=list)
    start_commands: list[dict[str, str]] = Field(default_factory=list)
    status_commands: list[dict[str, str]] = Field(default_factory=list)
    stop_commands: list[dict[str, str]] = Field(default_factory=list)
    generated_files: dict[str, str] = Field(default_factory=dict)
    solver_ready: bool = False
    notes: list[str] = Field(default_factory=list)


class HumanReadinessCheck(PlaytestModel):
    check_id: str
    step_id: str
    status: PlaytestStatus
    messages: list[str] = Field(default_factory=list)


class HumanReadinessReport(PlaytestModel):
    lab_id: str
    title: str
    status: PlaytestStatus
    checks: list[HumanReadinessCheck] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


def run_playtest(
    lab_root: Path,
    out: Path,
    *,
    provider: str,
    profile: str,
    materialize: bool = False,
    force: bool = False,
) -> PlaytestReport:
    working_lab = lab_root.resolve()
    if materialize:
        working_lab = out / "materialized-source"
        if working_lab.exists() and force:
            shutil.rmtree(working_lab)
        if not working_lab.exists():
            shutil.copytree(lab_root, working_lab, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        materialize_service_runtimes(LabSpec.load(working_lab), force=force)

    spec = LabSpec.load(working_lab)
    provider_out = out / "provider-output"
    build_lab(spec, provider_out, provider_name=provider, profile=profile)
    chain_manifest = write_chain_manifest(spec, out / "stage-chain")
    endpoints = load_endpoint_manifest(provider_out)
    runtime_smoke = run_plugin_runtime_smoke(spec, out / "plugin-runtime-smoke")

    learner_entrypoints = endpoint_group(endpoints, is_primary_learner_endpoint)
    attacker_entrypoints = endpoint_group(endpoints, lambda item: "attacker" in str(item.get("service", "")).lower() or "workstation" in str(item.get("service", "")).lower())
    final_submission_endpoints = endpoint_group(endpoints, lambda item: any(token in str(item.get("service", "")).lower() for token in ("drop", "submit", "controlled")))

    steps = [
        entrypoint_step(learner_entrypoints),
        attacker_step(attacker_entrypoints),
        vulnerability_runtime_step(runtime_smoke),
        evidence_unlock_step(runtime_smoke),
        service_realism_step(spec, working_lab),
        industry_context_step(spec),
        stage_implementation_coverage_step(spec, chain_manifest),
        service_chain_runtime_step(spec, working_lab, chain_manifest),
        scenario_stage_step(spec, chain_manifest),
        trusted_update_handoff_step(spec),
        final_submission_step(final_submission_endpoints),
    ]
    steps.extend(plugin_walkthrough_steps(spec, runtime_smoke))

    failures = [message for step in steps if step.status == "failed" for message in step.evidence]
    warnings = [message for step in steps if step.status == "warning" for message in step.evidence]
    status: PlaytestStatus = "failed" if failures else ("warning" if warnings else "passed")

    report = PlaytestReport(
        lab_id=spec.lab_id,
        title=spec.title,
        provider=provider,
        profile=profile,
        status=status,
        output_dir=str(out.resolve()),
        learner_entrypoints=learner_entrypoints,
        attacker_entrypoints=attacker_entrypoints,
        final_submission_endpoints=final_submission_endpoints,
        steps=steps,
        warnings=warnings,
        failures=failures,
    )
    write_text(out / "playtest-report.yaml", dump_yaml(report.model_dump()))
    write_text(out / "playtest-report.json", report.model_dump_json(indent=2))
    write_text(out / "playtest-report.md", render_playtest_markdown(report))
    solver_plan = build_solver_plan(report)
    write_text(out / "solver-plan.json", solver_plan.model_dump_json(indent=2))
    write_text(out / "solver-plan.md", render_solver_plan_markdown(solver_plan))
    access_manifest = build_learner_access_manifest(report, provider_out, solver_plan=solver_plan)
    write_text(out / "learner-access.json", access_manifest.model_dump_json(indent=2))
    write_text(out / "learner-access.md", render_learner_access_markdown(report))
    write_text(out / "playtest-walkthrough.md", render_playtest_walkthrough_markdown(report))
    access_bundle = build_lab_access_bundle(report, access_manifest, solver_plan, provider_out, out, chain_manifest=chain_manifest)
    write_text(out / "lab-access-bundle.json", access_bundle.model_dump_json(indent=2))
    write_text(out / "lab-access-bundle.md", render_lab_access_bundle_markdown(access_bundle))
    human_readiness = build_human_readiness_report(report, access_manifest, solver_plan)
    write_text(out / "human-readiness.json", human_readiness.model_dump_json(indent=2))
    write_text(out / "human-readiness.yaml", dump_yaml(human_readiness.model_dump()))
    write_text(out / "human-readiness.md", render_human_readiness_markdown(human_readiness))
    run_access_playtest(out / "learner-access.json", out / "access-playtest", execute=False)
    run_solver_plan(out / "solver-plan.json", out / "solver-run", access_manifest=out / "learner-access.json", execute=False)
    return report


def load_endpoint_manifest(provider_out: Path) -> dict[str, Any]:
    manifest = provider_out / "endpoints.json"
    if not manifest.exists():
        return {"published_endpoints": [], "internal_services": []}
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"published_endpoints": [], "internal_services": []}
    if not isinstance(data, dict):
        return {"published_endpoints": [], "internal_services": []}
    data.setdefault("published_endpoints", [])
    data.setdefault("internal_services", [])
    return data


def endpoint_group(endpoint_manifest: dict[str, Any], predicate) -> list[PlaytestEndpoint]:
    endpoints: list[PlaytestEndpoint] = []
    for item in endpoint_manifest.get("published_endpoints", []):
        if not isinstance(item, dict) or not predicate(item):
            continue
        endpoints.append(
            PlaytestEndpoint(
                service=str(item.get("service", "")),
                role=str(item.get("role", "")),
                protocol=str(item.get("protocol", "")),
                connect=str(item.get("connect") or item.get("url") or ""),
                health_url=str(item.get("health_url", "")),
                host=endpoint_host(item),
                default_host_port=endpoint_host_port(item),
                container_port=str(item.get("container_port", "")),
                override_env=str(item.get("override_env", "")),
                networks=[str(network) for network in item.get("networks", [])],
                expected_texts=normalize_endpoint_expected_texts(item),
                expected_selectors=normalize_endpoint_expected_selectors(item),
            )
        )
    return endpoints


def endpoint_host(item: dict[str, Any]) -> str:
    connect = str(item.get("connect") or item.get("url") or "")
    if "127.0.0.1" in connect:
        return "127.0.0.1"
    if "localhost" in connect:
        return "localhost"
    if connect.startswith("http://"):
        without_scheme = connect.removeprefix("http://")
        return without_scheme.split("/", maxsplit=1)[0].split(":", maxsplit=1)[0]
    return ""


def endpoint_host_port(item: dict[str, Any]) -> int | None:
    value = item.get("default_host_port")
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def tunnel_commands_for_internal_targets(
    internal_targets: list[InternalAccessTarget],
    attacker_entrypoints: list[PlaytestEndpoint],
    published_endpoints: list[PlaytestEndpoint],
) -> list[LearnerTunnelCommand]:
    attacker = next((endpoint for endpoint in attacker_entrypoints if endpoint.protocol == "ssh" and endpoint.connect), None)
    if not attacker:
        return []
    used_ports = {
        endpoint.default_host_port
        for endpoint in [*published_endpoints, *attacker_entrypoints]
        if endpoint.default_host_port is not None
    }
    local_port = 18080
    commands: list[LearnerTunnelCommand] = []
    for target in internal_targets:
        if not target.dns or not target.expose:
            continue
        internal_port = str(target.expose[0])
        while local_port in used_ports:
            local_port += 1
        used_ports.add(local_port)
        url = f"http://127.0.0.1:{local_port}/" if looks_like_http_port(internal_port) else ""
        commands.append(
            LearnerTunnelCommand(
                service=target.service,
                dns=target.dns,
                internal_port=internal_port,
                local_port=local_port,
                via=attacker.service,
                command=f"ssh -L {local_port}:{target.dns}:{internal_port} {ssh_destination(attacker.connect)}",
                url=url,
                access_note=(
                    f"Keep this SSH session open, then access {url or f'127.0.0.1:{local_port}'} "
                    f"to reach internal service `{target.dns}:{internal_port}` through `{attacker.service}`."
                ),
            )
        )
        local_port += 1
    return commands


def looks_like_http_port(port: str) -> bool:
    try:
        value = int(str(port).split("/", maxsplit=1)[0])
    except ValueError:
        return False
    return value not in {22, 389, 636, 1433, 1521, 3306, 5432, 6379}


def ssh_destination(connect: str) -> str:
    text = " ".join(str(connect).split())
    return text.removeprefix("ssh ").strip() or text


def internal_targets_from_endpoint_manifest(endpoint_manifest: dict[str, Any]) -> list[InternalAccessTarget]:
    targets: list[InternalAccessTarget] = []
    for item in endpoint_manifest.get("internal_services", []):
        if not isinstance(item, dict):
            continue
        service = str(item.get("service", "")).strip()
        dns = str(item.get("dns") or service).strip()
        networks = [str(network) for network in item.get("networks", []) or [] if str(network).strip()]
        expose = [str(port) for port in item.get("expose", []) or [] if str(port).strip()]
        if not service and not dns:
            continue
        scope = "internal-only"
        note_parts = []
        if dns:
            note_parts.append(f"resolve as `{dns}` from containers attached to {', '.join(networks) or 'the same lab network'}")
        if expose:
            note_parts.append(f"service ports: {', '.join(expose)}")
        note_parts.append("not directly reachable from the learner host unless a scenario stage creates an approved tunnel, pivot, or workstation route")
        targets.append(
            InternalAccessTarget(
                service=service or dns,
                role=str(item.get("role", "")),
                dns=dns or service,
                networks=networks,
                expose=expose,
                access_scope=scope,
                access_note="; ".join(note_parts),
            )
        )
    return targets


def normalize_endpoint_expected_texts(item: dict[str, Any]) -> list[str]:
    values: list[str] = []
    single = str(item.get("expected_text", "")).strip()
    if single:
        values.append(single)
    raw_many = item.get("expected_texts", [])
    if isinstance(raw_many, list):
        values.extend(str(value).strip() for value in raw_many if str(value).strip())
    return list(dict.fromkeys(values))


def normalize_endpoint_expected_selectors(item: dict[str, Any]) -> list[str]:
    values: list[str] = []
    single = str(item.get("expected_selector", "")).strip()
    if single:
        values.append(single)
    raw_many = item.get("expected_selectors", [])
    if isinstance(raw_many, list):
        values.extend(str(value).strip() for value in raw_many if str(value).strip())
    return list(dict.fromkeys(values))


def is_primary_learner_endpoint(item: dict[str, Any]) -> bool:
    if not (item.get("url") or item.get("connect")):
        return False
    service = str(item.get("service", "")).lower()
    role = str(item.get("role", "")).lower()
    if any(token in service for token in ("attacker", "workstation", "drop", "submit", "controlled")):
        return False
    if any(token in role for token in ("attacker", "workstation", "drop", "submission")):
        return False
    return True


def build_learner_access_manifest(report: PlaytestReport, provider_out: Path, *, solver_plan: SolverPlan | None = None) -> LearnerAccessManifest:
    endpoint_manifest = load_endpoint_manifest(provider_out)
    internal_targets = internal_targets_from_endpoint_manifest(endpoint_manifest)
    tunnel_commands = tunnel_commands_for_internal_targets(
        internal_targets,
        report.attacker_entrypoints,
        [*report.learner_entrypoints, *report.final_submission_endpoints],
    )
    first_action = ""
    if report.learner_entrypoints:
        first = report.learner_entrypoints[0]
        verb = "Connect to" if first.protocol == "ssh" else "Open"
        first_action = f"{verb} {first.connect}"
    health_checks = [
        LearnerAccessCheck(
            service=endpoint.service,
            kind="http-health",
            command=f"curl -i {endpoint.health_url}",
            expected="HTTP 200 or service-specific healthy response.",
        )
        for endpoint in report.learner_entrypoints + report.final_submission_endpoints
        if endpoint.health_url
    ]
    terminal_checks = [
        LearnerAccessCheck(
            service=endpoint.service,
            kind="ssh-connect",
            command=endpoint.connect,
            expected="Interactive learner shell prompt appears.",
        )
        for endpoint in report.attacker_entrypoints + report.learner_entrypoints
        if endpoint.protocol == "ssh" and endpoint.connect
    ]
    terminal_sequences = [
        LearnerTerminalSequence(
            service=endpoint.service,
            connect=endpoint.connect,
            commands=["echo labforge-terminal-ready", "pwd"],
            expected_texts=["labforge-terminal-ready"],
            expected="SSH target accepts non-interactive learner commands.",
        )
        for endpoint in report.attacker_entrypoints + report.learner_entrypoints
        if endpoint.protocol == "ssh" and endpoint.connect
    ]
    service_base_urls = service_base_urls_from_endpoint_manifest(endpoint_manifest)
    plugin_checks = (
        plugin_checks_from_solver_plan(
            solver_plan,
            service_base_urls=service_base_urls,
        )
        if solver_plan
        else []
    )
    return LearnerAccessManifest(
        lab_id=report.lab_id,
        title=report.title,
        provider=report.provider,
        profile=report.profile,
        provider_output_dir=str(provider_out.resolve()),
        start_commands=[
            LearnerAccessCommand(label="Windows PowerShell", shell="powershell", command="powershell -ExecutionPolicy Bypass -File .\\scripts\\start.ps1"),
            LearnerAccessCommand(label="Linux, macOS, or WSL", shell="sh", command="./scripts/start.sh"),
        ],
        status_commands=[
            LearnerAccessCommand(label="Windows PowerShell", shell="powershell", command="powershell -ExecutionPolicy Bypass -File .\\scripts\\status.ps1"),
            LearnerAccessCommand(label="Windows PowerShell healthcheck", shell="powershell", command="powershell -ExecutionPolicy Bypass -File .\\scripts\\services-healthcheck.ps1"),
            LearnerAccessCommand(label="Linux, macOS, or WSL", shell="sh", command="./scripts/status.sh"),
            LearnerAccessCommand(label="Linux, macOS, or WSL healthcheck", shell="sh", command="./scripts/services-healthcheck.sh"),
        ],
        stop_commands=[
            LearnerAccessCommand(label="Windows PowerShell", shell="powershell", command="powershell -ExecutionPolicy Bypass -File .\\scripts\\stop.ps1"),
            LearnerAccessCommand(label="Linux, macOS, or WSL", shell="sh", command="./scripts/stop.sh"),
        ],
        learner_entrypoints=report.learner_entrypoints,
        attacker_entrypoints=report.attacker_entrypoints,
        final_submission_endpoints=report.final_submission_endpoints,
        internal_targets=internal_targets,
        tunnel_commands=tunnel_commands,
        health_checks=health_checks,
        terminal_checks=terminal_checks,
        terminal_sequences=terminal_sequences,
        plugin_checks=plugin_checks,
        stage_chain_checks=[],
        first_action=first_action,
        notes=[
            "Run start commands from the generated provider output directory.",
            "Use health checks to confirm HTTP services before manual or automated playtest.",
            "Use terminal checks and terminal sequences for attacker workstation or SSH-based learner hosts.",
        ],
    )


def build_solver_plan(report: PlaytestReport) -> SolverPlan:
    steps: list[SolverPlanStep] = []
    learner_start = report.learner_entrypoints[0].connect if report.learner_entrypoints else ""
    attacker_shell = report.attacker_entrypoints[0].connect if report.attacker_entrypoints else ""
    final_submission = report.final_submission_endpoints[0].connect if report.final_submission_endpoints else ""
    for step in report.steps:
        action_type = "verification"
        service = ""
        plugin = ""
        if step.step_id.startswith("plugin-"):
            action_type = "vulnerability-behavior"
            service, plugin = parse_plugin_step_id(step.step_id)
        elif step.step_id.startswith("access-"):
            action_type = "access"
        elif step.step_id.startswith("final-"):
            action_type = "final-submission"
        elif step.step_id.startswith("chain-") or step.step_id.startswith("runtime-"):
            action_type = "stage-chain"
        elif step.step_id.startswith("implementation-"):
            action_type = "implementation-coverage"
        elif step.step_id.startswith("realism-"):
            action_type = "realism-review"
        elif step.step_id.startswith("industry-"):
            action_type = "industry-realism-review"
        steps.append(
            SolverPlanStep(
                order=len(steps) + 1,
                step_id=step.step_id,
                title=step.title,
                service=service,
                plugin=plugin,
                action_type=action_type,
                learner_action=step.learner_action,
                expected_result=step.expected_result,
                evidence=step.evidence,
                automation_hint=automation_hint_for_step(action_type, service, plugin),
                discovery_cues=step.discovery_cues,
                next_step_condition=step.next_step_condition,
            )
        )
    for endpoint in report.attacker_entrypoints + report.learner_entrypoints:
        if endpoint.protocol == "ssh" and endpoint.connect:
            steps.append(
                SolverPlanStep(
                    order=len(steps) + 1,
                    step_id=f"terminal-{slugify(endpoint.service)}-readiness",
                    title=f"{endpoint.service} terminal readiness",
                    service=endpoint.service,
                    action_type="command-sequence",
                    learner_action="Run a short non-interactive command sequence on the learner SSH target.",
                    expected_result="The SSH target accepts commands and returns the readiness marker.",
                    evidence=["labforge-terminal-ready"],
                    automation_hint="Run the commands over the generated SSH connection in batch mode.",
                    discovery_cues=["Generated attacker or learner workstation SSH endpoint is listed in learner-access.json."],
                    next_step_condition="Proceed when the terminal readiness marker is visible in stdout.",
                    terminal=endpoint.connect,
                    commands=["echo labforge-terminal-ready", "pwd"],
                    expected_texts=["labforge-terminal-ready"],
                )
            )
    warnings = list(report.failures or report.warnings or [])
    status: Literal["planned", "warning", "failed"] = "failed" if report.failures else ("warning" if report.warnings else "planned")
    return SolverPlan(
        lab_id=report.lab_id,
        title=report.title,
        provider=report.provider,
        profile=report.profile,
        status=status,
        learner_start=learner_start,
        attacker_shell=attacker_shell,
        final_submission=final_submission,
        steps=steps,
        warnings=warnings,
    )


def build_lab_access_bundle(
    report: PlaytestReport,
    access: LearnerAccessManifest,
    solver_plan: SolverPlan,
    provider_out: Path,
    playtest_out: Path,
    *,
    chain_manifest=None,
) -> LabAccessBundle:
    generated_files = {
        "provider_quickstart": str((provider_out / "QUICKSTART.md").resolve()),
        "provider_endpoints": str((provider_out / "endpoints.json").resolve()),
        "learner_access_markdown": str((playtest_out / "learner-access.md").resolve()),
        "learner_access_json": str((playtest_out / "learner-access.json").resolve()),
        "solver_plan_markdown": str((playtest_out / "solver-plan.md").resolve()),
        "solver_plan_json": str((playtest_out / "solver-plan.json").resolve()),
        "access_playtest_report": str((playtest_out / "access-playtest" / "access-playtest.md").resolve()),
        "solver_run_report": str((playtest_out / "solver-run" / "solver-run.md").resolve()),
        "walkthrough": str((playtest_out / "playtest-walkthrough.md").resolve()),
        "human_readiness_report": str((playtest_out / "human-readiness.md").resolve()),
    }
    endpoint_manifest = load_endpoint_manifest(provider_out)
    internal_targets = internal_targets_from_endpoint_manifest(endpoint_manifest)
    tunnel_commands = tunnel_commands_for_internal_targets(
        internal_targets,
        report.attacker_entrypoints,
        [*report.learner_entrypoints, *report.final_submission_endpoints],
    )
    service_base_urls = service_base_urls_from_endpoint_manifest(endpoint_manifest)
    plugin_checks = plugin_checks_from_solver_plan(
        solver_plan,
        service_base_urls=service_base_urls,
    )
    stage_handoffs = stage_handoffs_from_chain_manifest(chain_manifest)
    stage_chain_checks = stage_chain_checks_from_stage_handoffs(stage_handoffs, service_base_urls)
    readiness_findings = lab_access_solver_readiness_findings(
        report=report,
        access=access,
        solver_plan=solver_plan,
        internal_targets=internal_targets,
        tunnel_commands=tunnel_commands,
        plugin_checks=plugin_checks,
        stage_handoffs=stage_handoffs,
    )
    return LabAccessBundle(
        lab_id=report.lab_id,
        title=report.title,
        provider=report.provider,
        profile=report.profile,
        provider_output_dir=str(provider_out.resolve()),
        learner_urls=[endpoint.connect for endpoint in report.learner_entrypoints if endpoint.protocol == "http" and endpoint.connect],
        attacker_ssh=[endpoint.connect for endpoint in report.attacker_entrypoints if endpoint.protocol == "ssh" and endpoint.connect],
        final_submission_urls=[endpoint.connect for endpoint in report.final_submission_endpoints if endpoint.protocol == "http" and endpoint.connect],
        published_endpoints=[
            endpoint.model_dump()
            for endpoint in [*report.learner_entrypoints, *report.attacker_entrypoints, *report.final_submission_endpoints]
        ],
        internal_targets=[target.model_dump() for target in internal_targets],
        tunnel_commands=[command.model_dump() for command in tunnel_commands],
        health_commands=[check.command for check in access.health_checks],
        terminal_sequences=[
            {
                "service": sequence.service,
                "connect": sequence.connect,
                "commands": sequence.commands,
                "expected_texts": sequence.expected_texts,
            }
            for sequence in access.terminal_sequences
        ],
        plugin_checks=plugin_checks,
        stage_chain_checks=stage_chain_checks,
        stage_handoffs=stage_handoffs,
        start_commands=[command.model_dump() for command in access.start_commands],
        status_commands=[command.model_dump() for command in access.status_commands],
        stop_commands=[command.model_dump() for command in access.stop_commands],
        generated_files=generated_files,
        solver_ready=not readiness_findings,
        notes=[
            "Run start commands from provider_output_dir before opening learner URLs.",
            "Use learner_urls for browser playtest and attacker_ssh for terminal playtest.",
            "Run access-playtest and solver-run reports after deployment to prove the lab is playable.",
            *readiness_findings,
        ],
    )


def build_human_readiness_report(
    report: PlaytestReport,
    access: LearnerAccessManifest,
    solver_plan: SolverPlan,
) -> HumanReadinessReport:
    checks: list[HumanReadinessCheck] = [human_access_readiness_check(report, access)]
    plugin_check_keys = {
        (str(item.get("service", "")), str(item.get("plugin", "")))
        for item in access.plugin_checks
        if isinstance(item, dict)
    }
    for step in solver_plan.steps:
        checks.append(human_solver_step_readiness_check(step, plugin_check_keys))
    checks.append(human_chain_readiness_check(solver_plan, access))
    failures = [check for check in checks if check.status == "failed"]
    warnings = [check for check in checks if check.status == "warning"]
    status: PlaytestStatus = "failed" if failures else ("warning" if warnings else "passed")
    return HumanReadinessReport(
        lab_id=report.lab_id,
        title=report.title,
        status=status,
        checks=checks,
        summary={
            "checks": len(checks),
            "passed": len([check for check in checks if check.status == "passed"]),
            "warning": len(warnings),
            "failed": len(failures),
        },
    )


def human_access_readiness_check(report: PlaytestReport, access: LearnerAccessManifest) -> HumanReadinessCheck:
    messages: list[str] = []
    warnings: list[str] = []
    if not report.learner_entrypoints and not report.attacker_entrypoints:
        messages.append("No learner browser URL or attacker SSH endpoint is available.")
    if not access.first_action:
        messages.append("Learner access manifest has no first_action.")
    if not access.start_commands:
        messages.append("No provider start command is documented.")
    internal_targets = list(getattr(access, "internal_targets", []) or [])
    tunnel_commands = list(getattr(access, "tunnel_commands", []) or [])
    if report.attacker_entrypoints and not access.terminal_sequences:
        messages.append("Attacker SSH is published but no terminal command sequence is documented.")
    if internal_targets and not tunnel_commands:
        messages.append("Internal-only targets exist but no learner tunnel command is documented.")
    if tunnel_commands and not report.attacker_entrypoints:
        messages.append("Tunnel commands exist but no attacker SSH endpoint is available to anchor them.")
    if not report.final_submission_endpoints and not final_submission_reachable_via_tunnel(internal_targets, tunnel_commands):
        warnings.append("No final submission endpoint is available.")
    status: PlaytestStatus = "failed" if messages else ("warning" if warnings else "passed")
    return HumanReadinessCheck(
        check_id="human-access-01",
        step_id="access",
        status=status,
        messages=[*messages, *warnings] or ["Learner start, terminal access, and final submission handoff are documented."],
    )


def human_chain_readiness_check(solver_plan: SolverPlan, access: LearnerAccessManifest) -> HumanReadinessCheck:
    messages: list[str] = []
    vulnerability_steps = [step for step in solver_plan.steps if step.action_type == "vulnerability-behavior"]
    if vulnerability_steps and not access.plugin_checks:
        messages.append("Vulnerability stages exist but no plugin evidence checks are documented.")
    if len(solver_plan.steps) >= 4 and not any(step.action_type == "final-submission" for step in solver_plan.steps):
        messages.append("Multi-stage solver plan has no final-submission step.")
    internal_targets = list(getattr(access, "internal_targets", []) or [])
    tunnel_commands = list(getattr(access, "tunnel_commands", []) or [])
    if internal_targets and not tunnel_commands:
        messages.append("Internal target handoff is not backed by a tunnel or reachability command.")
    return HumanReadinessCheck(
        check_id="human-chain-01",
        step_id="stage-chain",
        status="failed" if messages else "passed",
        messages=messages or ["Stage chain has access, evidence, internal reachability, and completion handoff material."],
    )


def final_submission_reachable_via_tunnel(
    internal_targets: list[InternalAccessTarget],
    tunnel_commands: list[LearnerTunnelCommand],
) -> bool:
    final_services = {
        target.service
        for target in internal_targets
        if any(token in target.service.lower() for token in ("drop", "submit", "controlled"))
    }
    if not final_services:
        return False
    return any(command.service in final_services and bool(command.url or command.command) for command in tunnel_commands)


def human_solver_step_readiness_check(
    step: SolverPlanStep,
    plugin_check_keys: set[tuple[str, str]],
) -> HumanReadinessCheck:
    messages: list[str] = []
    learner_action = " ".join(step.learner_action.split())
    expected_result = " ".join(step.expected_result.split())
    if len(learner_action) < 24:
        messages.append("learner_action is too thin for a human learner.")
    if len(expected_result) < 24:
        messages.append("expected_result is too thin for a human learner.")
    if contains_answer_key_language(learner_action):
        messages.append("learner_action contains answer-key or CTF-style wording.")
    for cue in step.discovery_cues:
        if contains_answer_key_language(cue):
            messages.append("discovery_cues contain answer-key or CTF-style wording.")
    if step.action_type not in {"access", "final-submission", "command-sequence"}:
        has_human_anchor = bool(step.discovery_cues or step.evidence or step.commands or step.automation_hint)
        if not has_human_anchor:
            messages.append("step lacks evidence, discovery cues, commands, or automation guidance for a human solver.")
    if step.action_type == "vulnerability-behavior":
        if not step.discovery_cues:
            messages.append("vulnerability step has no discovery_cues.")
        if not step.next_step_condition:
            messages.append("vulnerability step has no next_step_condition.")
        if (step.service, step.plugin) not in plugin_check_keys:
            messages.append(f"missing plugin evidence check for {step.service}:{step.plugin}.")
    if step.action_type == "command-sequence":
        if not step.terminal:
            messages.append("terminal command sequence has no SSH target.")
        if not step.commands or not step.expected_texts:
            messages.append("terminal command sequence lacks commands or expected output.")
    return HumanReadinessCheck(
        check_id=f"human-{step.order:02d}",
        step_id=step.step_id,
        status="failed" if messages else "passed",
        messages=messages or ["Step has learner action, expected result, cues, and verification material."],
    )


def contains_answer_key_language(text: str) -> bool:
    normalized = text.lower()
    blocked = (
        "answer key",
        "copy paste",
        "copy/paste",
        "ctf",
        "flag",
        "just submit",
        "use the exact",
    )
    return any(term in normalized for term in blocked)


def lab_access_solver_readiness_findings(
    *,
    report: PlaytestReport,
    access: LearnerAccessManifest,
    solver_plan: SolverPlan,
    internal_targets: list[InternalAccessTarget],
    tunnel_commands: list[LearnerTunnelCommand],
    plugin_checks: list[dict[str, Any]],
    stage_handoffs: list[dict[str, Any]],
) -> list[str]:
    findings: list[str] = []
    if not solver_plan.steps:
        findings.append("readiness: solver plan has no ordered steps.")
    if not (report.learner_entrypoints or report.attacker_entrypoints):
        findings.append("readiness: no learner URL or attacker SSH endpoint is published.")
    if report.attacker_entrypoints and not access.terminal_sequences:
        findings.append("readiness: attacker SSH endpoint lacks a terminal command sequence.")
    if internal_targets and not tunnel_commands:
        findings.append("readiness: internal-only services exist without generated tunnel commands.")
    if tunnel_commands and not report.attacker_entrypoints:
        findings.append("readiness: tunnel commands require an attacker SSH endpoint.")
    vulnerability_steps = [step for step in solver_plan.steps if step.action_type == "vulnerability-behavior"]
    if vulnerability_steps and not plugin_checks:
        findings.append("readiness: vulnerability solver steps lack plugin evidence checks.")
    if len(solver_plan.steps) >= 4 and not stage_handoffs:
        findings.append("readiness: multi-stage solver plan lacks stage handoff evidence.")
    if (
        len(solver_plan.steps) >= 4
        and not (report.final_submission_endpoints or solver_plan.final_submission)
        and not final_submission_reachable_via_tunnel(internal_targets, tunnel_commands)
    ):
        findings.append("readiness: multi-stage solver plan lacks final submission access.")
    return findings


def stage_handoffs_from_chain_manifest(chain_manifest) -> list[dict[str, Any]]:
    if not chain_manifest:
        return []
    handoffs: list[dict[str, Any]] = []
    node_by_stage = {str(getattr(node, "stage_id", "")): node for node in getattr(chain_manifest, "nodes", []) or []}
    evidence_handoffs = list(getattr(chain_manifest, "evidence_handoffs", []) or [])
    if evidence_handoffs:
        grouped: dict[tuple[str, str], list[Any]] = {}
        for item in evidence_handoffs:
            producer = str(getattr(item, "producer_stage", ""))
            consumer = str(getattr(item, "consumer_stage", ""))
            if not consumer:
                continue
            grouped.setdefault((producer, consumer), []).append(item)
        for (from_stage, to_stage), items in grouped.items():
            source = node_by_stage.get(from_stage)
            target = node_by_stage.get(to_stage)
            handoffs.append(
                {
                    "from_stage": from_stage,
                    "from_title": str(getattr(source, "title", "")) if source else "",
                    "to_stage": to_stage,
                    "to_title": str(getattr(target, "title", "")) if target else "",
                    "from_services": [str(item) for item in getattr(source, "services", []) or []] if source else [],
                    "to_services": [str(item) for item in getattr(target, "services", []) or []] if target else [],
                    "carried_evidence": sorted({str(getattr(item, "evidence", "")) for item in items if str(getattr(item, "evidence", ""))}),
                    "status": ",".join(sorted({str(getattr(item, "status", "")) for item in items if str(getattr(item, "status", ""))})),
                    "learner_clue": str(getattr(target, "learner_clue", "")) if target else "",
                }
            )
        return handoffs
    for link in getattr(chain_manifest, "links", []) or []:
        from_stage = str(getattr(link, "from_stage", ""))
        to_stage = str(getattr(link, "to_stage", ""))
        source = node_by_stage.get(from_stage)
        target = node_by_stage.get(to_stage)
        handoffs.append(
            {
                "from_stage": from_stage,
                "from_title": str(getattr(source, "title", "")) if source else "",
                "to_stage": to_stage,
                "to_title": str(getattr(target, "title", "")) if target else "",
                "from_services": [str(item) for item in getattr(source, "services", []) or []] if source else [],
                "to_services": [str(item) for item in getattr(target, "services", []) or []] if target else [],
                "carried_evidence": [str(item) for item in getattr(link, "carried_evidence", []) or []],
                "status": str(getattr(link, "status", "")),
                "learner_clue": str(getattr(target, "learner_clue", "")) if target else "",
            }
        )
    return handoffs


def plugin_checks_from_solver_plan(plan: SolverPlan, *, service_base_urls: dict[str, str] | None = None) -> list[dict[str, Any]]:
    service_base_urls = service_base_urls or {}
    checks: list[dict[str, Any]] = []
    for step in plan.steps:
        if step.action_type != "vulnerability-behavior":
            continue
        emitted = expected_evidence_from_step(step)
        base_url = service_base_urls.get(step.service, "")
        state_url = f"{base_url}/api/state" if base_url else ""
        checks.append(
            {
                "step_id": step.step_id,
                "service": step.service,
                "plugin": step.plugin,
                "learner_action": step.learner_action,
                "discovery_cues": step.discovery_cues,
                "next_step_condition": step.next_step_condition,
                "expected_evidence": emitted,
                "state_url": state_url,
                "state_verification": state_verification_for_plugin_check(state_url, emitted),
            }
        )
    return checks


def stage_chain_checks_from_stage_handoffs(
    stage_handoffs: list[dict[str, Any]], service_base_urls: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    service_base_urls = service_base_urls or {}
    checks: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for handoff in stage_handoffs:
        from_stage = str(handoff.get("from_stage", "")).strip()
        to_stage = str(handoff.get("to_stage", "")).strip()
        carried = [str(item).strip() for item in handoff.get("carried_evidence", []) or [] if str(item).strip()]
        clue = str(handoff.get("learner_clue", "")).strip()
        for service in handoff.get("to_services", []) or []:
            service_name = str(service).strip()
            base_url = service_base_urls.get(service_name, "").rstrip("/")
            if not service_name or not base_url:
                continue
            key = (service_name, from_stage, to_stage)
            if key in seen:
                continue
            seen.add(key)
            checks.append(
                {
                    "service": service_name,
                    "from_stage": from_stage,
                    "to_stage": to_stage,
                    "chain_url": f"{base_url}/api/chain",
                    "expected_evidence": carried,
                    "expected_clue": clue,
                    "expected_stage": to_stage,
                    "learner_action": f"Read {service_name} chain context and confirm the handoff into {to_stage}.",
                }
            )
    return checks


def service_base_urls_from_endpoint_manifest(endpoint_manifest: dict[str, Any]) -> dict[str, str]:
    urls: dict[str, str] = {}
    for collection_name in ("published_endpoints", "internal_services"):
        collection = endpoint_manifest.get(collection_name, [])
        if not isinstance(collection, list):
            continue
        for item in collection:
            if not isinstance(item, dict):
                continue
            if str(item.get("protocol", "http")).lower() != "http":
                continue
            service = str(item.get("service", "")).strip()
            url = str(item.get("url") or item.get("connect") or "").strip().rstrip("/")
            if service and url.startswith("http"):
                urls.setdefault(service, url)
    return urls


def state_verification_for_plugin_check(state_url: str, expected_evidence: list[str]) -> str:
    if not state_url:
        if expected_evidence:
            return "service is not published as HTTP; verify expected evidence through solver-run execution output"
        return "service is not published as HTTP; no explicit emitted evidence declared"
    if not expected_evidence:
        return f"curl -sS {state_url}"
    expected = ",".join(expected_evidence)
    return f"curl -sS {state_url} and confirm acquired_evidence contains {expected}"


def expected_evidence_from_step(step: SolverPlanStep) -> list[str]:
    values: list[str] = []
    for item in step.evidence:
        text = str(item).strip()
        if not text.startswith("emitted_evidence="):
            continue
        for value in text.split("=", maxsplit=1)[1].split(","):
            value = value.strip()
            if value and value not in values:
                values.append(value)
    return values


def parse_plugin_step_id(step_id: str) -> tuple[str, str]:
    raw = step_id.removeprefix("plugin-")
    plugin_ids = [
        "customer-update-callback",
        "diagnostic-command-injection",
        "solr-velocity-rce",
        "credential-exposure",
        "path-traversal-download",
        "build-pipeline-abuse",
        "signed-update-publish",
        "ssrf-internal-fetch",
        "idor-object-access",
        "stored-xss-review",
        "unsafe-file-upload",
        "ssti-preview",
    ]
    for plugin_id in plugin_ids:
        suffix = f"-{plugin_id}"
        if raw.endswith(suffix):
            return raw[: -len(suffix)], plugin_id
    return raw, ""


def automation_hint_for_step(action_type: str, service: str, plugin: str) -> str:
    if action_type == "access":
        return "Use learner-access.json to open the learner URL and optional SSH terminal target."
    if action_type == "vulnerability-behavior":
        return f"Exercise the generated `{plugin}` scaffold or corresponding normal UI workflow on `{service}`; then verify emitted evidence in playtest/plugin-runtime-smoke output."
    if action_type == "final-submission":
        return "Submit the controlled final proof only to the generated final submission endpoint."
    if action_type == "stage-chain":
        return "Read /api/chain and /api/state from generated services when available to confirm stage evidence progression."
    if action_type == "implementation-coverage":
        return "Confirm that every scenario stage maps to a generated service runtime, plugin behavior, or final submission endpoint."
    if action_type == "realism-review":
        return "Inspect generated seed records, clues, and noise before automated browser solving."
    if action_type == "industry-realism-review":
        return "Verify that service names, records, UI surfaces, and stage clues read like the declared industry rather than generic lab infrastructure."
    return "Use playtest evidence to decide the next safe lab-contained action."


def entrypoint_step(entrypoints: list[PlaytestEndpoint]) -> PlaytestStep:
    if not entrypoints:
        return PlaytestStep(
            step_id="access-01",
            title="Learner-visible entrypoint exists",
            status="failed",
            evidence=["No learner-visible URL or SSH command was published."],
            learner_action="Open the first learner-visible URL or SSH command from learner-access.md.",
            expected_result="The learner can reach the first service without reading provider internals.",
        )
    return PlaytestStep(
        step_id="access-01",
        title="Learner-visible entrypoint exists",
        status="passed",
        evidence=[f"{item.service}: {item.connect}" for item in entrypoints],
        learner_action=f"Start from `{entrypoints[0].connect}`.",
        expected_result="The first learner-visible service is reachable after provider startup.",
    )


def attacker_step(entrypoints: list[PlaytestEndpoint]) -> PlaytestStep:
    if not entrypoints:
        return PlaytestStep(
            step_id="access-02",
            title="Attacker workstation access exists",
            status="warning",
            evidence=["No published attacker workstation endpoint was found."],
            learner_action="Use the declared learner entrypoint only; no attacker shell endpoint is available yet.",
            expected_result="Multi-stage labs should normally expose an attacker workstation SSH or web terminal.",
        )
    return PlaytestStep(
        step_id="access-02",
        title="Attacker workstation access exists",
        status="passed",
        evidence=[f"{item.service}: {item.connect}" for item in entrypoints],
        learner_action=f"Use attacker access at `{entrypoints[0].connect}` when the chain requires shell, tunneling, or callback handling.",
        expected_result="Learner has a controlled workstation for lab-contained tooling.",
    )


def vulnerability_runtime_step(runtime_smoke) -> PlaytestStep:
    if not runtime_smoke.items:
        return PlaytestStep(
            step_id="runtime-01",
            title="Runnable vulnerability behavior exists",
            status="warning",
            evidence=["No supported vulnerability plugin runtime smoke items were found."],
            learner_action="Inspect generated services and service blueprints; a service-builder result may still be required.",
            expected_result="At least one lab-scoped vulnerability behavior should be runnable for hands-on labs.",
        )
    failing = [item for item in runtime_smoke.items if item.status != "passed"]
    if failing:
        return PlaytestStep(
            step_id="runtime-01",
            title="Runnable vulnerability behavior exists",
            status="failed",
            evidence=[f"{item.service}:{item.plugin}:{item.status}:{item.message}" for item in failing],
            learner_action="Do not release the lab until failing plugin runtime behavior is fixed.",
            expected_result="All declared supported vulnerability plugin routes pass local Flask smoke tests.",
        )
    return PlaytestStep(
        step_id="runtime-01",
        title="Runnable vulnerability behavior exists",
        status="passed",
        evidence=[f"{item.service}:{item.plugin}:{item.endpoint}" for item in runtime_smoke.items],
        learner_action="Use the service's normal UI/API to discover the lab-scoped weakness, then validate the behavior.",
        expected_result="Supported vulnerability plugins are runnable without reading source code.",
    )


def evidence_unlock_step(runtime_smoke) -> PlaytestStep:
    plugin_items = [item for item in runtime_smoke.items if item.plugin != "service-contract"]
    if not plugin_items:
        return PlaytestStep(
            step_id="runtime-02",
            title="Vulnerability behavior emits stage evidence",
            status="warning",
            evidence=["No supported vulnerability plugin runtime smoke items were found for evidence verification."],
            learner_action="Add supported vulnerability plugins or service-builder implementations for evidence-driven stages.",
            expected_result="At least one exploited behavior should emit lab-wide evidence and unlock a later stage.",
        )
    failing = [item for item in plugin_items if item.status == "passed" and not item.emitted_evidence]
    if failing:
        return PlaytestStep(
            step_id="runtime-02",
            title="Vulnerability behavior emits stage evidence",
            status="warning",
            evidence=[f"{item.service}:{item.plugin} emitted no evidence" for item in failing],
            learner_action="Connect the vulnerable route success path to stage evidence emission.",
            expected_result="Successful vulnerability scaffolds should update shared stage-state evidence.",
        )
    status: PlaytestStatus = "passed"
    evidence = [
        f"{item.service}:{item.plugin} evidence={','.join(item.emitted_evidence) or '-'} unlocked={','.join(item.unlocked_stages) or '-'}"
        for item in plugin_items
    ]
    return PlaytestStep(
        step_id="runtime-02",
        title="Vulnerability behavior emits stage evidence",
        status=status,
        evidence=evidence,
        learner_action="Exercise vulnerable routes and confirm `/api/state` changes as evidence is collected.",
        expected_result="At least one vulnerable route emits evidence, and complete evidence sets unlock dependent stages.",
    )


def scenario_stage_step(spec: LabSpec, chain_manifest=None) -> PlaytestStep:
    manifest = chain_manifest or build_chain_manifest(spec)
    stages = spec.stage_list
    if manifest.status == "failed":
        return PlaytestStep(
            step_id="chain-01",
            title="Scenario has a connected multi-stage learner chain",
            status="failed",
            evidence=manifest.failures or ["Stage chain manifest failed."],
            learner_action="Scenario designer must define connected stages before release.",
            expected_result="A hands-on lab should include ordered stage links and evidence carried between stages.",
        )
    if manifest.status == "warning":
        return PlaytestStep(
            step_id="chain-01",
            title="Scenario has a connected multi-stage learner chain",
            status="warning",
            evidence=manifest.warnings,
            learner_action="Review stage-chain/stage-chain.md and resolve weak service mappings or missing carried evidence.",
            expected_result="Each stage should declare or infer inputs, outputs, touched services, and the next stage.",
        )
    return PlaytestStep(
        step_id="chain-01",
        title="Scenario has a connected multi-stage learner chain",
        status="passed",
        evidence=[f"{len(stages)} stages declared.", f"{len(manifest.links)} links generated."],
        learner_action="Follow the stages in the student guide or generated learner-access report.",
        expected_result="The scenario can be reviewed as an ordered learner path with carried evidence.",
    )


def service_realism_step(spec: LabSpec, working_lab: Path) -> PlaytestStep:
    checked = 0
    failures: list[str] = []
    warnings: list[str] = []
    for artifact in declared_service_artifacts(spec):
        service = str(artifact.service)
        lower = service.lower()
        if any(token in lower for token in ("attacker", "workstation", "control-", "drop")):
            continue
        checked += 1
        root = working_lab / artifact.source_path
        expected = [root / "seed" / "records.json", root / "seed" / "clues.json", root / "noise" / "events.jsonl"]
        absent = [path.relative_to(root).as_posix() for path in expected if not path.exists()]
        if absent:
            failures.append(f"{service}: missing {', '.join(absent)}")
            continue
        result = inspect_business_seed_quality(artifact, root)
        failures.extend(result["failures"])
        warnings.extend(result["warnings"])
    if checked == 0:
        return PlaytestStep(
            step_id="realism-01",
            title="Services include business records, clues, and operational noise",
            status="warning",
            evidence=["No business services were eligible for seed/noise realism checks."],
            learner_action="Review generated services manually.",
            expected_result="Business services should include seed records, clues, and operational noise.",
        )
    if failures:
        return PlaytestStep(
            step_id="realism-01",
            title="Services include business records, clues, and operational noise",
            status="failed",
            evidence=failures,
            learner_action="Do not release the lab until business services include realistic seed/noise artifacts.",
            expected_result="Every business service has parseable, non-empty, business-shaped records, clues, and operational noise.",
        )
    if warnings:
        return PlaytestStep(
            step_id="realism-01",
            title="Services include business records, clues, and operational noise",
            status="warning",
            evidence=warnings,
            learner_action="Review seed records, clues, and noise so each service feels like a real business system.",
            expected_result="Business seed data should carry enough context for natural discovery without CTF wording.",
        )
    return PlaytestStep(
        step_id="realism-01",
        title="Services include business records, clues, and operational noise",
        status="passed",
        evidence=[f"{checked} business services include parseable business records, clues, and operational noise."],
        learner_action="Use visible business records and operational notes to distinguish signal from ordinary company context.",
        expected_result="Generated services feel like business systems rather than empty CTF endpoints.",
    )


def inspect_business_seed_quality(artifact: Any, root: Path) -> dict[str, list[str]]:
    service = str(artifact.service)
    failures: list[str] = []
    warnings: list[str] = []
    records_path = root / "seed" / "records.json"
    clues_path = root / "seed" / "clues.json"
    events_path = root / "noise" / "events.jsonl"

    records, record_error = load_seed_items(records_path, key="items")
    clues, clue_error = load_seed_items(clues_path, key="items")
    events, event_error = load_jsonl_items(events_path)
    for label, error in (("records", record_error), ("clues", clue_error), ("events", event_error)):
        if error:
            failures.append(f"{service}: {label} seed is invalid: {error}")

    if not record_error and len(records) < 2:
        failures.append(f"{service}: seed/records.json must contain at least 2 business records")
    if not record_error:
        shape = business_record_shape_findings(service, records)
        failures.extend(shape["failures"])
        warnings.extend(shape["warnings"])
    if not clue_error and len(clues) < 2:
        failures.append(f"{service}: seed/clues.json must contain at least 2 discovery or operating clues")
    if not clue_error:
        shape = clue_record_shape_findings(service, clues)
        failures.extend(shape["failures"])
        warnings.extend(shape["warnings"])
    if not event_error and len(events) < 2:
        failures.append(f"{service}: noise/events.jsonl must contain at least 2 operational events")
    if not event_error:
        shape = noise_event_shape_findings(service, events)
        failures.extend(shape["failures"])
        warnings.extend(shape["warnings"])

    text_by_file = {
        "seed/records.json": safe_read_text(records_path),
        "seed/clues.json": safe_read_text(clues_path),
        "noise/events.jsonl": safe_read_text(events_path),
    }
    for filename, text in text_by_file.items():
        bad_terms = ctf_or_placeholder_terms(text)
        if bad_terms:
            failures.append(f"{service}: {filename} contains CTF/placeholder wording: {', '.join(bad_terms)}")
        if not contains_service_context(text, artifact):
            warnings.append(f"{service}: {filename} does not clearly reference the service, purpose, seed inputs, or noise inputs")

    clue_text = " ".join(json.dumps(item, ensure_ascii=False) for item in clues)
    if not any(term in clue_text.lower() for term in ("review", "workflow", "record", "event", "route", "operation", "audit")):
        warnings.append(f"{service}: clues do not look like natural operating guidance")

    return {"failures": failures, "warnings": warnings}


def business_record_shape_findings(service: str, records: list[Any]) -> dict[str, list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    dict_records = [item for item in records if isinstance(item, dict)]
    if len(dict_records) != len(records):
        failures.append(f"{service}: seed/records.json business records must be JSON objects")
        return {"failures": failures, "warnings": warnings}
    if not dict_records:
        return {"failures": failures, "warnings": warnings}
    key_union = {str(key) for item in dict_records for key in item}
    if len(key_union) < 5:
        failures.append(f"{service}: seed/records.json records are too thin; expected at least 5 business fields")
    if not any(key in key_union for key in ("id", "record_id", "case_id", "ticket_id", "object_key", "name", "title")):
        failures.append(f"{service}: seed/records.json records lack an identifier field")
    if not any(key in key_union for key in ("type", "category", "workflow", "dataset", "event")):
        warnings.append(f"{service}: seed/records.json records lack a type/category/workflow field")
    if not any(key in key_union for key in ("status", "state", "severity", "decision")):
        warnings.append(f"{service}: seed/records.json records lack a status/state/severity field")
    if not any(key in key_union for key in ("owner", "team", "assignee", "source", "source_service")):
        warnings.append(f"{service}: seed/records.json records lack an owner/team/source field")
    if len(dict_records) >= 3 and not has_record_value_variety(dict_records, ("type", "category", "status", "state", "owner", "team")):
        warnings.append(f"{service}: seed/records.json records have low business value variety")
    return {"failures": failures, "warnings": warnings}


def clue_record_shape_findings(service: str, clues: list[Any]) -> dict[str, list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    dict_clues = [item for item in clues if isinstance(item, dict)]
    if len(dict_clues) != len(clues):
        failures.append(f"{service}: seed/clues.json clue records must be JSON objects")
        return {"failures": failures, "warnings": warnings}
    for index, clue in enumerate(dict_clues, start=1):
        title = str(clue.get("title") or clue.get("name") or "").strip()
        detail = str(clue.get("detail") or clue.get("description") or clue.get("operator_note") or "").strip()
        if not title or len(detail) < 24:
            warnings.append(f"{service}: seed/clues.json item {index} should include a title and detailed operating clue")
    return {"failures": failures, "warnings": warnings}


def noise_event_shape_findings(service: str, events: list[Any]) -> dict[str, list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    dict_events = [item for item in events if isinstance(item, dict)]
    if len(dict_events) != len(events):
        failures.append(f"{service}: noise/events.jsonl events must be JSON objects")
        return {"failures": failures, "warnings": warnings}
    key_union = {str(key) for item in dict_events for key in item}
    if dict_events and not any(key in key_union for key in ("event", "action", "workflow")):
        failures.append(f"{service}: noise/events.jsonl events lack an event/action/workflow field")
    if dict_events and not any(key in key_union for key in ("severity", "level", "status")):
        warnings.append(f"{service}: noise/events.jsonl events lack severity/level/status context")
    if len(dict_events) >= 3 and not has_record_value_variety(dict_events, ("event", "action", "severity", "source")):
        warnings.append(f"{service}: noise/events.jsonl events have low operational variety")
    return {"failures": failures, "warnings": warnings}


def has_record_value_variety(records: list[dict], fields: tuple[str, ...]) -> bool:
    values: set[str] = set()
    for record in records:
        for field in fields:
            value = str(record.get(field, "")).strip()
            if value:
                values.add(f"{field}:{value}")
    return len(values) >= 3


def load_seed_items(path: Path, *, key: str) -> tuple[list[Any], str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [], f"{path.name} is not valid JSON: {exc.msg}"
    except OSError as exc:
        return [], str(exc)
    if isinstance(data, dict):
        items = data.get(key)
        if isinstance(items, list):
            return items, ""
        return [], f"{path.name} must contain a `{key}` list"
    if isinstance(data, list):
        return data, ""
    return [], f"{path.name} must be a JSON object or list"


def load_jsonl_items(path: Path) -> tuple[list[Any], str]:
    items: list[Any] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [], str(exc)
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError as exc:
            return [], f"{path.name}:{index} is not valid JSON: {exc.msg}"
    return items, ""


def safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def ctf_or_placeholder_terms(text: str) -> list[str]:
    lowered = text.lower()
    terms = [
        "todo",
        "lorem",
        "placeholder",
        "answer key",
        "copy paste",
        "copy/paste",
        "submit flag",
        "\"flag\"",
        "ctf",
        "pwn",
        "exploit here",
    ]
    return [term for term in terms if term in lowered]


def contains_service_context(text: str, artifact: Any) -> bool:
    lowered = text.lower()
    candidates: list[str] = []
    candidates.append(str(artifact.service).lower())
    candidates.extend(str(artifact.service).lower().replace("-", " ").split())
    candidates.extend(str(artifact.service).lower().split("-"))
    candidates.extend(str(artifact.purpose).lower().replace("/", " ").split())
    for value in list(getattr(artifact, "seed_inputs", []) or []) + list(getattr(artifact, "noise_inputs", []) or []):
        candidates.extend(str(value).lower().replace("-", " ").split())
        candidates.append(str(value).lower())
    meaningful = {item.strip(".,:_/") for item in candidates if len(item.strip(".,:_/")) >= 4}
    return any(term in lowered for term in meaningful)


def industry_context_step(spec: LabSpec) -> PlaytestStep:
    coverage = check_industry_context(spec)
    if coverage.status == "failed":
        return PlaytestStep(
            step_id="industry-01",
            title="Stages and services reflect the declared industry",
            status="failed",
            evidence=[finding.message for finding in coverage.findings] or ["Industry context coverage failed."],
            learner_action="Do not release the lab until industry-specific services, records, and stage clues are present.",
            expected_result="A learner should feel they are operating inside the declared business environment.",
        )
    if coverage.status == "warning":
        return PlaytestStep(
            step_id="industry-01",
            title="Stages and services reflect the declared industry",
            status="warning",
            evidence=[finding.message for finding in coverage.findings],
            learner_action="Review stage text, service names, seed records, and noise for industry-specific realism gaps.",
            expected_result="The lab should not feel like generic vulnerable services renamed after the target industry.",
        )
    evidence = [f"covered={', '.join(coverage.covered_capabilities) or '-'}"]
    if coverage.service_evidence:
        evidence.append(f"service_context={len(coverage.service_evidence)} capability group(s)")
    if coverage.stage_evidence:
        evidence.append(f"stage_context={len(coverage.stage_evidence)} capability group(s)")
    return PlaytestStep(
        step_id="industry-01",
        title="Stages and services reflect the declared industry",
        status="passed",
        evidence=evidence,
        learner_action="Use industry-specific service names, records, and operational clues as the normal discovery path.",
        expected_result="The learner path is embedded in realistic business context for the declared industry.",
    )


def stage_implementation_coverage_step(spec: LabSpec, chain_manifest) -> PlaytestStep:
    artifact_by_service = {str(artifact.service): artifact for artifact in declared_service_artifacts(spec)}
    plugin_evidence_by_service: dict[str, set[str]] = {}
    plugin_ids_by_service: dict[str, list[str]] = {}
    has_declared_plugins = False
    for service, artifact in artifact_by_service.items():
        for plugin in declared_vulnerability_plugins(artifact):
            has_declared_plugins = True
            plugin_id = str(plugin.get("id", "")).strip()
            if plugin_id:
                plugin_ids_by_service.setdefault(service, []).append(plugin_id)
            evidence_values = plugin.get("emits_evidence") or plugin.get("evidence") or plugin.get("produces") or []
            if isinstance(evidence_values, str):
                values = [evidence_values]
            else:
                values = [str(item) for item in evidence_values if str(item).strip()]
            if values:
                plugin_evidence_by_service.setdefault(service, set()).update(values)

    evidence_sources = list(getattr(chain_manifest, "evidence_runtime_sources", []) or [])
    required_unmapped_sources = [
        source
        for source in evidence_sources
        if getattr(source, "status", "") == "unmapped" and getattr(source, "required_by_stages", [])
    ]
    source_counts: dict[str, int] = {}
    for source in evidence_sources:
        source_counts[str(getattr(source, "status", "unknown"))] = source_counts.get(str(getattr(source, "status", "unknown")), 0) + 1

    covered: list[str] = []
    gaps: list[str] = []
    hard_gaps: list[str] = []
    if has_declared_plugins:
        for source in required_unmapped_sources:
            hard_gaps.append(
                f"{source.producer_stage}: evidence `{source.evidence}` is required by "
                f"{', '.join(source.required_by_stages)}, but has no plugin emitter or runtime evidence path"
            )
    for node in chain_manifest.nodes:
        stage_services = [service for service in node.services if service]
        artifact_services = [service for service in stage_services if service in artifact_by_service]
        final_services = [service for service in stage_services if any(token in service.lower() for token in ("drop", "submit", "controlled"))]
        if final_services:
            covered.append(f"{node.stage_id}: final submission via {', '.join(final_services)}")
            continue
        if not artifact_services:
            gaps.append(f"{node.stage_id}: no generated service artifact is mapped to services {stage_services or ['-']}")
            continue
        produced = set(node.produces)
        emitted = set().union(*(plugin_evidence_by_service.get(service, set()) for service in artifact_services))
        if produced and produced.intersection(emitted):
            matched = sorted(produced.intersection(emitted))
            covered.append(f"{node.stage_id}: plugin evidence {', '.join(matched[:3])}")
            continue
        tactic = node.tactic.lower()
        if produced and any(term in tactic for term in ("discovery", "collection")):
            covered.append(f"{node.stage_id}: service runtime context on {', '.join(artifact_services)}")
            continue
        if plugin_ids_by_service.get(artifact_services[0]):
            gaps.append(
                f"{node.stage_id}: service {artifact_services[0]} has plugins "
                f"{', '.join(plugin_ids_by_service[artifact_services[0]])}, but none emit this stage evidence {sorted(produced) or ['-']}"
            )
        else:
            gaps.append(f"{node.stage_id}: mapped service {artifact_services[0]} has no vulnerability plugin or explicit runtime evidence path")

    if not chain_manifest.nodes:
        return PlaytestStep(
            step_id="implementation-01",
            title="Scenario stages map to generated implementation paths",
            status="failed",
            evidence=["No stage-chain nodes were generated."],
            learner_action="Define scenario stages before implementation.",
            expected_result="Every stage has a concrete generated service, vulnerability behavior, or final endpoint.",
        )
    if hard_gaps:
        return PlaytestStep(
            step_id="implementation-01",
            title="Scenario stages map to generated implementation paths",
            status="failed",
            evidence=[
                *hard_gaps,
                f"evidence_runtime_sources={format_evidence_source_counts(source_counts)}",
            ],
            learner_action="Do not release the lab until every carried stage evidence is emitted by a generated vulnerability behavior, runtime evidence path, or final endpoint.",
            expected_result="A learner should never reach a later stage that waits for evidence no runtime can produce.",
        )
    if gaps:
        return PlaytestStep(
            step_id="implementation-01",
            title="Scenario stages map to generated implementation paths",
            status="warning",
            evidence=gaps,
            learner_action="Review unimplemented stage gaps before claiming the lab is end-to-end playable.",
            expected_result="Every stage should be backed by generated service context, emitted evidence, or final submission behavior.",
        )
    return PlaytestStep(
        step_id="implementation-01",
        title="Scenario stages map to generated implementation paths",
        status="passed",
        evidence=[
            *(covered or ["All stages have implementation coverage."]),
            f"evidence_runtime_sources={format_evidence_source_counts(source_counts)}",
        ],
        learner_action="Proceed through the generated service runtimes and plugin behaviors in stage order.",
        expected_result="The scenario path is not merely documented; it is mapped to runnable generated components.",
    )


def format_evidence_source_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "-"
    ordered = ["plugin-backed", "runtime-backed", "final-only", "unmapped"]
    parts = [f"{key}:{counts[key]}" for key in ordered if key in counts]
    parts.extend(f"{key}:{value}" for key, value in sorted(counts.items()) if key not in ordered)
    return ", ".join(parts)


def service_chain_runtime_step(spec: LabSpec, working_lab: Path, chain_manifest) -> PlaytestStep:
    checked = 0
    missing: list[str] = []
    weak: list[str] = []
    stages_by_service: dict[str, int] = {}
    for node in chain_manifest.nodes:
        for service in node.services:
            stages_by_service[service] = stages_by_service.get(service, 0) + 1

    for artifact in declared_service_artifacts(spec):
        service = str(artifact.service)
        lower = service.lower()
        if any(token in lower for token in ("attacker", "workstation")):
            continue
        checked += 1
        root = working_lab / artifact.source_path
        path = root / "seed" / "chain.json"
        state_path = root / "seed" / "stage-state.json"
        if not path.exists():
            missing.append(f"{service}: missing seed/chain.json")
            continue
        if not state_path.exists():
            missing.append(f"{service}: missing seed/stage-state.json")
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            missing.append(f"{service}: chain/state seed is not valid JSON")
            continue
        if data.get("service") != service:
            missing.append(f"{service}: seed/chain.json service mismatch")
        if state.get("state_scope") != "shared":
            missing.append(f"{service}: seed/stage-state.json is not marked as shared state")
        if state.get("local_service") != service:
            missing.append(f"{service}: seed/stage-state.json local_service mismatch")
        if "acquired_evidence" not in state or "stages" not in state:
            missing.append(f"{service}: seed/stage-state.json missing evidence state fields")
        expected_stages = stages_by_service.get(service, 0)
        actual_stages = int(data.get("stage_count") or 0)
        if expected_stages and actual_stages < expected_stages:
            weak.append(f"{service}: expected {expected_stages} related stages, found {actual_stages}")
        if expected_stages and not data.get("stages"):
            weak.append(f"{service}: related stages are empty")

    if checked == 0:
        return PlaytestStep(
            step_id="chain-runtime-01",
            title="Service runtimes carry stage-chain context",
            status="warning",
            evidence=["No service artifacts were eligible for chain runtime checks."],
            learner_action="Review generated service runtimes manually.",
            expected_result="Generated services should carry local stage-chain context for natural learner discovery.",
        )
    if missing:
        return PlaytestStep(
            step_id="chain-runtime-01",
            title="Service runtimes carry stage-chain context",
            status="failed",
            evidence=missing,
            learner_action="Regenerate or materialize service runtimes before release.",
            expected_result="Every generated runtime has seed/chain.json and seed/stage-state.json.",
        )
    if weak:
        return PlaytestStep(
            step_id="chain-runtime-01",
            title="Service runtimes carry stage-chain context",
            status="warning",
            evidence=weak,
            learner_action="Review stage-to-service mapping and service chain seed files.",
            expected_result="Services touched by scenario stages should expose related workflow context.",
        )
    return PlaytestStep(
        step_id="chain-runtime-01",
        title="Service runtimes carry stage-chain context",
        status="passed",
        evidence=[f"{checked} services include chain context and evidence state seeds."],
        learner_action="Use each service's Chain Context endpoint or UI panel to understand related workflow evidence.",
        expected_result="Learners can discover how evidence from one service leads to the next stage without reading source code.",
    )


def final_submission_step(endpoints: list[PlaytestEndpoint]) -> PlaytestStep:
    if not endpoints:
        return PlaytestStep(
            step_id="final-01",
            title="Final controlled submission endpoint exists",
            status="warning",
            evidence=["No published controlled-drop or submission endpoint was found."],
            learner_action="Collect the final object, but supervisor must define how proof is submitted.",
            expected_result="Hands-on labs should expose a controlled drop or equivalent final proof service.",
        )
    return PlaytestStep(
        step_id="final-01",
        title="Final controlled submission endpoint exists",
        status="passed",
        evidence=[f"{item.service}: {item.connect}" for item in endpoints],
        learner_action=f"Submit final proof to `{endpoints[0].connect}`.",
        expected_result="The learner has a clear, lab-contained completion point.",
    )


def plugin_walkthrough_steps(spec: LabSpec, runtime_smoke) -> list[PlaytestStep]:
    smoke_by_plugin = {(item.service, item.plugin): item for item in runtime_smoke.items}
    handoffs = plugin_handoff_context(spec)
    steps: list[PlaytestStep] = []
    for artifact in declared_service_artifacts(spec):
        for plugin in declared_vulnerability_plugins(artifact):
            plugin_id = str(plugin.get("id", ""))
            smoke = smoke_by_plugin.get((artifact.service, plugin_id))
            status: PlaytestStatus = "passed" if smoke and smoke.status == "passed" else "warning"
            guidance = guidance_for_plugin(plugin_id, artifact.service)
            handoff = handoffs.get((artifact.service, plugin_id), {})
            discovery_cues = [*guidance["discovery_cues"], *handoff.get("discovery_cues", [])]
            next_step_condition = handoff.get("next_step_condition") or guidance["next_step_condition"]
            steps.append(
                PlaytestStep(
                    step_id=f"plugin-{artifact.service}-{plugin_id}".replace("_", "-"),
                    title=f"{artifact.service}: {plugin_id}",
                    status=status,
                    evidence=plugin_walkthrough_evidence(smoke),
                    learner_action=guidance["learner_action"],
                    expected_result=guidance["expected_result"],
                    discovery_cues=discovery_cues,
                    next_step_condition=next_step_condition,
                )
            )
    return steps


def plugin_walkthrough_evidence(smoke) -> list[str]:
    if not smoke:
        return ["No runtime smoke evidence for this plugin."]
    evidence = [smoke.endpoint]
    emitted = [str(item) for item in getattr(smoke, "emitted_evidence", []) or [] if str(item).strip()]
    unlocked = [str(item) for item in getattr(smoke, "unlocked_stages", []) or [] if str(item).strip()]
    if emitted:
        evidence.append(f"emitted_evidence={','.join(emitted)}")
    if unlocked:
        evidence.append(f"unlocked_stages={','.join(unlocked)}")
    return evidence


def plugin_handoff_context(spec: LabSpec) -> dict[tuple[str, str], dict[str, Any]]:
    occurrences = declared_plugin_occurrences(spec)
    by_plugin = {plugin: service for service, plugin in occurrences}
    context: dict[tuple[str, str], dict[str, Any]] = {}
    for index, plugin in enumerate(TRUSTED_UPDATE_CHAIN):
        service = by_plugin.get(plugin)
        if not service:
            continue
        previous_plugin = TRUSTED_UPDATE_CHAIN[index - 1] if index > 0 else ""
        next_plugin = TRUSTED_UPDATE_CHAIN[index + 1] if index + 1 < len(TRUSTED_UPDATE_CHAIN) else ""
        cues: list[str] = []
        if previous_plugin and previous_plugin in by_plugin:
            cues.append(f"Use evidence produced by `{previous_plugin}` on `{by_plugin[previous_plugin]}` as input to this workflow.")
        if next_plugin and next_plugin in by_plugin:
            cues.append(f"This workflow should produce handoff material for `{next_plugin}` on `{by_plugin[next_plugin]}`.")
        next_condition = ""
        if next_plugin and next_plugin in by_plugin:
            next_condition = f"Proceed when `{plugin}` produces data that `{next_plugin}` can consume on `{by_plugin[next_plugin]}`."
        elif plugin == TRUSTED_UPDATE_CHAIN[-1]:
            next_condition = "Proceed when customer-side update state exposes the controlled final object or proof for submission."
        context[(service, plugin)] = {
            "discovery_cues": cues,
            "next_step_condition": next_condition,
        }
    return context


def declared_plugin_occurrences(spec: LabSpec) -> list[tuple[str, str]]:
    occurrences: list[tuple[str, str]] = []
    for artifact in declared_service_artifacts(spec):
        for plugin in declared_vulnerability_plugins(artifact):
            plugin_id = str(plugin.get("id", "")).strip()
            if plugin_id:
                occurrences.append((artifact.service, plugin_id))
    return occurrences


def trusted_update_handoff_step(spec: LabSpec) -> PlaytestStep:
    occurrences = declared_plugin_occurrences(spec)
    by_plugin = {plugin: service for service, plugin in occurrences}
    present = [plugin for plugin in TRUSTED_UPDATE_CHAIN if plugin in by_plugin]
    if not present:
        return PlaytestStep(
            step_id="trusted-update-handoff-01",
            title="Trusted update handoff chain",
            status="passed",
            evidence=["No trusted-update plugin chain declared for this scenario."],
            learner_action="No supply-chain trusted update handoff is required for this scenario.",
            expected_result="Non-supply-chain scenarios are not forced into this chain.",
        )
    missing = [plugin for plugin in TRUSTED_UPDATE_CHAIN if plugin not in by_plugin]
    if missing:
        return PlaytestStep(
            step_id="trusted-update-handoff-01",
            title="Trusted update handoff chain",
            status="warning",
            evidence=[
                f"present={', '.join(present)}",
                f"missing={', '.join(missing)}",
            ],
            learner_action="Review whether the scenario needs a complete build, signing, and customer update sequence.",
            expected_result="Supply-chain scenarios should declare build, signed update, and customer callback/update stages when that chain is part of the objective.",
            discovery_cues=["A partial trusted-update sequence can make the lab feel like disconnected service exercises."],
            next_step_condition="Add the missing plugin stages or explicitly remove the trusted-update objective.",
        )
    evidence = [
        f"{plugin} on {by_plugin[plugin]}"
        for plugin in TRUSTED_UPDATE_CHAIN
    ]
    return PlaytestStep(
        step_id="trusted-update-handoff-01",
        title="Trusted update handoff chain",
        status="passed",
        evidence=evidence,
        learner_action="Follow the trusted update chain from build metadata to signed channel publish to customer-side update evidence.",
        expected_result="Each stage produces material that the next stage can consume without hidden magic values.",
        discovery_cues=[
            "Build output should include artifact and canonical manifest metadata.",
            "Publish should require a signed manifest, not just a raw artifact.",
            "Customer update state should change only after the trusted channel contains the signed manifest.",
        ],
        next_step_condition="Proceed to final submission only after customer-side update evidence exposes the controlled object or proof.",
    )


def guidance_for_plugin(plugin_id: str, service: str) -> dict[str, Any]:
    cues = {
        "ssti-preview": [
            "Start with normal merge fields or preview variables before testing expressions.",
            "A safe arithmetic probe should change only the rendered preview, not application state.",
            "If the renderer discloses context keys, use those names to reason about available business objects.",
        ],
        "stored-xss-review": [
            "Look for content that is submitted by one role and later reviewed by another role.",
            "Confirm storage first with harmless markup before attempting browser-driven behavior.",
            "The important observation is the reviewer context, not the submitter confirmation.",
        ],
        "idor-object-access": [
            "Start from the owner-filtered object catalog, then open the access review queue for the same requester.",
            "Use review cases, relationship links, and entitlement output to identify object IDs that the catalog hides.",
            "The useful signal is when direct detail access returns a reviewed object that entitlement would deny.",
        ],
        "jwt-role-confusion": [
            "Start from issued session and identity policy before changing token material.",
            "Use token preview to compare header, claims, and validation reason.",
            "Proceed only inside the lab-scoped identity boundary; privileged export is synthetic.",
        ],
        "sql-injection-reporting": [
            "Start from the reporting console, catalog, policy, and schema before testing crafted search text.",
            "Compare normal owner-scoped search results with edge-case query results.",
            "The useful signal is a controlled restricted report row and audit record, not host database access.",
        ],
        "ssrf-internal-fetch": [
            "Find why the business service fetches URLs server-side, such as import, preview, or integration checks.",
            "Use blocked target errors to learn policy boundaries.",
            "Internal service names should come from normal docs, route metadata, or previous stage evidence.",
        ],
        "path-traversal-download": [
            "Start from the public document index and inspect how filenames are passed.",
            "Compare normal public downloads with adjacent synthetic document folders.",
            "Stay inside the generated lab document boundary; host filesystem access is not required.",
        ],
        "unsafe-file-upload": [
            "Read the stated attachment policy and review workbench before relying on the upload response.",
            "Upload a policy-mismatched attachment, mark it through the review workflow, then compare review state with retrieval behavior.",
            "The useful signal is when a quarantined or policy-mismatched attachment remains retrievable through normal service routes.",
        ],
        "diagnostic-command-injection": [
            "Run normal diagnostics first to establish user, host, and network context.",
            "Blocked-token messages are containment clues, not dead ends.",
            "Use command effects only inside the generated lab boundary.",
        ],
        "credential-exposure": [
            "Review normal runtime configuration first; redacted secret references are operational clues, not final credentials.",
            "Correlate the secret reference with startup or vault-cache restore diagnostics.",
            "Use only synthetic lab credentials against declared downstream lab services.",
        ],
        "solr-velocity-rce": [
            "Start with the search operations page and system-info API to identify version, core, and response-writer clues.",
            "Enable the lab-scoped Velocity response writer before testing a harmless command.",
            "Use adjacent-service clues from bounded command output to continue the internal path.",
        ],
        "build-pipeline-abuse": [
            "Read build context before creating a job; it should name required fields.",
            "Use release metadata and patch references visible through normal workflow context.",
            "The next step starts when a build returns artifact and canonical manifest metadata.",
        ],
        "signed-update-publish": [
            "Sign the canonical manifest before publishing; raw artifacts should not be enough.",
            "Compare channel state before and after publish.",
            "The next step starts when the controlled update channel contains a signed manifest.",
        ],
        "customer-update-callback": [
            "Check customer status before polling to confirm the export is gated.",
            "After update application, inspect status and callback evidence before reading exports.",
            "The final object should become reachable only after trusted update state changes.",
        ],
    }
    next_conditions = {
        "ssti-preview": "Proceed when the preview renderer evaluates a benign expression and exposes enough context to identify the next internal workflow.",
        "stored-xss-review": "Proceed when stored content is opened in the reviewer or manager context and produces observable reviewer-side evidence.",
        "idor-object-access": "Proceed when the access review queue reveals a hidden object reference and direct access retrieves it despite failed entitlement.",
        "jwt-role-confusion": "Proceed when a lab-scoped role-confused token reaches the controlled privileged export and the audit trail records both denied and accepted admin export attempts.",
        "sql-injection-reporting": "Proceed when crafted report search text returns a controlled restricted synthetic row and the audit trail records restricted rows returned.",
        "ssrf-internal-fetch": "Proceed when an allowed server-side fetch reaches a lab-internal target and returns useful metadata.",
        "path-traversal-download": "Proceed when a controlled restricted document is read from the synthetic document workspace.",
        "unsafe-file-upload": "Proceed when a policy-mismatched attachment is reviewed or quarantined but remains retrievable through normal service routes.",
        "diagnostic-command-injection": "Proceed when diagnostic execution proves lab-contained command influence and returns host or service context.",
        "credential-exposure": "Proceed when configuration references and startup diagnostics reveal a synthetic credential or token for the next declared lab service.",
        "solr-velocity-rce": "Proceed when the legacy search service executes a bounded diagnostic command and reveals adjacent internal service reachability.",
        "build-pipeline-abuse": "Proceed when a build job returns artifact metadata and a canonical manifest for the next trust step.",
        "signed-update-publish": "Proceed when the signed manifest is published into the intended update channel.",
        "customer-update-callback": "Proceed when customer update state unlocks the controlled final object or callback proof.",
    }
    return {
        "learner_action": learner_action_for_plugin(plugin_id, service),
        "expected_result": expected_result_for_plugin(plugin_id),
        "discovery_cues": cues.get(plugin_id, ["Use normal business workflows first, then test edge-case behavior that matches the scenario stage."]),
        "next_step_condition": next_conditions.get(plugin_id, "Proceed when the service emits the stage evidence needed by the next workflow."),
    }


def learner_action_for_plugin(plugin_id: str, service: str) -> str:
    actions = {
        "ssti-preview": f"Use the normal preview or template-like workflow in `{service}` and test whether expressions are rendered server-side.",
        "stored-xss-review": f"Find a review, ticket, note, or approval workflow in `{service}` where submitted content is later opened by another role.",
        "idor-object-access": f"Use the object catalog and access review workflow in `{service}` to find hidden object references, then compare entitlement and direct detail behavior.",
        "jwt-role-confusion": f"Use the identity/session workflow in `{service}` to compare issued analyst tokens, token preview, and privileged export authorization behavior.",
        "sql-injection-reporting": f"Use the report search workflow in `{service}` to compare owner-scoped searches with crafted SQL-like search text.",
        "ssrf-internal-fetch": f"Find a URL fetch, webhook, import, preview, or integration workflow in `{service}` and test internal-only destinations.",
        "path-traversal-download": f"Find a document download route in `{service}` and test whether path normalization allows crossing into adjacent document folders.",
        "unsafe-file-upload": f"Use the upload and attachment review workflow in `{service}` to compare policy decisions, quarantine state, and retrieval behavior.",
        "diagnostic-command-injection": f"Find an operational diagnostic workflow in `{service}` and test whether user-controlled command fragments affect execution.",
        "credential-exposure": f"Find a runtime configuration or startup diagnostics workflow in `{service}` and correlate redacted secret references with cached diagnostic values.",
        "solr-velocity-rce": f"Find the legacy search admin workflow in `{service}`, inspect the Solr-like API, enable the Velocity writer, and run a bounded diagnostic command.",
        "build-pipeline-abuse": f"Find build job metadata and submit a lab-scoped build request through `{service}`.",
        "signed-update-publish": f"Use signing and publish workflows in `{service}` to move a trusted manifest through the lab update path.",
        "customer-update-callback": f"Observe the customer update or callback workflow in `{service}` and use the resulting metadata to reach the controlled object.",
    }
    return actions.get(plugin_id, f"Discover and validate the `{plugin_id}` behavior in `{service}`.")


def expected_result_for_plugin(plugin_id: str) -> str:
    results = {
        "ssti-preview": "A benign expression such as arithmetic is evaluated by the server-side renderer.",
        "stored-xss-review": "Submitted content is stored and rendered in a privileged or reviewer context.",
        "idor-object-access": "A controlled synthetic object from an access review queue can be accessed through an authorization flaw.",
        "jwt-role-confusion": "A lab-scoped token role confusion path unlocks a controlled synthetic privileged export and leaves an audit trail.",
        "sql-injection-reporting": "A crafted report search returns a controlled restricted synthetic row and leaves an audit trail.",
        "ssrf-internal-fetch": "Internal fetch behavior is observable while blocked destinations remain contained.",
        "path-traversal-download": "A controlled restricted synthetic document is reachable through traversal behavior.",
        "unsafe-file-upload": "A policy-mismatched learner file remains retrievable after review or quarantine metadata says it should not.",
        "diagnostic-command-injection": "A controlled diagnostic command path executes inside lab boundaries.",
        "credential-exposure": "A synthetic lab credential or token is discovered through realistic configuration and diagnostic log correlation.",
        "solr-velocity-rce": "A Solr-like legacy search API enables bounded Velocity template command execution inside the lab service.",
        "build-pipeline-abuse": "A build job returns artifact or manifest metadata usable by the next stage.",
        "signed-update-publish": "A signed manifest is accepted by the controlled update channel.",
        "customer-update-callback": "Customer update state unlocks a controlled final object or callback proof.",
    }
    return results.get(plugin_id, "The lab-scoped behavior produces evidence for the next stage.")


def render_playtest_markdown(report: PlaytestReport) -> str:
    lines = [
        f"# Learner Path Playtest - {report.title}",
        "",
        f"- Lab ID: `{report.lab_id}`",
        f"- Provider: `{report.provider}`",
        f"- Profile: `{report.profile}`",
        f"- Status: `{report.status}`",
        "",
        "## Access Summary",
        "",
        "### Learner Entrypoints",
        "",
        endpoint_table(report.learner_entrypoints),
        "",
        "### Attacker Workstation",
        "",
        endpoint_table(report.attacker_entrypoints),
        "",
        "### Final Submission",
        "",
        endpoint_table(report.final_submission_endpoints),
        "",
        "## Playtest Steps",
        "",
        "| Step | Status | Learner Action | Expected Result | Evidence |",
        "|---|---|---|---|---|",
    ]
    for step in report.steps:
        evidence = "<br>".join(escape_cell(item) for item in step.evidence) or "-"
        lines.append(
            f"| `{step.step_id}` {escape_cell(step.title)} | {step.status} | "
            f"{escape_cell(step.learner_action)} | {escape_cell(step.expected_result)} | {evidence} |"
        )
    lines.append("")
    if report.failures:
        lines += ["## Failures", "", *[f"- {item}" for item in report.failures], ""]
    if report.warnings:
        lines += ["## Warnings", "", *[f"- {item}" for item in report.warnings], ""]
    return "\n".join(lines)


def render_human_readiness_markdown(report: HumanReadinessReport) -> str:
    lines = [
        f"# Human Readiness - {report.title}",
        "",
        "This supervisor-facing report checks whether generated learner guidance is actionable without reading source code.",
        "",
        f"- Lab ID: `{report.lab_id}`",
        f"- Status: `{report.status}`",
        f"- Checks: `{report.summary.get('checks', len(report.checks))}`",
        f"- Passed: `{report.summary.get('passed', 0)}`",
        f"- Warning: `{report.summary.get('warning', 0)}`",
        f"- Failed: `{report.summary.get('failed', 0)}`",
        "",
        "| Check | Step | Status | Messages |",
        "|---|---|---|---|",
    ]
    for check in report.checks:
        messages = "<br>".join(escape_cell(message) for message in check.messages) or "-"
        lines.append(f"| `{check.check_id}` | `{check.step_id}` | `{check.status}` | {messages} |")
    lines.append("")
    return "\n".join(lines)


def render_learner_access_markdown(report: PlaytestReport) -> str:
    internal_targets = internal_targets_from_endpoint_manifest(load_endpoint_manifest(Path(report.output_dir) / "provider-output"))
    tunnel_commands = tunnel_commands_for_internal_targets(
        internal_targets,
        report.attacker_entrypoints,
        [*report.learner_entrypoints, *report.final_submission_endpoints],
    )
    lines = [
        f"# Learner Access - {report.title}",
        "",
        "This file lists the generated learner-facing access points and the high-level learner path.",
        "It is safe to share with supervisors. Student-facing release may require redaction of expected results.",
        "",
        "## Quick Connect",
        "",
        "| Purpose | Service | Command or URL |",
        "|---|---|---|",
    ]
    if report.learner_entrypoints:
        for endpoint in report.learner_entrypoints:
            lines.append(f"| Browser start | `{endpoint.service}` | `{endpoint.connect}` |")
    if report.attacker_entrypoints:
        for endpoint in report.attacker_entrypoints:
            lines.append(f"| Terminal access | `{endpoint.service}` | `{endpoint.connect}` |")
    if report.final_submission_endpoints:
        for endpoint in report.final_submission_endpoints:
            lines.append(f"| Final submission | `{endpoint.service}` | `{endpoint.connect}` |")
    if not (report.learner_entrypoints or report.attacker_entrypoints or report.final_submission_endpoints):
        lines.append("| - | - | No generated learner access points. |")
    lines += [
        "",
        "## Start Here",
        "",
    ]
    if report.learner_entrypoints:
        for endpoint in report.learner_entrypoints:
            lines.append(f"- `{endpoint.service}`: `{endpoint.connect}`")
            if endpoint.health_url:
                lines.append(f"  - Health: `{endpoint.health_url}`")
    else:
        lines.append("- No learner-visible endpoint was generated.")
    lines += ["", "## Attacker Workstation", ""]
    if report.attacker_entrypoints:
        lines.extend(f"- `{endpoint.service}`: `{endpoint.connect}`" for endpoint in report.attacker_entrypoints)
    else:
        lines.append("- No attacker workstation endpoint was generated.")
    lines += ["", "## Final Submission", ""]
    if report.final_submission_endpoints:
        lines.extend(f"- `{endpoint.service}`: `{endpoint.connect}`" for endpoint in report.final_submission_endpoints)
    else:
        lines.append("- No final submission endpoint was generated.")
    lines += ["", "## Internal Targets", ""]
    if internal_targets:
        lines += [
            "These services are not directly opened on the learner host. They become reachable only from the right lab network, workstation, tunnel, pivot, or scenario-approved route.",
            "",
            internal_target_table(internal_targets),
        ]
    else:
        lines.append("- No internal-only targets were declared by the provider.")
    lines += ["", "## Suggested Internal Tunnels", ""]
    if tunnel_commands:
        lines += [
            "Run these commands from the learner host when the scenario path requires browser access to an internal service. Keep the SSH session open while using the local URL.",
            "",
            tunnel_command_table(tunnel_commands),
        ]
    else:
        lines.append("- No internal tunnel commands were generated.")
    health_lines = [
        f"- `{endpoint.service}`: `curl -i {endpoint.health_url}`"
        for endpoint in [*report.learner_entrypoints, *report.final_submission_endpoints]
        if endpoint.health_url
    ]
    lines += ["", "## Health Checks", ""]
    lines.extend(health_lines or ["- No HTTP health check URLs were generated."])
    sequence_lines = [
        f"- `{endpoint.service}`: `echo labforge-terminal-ready && pwd` via `{endpoint.connect}`"
        for endpoint in [*report.attacker_entrypoints, *report.learner_entrypoints]
        if endpoint.protocol == "ssh" and endpoint.connect
    ]
    lines += ["", "## Terminal Command Sequences", ""]
    lines.extend(sequence_lines or ["- No SSH terminal command sequence was generated."])
    lines += ["", "## High-Level Learner Path", ""]
    for step in report.steps:
        lines.append(f"- `{step.step_id}` {step.title}: {step.learner_action}")
    lines.append("")
    return "\n".join(lines)


def render_solver_plan_markdown(plan: SolverPlan) -> str:
    lines = [
        f"# Solver Plan - {plan.title}",
        "",
        "This supervisor-facing plan is machine-readable in `solver-plan.json` and is intended for automated playtest agents.",
        "It describes the ordered learner path without hard-coding a scenario-specific exploit script into the framework.",
        "",
        f"- Lab ID: `{plan.lab_id}`",
        f"- Provider: `{plan.provider}`",
        f"- Profile: `{plan.profile}`",
        f"- Status: `{plan.status}`",
        f"- Learner start: `{plan.learner_start or '-'}`",
        f"- Attacker shell: `{plan.attacker_shell or '-'}`",
        f"- Final submission: `{plan.final_submission or '-'}`",
        "",
        "## Ordered Steps",
        "",
        "| # | Type | Step | Service | Plugin | Learner Action | Discovery Cues | Next Condition | Expected Result | Automation Hint |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for step in plan.steps:
        lines.append(
            f"| {step.order} | `{step.action_type}` | `{step.step_id}` {escape_cell(step.title)} | "
            f"`{step.service or '-'}` | `{step.plugin or '-'}` | {escape_cell(step.learner_action)} | "
            f"{escape_cell('; '.join(step.discovery_cues) or '-')} | {escape_cell(step.next_step_condition or '-')} | "
            f"{escape_cell(step.expected_result)} | {escape_cell(step.automation_hint)} |"
        )
    if plan.warnings:
        lines += ["", "## Warnings", ""]
        lines.extend(f"- {warning}" for warning in plan.warnings)
    lines.append("")
    return "\n".join(lines)


def render_playtest_walkthrough_markdown(report: PlaytestReport) -> str:
    lines = [
        f"# Playtest Walkthrough - {report.title}",
        "",
        "This supervisor-facing walkthrough is generated from LabForge playtest evidence.",
        "It is intended to verify that a generated MVP has usable access points and lab-scoped runtime behavior.",
        "Do not publish it directly to learners unless the exercise is meant to include a full guided solution.",
        "",
        "## 1. Start the generated provider output",
        "",
        "From the generated provider directory:",
        "",
        "```powershell",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\start.ps1",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\status.ps1",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\services-healthcheck.ps1",
        "```",
        "",
        "On Linux, macOS, or WSL:",
        "",
        "```sh",
        "./scripts/start.sh",
        "./scripts/status.sh",
        "./scripts/services-healthcheck.sh",
        "```",
        "",
        "## 2. Open learner entrypoints",
        "",
    ]
    if report.learner_entrypoints:
        for endpoint in report.learner_entrypoints:
            lines.append(f"- `{endpoint.service}`: `{endpoint.connect}`")
            if endpoint.health_url:
                lines += ["", "```sh", f"curl -i {endpoint.health_url}", "```", ""]
    else:
        lines.append("- No learner-visible endpoint was generated.")
    lines += ["", "## 3. Connect to attacker workstation", ""]
    if report.attacker_entrypoints:
        for endpoint in report.attacker_entrypoints:
            lines += ["```sh", endpoint.connect, "```", ""]
    else:
        lines.append("- No attacker workstation endpoint was generated.")
    lines += [
        "",
        "## 4. Validate lab-scoped vulnerability behavior",
        "",
        "Use the normal UI first when available. For generated MVP scaffold verification, these are the behavior families the playtest found:",
        "",
    ]
    plugin_steps = [step for step in report.steps if step.step_id.startswith("plugin-")]
    if plugin_steps:
        for step in plugin_steps:
            lines += [
                f"### {step.title}",
                "",
                f"- Learner action: {step.learner_action}",
                f"- Discovery cues: {'; '.join(step.discovery_cues) if step.discovery_cues else '-'}",
                f"- Next step condition: {step.next_step_condition or '-'}",
                f"- Expected result: {step.expected_result}",
                f"- Evidence: {', '.join(step.evidence) if step.evidence else '-'}",
                "",
            ]
    else:
        lines.append("- No vulnerability plugin steps were detected.")
    lines += ["", "## 5. Complete final submission", ""]
    if report.final_submission_endpoints:
        for endpoint in report.final_submission_endpoints:
            lines.append(f"- Submit proof through `{endpoint.service}` at `{endpoint.connect}`.")
    else:
        lines.append("- No final submission endpoint was generated. Treat this as a release blocker for unguided labs.")
    lines += ["", "## 6. Stop or reset", "", "```powershell", "powershell -ExecutionPolicy Bypass -File .\\scripts\\stop.ps1", "```", "", "```sh", "./scripts/stop.sh", "```", ""]
    return "\n".join(lines)


def render_lab_access_bundle_markdown(bundle: LabAccessBundle) -> str:
    lines = [
        f"# Lab Access Bundle - {bundle.title}",
        "",
        "This supervisor-facing bundle is the compact handoff for starting, accessing, and playtesting the generated lab.",
        "",
        "## Summary",
        "",
        f"- Lab ID: `{bundle.lab_id}`",
        f"- Provider: `{bundle.provider}`",
        f"- Profile: `{bundle.profile}`",
        f"- Provider output: `{bundle.provider_output_dir}`",
        f"- Solver ready: `{str(bundle.solver_ready).lower()}`",
        "",
        "## Start Commands",
        "",
        command_table(bundle.start_commands),
        "",
        "## Access",
        "",
        "### Browser URLs",
        "",
    ]
    lines.extend(f"- `{url}`" for url in bundle.learner_urls or ["-"])
    lines += ["", "### Attacker SSH", ""]
    lines.extend(f"- `{command}`" for command in bundle.attacker_ssh or ["-"])
    lines += ["", "### Final Submission URLs", ""]
    lines.extend(f"- `{url}`" for url in bundle.final_submission_urls or ["-"])
    lines += ["", "### Published Endpoint Matrix", ""]
    if bundle.published_endpoints:
        lines.append(endpoint_table([PlaytestEndpoint.model_validate(item) for item in bundle.published_endpoints]))
    else:
        lines.append("No published endpoints declared.")
    lines += ["", "### Internal Targets", ""]
    if bundle.internal_targets:
        lines += [
            "These are provider-declared internal DNS targets. They are listed for supervisor/playtest context and require the scenario path to create reachability.",
            "",
            internal_target_table([InternalAccessTarget.model_validate(item) for item in bundle.internal_targets]),
        ]
    else:
        lines.append("- No internal targets declared.")
    lines += ["", "### Suggested Internal Tunnels", ""]
    if bundle.tunnel_commands:
        lines.append(tunnel_command_table([LearnerTunnelCommand.model_validate(item) for item in bundle.tunnel_commands]))
    else:
        lines.append("- No tunnel commands generated.")
    lines += ["", "## Health Commands", ""]
    lines.extend(f"- `{command}`" for command in bundle.health_commands or ["-"])
    lines += ["", "## Terminal Sequences", ""]
    if bundle.terminal_sequences:
        for sequence in bundle.terminal_sequences:
            commands = " && ".join(sequence.get("commands", []))
            expected = ", ".join(sequence.get("expected_texts", [])) or "-"
            lines.append(f"- `{sequence.get('service', '-')}` via `{sequence.get('connect', '-')}`: `{commands}`; expected `{expected}`")
    else:
        lines.append("- No terminal sequences generated.")
    lines += ["", "## Stage Handoffs", ""]
    if bundle.stage_handoffs:
        lines += [
            "| From | To | Carried Evidence | Learner Clue |",
            "|---|---|---|---|",
        ]
        for handoff in bundle.stage_handoffs:
            lines.append(
                f"| `{handoff.get('from_stage', '-')}` {escape_cell(handoff.get('from_title', ''))} | "
                f"`{handoff.get('to_stage', '-')}` {escape_cell(handoff.get('to_title', ''))} | "
                f"{escape_cell(', '.join(handoff.get('carried_evidence', []) or ['-']))} | "
                f"{escape_cell(handoff.get('learner_clue', '-') or '-')} |"
            )
    else:
        lines.append("- No stage handoffs generated.")
    lines += ["", "## Stage Chain Runtime Checks", ""]
    if bundle.stage_chain_checks:
        lines += [
            "| Service | Chain URL | Stage | Expected Evidence | Expected Clue |",
            "|---|---|---|---|---|",
        ]
        for check in bundle.stage_chain_checks:
            lines.append(
                f"| `{check.get('service', '-')}` | `{check.get('chain_url', '-')}` | `{check.get('expected_stage', '-')}` | "
                f"{escape_cell(', '.join(check.get('expected_evidence', []) or ['-']))} | "
                f"{escape_cell(check.get('expected_clue', '-') or '-')} |"
            )
    else:
        lines.append("- No published stage-chain runtime checks generated.")
    lines += ["", "## Plugin Evidence Checks", ""]
    if bundle.plugin_checks:
        lines += [
            "| Step | Service | Plugin | Expected Evidence | State Verification |",
            "|---|---|---|---|---|",
        ]
        for check in bundle.plugin_checks:
            lines.append(
                f"| `{check.get('step_id', '-')}` | `{check.get('service', '-')}` | `{check.get('plugin', '-')}` | "
                f"{escape_cell(', '.join(check.get('expected_evidence', []) or ['-']))} | "
                f"{escape_cell(check.get('state_verification', '-'))} |"
            )
    else:
        lines.append("- No plugin evidence checks generated.")
    lines += ["", "## Status Commands", "", command_table(bundle.status_commands), "", "## Stop Commands", "", command_table(bundle.stop_commands), ""]
    lines += ["## Generated Evidence Files", ""]
    for label, path in bundle.generated_files.items():
        lines.append(f"- `{label}`: `{path}`")
    lines += ["", "## Notes", ""]
    lines.extend(f"- {note}" for note in bundle.notes)
    lines.append("")
    return "\n".join(lines)


def command_table(commands: list[dict[str, str]]) -> str:
    if not commands:
        return "No commands generated."
    lines = ["| Label | Shell | Command |", "|---|---|---|"]
    for command in commands:
        lines.append(f"| {escape_cell(command.get('label', '-'))} | `{command.get('shell', '-')}` | `{command.get('command', '-')}` |")
    return "\n".join(lines)


def endpoint_table(endpoints: list[PlaytestEndpoint]) -> str:
    if not endpoints:
        return "No endpoint was published."
    lines = ["| Service | Role | Protocol | Host | Host Port | Container Port | Connect | Health | Override |", "|---|---|---|---|---|---|---|---|---|"]
    for endpoint in endpoints:
        lines.append(
            f"| `{endpoint.service}` | {escape_cell(endpoint.role or '-')} | `{endpoint.protocol or '-'}` | "
            f"`{endpoint.host or '-'}` | `{endpoint.default_host_port or '-'}` | `{endpoint.container_port or '-'}` | "
            f"`{endpoint.connect or '-'}` | `{endpoint.health_url or '-'}` | `{endpoint.override_env or '-'}` |"
        )
    return "\n".join(lines)


def internal_target_table(targets: list[InternalAccessTarget]) -> str:
    if not targets:
        return "No internal targets were declared."
    lines = ["| Service | Role | DNS | Networks | Exposed Ports | Access Note |", "|---|---|---|---|---|---|"]
    for target in targets:
        lines.append(
            f"| `{target.service}` | {escape_cell(target.role or '-')} | `{target.dns or '-'}` | "
            f"{escape_cell(', '.join(target.networks) or '-')} | `{', '.join(target.expose) or '-'}` | "
            f"{escape_cell(target.access_note or target.access_scope)} |"
        )
    return "\n".join(lines)


def tunnel_command_table(commands: list[LearnerTunnelCommand]) -> str:
    if not commands:
        return "No tunnel commands were generated."
    lines = ["| Service | Internal Target | Local URL | Command | Note |", "|---|---|---|---|---|"]
    for command in commands:
        lines.append(
            f"| `{command.service}` | `{command.dns}:{command.internal_port}` | `{command.url or '-'}` | "
            f"`{command.command}` | {escape_cell(command.access_note)} |"
        )
    return "\n".join(lines)


def slugify(value: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "terminal"


def escape_cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")
