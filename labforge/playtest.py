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
from .render import build_lab
from .service_artifacts import declared_service_artifacts, materialize_service_runtimes
from .solver_runner import run_solver_plan
from .vulnerability_plugins import declared_vulnerability_plugins


PlaytestStatus = Literal["passed", "warning", "failed"]


class PlaytestModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class PlaytestEndpoint(PlaytestModel):
    service: str
    role: str = ""
    protocol: str = ""
    connect: str = ""
    health_url: str = ""
    networks: list[str] = Field(default_factory=list)
    expected_texts: list[str] = Field(default_factory=list)


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
    health_checks: list[LearnerAccessCheck] = Field(default_factory=list)
    terminal_checks: list[LearnerAccessCheck] = Field(default_factory=list)
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
        service_chain_runtime_step(spec, working_lab, chain_manifest),
        scenario_stage_step(spec, chain_manifest),
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
    access_manifest = build_learner_access_manifest(report, provider_out)
    write_text(out / "learner-access.json", access_manifest.model_dump_json(indent=2))
    write_text(out / "learner-access.md", render_learner_access_markdown(report))
    solver_plan = build_solver_plan(report)
    write_text(out / "solver-plan.json", solver_plan.model_dump_json(indent=2))
    write_text(out / "solver-plan.md", render_solver_plan_markdown(solver_plan))
    write_text(out / "playtest-walkthrough.md", render_playtest_walkthrough_markdown(report))
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
                networks=[str(network) for network in item.get("networks", [])],
                expected_texts=normalize_endpoint_expected_texts(item),
            )
        )
    return endpoints


def normalize_endpoint_expected_texts(item: dict[str, Any]) -> list[str]:
    values: list[str] = []
    single = str(item.get("expected_text", "")).strip()
    if single:
        values.append(single)
    raw_many = item.get("expected_texts", [])
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


def build_learner_access_manifest(report: PlaytestReport, provider_out: Path) -> LearnerAccessManifest:
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
        health_checks=health_checks,
        terminal_checks=terminal_checks,
        first_action=first_action,
        notes=[
            "Run start commands from the generated provider output directory.",
            "Use health checks to confirm HTTP services before manual or automated playtest.",
            "Use terminal checks for attacker workstation or SSH-based learner hosts.",
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
        elif step.step_id.startswith("realism-"):
            action_type = "realism-review"
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


def parse_plugin_step_id(step_id: str) -> tuple[str, str]:
    raw = step_id.removeprefix("plugin-")
    plugin_ids = [
        "customer-update-callback",
        "diagnostic-command-injection",
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
    if action_type == "realism-review":
        return "Inspect generated seed records, clues, and noise before automated browser solving."
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
    missing: list[str] = []
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
            missing.append(f"{service}: missing {', '.join(absent)}")
    if checked == 0:
        return PlaytestStep(
            step_id="realism-01",
            title="Services include business records, clues, and operational noise",
            status="warning",
            evidence=["No business services were eligible for seed/noise realism checks."],
            learner_action="Review generated services manually.",
            expected_result="Business services should include seed records, clues, and operational noise.",
        )
    if missing:
        return PlaytestStep(
            step_id="realism-01",
            title="Services include business records, clues, and operational noise",
            status="failed",
            evidence=missing,
            learner_action="Do not release the lab until business services include realistic seed/noise artifacts.",
            expected_result="Every business service has records.json, clues.json, and noise/events.jsonl.",
        )
    return PlaytestStep(
        step_id="realism-01",
        title="Services include business records, clues, and operational noise",
        status="passed",
        evidence=[f"{checked} business services include records, clues, and noise."],
        learner_action="Use visible business records and operational notes to distinguish signal from ordinary company context.",
        expected_result="Generated services feel like business systems rather than empty CTF endpoints.",
    )


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
    steps: list[PlaytestStep] = []
    for artifact in declared_service_artifacts(spec):
        for plugin in declared_vulnerability_plugins(artifact):
            plugin_id = str(plugin.get("id", ""))
            smoke = smoke_by_plugin.get((artifact.service, plugin_id))
            status: PlaytestStatus = "passed" if smoke and smoke.status == "passed" else "warning"
            guidance = guidance_for_plugin(plugin_id, artifact.service)
            steps.append(
                PlaytestStep(
                    step_id=f"plugin-{artifact.service}-{plugin_id}".replace("_", "-"),
                    title=f"{artifact.service}: {plugin_id}",
                    status=status,
                    evidence=[smoke.endpoint if smoke else "No runtime smoke evidence for this plugin."],
                    learner_action=guidance["learner_action"],
                    expected_result=guidance["expected_result"],
                    discovery_cues=guidance["discovery_cues"],
                    next_step_condition=guidance["next_step_condition"],
                )
            )
    return steps


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
            "Compare a filtered object list with direct object read URLs.",
            "Look for adjacent identifiers in metadata, logs, or workflow references.",
            "The useful signal is when direct access returns an object that the list view would hide.",
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
            "Read the stated attachment policy, then verify what the backend actually stores.",
            "Follow the returned retrieval URL or review route after upload.",
            "The next step is available when uploaded content is accepted and observable through the service.",
        ],
        "diagnostic-command-injection": [
            "Run normal diagnostics first to establish user, host, and network context.",
            "Blocked-token messages are containment clues, not dead ends.",
            "Use command effects only inside the generated lab boundary.",
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
        "idor-object-access": "Proceed when a controlled restricted object is retrieved through direct reference behavior.",
        "ssrf-internal-fetch": "Proceed when an allowed server-side fetch reaches a lab-internal target and returns useful metadata.",
        "path-traversal-download": "Proceed when a controlled restricted document is read from the synthetic document workspace.",
        "unsafe-file-upload": "Proceed when a learner-supplied attachment is stored and retrievable through normal service routes.",
        "diagnostic-command-injection": "Proceed when diagnostic execution proves lab-contained command influence and returns host or service context.",
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
        "idor-object-access": f"Compare object identifiers in `{service}` and test whether authorization follows the object owner or only the supplied identifier.",
        "ssrf-internal-fetch": f"Find a URL fetch, webhook, import, preview, or integration workflow in `{service}` and test internal-only destinations.",
        "path-traversal-download": f"Find a document download route in `{service}` and test whether path normalization allows crossing into adjacent document folders.",
        "unsafe-file-upload": f"Find an upload workflow in `{service}` and test how file type, storage path, and retrieval behavior are enforced.",
        "diagnostic-command-injection": f"Find an operational diagnostic workflow in `{service}` and test whether user-controlled command fragments affect execution.",
        "build-pipeline-abuse": f"Find build job metadata and submit a lab-scoped build request through `{service}`.",
        "signed-update-publish": f"Use signing and publish workflows in `{service}` to move a trusted manifest through the lab update path.",
        "customer-update-callback": f"Observe the customer update or callback workflow in `{service}` and use the resulting metadata to reach the controlled object.",
    }
    return actions.get(plugin_id, f"Discover and validate the `{plugin_id}` behavior in `{service}`.")


def expected_result_for_plugin(plugin_id: str) -> str:
    results = {
        "ssti-preview": "A benign expression such as arithmetic is evaluated by the server-side renderer.",
        "stored-xss-review": "Submitted content is stored and rendered in a privileged or reviewer context.",
        "idor-object-access": "A controlled synthetic object can be accessed through an authorization flaw.",
        "ssrf-internal-fetch": "Internal fetch behavior is observable while blocked destinations remain contained.",
        "path-traversal-download": "A controlled restricted synthetic document is reachable through traversal behavior.",
        "unsafe-file-upload": "A learner-supplied file is accepted and retrievable through the lab service.",
        "diagnostic-command-injection": "A controlled diagnostic command path executes inside lab boundaries.",
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


def render_learner_access_markdown(report: PlaytestReport) -> str:
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
    health_lines = [
        f"- `{endpoint.service}`: `curl -i {endpoint.health_url}`"
        for endpoint in [*report.learner_entrypoints, *report.final_submission_endpoints]
        if endpoint.health_url
    ]
    lines += ["", "## Health Checks", ""]
    lines.extend(health_lines or ["- No HTTP health check URLs were generated."])
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


def endpoint_table(endpoints: list[PlaytestEndpoint]) -> str:
    if not endpoints:
        return "No endpoint was published."
    lines = ["| Service | Role | Protocol | Connect | Health |", "|---|---|---|---|---|"]
    for endpoint in endpoints:
        lines.append(
            f"| `{endpoint.service}` | {escape_cell(endpoint.role or '-')} | `{endpoint.protocol or '-'}` | "
            f"`{endpoint.connect or '-'}` | `{endpoint.health_url or '-'}` |"
        )
    return "\n".join(lines)


def escape_cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")
