from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .access_playtest import (
    AccessPlaytestReport,
    BrowserProbeEngine,
    collect_process_output,
    parse_ssh_local_forward,
    run_access_playtest,
    ssh_tunnel_argv,
    wait_for_tcp_port,
)
from .doctor import HostDoctorReport, inspect_host, report_to_markdown
from .io import dump_yaml, write_text
from .provider_lifecycle import ProviderLifecycleResult, provider_lifecycle
from .solver_runner import SolverRunReport, run_solver_plan


class E2ESolverModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class E2ETunnelResult(E2ESolverModel):
    service: str = ""
    command: str = ""
    local_port: str = ""
    target: str = ""
    status: Literal["passed", "failed", "skipped"]
    message: str = ""
    stdout: str = ""
    stderr: str = ""


class E2ESolverReport(E2ESolverModel):
    provider: str
    mode: Literal["dry-run", "execute"]
    status: Literal["planned", "passed", "warning", "failed"]
    provider_output: str
    solver_plan: str
    access_manifest: str
    access_bundle: str = ""
    access_bundle_ready: bool = False
    access_bundle_findings: list[str] = Field(default_factory=list)
    execution_depth_findings: list[str] = Field(default_factory=list)
    host_preflight: dict = Field(default_factory=dict)
    preflight_ready: bool = False
    lifecycle: list[ProviderLifecycleResult] = Field(default_factory=list)
    persistent_tunnels: list[E2ETunnelResult] = Field(default_factory=list)
    access_playtest: AccessPlaytestReport | None = None
    solver_run: SolverRunReport | None = None
    execution_proof: dict = Field(default_factory=dict)
    cleanup_requested: bool = False
    next_actions: list[str] = Field(default_factory=list)


def run_e2e_solver(
    provider_output: Path,
    solver_plan: Path,
    access_manifest: Path,
    out: Path,
    *,
    provider: str = "docker-compose",
    execute: bool = False,
    cleanup: bool = False,
    timeout_seconds: int = 60,
    host_preflight: HostDoctorReport | None = None,
    browser_engine: BrowserProbeEngine = "http",
    execute_tunnels: bool = False,
) -> E2ESolverReport:
    provider_output = provider_output.resolve()
    solver_plan = solver_plan.resolve()
    access_manifest = access_manifest.resolve()
    out.mkdir(parents=True, exist_ok=True)
    host_preflight = host_preflight or inspect_host()
    host_preflight_data = host_preflight_to_dict(host_preflight)
    preflight_ready = provider_preflight_ready(host_preflight, provider)
    write_text(out / "host-preflight.md", report_to_markdown(host_preflight))
    write_text(out / "host-preflight.json", json.dumps(host_preflight_data, ensure_ascii=False, indent=2) + "\n")
    endpoint_manifest = provider_output / "endpoints.json"
    endpoint_manifest_arg = endpoint_manifest if endpoint_manifest.exists() else None
    access_bundle_path = access_manifest.parent / "lab-access-bundle.json"
    access_bundle_findings = validate_access_bundle(
        access_bundle_path,
        provider_output,
        solver_plan,
        access_manifest,
    )
    access_bundle_ready = bool(access_bundle_path.exists()) and not any(item.startswith("missing=") or item.startswith("mismatch=") for item in access_bundle_findings)
    lifecycle: list[ProviderLifecycleResult] = []
    if execute and not preflight_ready:
        lifecycle.append(
            ProviderLifecycleResult(
                provider=provider,
                action="validate",
                mode="execute",
                status="failed",
                output_dir=str(provider_output),
                message="Host preflight is not ready for this provider. Review host-preflight.md before executing lifecycle commands.",
            )
        )
        access_report = run_access_playtest(
            access_manifest,
            out / "access-playtest",
            execute=False,
            timeout_seconds=min(timeout_seconds, 15),
            browser_engine=browser_engine,
            execute_tunnels=False,
        )
        solver_report = run_solver_plan(
            solver_plan,
            out / "solver-run",
            access_manifest=access_manifest,
            endpoint_manifest=endpoint_manifest_arg,
            execute=False,
            timeout_seconds=min(timeout_seconds, 15),
        )
    else:
        lifecycle.append(
            provider_lifecycle(
                provider_output,
                provider=provider,
                action="validate",
                execute=execute,
                timeout_seconds=timeout_seconds,
            )
        )
        lifecycle.append(
            provider_lifecycle(
                provider_output,
                provider=provider,
                action="deploy",
                execute=execute,
                timeout_seconds=timeout_seconds,
            )
        )
        lifecycle.append(
            provider_lifecycle(
                provider_output,
                provider=provider,
                action="status",
                execute=execute,
                timeout_seconds=timeout_seconds,
            )
        )
        persistent_tunnels: list[E2ETunnelResult] = []
        persistent_tunnel_processes: list[subprocess.Popen] = []
        if execute and execute_tunnels:
            persistent_tunnels, persistent_tunnel_processes = start_persistent_tunnels(
                access_manifest,
                timeout_seconds=min(timeout_seconds, 15),
            )
        try:
            access_report = run_access_playtest(
                access_manifest,
                out / "access-playtest",
                execute=execute,
                timeout_seconds=min(timeout_seconds, 15),
                browser_engine=browser_engine,
                execute_tunnels=False,
            )
            solver_report = run_solver_plan(
                solver_plan,
                out / "solver-run",
                access_manifest=access_manifest,
                endpoint_manifest=endpoint_manifest_arg,
                execute=execute,
                timeout_seconds=min(timeout_seconds, 15),
            )
        finally:
            stop_persistent_tunnels(persistent_tunnel_processes)
        if cleanup:
            lifecycle.append(
                provider_lifecycle(
                    provider_output,
                    provider=provider,
                    action="destroy",
                    execute=execute,
                    remove_volumes=False,
                    timeout_seconds=timeout_seconds,
                )
            )
    if "persistent_tunnels" not in locals():
        persistent_tunnels = []
    mode: Literal["dry-run", "execute"] = "execute" if execute else "dry-run"
    execution_depth_findings = validate_execution_depth(
        solver_plan,
        access_manifest,
        access_report,
        solver_report,
        execute=execute,
    )
    report = E2ESolverReport(
        provider=provider,
        mode=mode,
        status=aggregate_e2e_status(
            lifecycle,
            access_report,
            solver_report,
            execute=execute,
            access_bundle_ready=access_bundle_ready,
            execution_depth_findings=execution_depth_findings,
            persistent_tunnels=persistent_tunnels,
        ),
        provider_output=str(provider_output),
        solver_plan=str(solver_plan),
        access_manifest=str(access_manifest),
        access_bundle=str(access_bundle_path) if access_bundle_path.exists() else "",
        access_bundle_ready=access_bundle_ready,
        access_bundle_findings=access_bundle_findings,
        execution_depth_findings=execution_depth_findings,
        host_preflight=host_preflight_data,
        preflight_ready=preflight_ready,
        lifecycle=lifecycle,
        persistent_tunnels=persistent_tunnels,
        access_playtest=access_report,
        solver_run=solver_report,
        execution_proof=build_execution_proof(
            access_report,
            solver_report,
            persistent_tunnels,
            execute=execute,
        ),
        cleanup_requested=cleanup,
        next_actions=e2e_next_actions(provider_output, solver_plan, access_manifest, execute=execute, cleanup=cleanup),
    )
    write_text(out / "e2e-solver.yaml", dump_yaml(report.model_dump()))
    write_text(out / "e2e-solver.json", report.model_dump_json(indent=2))
    write_text(out / "e2e-solver.md", render_e2e_solver_markdown(report))
    return report


def start_persistent_tunnels(access_manifest: Path, *, timeout_seconds: int) -> tuple[list[E2ETunnelResult], list[subprocess.Popen]]:
    access = load_json(access_manifest)
    results: list[E2ETunnelResult] = []
    processes: list[subprocess.Popen] = []
    for item in access.get("tunnel_commands", []) or []:
        if not isinstance(item, dict):
            continue
        service = str(item.get("service", "")).strip()
        command = str(item.get("command", "")).strip()
        parsed = parse_ssh_local_forward(command)
        if not parsed:
            results.append(
                E2ETunnelResult(
                    service=service,
                    command=command,
                    status="failed",
                    message="unsupported SSH local-forward syntax",
                )
            )
            continue
        target = f"{parsed['target_host']}:{parsed['target_port']}"
        if not shutil.which("ssh"):
            results.append(
                E2ETunnelResult(
                    service=service,
                    command=command,
                    local_port=parsed["local_port"],
                    target=target,
                    status="failed",
                    message="missing executable: ssh",
                )
            )
            continue
        argv = ssh_tunnel_argv(command)
        if not argv:
            results.append(
                E2ETunnelResult(
                    service=service,
                    command=command,
                    local_port=parsed["local_port"],
                    target=target,
                    status="failed",
                    message="could not build non-interactive SSH tunnel argv",
                )
            )
            continue
        process = subprocess.Popen(  # noqa: S603 - lab-scoped SSH command parsed without shell.
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if wait_for_tcp_port("127.0.0.1", int(parsed["local_port"]), timeout_seconds):
            processes.append(process)
            results.append(
                E2ETunnelResult(
                    service=service,
                    command=command,
                    local_port=parsed["local_port"],
                    target=target,
                    status="passed",
                    message=f"tunnel_open=true; local=127.0.0.1:{parsed['local_port']}; target={target}",
                )
            )
            continue
        stdout, stderr = collect_process_output(process)
        terminate_process(process)
        results.append(
            E2ETunnelResult(
                service=service,
                command=command,
                local_port=parsed["local_port"],
                target=target,
                status="failed",
                stdout=stdout,
                stderr=stderr,
                message=f"tunnel did not open on 127.0.0.1:{parsed['local_port']} within {timeout_seconds}s",
            )
        )
    return results, processes


def stop_persistent_tunnels(processes: list[subprocess.Popen]) -> None:
    for process in processes:
        terminate_process(process)


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()


def aggregate_e2e_status(
    lifecycle: list[ProviderLifecycleResult],
    access_report: AccessPlaytestReport,
    solver_report: SolverRunReport,
    *,
    execute: bool,
    access_bundle_ready: bool = True,
    execution_depth_findings: list[str] | None = None,
    persistent_tunnels: list[E2ETunnelResult] | None = None,
) -> Literal["planned", "passed", "warning", "failed"]:
    if not execute:
        return "planned"
    execution_depth_findings = execution_depth_findings or []
    persistent_tunnels = persistent_tunnels or []
    if any(item.startswith("missing=") for item in execution_depth_findings):
        return "failed"
    if any(item.status == "failed" for item in lifecycle):
        return "failed"
    if any(item.status == "failed" for item in persistent_tunnels):
        return "failed"
    if access_report.status == "failed" or solver_report.status == "failed":
        return "failed"
    if any(item.status in {"planned", "not-implemented"} for item in lifecycle):
        return "warning"
    if any(item.status == "skipped" for item in persistent_tunnels):
        return "warning"
    if access_report.status == "warning" or solver_report.status == "warning":
        return "warning"
    if not access_bundle_ready:
        return "warning"
    if any(item.startswith("warning=") for item in execution_depth_findings):
        return "warning"
    return "passed"


def validate_execution_depth(
    solver_plan: Path,
    access_manifest: Path,
    access_report: AccessPlaytestReport,
    solver_report: SolverRunReport,
    *,
    execute: bool,
) -> list[str]:
    if not execute:
        return ["execution_depth=not-required-for-dry-run"]
    plan = load_json(solver_plan)
    access = load_json(access_manifest)
    expected_access = expected_access_check_count(access)
    actual_access = len(getattr(access_report, "items", []) or [])
    expected_solver = len([step for step in plan.get("steps", []) or [] if isinstance(step, dict)])
    actual_solver = len(getattr(solver_report, "steps", []) or [])
    findings = [
        f"access_checks=expected:{expected_access}:actual:{actual_access}",
        f"solver_steps=expected:{expected_solver}:actual:{actual_solver}",
    ]
    if actual_access < expected_access:
        findings.append(f"missing=access_checks:{expected_access - actual_access}")
    if actual_solver < expected_solver:
        findings.append(f"missing=solver_steps:{expected_solver - actual_solver}")
    plugin_alignment_findings = validate_plugin_check_alignment(plan, access)
    findings.extend(plugin_alignment_findings)
    if expected_access == 0:
        findings.append("warning=access_manifest_declares_no_checks")
    if expected_solver == 0:
        findings.append("warning=solver_plan_declares_no_steps")
    return findings


def expected_access_check_count(access_manifest: dict) -> int:
    count = 0
    for item in access_manifest.get("learner_entrypoints", []) or []:
        if isinstance(item, dict) and str(item.get("protocol", "")) == "http" and item.get("connect"):
            count += 1
    for item in access_manifest.get("final_submission_endpoints", []) or []:
        if isinstance(item, dict) and str(item.get("protocol", "")) == "http" and item.get("connect"):
            count += 1
    for key in ("health_checks", "terminal_checks", "terminal_sequences", "tunnel_commands", "plugin_checks"):
        count += len([item for item in access_manifest.get(key, []) or [] if isinstance(item, dict)])
    return count


def validate_plugin_check_alignment(solver_plan: dict, access_manifest: dict) -> list[str]:
    solver_plugin_steps = [
        str(step.get("step_id", "")).strip()
        for step in solver_plan.get("steps", []) or []
        if isinstance(step, dict) and str(step.get("action_type", "")).strip() == "vulnerability-behavior" and str(step.get("step_id", "")).strip()
    ]
    access_plugin_steps = [
        str(check.get("step_id", "")).strip()
        for check in access_manifest.get("plugin_checks", []) or []
        if isinstance(check, dict) and str(check.get("step_id", "")).strip()
    ]
    findings: list[str] = []
    if not solver_plugin_steps and not access_plugin_steps:
        return findings
    solver_set = set(solver_plugin_steps)
    access_set = set(access_plugin_steps)
    missing_access = sorted(solver_set - access_set)
    orphan_access = sorted(access_set - solver_set)
    if missing_access:
        findings.append(f"missing=plugin_checks_for_solver_steps:{','.join(missing_access)}")
    if orphan_access:
        findings.append(f"mismatch=plugin_checks_without_solver_steps:{','.join(orphan_access)}")
    return findings


def provider_preflight_ready(report: HostDoctorReport, provider: str) -> bool:
    if provider != "docker-compose":
        return True
    return report.host_docker_server or any(distro.docker_server for distro in report.wsl_distros)


def validate_access_bundle(access_bundle: Path, provider_output: Path, solver_plan: Path, access_manifest: Path) -> list[str]:
    if not access_bundle.exists():
        return [f"missing=lab-access-bundle.json at {access_bundle}"]
    try:
        data = json.loads(access_bundle.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"invalid=lab-access-bundle.json:{exc}"]
    if not isinstance(data, dict):
        return ["invalid=lab-access-bundle.json is not an object"]

    findings: list[str] = []
    expected_files = {
        "provider_endpoints": provider_output / "endpoints.json",
        "learner_access_json": access_manifest,
        "solver_plan_json": solver_plan,
    }
    generated = data.get("generated_files", {})
    if not isinstance(generated, dict):
        findings.append("missing=generated_files")
        generated = {}
    for key, expected in expected_files.items():
        actual = str(generated.get(key, "")).strip()
        if not actual:
            findings.append(f"missing=generated_files.{key}")
            continue
        if Path(actual).resolve() != expected.resolve():
            findings.append(f"mismatch=generated_files.{key}:{actual}")

    access = load_json(access_manifest)
    learner_urls = [
        str(item.get("connect", "")).strip()
        for item in access.get("learner_entrypoints", []) or []
        if isinstance(item, dict) and str(item.get("protocol", "")) == "http" and item.get("connect")
    ]
    attacker_ssh = [
        str(item.get("connect", "")).strip()
        for item in access.get("attacker_entrypoints", []) or []
        if isinstance(item, dict) and str(item.get("protocol", "")) == "ssh" and item.get("connect")
    ]
    final_urls = [
        str(item.get("connect", "")).strip()
        for item in access.get("final_submission_endpoints", []) or []
        if isinstance(item, dict) and str(item.get("protocol", "")) == "http" and item.get("connect")
    ]
    published_endpoints = compact_published_endpoints(access)
    internal_targets = [
        {
            "service": str(item.get("service", "")).strip(),
            "dns": str(item.get("dns", "")).strip(),
            "expose": [str(port) for port in item.get("expose", []) or []],
        }
        for item in access.get("internal_targets", []) or []
        if isinstance(item, dict) and (str(item.get("service", "")).strip() or str(item.get("dns", "")).strip())
    ]
    tunnel_commands = compact_tunnel_commands(access)
    plugin_checks = [
        {"step_id": str(item.get("step_id", "")).strip()}
        for item in access.get("plugin_checks", []) or []
        if isinstance(item, dict) and str(item.get("step_id", "")).strip()
    ]
    terminal_sequences = [
        str(item.get("service", "")).strip()
        for item in access.get("terminal_sequences", []) or []
        if isinstance(item, dict)
    ]
    solver = load_json(solver_plan)
    solver_steps = [item for item in solver.get("steps", []) or [] if isinstance(item, dict)]
    solver_vulnerability_steps = [
        item
        for item in solver_steps
        if str(item.get("action_type", "")).strip() == "vulnerability-behavior"
    ]
    compare_bundle_list(findings, data, "learner_urls", learner_urls)
    compare_bundle_list(findings, data, "attacker_ssh", attacker_ssh)
    compare_bundle_list(findings, data, "final_submission_urls", final_urls)
    compare_bundle_targets(findings, data, "published_endpoints", published_endpoints)
    compare_bundle_targets(findings, data, "internal_targets", internal_targets)
    compare_bundle_targets(findings, data, "tunnel_commands", tunnel_commands)
    compare_bundle_targets(findings, data, "plugin_checks", plugin_checks, subset=True)
    if attacker_ssh and not terminal_sequences:
        findings.append("missing=terminal_sequences_for_attacker_ssh")
    if internal_targets and not tunnel_commands:
        findings.append("missing=tunnel_commands_for_internal_targets")
    if solver_vulnerability_steps and not plugin_checks:
        findings.append("missing=plugin_checks_for_vulnerability_steps")
    if not data.get("solver_ready"):
        findings.append("missing=solver_ready")
    return findings or ["access_bundle=ready"]


def build_execution_proof(
    access_report: AccessPlaytestReport,
    solver_report: SolverRunReport,
    persistent_tunnels: list[E2ETunnelResult],
    *,
    execute: bool,
) -> dict:
    access_items = list(getattr(access_report, "items", []) or [])
    solver_steps = list(getattr(solver_report, "steps", []) or [])
    plugin_access_items = [item for item in access_items if str(getattr(item, "kind", "")).startswith("plugin")]
    plugin_solver_steps = [
        step
        for step in solver_steps
        if str(getattr(step, "action_type", "")) == "vulnerability-behavior"
    ]
    return {
        "mode": "execute" if execute else "dry-run",
        "access": proof_counts(access_items),
        "solver": proof_counts(solver_steps),
        "persistent_tunnels": proof_counts(persistent_tunnels),
        "browser_targets": len(getattr(access_report, "browser_targets", []) or []),
        "terminal_targets": len(getattr(access_report, "terminal_targets", []) or []),
        "plugin_evidence_checks": {
            "access_items": proof_counts(plugin_access_items),
            "solver_steps": proof_counts(plugin_solver_steps),
        },
        "failed_or_warning": [
            *proof_problem_items("access", access_items),
            *proof_problem_items("solver", solver_steps),
            *proof_problem_items("tunnel", persistent_tunnels),
        ],
    }


def proof_counts(items: list) -> dict[str, int]:
    counts = {"total": len(items), "passed": 0, "warning": 0, "failed": 0, "planned": 0, "skipped": 0, "other": 0}
    for item in items:
        status = str(getattr(item, "status", "other"))
        if status in counts:
            counts[status] += 1
        else:
            counts["other"] += 1
    return counts


def proof_problem_items(prefix: str, items: list) -> list[str]:
    values: list[str] = []
    for item in items:
        status = str(getattr(item, "status", ""))
        if status not in {"failed", "warning", "skipped"}:
            continue
        label = str(getattr(item, "check_id", "") or getattr(item, "step_id", "") or getattr(item, "service", "") or "-")
        message = str(getattr(item, "message", "") or getattr(item, "expected", "") or "")
        values.append(f"{prefix}:{label}:{status}:{message}")
    return values


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def compare_bundle_list(findings: list[str], bundle: dict, key: str, expected: list[str]) -> None:
    actual = [str(item).strip() for item in bundle.get(key, []) or [] if str(item).strip()]
    if actual != expected:
        findings.append(f"mismatch={key}:expected={expected}:actual={actual}")


def compare_bundle_targets(findings: list[str], bundle: dict, key: str, expected: list[dict], *, subset: bool = False) -> None:
    fields = sorted({field for item in expected for field in item.keys()})
    actual = [compact_record(item, fields) for item in bundle.get(key, []) or [] if isinstance(item, dict)]
    expected_compact = [compact_record(item, fields) for item in expected]
    actual = [item for item in actual if any(value not in ("", [], None) for value in item.values())]
    if subset:
        missing = [item for item in expected_compact if item not in actual]
        if missing:
            findings.append(f"mismatch={key}:missing={missing}:actual={actual}")
        return
    if actual != expected_compact:
        findings.append(f"mismatch={key}:expected={expected_compact}:actual={actual}")


def compact_record(item: dict, fields: list[str]) -> dict:
    record: dict = {}
    for field in fields:
        value = item.get(field)
        if field == "expose":
            record[field] = [str(port) for port in value or []]
        elif field in {"default_host_port", "local_port"}:
            record[field] = value
        else:
            record[field] = str(value or "").strip()
    return record


def compact_published_endpoints(access: dict) -> list[dict]:
    values: list[dict] = []
    for key in ("learner_entrypoints", "attacker_entrypoints", "final_submission_endpoints"):
        for item in access.get(key, []) or []:
            if not isinstance(item, dict):
                continue
            service = str(item.get("service", "")).strip()
            connect = str(item.get("connect", "")).strip()
            if not service and not connect:
                continue
            values.append(
                {
                    "service": service,
                    "protocol": str(item.get("protocol", "")).strip(),
                    "connect": connect,
                    "default_host_port": item.get("default_host_port"),
                    "container_port": str(item.get("container_port", "")).strip(),
                    "override_env": str(item.get("override_env", "")).strip(),
                }
            )
    return values


def compact_tunnel_commands(access: dict) -> list[dict]:
    values: list[dict] = []
    for item in access.get("tunnel_commands", []) or []:
        if not isinstance(item, dict):
            continue
        service = str(item.get("service", "")).strip()
        command = str(item.get("command", "")).strip()
        if not service and not command:
            continue
        values.append(
            {
                "service": service,
                "dns": str(item.get("dns", "")).strip(),
                "internal_port": str(item.get("internal_port", "")).strip(),
                "local_port": item.get("local_port"),
                "command": command,
                "url": str(item.get("url", "")).strip(),
            }
        )
    return values


def host_preflight_to_dict(report: HostDoctorReport) -> dict:
    return {
        "host_os": report.host_os,
        "platform": report.platform,
        "architecture": report.architecture,
        "shell_hint": report.shell_hint,
        "cwd": report.cwd,
        "wsl_available": report.wsl_available,
        "wsl_distros": [
            {
                "name": distro.name,
                "state": distro.state,
                "version": distro.version,
                "docker_cli": distro.docker_cli,
                "docker_server": distro.docker_server,
                "docker_server_version": distro.docker_server_version,
            }
            for distro in report.wsl_distros
        ],
        "host_docker_cli": report.host_docker_cli,
        "host_docker_server": report.host_docker_server,
        "host_docker_server_version": report.host_docker_server_version,
        "recommended_execution": report.recommended_execution,
        "findings": list(report.findings),
        "warnings": list(report.warnings),
        "next_steps": list(report.next_steps),
    }


def e2e_next_actions(provider_output: Path, solver_plan: Path, access_manifest: Path, *, execute: bool, cleanup: bool) -> list[str]:
    if execute:
        actions = ["Review e2e-solver.md, solver-run.md, and access-playtest.md for failed or warning checks."]
        if not cleanup:
            actions.append("Stop the generated provider output when finished.")
        return actions
    return [
        f"Review provider output: {provider_output}",
        f"Review solver plan: {solver_plan}",
        f"Review access manifest: {access_manifest}",
        "Re-run this command with --execute after confirming the provider can run on this host.",
    ]


def render_e2e_solver_markdown(report: E2ESolverReport) -> str:
    lines = [
        "# E2E Solver Report",
        "",
        f"- Provider: `{report.provider}`",
        f"- Mode: `{report.mode}`",
        f"- Status: `{report.status}`",
        f"- Provider output: `{report.provider_output}`",
        f"- Solver plan: `{report.solver_plan}`",
        f"- Access manifest: `{report.access_manifest}`",
        f"- Access bundle: `{report.access_bundle or '-'}`",
        f"- Access bundle ready: `{str(report.access_bundle_ready).lower()}`",
        f"- Host preflight ready: `{str(report.preflight_ready).lower()}`",
        f"- Cleanup requested: `{str(report.cleanup_requested).lower()}`",
        "",
        "## Host Preflight",
        "",
        f"- OS: `{report.host_preflight.get('host_os', '-') if report.host_preflight else '-'}`",
        f"- Recommended execution: `{report.host_preflight.get('recommended_execution', '-') if report.host_preflight else '-'}`",
        f"- Host Docker server: `{str(report.host_preflight.get('host_docker_server', '-')).lower() if report.host_preflight else '-'}`",
        f"- WSL available: `{str(report.host_preflight.get('wsl_available', '-')).lower() if report.host_preflight else '-'}`",
        "",
        "## Access Bundle",
        "",
    ]
    lines.extend(f"- {item}" for item in report.access_bundle_findings or ["No access bundle findings."])
    lines += [
        "",
        "## Execution Depth",
        "",
    ]
    lines.extend(f"- {item}" for item in report.execution_depth_findings or ["No execution depth findings."])
    proof = report.execution_proof or {}
    lines += [
        "",
        "## Execution Proof Summary",
        "",
        f"- Mode: `{proof.get('mode', '-')}`",
        f"- Browser targets: `{proof.get('browser_targets', 0)}`",
        f"- Terminal targets: `{proof.get('terminal_targets', 0)}`",
        f"- Access checks: `{format_proof_counts(proof.get('access', {}))}`",
        f"- Solver steps: `{format_proof_counts(proof.get('solver', {}))}`",
        f"- Persistent tunnels: `{format_proof_counts(proof.get('persistent_tunnels', {}))}`",
        f"- Plugin access evidence: `{format_proof_counts((proof.get('plugin_evidence_checks') or {}).get('access_items', {}))}`",
        f"- Plugin solver evidence: `{format_proof_counts((proof.get('plugin_evidence_checks') or {}).get('solver_steps', {}))}`",
        "",
        "### Proof Problems",
        "",
    ]
    lines.extend(f"- {item}" for item in proof.get("failed_or_warning", []) or ["No failed, warning, or skipped proof items."])
    lines += [
        "",
        "## Lifecycle",
        "",
        "| Action | Mode | Status | Message |",
        "|---|---|---|---|",
    ]
    for item in report.lifecycle:
        lines.append(f"| `{item.action}` | `{item.mode}` | {item.status} | {escape_cell(item.message or '-')} |")
    lines += [
        "",
        "## Persistent Tunnels",
        "",
        "| Service | Local Port | Target | Status | Message |",
        "|---|---:|---|---|---|",
    ]
    if report.persistent_tunnels:
        for item in report.persistent_tunnels:
            lines.append(
                f"| `{item.service or '-'}` | `{item.local_port or '-'}` | `{item.target or '-'}` | "
                f"{item.status} | {escape_cell(item.message or '-')} |"
            )
    else:
        lines.append("| `-` | `-` | `-` | skipped | No persistent tunnel execution requested. |")
    lines += [
        "",
        "## Access Playtest",
        "",
        f"- Status: `{report.access_playtest.status if report.access_playtest else 'missing'}`",
        f"- Browser targets: `{len(report.access_playtest.browser_targets) if report.access_playtest else 0}`",
        f"- Terminal targets: `{len(report.access_playtest.terminal_targets) if report.access_playtest else 0}`",
        "",
        "## Solver Run",
        "",
        f"- Status: `{report.solver_run.status if report.solver_run else 'missing'}`",
        f"- Steps: `{len(report.solver_run.steps) if report.solver_run else 0}`",
        "",
        "## Next Actions",
        "",
    ]
    lines.extend(f"- {item}" for item in report.next_actions)
    lines.append("")
    return "\n".join(lines)


def escape_cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def format_proof_counts(counts: dict) -> str:
    if not isinstance(counts, dict):
        return "total=0 passed=0 warning=0 failed=0"
    return (
        f"total={counts.get('total', 0)} "
        f"passed={counts.get('passed', 0)} "
        f"warning={counts.get('warning', 0)} "
        f"failed={counts.get('failed', 0)} "
        f"planned={counts.get('planned', 0)} "
        f"skipped={counts.get('skipped', 0)}"
    )
