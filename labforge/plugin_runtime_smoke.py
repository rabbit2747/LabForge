from __future__ import annotations

import importlib.util
import json
import tempfile
import uuid
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, write_text
from .model import LabSpec
from .service_artifacts import declared_service_artifacts
from .service_templates import normalize_template_id
from .vulnerability_plugins import declared_vulnerability_plugins
from .vulnerability_scaffolds import SUPPORTED_VULNERABILITY_SCAFFOLDS


SmokeStatus = Literal["passed", "warning", "failed", "skipped"]


class PluginRuntimeSmokeModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class PluginRuntimeSmokeItem(PluginRuntimeSmokeModel):
    service: str
    plugin: str
    status: SmokeStatus
    message: str = ""
    endpoint: str = ""
    emitted_evidence: list[str] = Field(default_factory=list)
    unlocked_stages: list[str] = Field(default_factory=list)


class PluginRuntimeSmokeReport(PluginRuntimeSmokeModel):
    lab_id: str
    status: Literal["passed", "warning", "failed"]
    items: list[PluginRuntimeSmokeItem] = Field(default_factory=list)


def run_plugin_runtime_smoke(spec: LabSpec, out: Path | None = None) -> PluginRuntimeSmokeReport:
    items: list[PluginRuntimeSmokeItem] = []
    for artifact in declared_service_artifacts(spec):
        service_root = spec.root / artifact.source_path
        plugins = declared_vulnerability_plugins(artifact)
        supported_plugins = [
            normalize_template_id(str(plugin.get("id", "")))
            for plugin in plugins
            if normalize_template_id(str(plugin.get("id", ""))) in SUPPORTED_VULNERABILITY_SCAFFOLDS
        ]
        app_path = service_root / "app.py"
        if not app_path.exists():
            for plugin_id in supported_plugins:
                items.append(
                    PluginRuntimeSmokeItem(
                        service=artifact.service,
                        plugin=plugin_id,
                        status="failed",
                        message="app.py is missing; run `labforge services materialize` first.",
                    )
                )
            continue
        should_check_service_contract = generated_flask_contract_expected(app_path)
        if not supported_plugins and not should_check_service_contract:
            continue
        module, load_error = load_generated_app_module(artifact.service, app_path)
        if load_error:
            if should_check_service_contract and not supported_plugins:
                items.append(
                    PluginRuntimeSmokeItem(
                        service=artifact.service,
                        plugin="service-import",
                        status="failed",
                        message=f"failed to import generated app.py: {load_error}",
                    )
                )
            for plugin_id in supported_plugins:
                items.append(
                    PluginRuntimeSmokeItem(
                        service=artifact.service,
                        plugin=plugin_id,
                        status="failed",
                        message=f"failed to import generated app.py: {load_error}",
                    )
                )
            continue
        isolate_generated_state(module, artifact.service)
        seed_runtime_smoke_inputs(module, service_root)
        client = module.app.test_client()
        contract_item = run_service_contract_smoke(artifact.service, module, client)
        if contract_item:
            items.append(contract_item)
        for plugin_id in supported_plugins:
            before = stage_state_snapshot(module)
            item = run_single_plugin_smoke(artifact.service, plugin_id, client)
            items.append(enrich_smoke_item_with_stage_state(item, module, before))

    report = PluginRuntimeSmokeReport(
        lab_id=spec.lab_id,
        status=aggregate_runtime_status(items),
        items=items,
    )
    if out:
        out.mkdir(parents=True, exist_ok=True)
        write_text(out / "plugin-runtime-smoke.yaml", dump_yaml(report.model_dump()))
        write_text(out / "plugin-runtime-smoke.md", plugin_runtime_smoke_to_markdown(report))
    return report


def load_generated_app_module(service: str, app_path: Path) -> tuple[Any | None, str]:
    module_name = f"labforge_runtime_smoke_{normalize_template_id(service).replace('-', '_')}_{uuid.uuid4().hex}"
    try:
        spec = importlib.util.spec_from_file_location(module_name, app_path)
        if not spec or not spec.loader:
            return None, "could not create import spec"
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not hasattr(module, "app"):
            return None, "module does not expose Flask app"
        return module, ""
    except Exception as exc:  # noqa: BLE001 - smoke report must preserve import failures.
        return None, str(exc)


def isolate_generated_state(module: Any, service: str) -> None:
    root = Path(tempfile.mkdtemp(prefix=f"labforge-runtime-smoke-{normalize_template_id(service)}-"))
    state = root / "state"
    seed = root / "seed"
    logs = root / "logs"
    seed.mkdir(parents=True, exist_ok=True)
    patches = {
        "SEED_DIR": seed,
        "STATE_DIR": state,
        "STAGE_STATE_PATH": state / "stage-state.json",
        "LOG_PATH": logs / "service-events.jsonl",
        "REVIEW_ITEMS_PATH": state / "stored-xss-review-items.json",
        "REVIEW_AUDIT_PATH": state / "stored-xss-review-audit.json",
        "UPLOAD_ACCESS_AUDIT_PATH": state / "upload-access-audit.json",
        "BUILD_JOBS_PATH": state / "build-pipeline-jobs.json",
        "BUILD_AUDIT_PATH": state / "build-pipeline-audit.json",
        "UPDATE_CHANNELS_PATH": state / "signed-update-channels.json",
        "SIGNED_MANIFESTS_PATH": state / "signed-update-manifests.json",
        "SIGNING_AUDIT_PATH": state / "signed-update-signing-audit.json",
        "PUBLISH_AUDIT_PATH": state / "signed-update-publish-audit.json",
        "CUSTOMER_UPDATE_STATE_PATH": state / "customer-update-state.json",
        "CUSTOMER_UPDATE_AUDIT_PATH": state / "customer-update-audit.json",
        "SOLR_VELOCITY_STATE_PATH": state / "solr-velocity-state.json",
        "SOLR_VELOCITY_AUDIT_PATH": state / "solr-velocity-audit.json",
    }
    for name, value in patches.items():
        if hasattr(module, name):
            setattr(module, name, value)


def seed_runtime_smoke_inputs(module: Any, service_root: Path) -> None:
    seed_dir = getattr(module, "SEED_DIR", None)
    if seed_dir is None:
        return
    seed_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("vulnerability-evidence.json", "vulnerability-discovery.json", "stage-state.json"):
        source = service_root / "seed" / filename
        if source.exists():
            (seed_dir / filename).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")


def stage_state_snapshot(module: Any) -> dict[str, Any]:
    path = getattr(module, "STAGE_STATE_PATH", None)
    if path is None or not Path(path).exists():
        return {"acquired_evidence": [], "stages": []}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"acquired_evidence": [], "stages": []}
    if not isinstance(data, dict):
        return {"acquired_evidence": [], "stages": []}
    return data


def enrich_smoke_item_with_stage_state(item: PluginRuntimeSmokeItem, module: Any, before: dict[str, Any]) -> PluginRuntimeSmokeItem:
    after = stage_state_snapshot(module)
    before_evidence = set(str(value) for value in before.get("acquired_evidence", []) or [])
    after_evidence = set(str(value) for value in after.get("acquired_evidence", []) or [])
    emitted = sorted(after_evidence - before_evidence)
    before_event_count = len(before.get("events", []) or [])
    new_events = (after.get("events", []) or [])[before_event_count:]
    event_evidence: list[str] = []
    for event in new_events:
        if not isinstance(event, dict):
            continue
        if event.get("event") != "evidence.emitted":
            continue
        if str(event.get("plugin", "")) != item.plugin:
            continue
        if str(event.get("service", "")) != item.service:
            continue
        for value in event.get("evidence", []) or []:
            evidence = str(value)
            if evidence and evidence not in event_evidence:
                event_evidence.append(evidence)
    before_unlocked = {
        str(stage.get("stage_id"))
        for stage in before.get("stages", []) or []
        if isinstance(stage, dict) and stage.get("status") == "unlocked"
    }
    after_unlocked = {
        str(stage.get("stage_id"))
        for stage in after.get("stages", []) or []
        if isinstance(stage, dict) and stage.get("status") == "unlocked"
    }
    item.emitted_evidence = sorted(set([*emitted, *event_evidence]))
    item.unlocked_stages = sorted(after_unlocked - before_unlocked)
    return item


def run_single_plugin_smoke(service: str, plugin_id: str, client: Any) -> PluginRuntimeSmokeItem:
    try:
        if plugin_id == "ssti-preview":
            context = client.get("/labforge/scaffold/ssti-preview/context")
            normal = client.post("/labforge/scaffold/ssti-preview", json={"body": "Hello {{ customer.name }} from {{ service.name }}"})
            response = client.post("/labforge/scaffold/ssti-preview", json={"body": "{{ 7*7 }}"})
            audit = client.get("/labforge/scaffold/ssti-preview/audit")
            data = response.get_json(silent=True) or {}
            context_data = context.get_json(silent=True) or {}
            audit_data = audit.get_json(silent=True) or {}
            audit_records = audit_data.get("records", [])
            return assert_condition(
                service,
                plugin_id,
                context.status_code == 200
                and normal.status_code == 200
                and response.status_code == 200
                and audit.status_code == 200
                and data.get("preview") == "49"
                and context_data.get("render_api") == "POST /operations/preview"
                and any(record.get("classification") == "unexpected-expression" for record in audit_records),
                "/labforge/scaffold/ssti-preview + context + audit",
                response,
            )
        if plugin_id == "stored-xss-review":
            policy = client.get("/labforge/scaffold/reviewer/policy")
            created = client.post("/labforge/scaffold/review-items", json={"title": "Smoke", "body": "<b>stored</b>"})
            data = created.get_json(silent=True) or {}
            item_id = data.get("id", "")
            opened = client.get(f"/labforge/scaffold/reviewer/items/{item_id}") if item_id else created
            context = client.get("/labforge/scaffold/reviewer/context")
            callback = client.post("/labforge/scaffold/reviewer/callback", json={"source": "runtime-smoke", "item_id": item_id})
            audit = client.get("/labforge/scaffold/reviewer/audit")
            policy_data = policy.get_json(silent=True) or {}
            context_data = context.get_json(silent=True) or {}
            callback_data = callback.get_json(silent=True) or {}
            audit_data = audit.get_json(silent=True) or {}
            records = audit_data.get("records", []) if isinstance(audit_data, dict) else []
            return assert_condition(
                service,
                plugin_id,
                policy.status_code == 200
                and policy_data.get("callback_api") == "POST /operations/reviewer/callback"
                and created.status_code == 201
                and opened.status_code == 200
                and "stored" in opened.get_data(as_text=True)
                and "reviewer/context" in opened.get_data(as_text=True)
                and context.status_code == 200
                and isinstance(context_data.get("session_context"), dict)
                and callback.status_code == 202
                and callback_data.get("accepted") is True
                and audit.status_code == 200
                and any(record.get("action") == "item-created" and record.get("accepted") is True for record in records)
                and any(record.get("action") == "item-opened" and record.get("accepted") is True for record in records)
                and any(record.get("action") == "context-read" and record.get("accepted") is True for record in records)
                and any(record.get("action") == "callback-received" and record.get("accepted") is True for record in records),
                "/labforge/scaffold/reviewer/policy + review-items + reviewer context/callback/audit",
                audit,
            )
        if plugin_id == "idor-object-access":
            catalog = client.get("/labforge/scaffold/objects?owner=learner")
            visible = catalog.get_json(silent=True) or {}
            policy = client.get("/labforge/scaffold/objects/access-policy")
            entitlement = client.get("/labforge/scaffold/objects/obj-9001/entitlement?owner=learner")
            entitlement_data = entitlement.get_json(silent=True) or {}
            response = client.get("/labforge/scaffold/objects/obj-9001?owner=learner")
            data = response.get_json(silent=True) or {}
            audit = client.get("/labforge/scaffold/objects/audit")
            audit_data = audit.get_json(silent=True) or {}
            audit_records = audit_data.get("records", [])
            visible_ids = {str(item.get("id")) for item in visible.get("items", []) if isinstance(item, dict)}
            direct_read_audited = any(
                record.get("object_id") == "obj-9001"
                and record.get("action") == "direct-read"
                and record.get("allowed_by_entitlement") is False
                and record.get("visible_in_catalog") is False
                for record in audit_records
            )
            return assert_condition(
                service,
                plugin_id,
                catalog.status_code == 200
                and "obj-9001" not in visible_ids
                and policy.status_code == 200
                and entitlement.status_code == 200
                and entitlement_data.get("allowed") is False
                and response.status_code == 200
                and audit.status_code == 200
                and "LABFORGE_SYNTHETIC_OBJECT" in str(data.get("content", ""))
                and direct_read_audited,
                "/labforge/scaffold/objects catalog + policy + entitlement + direct read + audit",
                response,
            )
        if plugin_id == "ssrf-internal-fetch":
            registry = client.get("/labforge/scaffold/source-registry")
            policy = client.get("/labforge/scaffold/fetch/policy")
            registry_data = registry.get_json(silent=True) or {}
            sources = registry_data.get("sources", [])
            first_source_record = sources[0] if sources and isinstance(sources[0], dict) else {}
            first_source = first_source_record.get("url") or "http://metadata-service:8080/metadata"
            source_id = first_source_record.get("id") or "src-metadata-service"
            source_detail = client.get(f"/labforge/scaffold/source-registry/{source_id}")
            blocked = client.get("/labforge/scaffold/fetch?url=http://169.254.169.254/latest")
            import urllib.request

            original_urlopen = urllib.request.urlopen

            class FakeResponse:
                status = 200

                def __enter__(self) -> "FakeResponse":
                    return self

                def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
                    return None

                def read(self, _size: int) -> bytes:
                    return b'{"service":"metadata-service","scope":"lab-internal"}'

            def fake_urlopen(_request: Any, timeout: int = 3) -> FakeResponse:
                return FakeResponse()

            urllib.request.urlopen = fake_urlopen
            try:
                allowed = client.get(f"/labforge/scaffold/fetch?url={first_source}")
            finally:
                urllib.request.urlopen = original_urlopen
            blocked_data = blocked.get_json(silent=True) or {}
            allowed_data = allowed.get_json(silent=True) or {}
            source_detail_data = source_detail.get_json(silent=True) or {}
            allowed_provenance = allowed_data.get("provenance", {}) if isinstance(allowed_data, dict) else {}
            blocked_provenance = blocked_data.get("provenance", {}) if isinstance(blocked_data, dict) else {}
            audit = client.get("/labforge/scaffold/fetch/audit")
            audit_data = audit.get_json(silent=True) or {}
            records = audit_data.get("records", [])
            blocked_recorded = any(
                record.get("url") == "http://169.254.169.254/latest"
                and record.get("allowed") is False
                and record.get("provenance", {}).get("policy_decision") == "deny"
                for record in records
            )
            allowed_recorded = any(
                record.get("url") == first_source
                and record.get("allowed") is True
                and record.get("provenance", {}).get("registry_match") is True
                and record.get("response_fingerprint")
                for record in records
            )
            return assert_condition(
                service,
                plugin_id,
                registry.status_code == 200
                and policy.status_code == 200
                and source_detail.status_code == 200
                and source_detail_data.get("source", {}).get("id") == source_id
                and isinstance(sources, list)
                and len(sources) >= 1
                and blocked.status_code == 400
                and blocked_data.get("allowed") is False
                and blocked_provenance.get("policy_decision") == "deny"
                and allowed.status_code == 200
                and allowed_data.get("allowed") is True
                and allowed_provenance.get("registry_match") is True
                and allowed_provenance.get("source_id") == source_id
                and bool(allowed_data.get("response_fingerprint"))
                and audit.status_code == 200
                and blocked_recorded
                and allowed_recorded,
                "/labforge/scaffold/source-registry detail + fetch provenance/audit comparison",
                allowed,
            )
        if plugin_id == "path-traversal-download":
            catalog = client.get("/api/documents")
            policy = client.get("/labforge/scaffold/documents/policy")
            resolution = client.get("/labforge/scaffold/documents/resolve?name=../restricted/audit-export.txt")
            public = client.get("/labforge/scaffold/documents/download?name=welcome.txt")
            traversed = client.get("/labforge/scaffold/documents/download?name=../restricted/audit-export.txt")
            audit = client.get("/labforge/scaffold/documents/audit")
            catalog_data = catalog.get_json(silent=True) or {}
            resolution_data = resolution.get_json(silent=True) or {}
            resolved = resolution_data.get("resolution", {}) if isinstance(resolution_data, dict) else {}
            audit_data = audit.get_json(silent=True) or {}
            audit_records = audit_data.get("records", [])
            return assert_condition(
                service,
                plugin_id,
                catalog.status_code == 200
                and policy.status_code == 200
                and resolution.status_code == 200
                and resolved.get("traversal") is True
                and resolved.get("inside_document_root") is True
                and resolved.get("inside_active_workspace") is False
                and public.status_code == 200
                and traversed.status_code == 200
                and "LABFORGE_SYNTHETIC_RESTRICTED_DOCUMENT" in traversed.get_data(as_text=True)
                and any(record.get("traversal") and record.get("status") == 200 for record in audit_records)
                and catalog_data.get("policy_api") == "/api/documents/policy",
                "/api/documents + resolve + download + audit",
                traversed,
            )
        if plugin_id == "unsafe-file-upload":
            from io import BytesIO

            policy = client.get("/labforge/scaffold/uploads/policy")
            uploaded = client.post(
                "/labforge/scaffold/uploads",
                data={"file": (BytesIO(b"labforge upload smoke"), "case-note.bin")},
                content_type="multipart/form-data",
            )
            data = uploaded.get_json(silent=True) or {}
            filename = data.get("filename", "")
            retrieved = client.get(f"/labforge/scaffold/uploads/{filename}") if filename else uploaded
            review = client.get("/labforge/scaffold/uploads/review")
            storage = client.get("/labforge/scaffold/uploads/storage")
            access_audit = client.get("/labforge/scaffold/uploads/access-audit")
            review_data = review.get_json(silent=True) or {}
            records = review_data.get("records", [])
            storage_data = storage.get_json(silent=True) or {}
            access_data = access_audit.get_json(silent=True) or {}
            access_records = access_data.get("records", []) if isinstance(access_data, dict) else []
            return assert_condition(
                service,
                plugin_id,
                policy.status_code == 200
                and uploaded.status_code == 201
                and retrieved.status_code == 200
                and storage.status_code == 200
                and any(obj.get("filename") == filename and obj.get("retrieval_url") == f"/attachments/{filename}" for obj in storage_data.get("objects", []))
                and access_audit.status_code == 200
                and any(record.get("action") == "upload" and record.get("filename") == filename and record.get("status") == 201 for record in access_records)
                and any(record.get("action") == "retrieve" and record.get("filename") == filename and record.get("status") == 200 for record in access_records)
                and b"labforge upload smoke" in retrieved.get_data()
                and any(record.get("filename") == filename and record.get("policy_match") is False for record in records),
                "/labforge/scaffold/uploads + policy + review + storage + access-audit",
                access_audit,
            )
        if plugin_id == "diagnostic-command-injection":
            info = client.get("/api/diagnostics")
            info_data = info.get_json(silent=True) or {}
            policy = client.get("/labforge/scaffold/diagnostics/policy")
            policy_data = policy.get_json(silent=True) or {}
            response = client.post("/labforge/scaffold/diagnostics/run", json={"preset": "runtime-identity", "target": "localhost"})
            data = response.get_json(silent=True) or {}
            blocked = client.post("/labforge/scaffold/diagnostics/run", json={"command": "docker ps", "target": "localhost"})
            blocked_data = blocked.get_json(silent=True) or {}
            audit = client.get("/labforge/scaffold/diagnostics/audit")
            audit_data = audit.get_json(silent=True) or {}
            records = audit_data.get("records", [])
            return assert_condition(
                service,
                plugin_id,
                info.status_code == 200
                and isinstance(info_data.get("presets"), list)
                and isinstance(info_data.get("targets"), list)
                and policy.status_code == 200
                and "docker" in policy_data.get("blocked_tokens", [])
                and response.status_code == 200
                and data.get("accepted") is True
                and blocked.status_code == 400
                and blocked_data.get("accepted") is False
                and audit.status_code == 200
                and any(record.get("preset") == "runtime-identity" and record.get("accepted") is True for record in records)
                and any(record.get("accepted") is False and record.get("blocked_token_matched") is True for record in records),
                "/api/diagnostics + policy + run preset + blocked audit",
                audit,
            )
        if plugin_id == "credential-exposure":
            config = client.get("/labforge/scaffold/config")
            policy = client.get("/labforge/scaffold/config/secret-policy")
            log = client.get("/labforge/scaffold/config/startup-log")
            correlation = client.get("/labforge/scaffold/config/correlation")
            audit = client.get("/labforge/scaffold/config/access-audit")
            config_data = config.get_json(silent=True) or {}
            policy_data = policy.get_json(silent=True) or {}
            correlation_data = correlation.get_json(silent=True) or {}
            audit_data = audit.get_json(silent=True) or {}
            log_body = log.get_data(as_text=True)
            audit_records = audit_data.get("records", [])
            return assert_condition(
                service,
                plugin_id,
                config.status_code == 200
                and policy.status_code == 200
                and log.status_code == 200
                and correlation.status_code == 200
                and audit.status_code == 200
                and config_data.get("secret_value") == "redacted"
                and policy_data.get("redaction_policy", "").startswith("runtime config")
                and correlation_data.get("cache_profile_matches_account") is True
                and "LabForge-Operator-Training-Secret!" in str(correlation_data.get("recovered_credential", ""))
                and "vault-cache export" in log_body
                and "LabForge-Operator-Training-Secret!" in log_body
                and any(record.get("action") == "config-read" and record.get("secret_value_visible") is False for record in audit_records)
                and any(record.get("action") == "startup-log-read" and record.get("secret_value_visible") is True for record in audit_records),
                "/labforge/scaffold/config + secret-policy + startup-log + correlation + access-audit",
                correlation,
            )
        if plugin_id == "solr-velocity-rce":
            cores = client.get("/labforge/scaffold/solr/cores")
            policy = client.get("/labforge/scaffold/solr/policy")
            drift_before = client.get("/labforge/scaffold/solr/config-drift")
            system = client.get("/labforge/scaffold/solr/admin/info/system")
            enabled = client.post(
                "/labforge/scaffold/solr/config",
                json={
                    "update-queryresponsewriter": {
                        "name": "velocity",
                        "class": "solr.VelocityResponseWriter",
                        "params.resource.loader.enabled": "true",
                    }
                },
            )
            executed = client.get(
                "/labforge/scaffold/solr/select",
                query_string={
                    "q": "*:*",
                    "wt": "velocity",
                    "v.template": "custom",
                    "v.template.custom": '#set($x="")#set($p=$x.class.forName("java.lang.Runtime").getRuntime().exec("id"))',
                },
            )
            drift_after = client.get("/labforge/scaffold/solr/config-drift")
            audit = client.get("/labforge/scaffold/solr/audit")
            cores_data = cores.get_json(silent=True) or {}
            policy_data = policy.get_json(silent=True) or {}
            drift_before_data = drift_before.get_json(silent=True) or {}
            drift_after_data = drift_after.get_json(silent=True) or {}
            audit_data = audit.get_json(silent=True) or {}
            audit_records = audit_data.get("records", []) if isinstance(audit_data, dict) else []
            return assert_condition(
                service,
                plugin_id,
                cores.status_code == 200
                and any(core.get("legacy") is True for core in cores_data.get("cores", []) if isinstance(core, dict))
                and policy.status_code == 200
                and policy_data.get("audit_api") == "/api/search/audit"
                and drift_before.status_code == 200
                and drift_before_data.get("legacy_track") is True
                and system.status_code == 200
                and enabled.status_code == 200
                and executed.status_code == 200
                and drift_after.status_code == 200
                and drift_after_data.get("velocity_response_writer") is True
                and audit.status_code == 200
                and any(record.get("action") == "response-writer-config-change" and record.get("accepted") is True for record in audit_records)
                and any(record.get("action") == "template-query-executed" and record.get("accepted") is True for record in audit_records)
                and "uid=8983(solr)" in executed.get_data(as_text=True),
                "/labforge/scaffold/solr/cores + policy + config-drift + select + audit",
                audit,
            )
        if plugin_id == "build-pipeline-abuse":
            context = client.get("/labforge/scaffold/build/context")
            metadata = client.get("/labforge/scaffold/build/release-metadata")
            metadata_data = metadata.get_json(silent=True) or {}
            payload = {
                "repo": metadata_data.get("repo", "smoke/product-agent"),
                "ref": metadata_data.get("ref", "refs/heads/release/smoke"),
                "channel": metadata_data.get("channel", "smoke"),
                "support_patch_ref": "lab://smoke.patch",
            }
            policy = client.post("/labforge/scaffold/build/policy", json=payload)
            policy_data = policy.get_json(silent=True) or {}
            response = client.post(
                "/labforge/scaffold/build/jobs",
                json=payload,
            )
            data = response.get_json(silent=True) or {}
            job_id = str(data.get("job_id") or "")
            provenance = client.get(f"/labforge/scaffold/build/jobs/{job_id}/provenance") if job_id else None
            provenance_data = provenance.get_json(silent=True) if provenance is not None else {}
            audit = client.get("/labforge/scaffold/build/audit")
            audit_data = audit.get_json(silent=True) or {}
            audit_records = audit_data.get("records", []) if isinstance(audit_data, dict) else []
            return assert_condition(
                service,
                plugin_id,
                context.status_code == 200
                and metadata.status_code == 200
                and policy.status_code == 200
                and policy_data.get("allowed") is True
                and response.status_code == 201
                and data.get("status") == "built"
                and "canonical_manifest" in data
                and provenance is not None
                and provenance.status_code == 200
                and provenance_data.get("provenance", {}).get("artifact_sha256") == data.get("artifact", {}).get("sha256")
                and audit.status_code == 200
                and any(record.get("action") == "policy-check" and record.get("accepted") is True for record in audit_records)
                and any(record.get("action") == "job-create" and record.get("accepted") is True for record in audit_records),
                "/labforge/scaffold/build context + release metadata + policy + jobs + provenance + audit",
                audit,
            )
        if plugin_id == "signed-update-publish":
            manifest = {
                "product": "product-agent",
                "channel": "smoke",
                "version": "0.0.0",
                "build_id": "build-smoke",
                "artifact": {"name": "smoke.tar", "sha256": "0" * 64, "url": "http://build-server/smoke.tar", "size_bytes": 1},
            }
            policy = client.get("/labforge/scaffold/signing/policy")
            validation = client.post("/labforge/scaffold/sign/validate", json={"canonical_manifest": manifest})
            signed = client.post("/labforge/scaffold/sign", json={"canonical_manifest": manifest})
            signed_data = signed.get_json(silent=True) or {}
            sign_audit = client.get("/labforge/scaffold/sign/audit")
            inventory = client.get("/labforge/scaffold/signed-manifests")
            published = client.post("/labforge/scaffold/publish", json={"channel": "smoke", "signed_manifest": signed_data.get("signed_manifest")})
            audit = client.get("/labforge/scaffold/publish/audit")
            channel = client.get("/labforge/scaffold/channels/smoke")
            validation_data = validation.get_json(silent=True) or {}
            sign_audit_data = sign_audit.get_json(silent=True) or {}
            sign_records = sign_audit_data.get("records", []) if isinstance(sign_audit_data, dict) else []
            inventory_data = inventory.get_json(silent=True) or {}
            audit_data = audit.get_json(silent=True) or {}
            return assert_condition(
                service,
                plugin_id,
                policy.status_code == 200
                and validation.status_code == 200
                and validation_data.get("allowed") is True
                and signed.status_code == 200
                and sign_audit.status_code == 200
                and any(record.get("action") == "manifest-validate" and record.get("accepted") is True for record in sign_records)
                and any(record.get("action") == "manifest-sign" and record.get("accepted") is True for record in sign_records)
                and inventory.status_code == 200
                and inventory_data.get("count", 0) >= 1
                and published.status_code == 201
                and audit.status_code == 200
                and audit_data.get("count", 0) >= 1
                and channel.status_code == 200,
                "/labforge/scaffold/signing/policy + /sign/validate + /sign + /sign/audit + /signed-manifests + /publish + /publish/audit",
                sign_audit,
            )
        if plugin_id == "customer-update-callback":
            policy = client.get("/labforge/scaffold/customer/update-policy")
            pre = client.get("/labforge/scaffold/customer/export")
            response = client.post(
                "/labforge/scaffold/customer/poll",
                json={
                    "manifest": {
                        "product": "product-agent",
                        "channel": "smoke",
                        "build_id": "build-smoke",
                        "artifact": {"name": "product-agent-smoke.tar", "sha256": "0" * 64, "url": "http://update/product-agent-smoke.tar"},
                        "signature": "smoke",
                    }
                },
            )
            export = client.get("/labforge/scaffold/customer/export")
            audit = client.get("/labforge/scaffold/customer/audit")
            data = export.get_json(silent=True) or {}
            audit_data = audit.get_json(silent=True) or {}
            records = audit_data.get("records", []) if isinstance(audit_data, dict) else []
            return assert_condition(
                service,
                plugin_id,
                policy.status_code == 200
                and pre.status_code == 403
                and response.status_code == 202
                and export.status_code == 200
                and data.get("content") == "LABFORGE_SUPPLY_CHAIN_FINAL_OBJECT"
                and audit.status_code == 200
                and any(record.get("action") == "poll" and record.get("accepted") is True for record in records)
                and any(record.get("action") == "update-applied" and record.get("accepted") is True for record in records)
                and any(record.get("action") == "export-read" and record.get("accepted") is True for record in records),
                "/labforge/scaffold/customer/update-policy + /poll + /audit + /export",
                audit,
            )
    except Exception as exc:  # noqa: BLE001 - smoke report should preserve route failures.
        return PluginRuntimeSmokeItem(service=service, plugin=plugin_id, status="failed", message=str(exc))
    return PluginRuntimeSmokeItem(service=service, plugin=plugin_id, status="skipped", message="no runtime smoke is defined for this plugin")


def generated_flask_contract_expected(app_path: Path) -> bool:
    text = app_path.read_text(encoding="utf-8", errors="replace")
    return "Flask(" in text and "ROUTES =" in text


def run_service_contract_smoke(service: str, module: Any, client: Any) -> PluginRuntimeSmokeItem | None:
    if not hasattr(module, "ROUTES"):
        return None
    try:
        response = client.get("/api/routes")
        data = response.get_json(silent=True) or {}
        routes = data.get("routes")
        return assert_condition(service, "service-contract", response.status_code == 200 and isinstance(routes, list), "/api/routes", response)
    except Exception as exc:  # noqa: BLE001 - smoke report should preserve route failures.
        return PluginRuntimeSmokeItem(service=service, plugin="service-contract", status="failed", message=str(exc), endpoint="/api/routes")


def assert_condition(service: str, plugin_id: str, ok: bool, endpoint: str, response: Any) -> PluginRuntimeSmokeItem:
    if ok:
        return PluginRuntimeSmokeItem(service=service, plugin=plugin_id, status="passed", endpoint=endpoint)
    body = response.get_data(as_text=True)[:500] if hasattr(response, "get_data") else ""
    return PluginRuntimeSmokeItem(
        service=service,
        plugin=plugin_id,
        status="failed",
        endpoint=endpoint,
        message=f"unexpected response status={getattr(response, 'status_code', 'unknown')} body={body}",
    )


def aggregate_runtime_status(items: list[PluginRuntimeSmokeItem]) -> Literal["passed", "warning", "failed"]:
    if any(item.status == "failed" for item in items):
        return "failed"
    if any(item.status in {"warning", "skipped"} for item in items):
        return "warning"
    return "passed"


def plugin_runtime_smoke_to_markdown(report: PluginRuntimeSmokeReport) -> str:
    lines = [
        f"# Plugin Runtime Smoke Report - {report.lab_id}",
        "",
        f"- Status: `{report.status}`",
        f"- Checked plugin instances: `{len(report.items)}`",
        "",
        "| Service | Plugin | Status | Endpoint | Evidence | Unlocked | Message |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in report.items:
        message = item.message.replace("|", "\\|") if item.message else "-"
        evidence = ", ".join(item.emitted_evidence) or "-"
        unlocked = ", ".join(item.unlocked_stages) or "-"
        lines.append(f"| `{item.service}` | `{item.plugin}` | {item.status} | `{item.endpoint or '-'}` | {evidence} | {unlocked} | {message} |")
    lines.append("")
    return "\n".join(lines)


def plugin_runtime_smoke_to_json(report: PluginRuntimeSmokeReport) -> str:
    return report.model_dump_json(indent=2)
