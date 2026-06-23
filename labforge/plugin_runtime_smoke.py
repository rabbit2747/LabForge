from __future__ import annotations

import importlib.util
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


class PluginRuntimeSmokeReport(PluginRuntimeSmokeModel):
    lab_id: str
    status: Literal["passed", "warning", "failed"]
    items: list[PluginRuntimeSmokeItem] = Field(default_factory=list)


def run_plugin_runtime_smoke(spec: LabSpec, out: Path | None = None) -> PluginRuntimeSmokeReport:
    items: list[PluginRuntimeSmokeItem] = []
    for artifact in declared_service_artifacts(spec):
        service_root = spec.root / artifact.source_path
        plugins = declared_vulnerability_plugins(artifact)
        if not plugins:
            continue
        app_path = service_root / "app.py"
        if not app_path.exists():
            for plugin in plugins:
                plugin_id = normalize_template_id(str(plugin.get("id", "")))
                if plugin_id in SUPPORTED_VULNERABILITY_SCAFFOLDS:
                    items.append(
                        PluginRuntimeSmokeItem(
                            service=artifact.service,
                            plugin=plugin_id,
                            status="failed",
                            message="app.py is missing; run `labforge services materialize` first.",
                        )
                    )
            continue
        module, load_error = load_generated_app_module(artifact.service, app_path)
        if load_error:
            for plugin in plugins:
                plugin_id = normalize_template_id(str(plugin.get("id", "")))
                if plugin_id in SUPPORTED_VULNERABILITY_SCAFFOLDS:
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
        client = module.app.test_client()
        for plugin in plugins:
            plugin_id = normalize_template_id(str(plugin.get("id", "")))
            if plugin_id not in SUPPORTED_VULNERABILITY_SCAFFOLDS:
                continue
            items.append(run_single_plugin_smoke(artifact.service, plugin_id, client))

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
    logs = root / "logs"
    patches = {
        "STATE_DIR": state,
        "LOG_PATH": logs / "service-events.jsonl",
        "REVIEW_ITEMS_PATH": state / "stored-xss-review-items.json",
        "BUILD_JOBS_PATH": state / "build-pipeline-jobs.json",
        "UPDATE_CHANNELS_PATH": state / "signed-update-channels.json",
        "CUSTOMER_UPDATE_STATE_PATH": state / "customer-update-state.json",
    }
    for name, value in patches.items():
        if hasattr(module, name):
            setattr(module, name, value)


def run_single_plugin_smoke(service: str, plugin_id: str, client: Any) -> PluginRuntimeSmokeItem:
    try:
        if plugin_id == "ssti-preview":
            response = client.post("/labforge/scaffold/ssti-preview", json={"body": "{{ 7*7 }}"})
            data = response.get_json(silent=True) or {}
            return assert_condition(service, plugin_id, response.status_code == 200 and data.get("preview") == "49", "/labforge/scaffold/ssti-preview", response)
        if plugin_id == "stored-xss-review":
            created = client.post("/labforge/scaffold/review-items", json={"title": "Smoke", "body": "<b>stored</b>"})
            data = created.get_json(silent=True) or {}
            item_id = data.get("id", "")
            opened = client.get(f"/labforge/scaffold/reviewer/items/{item_id}") if item_id else created
            return assert_condition(service, plugin_id, created.status_code == 201 and opened.status_code == 200 and "stored" in opened.get_data(as_text=True), "/labforge/scaffold/review-items", opened)
        if plugin_id == "idor-object-access":
            response = client.get("/labforge/scaffold/objects/obj-9001?owner=learner")
            data = response.get_json(silent=True) or {}
            return assert_condition(service, plugin_id, response.status_code == 200 and "LABFORGE_SYNTHETIC_OBJECT" in str(data.get("content", "")), "/labforge/scaffold/objects/obj-9001", response)
        if plugin_id == "ssrf-internal-fetch":
            response = client.get("/labforge/scaffold/fetch?url=http://169.254.169.254/latest")
            data = response.get_json(silent=True) or {}
            return assert_condition(service, plugin_id, response.status_code == 400 and data.get("allowed") is False, "/labforge/scaffold/fetch", response)
        if plugin_id == "diagnostic-command-injection":
            response = client.post("/labforge/scaffold/diagnostics/run", json={"command": "id"})
            data = response.get_json(silent=True) or {}
            return assert_condition(service, plugin_id, response.status_code == 200 and data.get("accepted") is True, "/labforge/scaffold/diagnostics/run", response)
        if plugin_id == "build-pipeline-abuse":
            response = client.post(
                "/labforge/scaffold/build/jobs",
                json={"repo": "smoke/product-agent", "ref": "refs/heads/release/smoke", "channel": "smoke", "support_patch_ref": "lab://smoke.patch"},
            )
            data = response.get_json(silent=True) or {}
            return assert_condition(service, plugin_id, response.status_code == 201 and data.get("status") == "built" and "canonical_manifest" in data, "/labforge/scaffold/build/jobs", response)
        if plugin_id == "signed-update-publish":
            manifest = {
                "product": "product-agent",
                "channel": "smoke",
                "version": "0.0.0",
                "build_id": "build-smoke",
                "artifact": {"name": "smoke.tar", "sha256": "0" * 64, "url": "http://build-server/smoke.tar", "size_bytes": 1},
            }
            signed = client.post("/labforge/scaffold/sign", json={"canonical_manifest": manifest})
            signed_data = signed.get_json(silent=True) or {}
            published = client.post("/labforge/scaffold/publish", json={"channel": "smoke", "signed_manifest": signed_data.get("signed_manifest")})
            return assert_condition(service, plugin_id, signed.status_code == 200 and published.status_code == 201, "/labforge/scaffold/sign + /publish", published)
        if plugin_id == "customer-update-callback":
            pre = client.get("/labforge/scaffold/customer/export")
            response = client.post(
                "/labforge/scaffold/customer/poll",
                json={"manifest": {"product": "product-agent", "channel": "smoke", "build_id": "build-smoke", "artifact": {}, "signature": "smoke"}},
            )
            export = client.get("/labforge/scaffold/customer/export")
            data = export.get_json(silent=True) or {}
            return assert_condition(service, plugin_id, pre.status_code == 403 and response.status_code == 202 and export.status_code == 200 and data.get("content") == "LABFORGE_SUPPLY_CHAIN_FINAL_OBJECT", "/labforge/scaffold/customer/poll", export)
    except Exception as exc:  # noqa: BLE001 - smoke report should preserve route failures.
        return PluginRuntimeSmokeItem(service=service, plugin=plugin_id, status="failed", message=str(exc))
    return PluginRuntimeSmokeItem(service=service, plugin=plugin_id, status="skipped", message="no runtime smoke is defined for this plugin")


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
        "| Service | Plugin | Status | Endpoint | Message |",
        "|---|---|---|---|---|",
    ]
    for item in report.items:
        message = item.message.replace("|", "\\|") if item.message else "-"
        lines.append(f"| `{item.service}` | `{item.plugin}` | {item.status} | `{item.endpoint or '-'}` | {message} |")
    lines.append("")
    return "\n".join(lines)


def plugin_runtime_smoke_to_json(report: PluginRuntimeSmokeReport) -> str:
    return report.model_dump_json(indent=2)
