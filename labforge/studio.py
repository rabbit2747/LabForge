from __future__ import annotations

from datetime import datetime
import json
import platform
import socket
import subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from pydantic import BaseModel, ConfigDict, Field

from .agent_adapters import get_agent_adapter
from .design import (
    apply_design_fix_results,
    create_design_fix_task_packages,
    create_design_fix_tasks,
    create_design_workspace_from_prompt,
    review_design_fix_results,
    review_design_workspace,
)
from .intake import normalize_prompt_text, slugify
from .io import load_yaml
from .model import LabSpec
from .pipeline import create_lab_pipeline
from .provider_lifecycle import provider_lifecycle, render_lifecycle_result
from .qa import run_release_gate
from .service_blueprints import inspect_service_implementation_status
from .verified_mvp import write_verified_mvp_manifest


class StudioModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class StudioScenarioSummary(StudioModel):
    scenario_id: str
    title: str
    industry: str = "enterprise"
    status: str = "draft"
    realism_score: int | None = None
    path: str
    updated_at: str = ""
    steps: list[dict[str, str | bool]] = Field(default_factory=list)
    fix_tasks: list[dict] = Field(default_factory=list)


class StudioState(StudioModel):
    workspace: str
    scenarios: list[StudioScenarioSummary] = Field(default_factory=list)


def run_studio(host: str, port: int, workspace: Path) -> None:
    workspace.mkdir(parents=True, exist_ok=True)

    class Handler(StudioRequestHandler):
        studio_workspace = workspace.resolve()

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"LabForge Studio listening on http://{host}:{port}")
    print(f"Workspace: {workspace.resolve()}")
    server.serve_forever()


class StudioRequestHandler(BaseHTTPRequestHandler):
    studio_workspace: Path

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_html(render_studio_html())
            return
        if parsed.path == "/api/scenarios":
            self.send_json(studio_state(self.studio_workspace).model_dump())
            return
        if parsed.path.startswith("/api/scenarios/"):
            parts = parsed.path.strip("/").split("/")
            if len(parts) == 3:
                self.send_json(read_scenario_detail(self.studio_workspace, parts[2]))
                return
            if len(parts) == 4 and parts[3] == "file":
                query = parse_qs(parsed.query)
                self.send_text(read_scenario_file(self.studio_workspace, parts[2], query.get("path", [""])[0]))
                return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlparse(self.path)
        try:
            payload = self.read_json_body()
            if parsed.path == "/api/scenarios":
                self.send_json(create_scenario(self.studio_workspace, payload), status=HTTPStatus.CREATED)
                return
            if parsed.path == "/api/scenarios/pipeline":
                self.send_json(create_pipeline_scenario(self.studio_workspace, payload), status=HTTPStatus.CREATED)
                return
            if parsed.path == "/api/scenarios/mvp":
                self.send_json(create_verified_mvp_scenario(self.studio_workspace, payload), status=HTTPStatus.CREATED)
                return
            if parsed.path.startswith("/api/scenarios/") and parsed.path.endswith("/review"):
                scenario_id = parsed.path.strip("/").split("/")[2]
                self.send_json(review_scenario(self.studio_workspace, scenario_id, payload))
                return
            if parsed.path.startswith("/api/scenarios/") and parsed.path.endswith("/tasks"):
                scenario_id = parsed.path.strip("/").split("/")[2]
                self.send_json(generate_fix_tasks(self.studio_workspace, scenario_id))
                return
            if parsed.path.startswith("/api/scenarios/") and parsed.path.endswith("/package-tasks"):
                scenario_id = parsed.path.strip("/").split("/")[2]
                self.send_json(package_fix_tasks(self.studio_workspace, scenario_id, payload))
                return
            if parsed.path.startswith("/api/scenarios/") and parsed.path.endswith("/review-fix-results"):
                scenario_id = parsed.path.strip("/").split("/")[2]
                self.send_json(review_fix_results(self.studio_workspace, scenario_id))
                return
            if parsed.path.startswith("/api/scenarios/") and parsed.path.endswith("/apply-fix-results"):
                scenario_id = parsed.path.strip("/").split("/")[2]
                self.send_json(apply_fix_results(self.studio_workspace, scenario_id, payload))
                return
            if parsed.path.startswith("/api/scenarios/") and parsed.path.endswith("/lifecycle"):
                scenario_id = parsed.path.strip("/").split("/")[2]
                self.send_json(run_package_lifecycle(self.studio_workspace, scenario_id, payload))
                return
            if parsed.path.startswith("/api/scenarios/") and parsed.path.endswith("/release-gate"):
                scenario_id = parsed.path.strip("/").split("/")[2]
                self.send_json(run_release_gate_for_scenario(self.studio_workspace, scenario_id, payload))
                return
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:  # noqa: BLE001 - UI should surface framework errors.
            self.send_json({"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        if not raw.strip():
            return {}
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("JSON object expected")
        return data

    def send_json(self, payload: dict, *, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[studio] {self.address_string()} - {format % args}")


def studio_state(workspace: Path) -> StudioState:
    scenarios = [summarize_scenario(path) for path in sorted(workspace.iterdir()) if path.is_dir()]
    return StudioState(workspace=str(workspace), scenarios=scenarios)


def summarize_scenario(path: Path) -> StudioScenarioSummary:
    scenario_yaml = path / "lab" / "scenario.yaml"
    review_yaml = path / "review" / "design-review-report.yaml"
    realism_json = path / "review" / "realism-report.json"
    title = path.name
    industry = "enterprise"
    status = "created"
    realism_score = None
    if scenario_yaml.exists():
        scenario = load_yaml(scenario_yaml)
        title = str(scenario.get("title", title))
        industry = str(scenario.get("target_industry", industry))
        status = "draft-lab"
    if review_yaml.exists():
        review = load_yaml(review_yaml)
        status = str(review.get("status", "reviewed"))
        score = review.get("realism_score")
        realism_score = int(score) if isinstance(score, int) else realism_score
    if realism_json.exists() and realism_score is None:
        try:
            data = json.loads(realism_json.read_text(encoding="utf-8"))
            score = data.get("overall_score")
            realism_score = int(score) if isinstance(score, int) else None
        except Exception:  # noqa: BLE001 - score is optional UI metadata.
            realism_score = None
    updated_at = datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
    return StudioScenarioSummary(
        scenario_id=path.name,
        title=title,
        industry=industry,
        status=status,
        realism_score=realism_score,
        path=str(path),
        updated_at=updated_at,
        steps=scenario_steps(path),
    )


def scenario_steps(path: Path) -> list[dict[str, str | bool]]:
    checks = [
        ("Source prompt", path / "lab" / "scenario-prompt.md"),
        ("Pipeline result", path / "pipeline-summary.md"),
        ("Pipeline gate", path / "pipeline-gate.md"),
        ("Draft lab", path / "lab" / "scenario.yaml"),
        ("Agent workspace", path / "agents" / ".ai" / "orchestration-plan.yaml"),
        ("Run packages", path / "agents" / ".ai" / "run" / "run-plan.yaml"),
        ("Design review", path / "review" / "design-review-report.md"),
        ("Fix tasks", path / "review" / "design-fix-tasks.md"),
        ("Fix packages", path / "review" / "fix-agent-package-report.md"),
        ("Fix result review", path / "review" / "fix-result-review.md"),
        ("Fix apply report", path / "review" / "fix-apply-report.md"),
        ("Service status", path / "service-status" / "service-status.md"),
        ("Plugin smoke", path / "plugin-runtime-smoke" / "plugin-runtime-smoke.md"),
        ("Supervisor package", path / "supervisor-package" / "package-report.md"),
        ("Quickstart", path / "supervisor-package" / "generated" / "QUICKSTART.md"),
        ("Endpoints", path / "supervisor-package" / "generated" / "endpoints.json"),
        ("Release gate", path / "release-gate" / "release-gate-report.md"),
        ("Verified MVP", path / "mvp" / "verified-mvp.md"),
    ]
    return [{"name": name, "complete": item.exists(), "path": str(item)} for name, item in checks]


def create_scenario(workspace: Path, payload: dict) -> dict:
    prompt = normalize_prompt_text(str(payload.get("prompt", "")))
    if not prompt:
        raise ValueError("prompt is required")
    title = normalize_prompt_text(str(payload.get("title", ""))) or None
    industry = str(payload.get("industry", "")).strip() or None
    provider = str(payload.get("provider", "auto")).strip() or "auto"
    adapter = str(payload.get("adapter", "manual")).strip() or "manual"
    scenario_id = unique_scenario_id(workspace, str(payload.get("lab_id", "")).strip() or title or prompt)
    target = workspace / scenario_id
    create_design_workspace_from_prompt(
        target,
        prompt=prompt,
        lab_id=scenario_id,
        title=title,
        industry=industry,
        provider=provider,
        adapter=adapter,
        force=True,
    )
    return read_scenario_detail(workspace, scenario_id)


def create_pipeline_scenario(workspace: Path, payload: dict) -> dict:
    prompt = normalize_prompt_text(str(payload.get("prompt", "")))
    if not prompt:
        raise ValueError("prompt is required")
    title = normalize_prompt_text(str(payload.get("title", ""))) or None
    industry = str(payload.get("industry", "")).strip() or None
    provider = str(payload.get("provider", "auto")).strip() or "auto"
    adapter = str(payload.get("adapter", "manual")).strip() or "manual"
    scenario_id = unique_scenario_id(workspace, str(payload.get("lab_id", "")).strip() or title or prompt)
    target = workspace / scenario_id
    create_lab_pipeline(
        target,
        prompt=prompt,
        lab_id=scenario_id,
        title=title,
        industry=industry,
        provider=provider,
        adapter=adapter,
        force=True,
    )
    return read_scenario_detail(workspace, scenario_id)


def create_verified_mvp_scenario(workspace: Path, payload: dict) -> dict:
    detail = create_pipeline_scenario(workspace, payload)
    scenario_id = str(detail["scenario_id"])
    release_provider = str(payload.get("release_provider") or payload.get("provider") or "docker-compose").strip() or "docker-compose"
    if release_provider == "auto":
        release_provider = "docker-compose"
    release_payload = {
        "provider": release_provider,
        "profile": str(payload.get("profile", "protected")).strip() or "protected",
        "materialize": bool(payload.get("materialize", True)),
    }
    run_release_gate_for_scenario(workspace, scenario_id, release_payload)
    write_verified_mvp_manifest(safe_scenario_path(workspace, scenario_id), read_scenario_detail(workspace, scenario_id))
    detail = read_scenario_detail(workspace, scenario_id)
    detail["last_release_gate"] = detail.get("release_gate", {})
    return detail


def review_scenario(workspace: Path, scenario_id: str, payload: dict) -> dict:
    path = safe_scenario_path(workspace, scenario_id)
    industry = str(payload.get("industry", "")).strip() or None
    review_design_workspace(path, out=path / "review", industry=industry, force=True)
    return read_scenario_detail(workspace, scenario_id)


def generate_fix_tasks(workspace: Path, scenario_id: str) -> dict:
    path = safe_scenario_path(workspace, scenario_id)
    create_design_fix_tasks(path, review_dir=path / "review")
    return read_scenario_detail(workspace, scenario_id)


def package_fix_tasks(workspace: Path, scenario_id: str, payload: dict) -> dict:
    path = safe_scenario_path(workspace, scenario_id)
    adapter_name = str(payload.get("adapter", "manual")).strip() or "manual"
    report = create_design_fix_task_packages(path, adapter=adapter_name, review_dir=path / "review")
    adapter = get_agent_adapter(adapter_name)
    for package in report.packages:
        adapter.prepare(Path(package["package_file"]))
    return read_scenario_detail(workspace, scenario_id)


def review_fix_results(workspace: Path, scenario_id: str) -> dict:
    path = safe_scenario_path(workspace, scenario_id)
    review_design_fix_results(path, review_dir=path / "review")
    return read_scenario_detail(workspace, scenario_id)


def apply_fix_results(workspace: Path, scenario_id: str, payload: dict) -> dict:
    path = safe_scenario_path(workspace, scenario_id)
    execute = bool(payload.get("execute", False))
    force = bool(payload.get("force", False))
    task = str(payload.get("task", "")).strip() or None
    apply_design_fix_results(path, review_dir=path / "review", task_id=task, execute=execute, force=force)
    return read_scenario_detail(workspace, scenario_id)


def run_package_lifecycle(workspace: Path, scenario_id: str, payload: dict) -> dict:
    path = safe_scenario_path(workspace, scenario_id)
    action = str(payload.get("action", "")).strip().lower()
    if action not in {"validate", "start", "healthcheck", "status", "stop"}:
        raise ValueError("unsupported lifecycle action")
    generated_dir = path / "supervisor-package" / "generated"
    if not generated_dir.exists():
        raise ValueError("supervisor package has not been generated")

    lifecycle_dir = path / "supervisor-package" / "lifecycle"
    lifecycle_dir.mkdir(parents=True, exist_ok=True)

    if action == "validate":
        result = provider_lifecycle(generated_dir, provider="docker-compose", action="validate", execute=True, timeout_seconds=120)
        result_payload = result.model_dump()
        report = render_lifecycle_result(result)
    elif action == "start":
        env_overrides = allocate_port_overrides(generated_dir)
        result = provider_lifecycle(
            generated_dir,
            provider="docker-compose",
            action="deploy",
            execute=True,
            timeout_seconds=240,
            env_overrides=env_overrides,
        )
        result_payload = result.model_dump()
        if env_overrides:
            result_payload["env_overrides"] = env_overrides
        if result.status == "completed":
            runtime_state = write_runtime_state(path, generated_dir, env_overrides, active=True)
            result_payload["runtime_state"] = runtime_state
        report = render_lifecycle_result(result)
        if env_overrides:
            report += "\n## Environment Overrides\n\n" + "\n".join(f"- `{key}={value}`" for key, value in env_overrides.items()) + "\n"
    elif action == "stop":
        result = provider_lifecycle(generated_dir, provider="docker-compose", action="destroy", execute=True, remove_volumes=False, timeout_seconds=120)
        result_payload = result.model_dump()
        if result.status == "completed":
            runtime_state = write_runtime_state(path, generated_dir, read_runtime_overrides(path), active=False)
            result_payload["runtime_state"] = runtime_state
        report = render_lifecycle_result(result)
    elif action == "status":
        result = provider_lifecycle(generated_dir, provider="docker-compose", action="status", execute=True, timeout_seconds=60)
        result_payload = result.model_dump()
        report = render_lifecycle_result(result)
    else:
        result_payload = run_service_healthcheck(generated_dir, timeout_seconds=180)
        report = lifecycle_payload_to_markdown(result_payload)

    report_path = lifecycle_dir / f"studio-{action}-last.md"
    json_path = lifecycle_dir / f"studio-{action}-last.json"
    report_path.write_text(report, encoding="utf-8", newline="\n")
    json_path.write_text(json.dumps(result_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    detail = read_scenario_detail(workspace, scenario_id)
    detail["last_lifecycle"] = {
        "action": action,
        "status": result_payload.get("status", "unknown"),
        "report": str(report_path.relative_to(path)),
        "json": str(json_path.relative_to(path)),
        "result": result_payload,
    }
    return detail


def run_release_gate_for_scenario(workspace: Path, scenario_id: str, payload: dict) -> dict:
    path = safe_scenario_path(workspace, scenario_id)
    lab_dir = path / "lab"
    if not (lab_dir / "scenario.yaml").exists():
        raise ValueError("lab scenario.yaml has not been generated")
    provider = str(payload.get("provider", "docker-compose")).strip() or "docker-compose"
    profile = str(payload.get("profile", "protected")).strip() or "protected"
    materialize = bool(payload.get("materialize", True))
    agent_result_dir = path / "agents" / ".ai" / "outputs"
    report = run_release_gate(
        lab_dir,
        path / "release-gate",
        provider=provider,
        profile=profile,
        materialize=materialize,
        force=True,
        agent_result_dir=agent_result_dir if agent_result_dir.exists() else None,
    )
    detail = read_scenario_detail(workspace, scenario_id)
    detail["last_release_gate"] = release_gate_payload(path, report.model_dump())
    return detail


def run_service_healthcheck(generated_dir: Path, *, timeout_seconds: int) -> dict:
    command = fixed_script_command(generated_dir, "services-healthcheck")
    if not command:
        return {
            "provider": "docker-compose",
            "action": "healthcheck",
            "mode": "execute",
            "status": "failed",
            "output_dir": str(generated_dir.resolve()),
            "commands": [],
            "stdout": "",
            "stderr": "",
            "message": "services-healthcheck script was not found.",
        }
    try:
        completed = subprocess.run(
            command,
            cwd=generated_dir,
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
        return {
            "provider": "docker-compose",
            "action": "healthcheck",
            "mode": "execute",
            "status": "failed",
            "output_dir": str(generated_dir.resolve()),
            "commands": [command],
            "stdout": stdout,
            "stderr": stderr,
            "message": f"Command timed out after {timeout_seconds}s.",
        }
    return {
        "provider": "docker-compose",
        "action": "healthcheck",
        "mode": "execute",
        "status": "completed" if completed.returncode == 0 else "failed",
        "output_dir": str(generated_dir.resolve()),
        "commands": [command],
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "message": "" if completed.returncode == 0 else f"Command failed with exit code {completed.returncode}.",
    }


def allocate_port_overrides(generated_dir: Path) -> dict[str, str]:
    manifest_path = generated_dir / "endpoints.json"
    if not manifest_path.exists():
        return {}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - start can continue without auto overrides.
        return {}
    endpoints = manifest.get("published_endpoints", [])
    if not isinstance(endpoints, list):
        return {}
    overrides: dict[str, str] = {}
    reserved: set[int] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        env_name = endpoint.get("override_env")
        default_port = endpoint.get("default_host_port")
        if not env_name or not isinstance(default_port, int):
            continue
        if is_port_available(default_port, reserved):
            reserved.add(default_port)
            continue
        replacement = find_available_port(19000, reserved)
        overrides[str(env_name)] = str(replacement)
        reserved.add(replacement)
    return overrides


def write_runtime_state(path: Path, generated_dir: Path, env_overrides: dict[str, str], *, active: bool) -> dict:
    manifest = read_endpoint_manifest_from_generated(generated_dir)
    state = {
        "active": active,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "env_overrides": env_overrides,
        "effective_endpoints": apply_endpoint_overrides(manifest, env_overrides).get("published_endpoints", []),
    }
    state_path = runtime_state_path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return state


def read_runtime_state(path: Path) -> dict:
    state_path = runtime_state_path(path)
    if not state_path.exists():
        return {"active": False, "env_overrides": {}, "effective_endpoints": []}
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - runtime state is optional UI metadata.
        return {"active": False, "env_overrides": {}, "effective_endpoints": [], "error": "runtime state could not be parsed"}
    if not isinstance(data, dict):
        return {"active": False, "env_overrides": {}, "effective_endpoints": [], "error": "runtime state is not an object"}
    data.setdefault("active", False)
    data.setdefault("env_overrides", {})
    data.setdefault("effective_endpoints", [])
    return data


def read_runtime_overrides(path: Path) -> dict[str, str]:
    state = read_runtime_state(path)
    overrides = state.get("env_overrides", {})
    if not isinstance(overrides, dict):
        return {}
    return {str(key): str(value) for key, value in overrides.items()}


def runtime_state_path(path: Path) -> Path:
    return path / "supervisor-package" / "lifecycle" / "studio-runtime.json"


def read_endpoint_manifest_from_generated(generated_dir: Path) -> dict:
    manifest_path = generated_dir / "endpoints.json"
    if not manifest_path.exists():
        return {"published_endpoints": [], "internal_services": []}
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - endpoint manifest is optional UI metadata.
        return {"published_endpoints": [], "internal_services": [], "error": "endpoint manifest could not be parsed"}
    if not isinstance(data, dict):
        return {"published_endpoints": [], "internal_services": [], "error": "endpoint manifest is not an object"}
    data.setdefault("published_endpoints", [])
    data.setdefault("internal_services", [])
    return data


def apply_endpoint_overrides(manifest: dict, env_overrides: dict[str, str]) -> dict:
    result = json.loads(json.dumps(manifest))
    published = result.get("published_endpoints", [])
    if not isinstance(published, list):
        result["published_endpoints"] = []
        return result
    for endpoint in published:
        if not isinstance(endpoint, dict):
            continue
        env_name = endpoint.get("override_env")
        if not env_name or env_name not in env_overrides:
            endpoint["effective_host_port"] = endpoint.get("default_host_port")
            endpoint["overridden"] = False
            continue
        try:
            port = int(env_overrides[str(env_name)])
        except ValueError:
            endpoint["effective_host_port"] = endpoint.get("default_host_port")
            endpoint["overridden"] = False
            continue
        endpoint["effective_host_port"] = port
        endpoint["overridden"] = True
        if endpoint.get("protocol") == "ssh":
            user = "attacker" if "attacker" in str(endpoint.get("service", "")) or "workstation" in str(endpoint.get("service", "")) else "lab"
            endpoint["connect"] = f"ssh {user}@127.0.0.1 -p {port}"
        else:
            endpoint["url"] = f"http://127.0.0.1:{port}/"
            endpoint["health_url"] = f"http://127.0.0.1:{port}/healthz"
    return result


def is_port_available(port: int, reserved: set[int]) -> bool:
    if port in reserved:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def find_available_port(start: int, reserved: set[int]) -> int:
    for port in range(start, 65535):
        if is_port_available(port, reserved):
            return port
    raise ValueError("no available TCP port found for Studio lifecycle start")


def fixed_script_command(generated_dir: Path, script_name: str) -> list[str] | None:
    if platform.system().lower() == "windows":
        script = generated_dir / "scripts" / f"{script_name}.ps1"
        if script.exists():
            return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)]
    script = generated_dir / "scripts" / f"{script_name}.sh"
    if script.exists():
        return ["sh", str(script)]
    return None


def lifecycle_payload_to_markdown(result: dict) -> str:
    lines = [
        "# Provider Lifecycle Result",
        "",
        f"- Provider: `{result.get('provider', '-')}`",
        f"- Action: `{result.get('action', '-')}`",
        f"- Mode: `{result.get('mode', '-')}`",
        f"- Status: `{result.get('status', '-')}`",
        f"- Output directory: `{result.get('output_dir', '-')}`",
        f"- Host OS: `{platform.system()}`",
        "",
        "## Commands",
        "",
    ]
    commands = result.get("commands") or []
    if commands:
        lines.extend(f"- `{' '.join(command)}`" for command in commands)
    else:
        lines.append("- No commands planned.")
    if result.get("message"):
        lines += ["", "## Message", "", str(result["message"])]
    if result.get("stdout"):
        lines += ["", "## Stdout", "", "```text", str(result["stdout"]).strip(), "```"]
    if result.get("stderr"):
        lines += ["", "## Stderr", "", "```text", str(result["stderr"]).strip(), "```"]
    lines.append("")
    return "\n".join(lines)


def read_scenario_detail(workspace: Path, scenario_id: str) -> dict:
    path = safe_scenario_path(workspace, scenario_id)
    summary = summarize_scenario(path).model_dump()
    summary["reports"] = available_reports(path)
    summary["fix_tasks"] = read_fix_tasks(path)
    summary["service_status"] = read_service_status(path)
    summary["endpoints"] = read_endpoint_manifest(path)
    summary["pipeline_gate"] = read_pipeline_gate_summary(path)
    summary["release_gate"] = read_release_gate_summary(path)
    summary["playtest"] = read_playtest_summary(path)
    return summary


def read_service_status(path: Path) -> list[dict]:
    lab_dir = path / "lab"
    try:
        report = inspect_service_implementation_status(LabSpec.load(lab_dir))
    except Exception:  # noqa: BLE001 - Studio should still render partial workspaces.
        return []
    return [item.model_dump() for item in report.items]


def read_fix_tasks(path: Path) -> list[dict]:
    task_path = path / "review" / "design-fix-tasks.yaml"
    if not task_path.exists():
        return []
    report = load_yaml(task_path)
    tasks = report.get("tasks", [])
    return tasks if isinstance(tasks, list) else []


def available_reports(path: Path) -> list[dict[str, str]]:
    candidates = [
        ("Scenario Prompt", "lab/scenario-prompt.md"),
        ("Pipeline Summary", "pipeline-summary.md"),
        ("Pipeline Gate", "pipeline-gate.md"),
        ("Pipeline Result", "pipeline-result.yaml"),
        ("Design Summary", "design-workspace-summary.md"),
        ("Design Review", "review/design-review-report.md"),
        ("Fix Tasks", "review/design-fix-tasks.md"),
        ("Fix Agent Packages", "review/fix-agent-package-report.md"),
        ("Fix Result Review", "review/fix-result-review.md"),
        ("Fix Apply Report", "review/fix-apply-report.md"),
        ("Service Blueprints", "service-blueprints/service-blueprints.md"),
        ("Service Status", "service-status/service-status.md"),
        ("Service Result Review", "service-result-review/service-result-review.md"),
        ("Plugin Runtime Smoke", "plugin-runtime-smoke/plugin-runtime-smoke.md"),
        ("Stage Chain", "stage-chain/stage-chain.md"),
        ("Stage Chain YAML", "stage-chain/stage-chain.yaml"),
        ("Learner Access", "playtest/learner-access.md"),
        ("Learner Playtest", "playtest/playtest-report.md"),
        ("Playtest Walkthrough", "playtest/playtest-walkthrough.md"),
        ("Learner Playtest YAML", "playtest/playtest-report.yaml"),
        ("Supervisor Package", "supervisor-package/package-report.md"),
        ("Quickstart", "supervisor-package/generated/QUICKSTART.md"),
        ("Endpoint Manifest", "supervisor-package/generated/endpoints.json"),
        ("Last Validate", "supervisor-package/lifecycle/studio-validate-last.md"),
        ("Last Start", "supervisor-package/lifecycle/studio-start-last.md"),
        ("Last Healthcheck", "supervisor-package/lifecycle/studio-healthcheck-last.md"),
        ("Last Status", "supervisor-package/lifecycle/studio-status-last.md"),
        ("Last Stop", "supervisor-package/lifecycle/studio-stop-last.md"),
        ("Release Gate", "release-gate/release-gate-report.md"),
        ("Release Gate YAML", "release-gate/release-gate-report.yaml"),
        ("Verified MVP", "mvp/verified-mvp.md"),
        ("Verified MVP JSON", "mvp/verified-mvp.json"),
        ("Provider README", "supervisor-package/generated/README.md"),
        ("Docker Compose", "supervisor-package/generated/docker-compose.yml"),
        ("Workflow Report", "workflow/workflow-report.md"),
        ("Realism Report", "review/realism-report.md"),
        ("Lint Report", "review/lint-report.md"),
        ("Agent Review", "review/agent-review.md"),
    ]
    return [{"name": name, "path": rel} for name, rel in candidates if (path / rel).exists()]


def read_pipeline_gate_summary(path: Path) -> dict:
    report_path = path / "pipeline-gate.yaml"
    if not report_path.exists():
        return {}
    try:
        data = load_yaml(report_path)
    except Exception as exc:  # noqa: BLE001 - optional Studio metadata must not hide the scenario.
        return {"decision": "error", "ready_for_supervisor": False, "ready_for_release_gate": False, "error": str(exc)}
    items = data.get("items", [])
    if not isinstance(items, list):
        items = []
    next_commands = data.get("next_commands", [])
    if not isinstance(next_commands, list):
        next_commands = []
    blockers = [
        item
        for item in items
        if isinstance(item, dict) and str(item.get("status", "")).lower() in {"failed", "missing", "warning"}
    ]
    return {
        "decision": str(data.get("decision", "unknown")),
        "ready_for_supervisor": bool(data.get("ready_for_supervisor", False)),
        "ready_for_release_gate": bool(data.get("ready_for_release_gate", False)),
        "items": items,
        "blockers": blockers,
        "next_commands": [str(command) for command in next_commands],
        "report": "pipeline-gate.md",
        "yaml": "pipeline-gate.yaml",
    }


def read_release_gate_summary(path: Path) -> dict:
    report_path = path / "release-gate" / "release-gate-report.yaml"
    if not report_path.exists():
        return {}
    try:
        return release_gate_payload(path, load_yaml(report_path))
    except Exception as exc:  # noqa: BLE001 - optional Studio metadata must not hide the scenario.
        return {"status": "error", "release_ready": False, "error": str(exc)}


def read_playtest_summary(path: Path) -> dict:
    report_path = path / "playtest" / "playtest-report.yaml"
    if not report_path.exists():
        return {}
    try:
        report = load_yaml(report_path)
    except Exception as exc:  # noqa: BLE001 - optional Studio metadata must not hide the scenario.
        return {"status": "error", "error": str(exc)}
    if not isinstance(report, dict):
        return {}
    return {
        "status": str(report.get("status", "unknown")),
        "learner_entrypoints": report.get("learner_entrypoints", []),
        "attacker_entrypoints": report.get("attacker_entrypoints", []),
        "final_submission_endpoints": report.get("final_submission_endpoints", []),
        "steps": report.get("steps", []),
        "warnings": report.get("warnings", []),
        "failures": report.get("failures", []),
        "report": "playtest/playtest-report.md",
        "access": "playtest/learner-access.md",
    }


def release_gate_payload(path: Path, report: dict) -> dict:
    checks = report.get("checks", [])
    if not isinstance(checks, list):
        checks = []
    return {
        "status": str(report.get("status", "unknown")),
        "release_ready": bool(report.get("release_ready", False)),
        "provider": str(report.get("provider", "")),
        "profile": str(report.get("profile", "")),
        "report": "release-gate/release-gate-report.md",
        "yaml": "release-gate/release-gate-report.yaml",
        "checks": checks,
        "output_dir": str((path / "release-gate").resolve()),
    }


def read_endpoint_manifest(path: Path) -> dict:
    data = read_endpoint_manifest_from_generated(path / "supervisor-package" / "generated")
    runtime = read_runtime_state(path)
    overrides = runtime.get("env_overrides", {})
    if isinstance(overrides, dict) and overrides:
        data = apply_endpoint_overrides(data, {str(key): str(value) for key, value in overrides.items()})
    data["runtime"] = runtime
    return data


def read_scenario_file(workspace: Path, scenario_id: str, rel_path: str) -> str:
    scenario_path = safe_scenario_path(workspace, scenario_id)
    target = (scenario_path / unquote(rel_path)).resolve()
    if not str(target).startswith(str(scenario_path.resolve())):
        raise ValueError("file path escapes scenario workspace")
    if not target.exists() or not target.is_file():
        raise ValueError("file not found")
    return target.read_text(encoding="utf-8")


def safe_scenario_path(workspace: Path, scenario_id: str) -> Path:
    safe_id = slugify(scenario_id)
    path = (workspace / safe_id).resolve()
    if not str(path).startswith(str(workspace.resolve())) or not path.exists():
        raise ValueError("unknown scenario")
    return path


def unique_scenario_id(workspace: Path, seed: str) -> str:
    base = slugify(seed)[:80] or "scenario"
    candidate = base
    index = 2
    while (workspace / candidate).exists():
        candidate = f"{base}-{index}"
        index += 1
    return candidate


def render_studio_html() -> str:
    return r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LabForge Studio</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --line: #d9dee7;
      --text: #1f2937;
      --muted: #667085;
      --accent: #0f766e;
      --accent-dark: #115e59;
      --warn: #9a3412;
      --fail: #b42318;
      --ok: #167647;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--text); }
    header { height: 56px; display: flex; align-items: center; justify-content: space-between; padding: 0 22px; border-bottom: 1px solid var(--line); background: var(--panel); }
    header h1 { font-size: 18px; margin: 0; font-weight: 700; }
    header span { color: var(--muted); font-size: 13px; }
    main { display: grid; grid-template-columns: 320px minmax(0, 1fr); min-height: calc(100vh - 56px); }
    aside { border-right: 1px solid var(--line); background: #fbfcfd; padding: 16px; overflow: auto; }
    section { padding: 18px 22px; overflow: auto; }
    .toolbar { display: flex; gap: 8px; align-items: center; justify-content: space-between; margin-bottom: 14px; }
    .toolbar h2 { font-size: 15px; margin: 0; }
    button { border: 1px solid var(--line); background: var(--panel); color: var(--text); height: 34px; padding: 0 12px; border-radius: 6px; cursor: pointer; font-weight: 600; }
    button.primary { background: var(--accent); color: white; border-color: var(--accent); }
    button.primary:hover { background: var(--accent-dark); }
    button:disabled { opacity: .55; cursor: wait; }
    input, select, textarea { width: 100%; border: 1px solid var(--line); border-radius: 6px; background: white; color: var(--text); padding: 9px 10px; font: inherit; }
    textarea { min-height: 170px; resize: vertical; line-height: 1.45; }
    label { display: block; font-size: 12px; color: var(--muted); font-weight: 700; margin: 10px 0 5px; }
    .grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
    .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px; margin-bottom: 14px; }
    .scenario { border: 1px solid var(--line); background: white; border-radius: 8px; padding: 12px; margin-bottom: 10px; cursor: pointer; }
    .scenario.active { border-color: var(--accent); box-shadow: inset 3px 0 0 var(--accent); }
    .scenario strong { display: block; font-size: 14px; margin-bottom: 5px; }
    .meta { color: var(--muted); font-size: 12px; display: flex; gap: 8px; flex-wrap: wrap; }
    .status { display: inline-flex; align-items: center; height: 22px; padding: 0 8px; border-radius: 999px; font-size: 12px; font-weight: 700; background: #eef6f5; color: var(--accent-dark); }
    .status.warning, .status.needs-agent-output { background: #fff4ed; color: var(--warn); }
    .status.failed { background: #fff1f3; color: var(--fail); }
    .status.passed { background: #ecfdf3; color: var(--ok); }
    .score { display:inline-flex; align-items:center; height:22px; padding:0 8px; border-radius:6px; background:#eef2ff; color:#3538cd; font-size:12px; font-weight:700; }
    .steps { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 8px; }
    .step { border: 1px solid var(--line); border-radius: 8px; padding: 10px; min-height: 70px; background: #fbfcfd; }
    .step.done { border-color: #9dd6c9; background: #f0fdfa; }
    .step b { display: block; font-size: 13px; margin-bottom: 6px; }
    .step span { color: var(--muted); font-size: 12px; }
    pre { white-space: pre-wrap; overflow: auto; background: #111827; color: #e5e7eb; padding: 14px; border-radius: 8px; min-height: 220px; max-height: 520px; }
    .reports { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; }
    .empty { color: var(--muted); padding: 28px; border: 1px dashed var(--line); border-radius: 8px; background: #fbfcfd; }
    @media (max-width: 900px) {
      main { grid-template-columns: 1fr; }
      aside { border-right: 0; border-bottom: 1px solid var(--line); }
      .grid, .steps { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <h1>LabForge Studio</h1>
    <span id="workspace">Loading workspace...</span>
  </header>
  <main>
    <aside>
      <div class="toolbar">
        <h2>Scenarios</h2>
        <button id="refresh">Refresh</button>
      </div>
      <div id="scenarioList"></div>
    </aside>
    <section>
      <div class="panel">
        <div class="toolbar">
          <h2>Create Scenario</h2>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <button id="createScenario">Create Design</button>
            <button id="createPipeline">Create Full Pipeline</button>
            <button class="primary" id="createMvp">Create Verified MVP</button>
          </div>
        </div>
        <div class="grid">
          <div><label>Title</label><input id="title" placeholder="Brokerage compliance export lab"></div>
          <div><label>Industry</label><select id="industry"><option value="">Auto</option><option>enterprise</option><option>securities</option><option>banking</option><option>healthcare</option><option>manufacturing</option><option>active-directory</option><option>supply-chain</option></select></div>
          <div><label>Adapter</label><select id="adapter"><option>manual</option><option>codex</option><option>claude-code</option><option>openai</option></select></div>
        </div>
        <label>Prompt file</label>
        <input id="promptFile" type="file" accept=".txt,.md,.yaml,.yml">
        <label>Scenario prompt</label>
        <textarea id="prompt" placeholder="Describe the lab you want to build in natural language."></textarea>
      </div>
      <div id="detail" class="empty">Select or create a scenario.</div>
    </section>
  </main>
  <script>
    let scenarios = [];
    let selectedId = null;

    async function api(path, options = {}) {
      const res = await fetch(path, options);
      const text = await res.text();
      let data;
      try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text }; }
      if (!res.ok) throw new Error(data.error || res.statusText);
      return data;
    }

    async function loadScenarios() {
      const state = await api('/api/scenarios');
      document.getElementById('workspace').textContent = state.workspace;
      scenarios = state.scenarios || [];
      renderScenarioList();
      if (selectedId) await selectScenario(selectedId, false);
    }

    function renderScenarioList() {
      const list = document.getElementById('scenarioList');
      if (!scenarios.length) {
        list.innerHTML = '<div class="empty">No scenarios yet.</div>';
        return;
      }
      list.innerHTML = scenarios.map(s => `
        <div class="scenario ${s.scenario_id === selectedId ? 'active' : ''}" data-id="${s.scenario_id}">
          <strong>${escapeHtml(s.title)}</strong>
          <div class="meta"><span>${escapeHtml(s.industry)}</span><span class="status ${escapeHtml(s.status)}">${escapeHtml(s.status)}</span>${scoreBadge(s.realism_score)}</div>
        </div>`).join('');
      list.querySelectorAll('.scenario').forEach(el => el.onclick = () => selectScenario(el.dataset.id));
    }

    async function selectScenario(id, rerender = true) {
      selectedId = id;
      if (rerender) renderScenarioList();
      const detail = await api(`/api/scenarios/${encodeURIComponent(id)}`);
      renderDetail(detail);
    }

    function renderDetail(s) {
      const detail = document.getElementById('detail');
      detail.className = '';
      const reports = (s.reports || []).map(r => `<button data-report="${encodeURIComponent(r.path)}">${escapeHtml(r.name)}</button>`).join('');
      detail.innerHTML = `
        <div class="panel">
          <div class="toolbar">
            <div>
              <h2>${escapeHtml(s.title)}</h2>
              <div class="meta"><span>${escapeHtml(s.scenario_id)}</span><span>${escapeHtml(s.industry)}</span><span class="status ${escapeHtml(s.status)}">${escapeHtml(s.status)}</span>${scoreBadge(s.realism_score)}</div>
            </div>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
              <button id="applyFixResults">Apply Fix Results Dry Run</button>
              <button id="reviewFixResults">Review Fix Results</button>
              <button id="packageTasks">Package Fix Tasks</button>
              <button id="generateTasks">Generate Fix Tasks</button>
              <button class="primary" id="runReview">Run Review</button>
            </div>
          </div>
          <div class="steps">
            ${(s.steps || []).map(step => `<div class="step ${step.complete ? 'done' : ''}"><b>${escapeHtml(step.name)}</b><span>${step.complete ? 'complete' : 'pending'}</span></div>`).join('')}
          </div>
        </div>
        <div class="panel">
          <h2>Reports</h2>
          <div class="reports">${reports || '<span class="meta">No reports yet.</span>'}</div>
          <pre id="reportViewer">Select a report.</pre>
        </div>
        <div class="panel">
          <h2>Generated Endpoints</h2>
          <div id="endpointSummary">${renderEndpoints(s.endpoints || {})}</div>
        </div>
        <div class="panel">
          <h2>Supervisor Gate</h2>
          <div id="pipelineGateSummary">${renderPipelineGateSummary(s.pipeline_gate || {})}</div>
        </div>
        <div class="panel">
          <div class="toolbar">
            <h2>Runtime Lifecycle</h2>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
              <button data-lifecycle="validate">Validate</button>
              <button data-lifecycle="start" class="primary">Start</button>
              <button data-lifecycle="healthcheck">Healthcheck</button>
              <button data-lifecycle="status">Status</button>
              <button data-lifecycle="stop">Stop</button>
            </div>
          </div>
          <pre id="lifecycleViewer">${renderLifecycleSummary(s.last_lifecycle)}</pre>
        </div>
        <div class="panel">
          <div class="toolbar">
            <h2>Release Gate</h2>
            <button id="runReleaseGate" class="primary">Run Release Gate</button>
          </div>
          <div id="releaseGateSummary">${renderReleaseGateSummary(s.last_release_gate || s.release_gate || {})}</div>
        </div>
        <div class="panel">
          <h2>Fix Tasks</h2>
          <div id="fixTasks">${renderFixTasks(s.fix_tasks || [])}</div>
        </div>
        <div class="panel">
          <h2>Service Implementation</h2>
          <div id="serviceStatus">${renderServiceStatus(s.service_status || [])}</div>
        </div>`;
      document.getElementById('runReview').onclick = () => runReview(s.scenario_id);
      document.getElementById('generateTasks').onclick = () => generateTasks(s.scenario_id);
      document.getElementById('packageTasks').onclick = () => packageTasks(s.scenario_id);
      document.getElementById('reviewFixResults').onclick = () => reviewFixResults(s.scenario_id);
      document.getElementById('applyFixResults').onclick = () => applyFixResults(s.scenario_id);
      document.getElementById('runReleaseGate').onclick = () => runReleaseGate(s.scenario_id);
      detail.querySelectorAll('[data-report]').forEach(btn => btn.onclick = () => loadReport(s.scenario_id, decodeURIComponent(btn.dataset.report)));
      detail.querySelectorAll('[data-lifecycle]').forEach(btn => btn.onclick = () => runLifecycle(s.scenario_id, btn.dataset.lifecycle, btn));
    }

    async function runReview(id) {
      const btn = document.getElementById('runReview');
      btn.disabled = true;
      btn.textContent = 'Reviewing...';
      try {
        const detail = await api(`/api/scenarios/${encodeURIComponent(id)}/review`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}' });
        renderDetail(detail);
        await loadScenarios();
      } catch (err) {
        alert(err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Run Review';
      }
    }

    async function generateTasks(id) {
      const btn = document.getElementById('generateTasks');
      btn.disabled = true;
      btn.textContent = 'Generating...';
      try {
        const detail = await api(`/api/scenarios/${encodeURIComponent(id)}/tasks`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}' });
        renderDetail(detail);
        await loadScenarios();
      } catch (err) {
        alert(err.message);
      } finally {
        btn.disabled = false;
      }
    }

    async function packageTasks(id) {
      const btn = document.getElementById('packageTasks');
      btn.disabled = true;
      btn.textContent = 'Packaging...';
      try {
        const detail = await api(`/api/scenarios/${encodeURIComponent(id)}/package-tasks`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ adapter: document.getElementById('adapter').value || 'manual' }) });
        renderDetail(detail);
        await loadScenarios();
      } catch (err) {
        alert(err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Package Fix Tasks';
      }
    }

    async function reviewFixResults(id) {
      const btn = document.getElementById('reviewFixResults');
      btn.disabled = true;
      btn.textContent = 'Reviewing results...';
      try {
        const detail = await api(`/api/scenarios/${encodeURIComponent(id)}/review-fix-results`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}' });
        renderDetail(detail);
        await loadScenarios();
      } catch (err) {
        alert(err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Review Fix Results';
      }
    }

    async function applyFixResults(id) {
      const btn = document.getElementById('applyFixResults');
      btn.disabled = true;
      btn.textContent = 'Dry-running apply...';
      try {
        const detail = await api(`/api/scenarios/${encodeURIComponent(id)}/apply-fix-results`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ execute: false }) });
        renderDetail(detail);
        await loadScenarios();
      } catch (err) {
        alert(err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Apply Fix Results Dry Run';
      }
    }

    async function loadReport(id, path) {
      const res = await fetch(`/api/scenarios/${encodeURIComponent(id)}/file?path=${encodeURIComponent(path)}`);
      document.getElementById('reportViewer').textContent = await res.text();
    }

    async function runLifecycle(id, action, btn) {
      btn.disabled = true;
      const oldText = btn.textContent;
      btn.textContent = `${oldText}...`;
      const viewer = document.getElementById('lifecycleViewer');
      viewer.textContent = `Running ${action}...`;
      try {
        const detail = await api(`/api/scenarios/${encodeURIComponent(id)}/lifecycle`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ action })
        });
        renderDetail(detail);
        await loadScenarios();
      } catch (err) {
        viewer.textContent = err.message;
      } finally {
        btn.disabled = false;
        btn.textContent = oldText;
      }
    }

    async function runReleaseGate(id) {
      const btn = document.getElementById('runReleaseGate');
      btn.disabled = true;
      btn.textContent = 'Running...';
      const summary = document.getElementById('releaseGateSummary');
      summary.innerHTML = '<div class="empty">Running strict release readiness checks...</div>';
      try {
        const detail = await api(`/api/scenarios/${encodeURIComponent(id)}/release-gate`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ provider: 'docker-compose', profile: 'protected', materialize: true })
        });
        renderDetail(detail);
        await loadScenarios();
      } catch (err) {
        summary.innerHTML = `<div class="empty">${escapeHtml(err.message)}</div>`;
      } finally {
        btn.disabled = false;
        btn.textContent = 'Run Release Gate';
      }
    }

    document.getElementById('promptFile').addEventListener('change', async (event) => {
      const file = event.target.files[0];
      if (file) document.getElementById('prompt').value = await file.text();
    });

    document.getElementById('createScenario').onclick = async () => {
      const btn = document.getElementById('createScenario');
      btn.disabled = true;
      btn.textContent = 'Creating...';
      try {
        const detail = await api('/api/scenarios', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            title: document.getElementById('title').value,
            industry: document.getElementById('industry').value,
            adapter: document.getElementById('adapter').value,
            prompt: document.getElementById('prompt').value
          })
        });
        selectedId = detail.scenario_id;
        await loadScenarios();
        renderDetail(detail);
      } catch (err) {
        alert(err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Create Design';
      }
    };

    document.getElementById('createPipeline').onclick = async () => {
      const btn = document.getElementById('createPipeline');
      btn.disabled = true;
      btn.textContent = 'Running pipeline...';
      try {
        const detail = await api('/api/scenarios/pipeline', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            title: document.getElementById('title').value,
            industry: document.getElementById('industry').value,
            adapter: document.getElementById('adapter').value,
            prompt: document.getElementById('prompt').value
          })
        });
        selectedId = detail.scenario_id;
        await loadScenarios();
        renderDetail(detail);
      } catch (err) {
        alert(err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Create Full Pipeline';
      }
    };

    document.getElementById('createMvp').onclick = async () => {
      const btn = document.getElementById('createMvp');
      btn.disabled = true;
      btn.textContent = 'Creating verified MVP...';
      try {
        const detail = await api('/api/scenarios/mvp', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            title: document.getElementById('title').value,
            industry: document.getElementById('industry').value,
            adapter: document.getElementById('adapter').value,
            prompt: document.getElementById('prompt').value
          })
        });
        selectedId = detail.scenario_id;
        await loadScenarios();
        renderDetail(detail);
      } catch (err) {
        alert(err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Create Verified MVP';
      }
    };

    document.getElementById('refresh').onclick = loadScenarios;
    function renderFixTasks(tasks) {
      if (!tasks.length) return '<div class="empty">No fix tasks generated yet.</div>';
      return `<table style="width:100%; border-collapse:collapse;">
        <thead><tr><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">ID</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Agent</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Status</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Task</th></tr></thead>
        <tbody>${tasks.map(t => `<tr>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><code>${escapeHtml(t.task_id)}</code></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;">${escapeHtml(t.assigned_agent)}</td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><span class="status">${escapeHtml(t.status)}</span></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><b>${escapeHtml(t.title)}</b><br><span class="meta">${escapeHtml(t.required_action)}</span></td>
        </tr>`).join('')}</tbody>
      </table>`;
    }

    function renderServiceStatus(items) {
      if (!items.length) return '<div class="empty">No service artifacts found yet.</div>';
      return `<table style="width:100%; border-collapse:collapse;">
        <thead><tr><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Service</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Role</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Status</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Checks</th></tr></thead>
        <tbody>${items.map(item => `<tr>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><code>${escapeHtml(item.service)}</code><br><span class="meta">${escapeHtml(item.source_path)}</span></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;">${escapeHtml(item.role)}</td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><span class="status">${escapeHtml(item.status)}</span></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><span class="meta">blueprint=${item.blueprint} scaffold=${item.scaffold} runtime=${item.runtime} tests=${item.tests}</span></td>
        </tr>`).join('')}</tbody>
      </table>`;
    }
    function renderEndpoints(manifest) {
      const published = manifest.published_endpoints || [];
      const internal = manifest.internal_services || [];
      if (!published.length && !internal.length) return '<div class="empty">No generated endpoint manifest yet. Run Create Full Pipeline or open a pipeline workspace with a supervisor package.</div>';
      const runtime = manifest.runtime || {};
      const runtimeBanner = runtime.updated_at ? `<div class="meta" style="margin-bottom:10px;"><span class="status ${runtime.active ? 'passed' : ''}">runtime ${runtime.active ? 'active' : 'stopped'}</span><span>updated ${escapeHtml(runtime.updated_at)}</span></div>` : '';
      const publishedRows = published.length ? published.map(item => {
        const main = item.connect || item.url || '-';
        const health = item.health_url ? `<br><span class="meta">health ${escapeHtml(item.health_url)}</span>` : '';
        const portNote = item.overridden ? `<br><span class="meta">default ${escapeHtml(item.default_host_port)} -> active ${escapeHtml(item.effective_host_port)}</span>` : '';
        return `<tr>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><code>${escapeHtml(item.service)}</code><br><span class="meta">${escapeHtml(item.role)}</span></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><code>${escapeHtml(item.protocol)}</code></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><code>${escapeHtml(main)}</code>${health}${portNote}</td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><code>${escapeHtml(item.override_env || '-')}</code></td>
        </tr>`;
      }).join('') : '<tr><td colspan="4" style="padding:8px;">No published endpoints.</td></tr>';
      const internalRows = internal.length ? internal.map(item => `<tr>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><code>${escapeHtml(item.service)}</code><br><span class="meta">${escapeHtml(item.role)}</span></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><code>${escapeHtml(item.dns || item.service)}</code></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;">${escapeHtml((item.networks || []).join(', ') || '-')}</td>
        </tr>`).join('') : '<tr><td colspan="3" style="padding:8px;">No internal services.</td></tr>';
      return `
        ${runtimeBanner}
        <h3 style="font-size:14px;margin:0 0 8px;">Published</h3>
        <table style="width:100%; border-collapse:collapse; margin-bottom:14px;">
          <thead><tr><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Service</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Protocol</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Connect</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Override</th></tr></thead>
          <tbody>${publishedRows}</tbody>
        </table>
        <h3 style="font-size:14px;margin:0 0 8px;">Internal DNS</h3>
        <table style="width:100%; border-collapse:collapse;">
          <thead><tr><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Service</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">DNS</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Networks</th></tr></thead>
          <tbody>${internalRows}</tbody>
        </table>`;
    }
    function renderPipelineGateSummary(gate) {
      if (!gate || !gate.decision) return '<div class="empty">No pipeline gate has been generated yet.</div>';
      const blockers = gate.blockers || [];
      const nextCommands = gate.next_commands || [];
      const blockerRows = blockers.length ? blockers.map(item => {
        const evidence = (item.evidence || []).join(' | ') || '-';
        return `<tr>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><code>${escapeHtml(item.name)}</code></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><span class="status ${item.status === 'passed' ? 'passed' : ''}">${escapeHtml(item.status)}</span></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><span class="meta">${escapeHtml(evidence)}</span></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><span class="meta">${escapeHtml(item.required_action || '-')}</span></td>
        </tr>`;
      }).join('') : '<tr><td colspan="4" style="padding:8px;">No blocking gate items.</td></tr>';
      const commands = nextCommands.length ? `<pre style="min-height:0;max-height:220px;">${escapeHtml(nextCommands.join('\\n'))}</pre>` : '<div class="empty">No next command suggested.</div>';
      return `
        <div class="meta" style="margin-bottom:10px;">
          <span class="status ${gate.ready_for_release_gate ? 'passed' : ''}">decision ${escapeHtml(gate.decision)}</span>
          <span>supervisor ${gate.ready_for_supervisor ? 'ready' : 'not ready'}</span>
          <span>release gate ${gate.ready_for_release_gate ? 'ready' : 'not ready'}</span>
        </div>
        <table style="width:100%; border-collapse:collapse; margin-bottom:14px;">
          <thead><tr><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Item</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Status</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Evidence</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Required Action</th></tr></thead>
          <tbody>${blockerRows}</tbody>
        </table>
        <h3 style="font-size:14px;margin:0 0 8px;">Next Commands</h3>
        ${commands}`;
    }
    function renderLifecycleSummary(item) {
      if (!item) return 'No lifecycle action has been executed from Studio yet.';
      const result = item.result || {};
      const commands = (result.commands || []).map(cmd => Array.isArray(cmd) ? cmd.join(' ') : String(cmd)).join('\n');
      return [
        `action: ${item.action}`,
        `status: ${item.status}`,
        `report: ${item.report}`,
        commands ? `commands:\n${commands}` : '',
        result.message ? `message:\n${result.message}` : '',
        result.stdout ? `stdout:\n${result.stdout}` : '',
        result.stderr ? `stderr:\n${result.stderr}` : ''
      ].filter(Boolean).join('\n\n');
    }
    function renderReleaseGateSummary(report) {
      if (!report || !report.status) return '<div class="empty">No release gate has been executed yet.</div>';
      const checks = report.checks || [];
      const rows = checks.length ? checks.map(check => {
        const messages = (check.messages || []).join(' | ') || '-';
        return `<tr>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><code>${escapeHtml(check.name)}</code></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><span class="status ${check.status === 'passed' ? 'passed' : ''}">${escapeHtml(check.status)}</span></td>
          <td style="border-bottom:1px solid var(--line);padding:8px;"><span class="meta">${escapeHtml(messages)}</span></td>
        </tr>`;
      }).join('') : '<tr><td colspan="3" style="padding:8px;">No checks recorded.</td></tr>';
      return `
        <div class="meta" style="margin-bottom:10px;">
          <span class="status ${report.status === 'passed' ? 'passed' : ''}">status ${escapeHtml(report.status)}</span>
          <span>release ready ${report.release_ready ? 'yes' : 'no'}</span>
          <span>${escapeHtml(report.provider || 'docker-compose')} / ${escapeHtml(report.profile || 'protected')}</span>
        </div>
        <table style="width:100%; border-collapse:collapse;">
          <thead><tr><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Check</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Status</th><th style="text-align:left;border-bottom:1px solid var(--line);padding:8px;">Messages</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>`;
    }
    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    function scoreBadge(score) {
      return Number.isInteger(score) ? `<span class="score">realism ${score}/100</span>` : '';
    }
    loadScenarios();
  </script>
</body>
</html>"""


STUDIO_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "studio-state.schema.json": StudioState,
    "studio-scenario-summary.schema.json": StudioScenarioSummary,
}
