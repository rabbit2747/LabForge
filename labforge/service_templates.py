from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class ServiceTemplate:
    template_id: str
    description: str
    aliases: tuple[str, ...]
    renderer: Callable[..., dict[str, str]]


def normalize_template_id(value: str) -> str:
    return "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-")


def template_id_for_artifact(artifact: Any) -> str:
    extra = getattr(artifact, "model_extra", None) or {}
    explicit = extra.get("template")
    if isinstance(explicit, dict):
        explicit = explicit.get("id")
    if explicit:
        return normalize_template_id(str(explicit))
    return normalize_template_id(str(getattr(artifact, "runtime", "")))


def get_service_template(artifact: Any) -> ServiceTemplate | None:
    template_id = template_id_for_artifact(artifact)
    return get_service_template_by_id(template_id)


def get_service_template_by_id(template_id: str) -> ServiceTemplate | None:
    if not template_id:
        return None
    for template in SERVICE_TEMPLATES:
        candidates = {template.template_id, *template.aliases}
        if template_id in {normalize_template_id(item) for item in candidates}:
            return template
    return None


def list_service_templates() -> list[ServiceTemplate]:
    return list(SERVICE_TEMPLATES)


def render_template_files(artifact: Any, port: int, *, blueprint: Any | None = None) -> dict[str, str] | None:
    template = get_service_template_by_id(getattr(blueprint, "template", "")) if blueprint else None
    template = template or get_service_template(artifact)
    if not template:
        return None
    files = template.renderer(artifact, port, blueprint=blueprint)
    files.setdefault("seed/metadata.json", render_metadata(artifact, port, template.template_id))
    files.setdefault("seed/workflow.json", render_workflow_seed(artifact, blueprint))
    files.setdefault("noise/events.jsonl", render_noise_seed(artifact))
    if blueprint:
        files.setdefault("seed/blueprint.json", json.dumps(blueprint.model_dump(), ensure_ascii=False, indent=2) + "\n")
    files.setdefault("tests/test_smoke.py", render_smoke_test(artifact, port))
    return files


def render_metadata(artifact: Any, port: int, template_id: str) -> str:
    data = {
        "service": artifact.service,
        "runtime": artifact.runtime,
        "template": template_id,
        "purpose": artifact.purpose,
        "port": port,
        "status": "template-runtime",
        "template_policy": {
            "role": "infrastructure-part",
            "puzzle_logic": "scenario-specific",
        },
    }
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def render_workflow_seed(artifact: Any, blueprint: Any | None) -> str:
    routes = []
    workflows = []
    if blueprint:
        routes = [
            {
                "method": getattr(route, "method", "GET"),
                "path": getattr(route, "path", "/"),
                "purpose": getattr(route, "purpose", ""),
                "auth": getattr(route, "auth", "none"),
            }
            for route in getattr(blueprint, "routes", []) or []
        ]
        workflows = [
            {
                "name": getattr(workflow, "name", ""),
                "actor": getattr(workflow, "actor", ""),
                "steps": getattr(workflow, "steps", []) or [],
                "normal_outcome": getattr(workflow, "normal_outcome", ""),
            }
            for workflow in getattr(blueprint, "normal_workflows", []) or []
        ]
    data = {
        "service": artifact.service,
        "purpose": artifact.purpose,
        "routes": routes,
        "normal_workflows": workflows,
        "evidence_logs": list(getattr(artifact, "evidence_logs", []) or []),
    }
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def render_noise_seed(artifact: Any) -> str:
    events = [
        {
            "service": artifact.service,
            "event": "baseline.startup",
            "severity": "info",
            "source": "labforge-mvp-runtime",
        },
        {
            "service": artifact.service,
            "event": "baseline.healthcheck",
            "severity": "info",
            "source": "labforge-mvp-runtime",
        },
    ]
    return "\n".join(json.dumps(item, ensure_ascii=False) for item in events) + "\n"


def render_smoke_test(artifact: Any, port: int) -> str:
    return "\n".join(
        [
            "from pathlib import Path",
            "",
            "",
            "def test_service_contract_files_exist():",
            "    root = Path(__file__).resolve().parents[1]",
            "    assert (root / 'Dockerfile').exists()",
            "    assert (root / 'healthcheck.sh').exists()",
            "    assert (root / 'reset.sh').exists()",
            "    assert (root / 'seed' / 'metadata.json').exists()",
            "",
        ]
    )


def render_python_flask_web(artifact: Any, port: int, *, blueprint: Any | None = None) -> dict[str, str]:
    return {
        "Dockerfile": "\n".join(
            [
                "FROM python:3.12-alpine",
                "",
                "WORKDIR /app",
                "RUN pip install --no-cache-dir Flask==3.0.3",
                "COPY app.py /app/app.py",
                "COPY seed /app/seed",
                "COPY healthcheck.sh /usr/local/bin/labforge-healthcheck",
                "COPY reset.sh /usr/local/bin/labforge-reset",
                "RUN mkdir -p /var/log/labforge /state && chmod -R 755 /app /var/log/labforge /state && chmod +x /usr/local/bin/labforge-healthcheck /usr/local/bin/labforge-reset",
                f"EXPOSE {port}",
                "CMD [\"python\", \"/app/app.py\"]",
                "",
            ]
        ),
        "app.py": "\n".join(
            [
                "from __future__ import annotations",
                "",
                "import json",
                "import os",
                "from pathlib import Path",
                "from flask import Flask, jsonify",
                "",
                f"SERVICE = {artifact.service!r}",
                f"PURPOSE = {artifact.purpose!r}",
                f"PORT = {port}",
                "SEED_PATH = Path('/app/seed/metadata.json')",
                "",
                "app = Flask(__name__)",
                "",
                "",
                "def metadata():",
                "    if SEED_PATH.exists():",
                "        return json.loads(SEED_PATH.read_text(encoding='utf-8'))",
                "    return {'service': SERVICE, 'purpose': PURPOSE}",
                "",
                "",
                "@app.get('/')",
                "def index():",
                "    return jsonify({'service': SERVICE, 'purpose': PURPOSE, 'endpoints': ['/', '/metadata', '/healthz']})",
                "",
                "",
                "@app.get('/metadata')",
                "def metadata_route():",
                "    return jsonify(metadata())",
                "",
                "",
                "@app.get('/workflow')",
                "def workflow_route():",
                "    path = SEED_PATH.parent / 'workflow.json'",
                "    if path.exists():",
                "        return jsonify(json.loads(path.read_text(encoding='utf-8')))",
                "    return jsonify({'service': SERVICE, 'routes': [], 'normal_workflows': []})",
                "",
                "",
                "@app.get('/healthz')",
                "def healthz():",
                "    return 'ok\\n', 200",
                "",
                "",
                "if __name__ == '__main__':",
                "    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', PORT)))",
                "",
            ]
        ),
        "healthcheck.sh": render_http_healthcheck(port),
        "reset.sh": render_reset_script(),
    }


def render_enterprise_flask_service(artifact: Any, port: int, *, blueprint: Any | None = None) -> dict[str, str]:
    role = getattr(blueprint, "role", "generic-service") if blueprint else "generic-service"
    routes = getattr(blueprint, "routes", []) if blueprint else []
    route_payload = [
        {
            "method": getattr(route, "method", "GET"),
            "path": getattr(route, "path", "/"),
            "purpose": getattr(route, "purpose", ""),
            "auth": getattr(route, "auth", "none"),
        }
        for route in routes
    ]
    return {
        "Dockerfile": "\n".join(
            [
                "FROM python:3.12-alpine",
                "",
                "WORKDIR /app",
                "RUN pip install --no-cache-dir Flask==3.0.3",
                "COPY app.py /app/app.py",
                "COPY seed /app/seed",
                "COPY healthcheck.sh /usr/local/bin/labforge-healthcheck",
                "COPY reset.sh /usr/local/bin/labforge-reset",
                "RUN mkdir -p /state /var/log/labforge && chmod -R 755 /app /state /var/log/labforge && chmod +x /usr/local/bin/labforge-healthcheck /usr/local/bin/labforge-reset",
                f"EXPOSE {port}",
                "CMD [\"python\", \"/app/app.py\"]",
                "",
            ]
        ),
        "app.py": "\n".join(
            [
                "from __future__ import annotations",
                "",
                "import json",
                "import os",
                "from datetime import datetime, timezone",
                "from pathlib import Path",
                "from flask import Flask, jsonify, request",
                "",
                f"SERVICE = {artifact.service!r}",
                f"PURPOSE = {artifact.purpose!r}",
                f"ROLE = {role!r}",
                f"PORT = {port}",
                f"ROUTES = {json.dumps(route_payload, ensure_ascii=False)}",
                "SEED_DIR = Path('/app/seed')",
                "STATE_DIR = Path('/state')",
                "LOG_PATH = Path('/var/log/labforge/service-events.jsonl')",
                "app = Flask(__name__)",
                "",
                "",
                "def load_json(name, fallback):",
                "    path = SEED_DIR / name",
                "    if path.exists():",
                "        return json.loads(path.read_text(encoding='utf-8'))",
                "    return fallback",
                "",
                "",
                "def append_event(event, payload=None):",
                "    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)",
                "    record = {'time': datetime.now(timezone.utc).isoformat(), 'service': SERVICE, 'event': event, 'payload': payload or {}}",
                "    with LOG_PATH.open('a', encoding='utf-8') as handle:",
                "        handle.write(json.dumps(record, ensure_ascii=False) + '\\n')",
                "",
                "",
                "@app.get('/healthz')",
                "def healthz():",
                "    return 'ok\\n', 200",
                "",
                "",
                "@app.get('/')",
                "def index():",
                "    append_event('index.viewed')",
                "    return jsonify({'service': SERVICE, 'role': ROLE, 'purpose': PURPOSE, 'routes': ROUTES})",
                "",
                "",
                "@app.get('/metadata')",
                "def metadata():",
                "    return jsonify(load_json('metadata.json', {'service': SERVICE, 'role': ROLE, 'purpose': PURPOSE}))",
                "",
                "",
                "@app.get('/api/routes')",
                "def api_routes():",
                "    return jsonify({'service': SERVICE, 'routes': ROUTES})",
                "",
                "",
                "@app.get('/workflow')",
                "def workflow():",
                "    return jsonify(load_json('workflow.json', {'service': SERVICE, 'routes': ROUTES, 'normal_workflows': []}))",
                "",
                "",
                "@app.get('/api/records')",
                "def api_records():",
                "    append_event('records.queried', {'query': dict(request.args)})",
                "    return jsonify(load_json('records.json', {'items': []}))",
                "",
                "",
                "@app.post('/api/actions')",
                "def api_actions():",
                "    payload = request.get_json(silent=True) or {}",
                "    append_event('action.received', payload)",
                "    return jsonify({'accepted': True, 'service': SERVICE, 'received': payload})",
                "",
                "",
                "@app.get('/logs/events')",
                "def log_events():",
                "    if not LOG_PATH.exists():",
                "        return jsonify({'items': []})",
                "    return jsonify({'items': [json.loads(line) for line in LOG_PATH.read_text(encoding='utf-8').splitlines() if line.strip()]})",
                "",
                "",
                "if __name__ == '__main__':",
                "    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', PORT)))",
                "",
            ]
        ),
        "seed/records.json": render_default_records(artifact, role),
        "noise/events.jsonl": render_default_events(artifact, role),
        "healthcheck.sh": render_http_healthcheck(port),
        "reset.sh": render_reset_script(),
        "README.runtime.md": render_enterprise_runtime_readme(artifact, role),
    }


def render_attacker_workstation_ssh(artifact: Any, port: int, *, blueprint: Any | None = None) -> dict[str, str]:
    return {
        "Dockerfile": "\n".join(
            [
                "FROM alpine:3.20",
                "",
                "RUN apk add --no-cache bash curl jq netcat-openbsd openssh socat python3 shadow",
                "RUN adduser -D -s /bin/bash attacker && echo 'attacker:attacker' | chpasswd",
                "RUN ssh-keygen -A && mkdir -p /home/attacker/workspace /var/log/labforge /state",
                "COPY app.py /usr/local/bin/labforge-workstation-info",
                "COPY seed /opt/labforge/seed",
                "COPY healthcheck.sh /usr/local/bin/labforge-healthcheck",
                "COPY reset.sh /usr/local/bin/labforge-reset",
                "RUN chmod +x /usr/local/bin/labforge-workstation-info /usr/local/bin/labforge-healthcheck /usr/local/bin/labforge-reset && chown -R attacker:attacker /home/attacker /state",
                "EXPOSE 22",
                "CMD [\"/usr/sbin/sshd\", \"-D\", \"-e\"]",
                "",
            ]
        ),
        "app.py": "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "",
                "import json",
                "from pathlib import Path",
                "",
                "metadata = Path('/opt/labforge/seed/metadata.json')",
                "if metadata.exists():",
                "    print(metadata.read_text(encoding='utf-8'))",
                "else:",
                f"    print(json.dumps({{'service': {artifact.service!r}, 'role': 'attacker-workstation'}}, indent=2))",
                "",
            ]
        ),
        "healthcheck.sh": "\n".join(
            [
                "#!/usr/bin/env sh",
                "set -eu",
                "test -d /home/attacker/workspace",
                "test -x /usr/local/bin/labforge-workstation-info || test -f app.py",
                "echo ok",
                "",
            ]
        ),
        "reset.sh": "\n".join(
            [
                "#!/usr/bin/env sh",
                "set -eu",
                "rm -rf /home/attacker/workspace/tmp 2>/dev/null || true",
                "mkdir -p /home/attacker/workspace",
                "echo ok",
                "",
            ]
        ),
    }


def render_controlled_drop(artifact: Any, port: int, *, blueprint: Any | None = None) -> dict[str, str]:
    return {
        "Dockerfile": "\n".join(
            [
                "FROM python:3.12-alpine",
                "",
                "WORKDIR /app",
                "RUN pip install --no-cache-dir Flask==3.0.3",
                "COPY app.py /app/app.py",
                "COPY seed /app/seed",
                "COPY healthcheck.sh /usr/local/bin/labforge-healthcheck",
                "COPY reset.sh /usr/local/bin/labforge-reset",
                "RUN mkdir -p /state /var/log/labforge && chmod -R 755 /app /state /var/log/labforge && chmod +x /usr/local/bin/labforge-healthcheck /usr/local/bin/labforge-reset",
                f"EXPOSE {port}",
                "CMD [\"python\", \"/app/app.py\"]",
                "",
            ]
        ),
        "app.py": "\n".join(
            [
                "from __future__ import annotations",
                "",
                "import json",
                "import os",
                "from datetime import datetime, timezone",
                "from pathlib import Path",
                "from flask import Flask, jsonify, request",
                "",
                f"SERVICE = {artifact.service!r}",
                f"PORT = {port}",
                "STATE = Path('/state/submissions.jsonl')",
                "app = Flask(__name__)",
                "",
                "",
                "@app.get('/healthz')",
                "def healthz():",
                "    return 'ok\\n', 200",
                "",
                "",
                "@app.get('/')",
                "def index():",
                "    return jsonify({'service': SERVICE, 'endpoints': ['/', '/healthz', '/submit', '/submissions']})",
                "",
                "",
                "@app.get('/workflow')",
                "def workflow():",
                "    path = Path('/app/seed/workflow.json')",
                "    if path.exists():",
                "        return jsonify(json.loads(path.read_text(encoding='utf-8')))",
                "    return jsonify({'service': SERVICE, 'routes': ['/submit', '/submissions']})",
                "",
                "",
                "@app.post('/submit')",
                "def submit():",
                "    payload = request.get_json(silent=True) or {'raw': request.get_data(as_text=True)}",
                "    record = {'received_at': datetime.now(timezone.utc).isoformat(), 'payload': payload}",
                "    STATE.parent.mkdir(parents=True, exist_ok=True)",
                "    with STATE.open('a', encoding='utf-8') as handle:",
                "        handle.write(json.dumps(record, ensure_ascii=False) + '\\n')",
                "    return jsonify({'accepted': True, 'service': SERVICE})",
                "",
                "",
                "@app.get('/submissions')",
                "def submissions():",
                "    if not STATE.exists():",
                "        return jsonify({'items': []})",
                "    items = [json.loads(line) for line in STATE.read_text(encoding='utf-8').splitlines() if line.strip()]",
                "    return jsonify({'items': items})",
                "",
                "",
                "if __name__ == '__main__':",
                "    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', PORT)))",
                "",
            ]
        ),
        "healthcheck.sh": render_http_healthcheck(port),
        "reset.sh": "\n".join(
            [
                "#!/usr/bin/env sh",
                "set -eu",
                "rm -f /state/submissions.jsonl 2>/dev/null || true",
                "echo ok",
                "",
            ]
        ),
    }


def render_http_healthcheck(port: int) -> str:
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            "set -eu",
            "python - <<'PY'",
            "import os",
            "import urllib.request",
            f"port = int(os.environ.get('PORT', {port}))",
            "with urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=5) as response:",
            "    body = response.read().decode('utf-8', 'replace')",
            "    if response.status != 200 or 'ok' not in body.lower():",
            "        raise SystemExit(f'unhealthy response: {response.status} {body!r}')",
            "print('ok')",
            "PY",
            "",
        ]
    )


def render_reset_script() -> str:
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            "set -eu",
            "rm -rf /state/tmp 2>/dev/null || true",
            "mkdir -p /state",
            "echo ok",
            "",
        ]
    )


def render_default_records(artifact: Any, role: str) -> str:
    data = {
        "items": [
            {"id": f"{artifact.service}-record-001", "type": role, "status": "active", "classification": "synthetic-training-data"},
            {"id": f"{artifact.service}-record-002", "type": role, "status": "archived", "classification": "synthetic-training-data"},
        ]
    }
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def render_default_events(artifact: Any, role: str) -> str:
    events = [
        {"service": artifact.service, "role": role, "event": "service.started", "severity": "info"},
        {"service": artifact.service, "role": role, "event": "routine.healthcheck", "severity": "info"},
    ]
    return "\n".join(json.dumps(item, ensure_ascii=False) for item in events) + "\n"


def render_enterprise_runtime_readme(artifact: Any, role: str) -> str:
    return "\n".join(
        [
            f"# {artifact.service}",
            "",
            f"- Role: `{role}`",
            f"- Purpose: {artifact.purpose}",
            "",
            "This is a reusable enterprise service runtime scaffold. It provides",
            "business-shaped routes, deterministic seed data, operational noise,",
            "healthcheck/reset hooks, and event logging. Scenario-specific",
            "vulnerability behavior must be implemented in service code or",
            "declared vulnerability plugin contracts, not hidden in this template.",
            "",
        ]
    )


SERVICE_TEMPLATES: tuple[ServiceTemplate, ...] = (
    ServiceTemplate(
        "python-flask-web",
        "Generic Flask HTTP service with metadata and healthcheck endpoints.",
        ("flask", "python web application", "python-flask", "python flask web"),
        render_python_flask_web,
    ),
    ServiceTemplate(
        "business-portal",
        "Business-facing Flask portal with records, actions, route metadata, logs, seed, and noise scaffolds.",
        ("portal", "support portal", "customer portal", "investor portal"),
        render_enterprise_flask_service,
    ),
    ServiceTemplate(
        "reverse-proxy-stub",
        "Runnable reverse-proxy-shaped scaffold for edge routing metadata, healthcheck, and logs.",
        ("nginx", "reverse proxy", "edge proxy", "nginx-or-equivalent-reverse-proxy"),
        render_enterprise_flask_service,
    ),
    ServiceTemplate(
        "internal-admin-console",
        "Internal operator/admin console scaffold with action and audit routes.",
        ("admin console", "ops console", "release console", "internal console"),
        render_enterprise_flask_service,
    ),
    ServiceTemplate(
        "identity-gateway",
        "Identity and session gateway scaffold with login-shaped API routes.",
        ("identity", "auth", "sso", "mfa", "iam"),
        render_enterprise_flask_service,
    ),
    ServiceTemplate(
        "data-api",
        "Internal data API scaffold with records, metadata, and export-shaped routes.",
        ("data api", "warehouse", "records api", "customer api"),
        render_enterprise_flask_service,
    ),
    ServiceTemplate(
        "audit-log-service",
        "Audit/event service scaffold with event ingest and query behavior.",
        ("audit", "log service", "event service"),
        render_enterprise_flask_service,
    ),
    ServiceTemplate(
        "message-broker-stub",
        "Lab-scoped broker-like HTTP scaffold for event and message workflows.",
        ("broker", "message broker", "queue", "event bus"),
        render_enterprise_flask_service,
    ),
    ServiceTemplate(
        "object-store",
        "Object-store style HTTP scaffold with object metadata and retrieval-shaped routes.",
        ("object store", "archive store", "blob store"),
        render_enterprise_flask_service,
    ),
    ServiceTemplate(
        "siem-log-viewer",
        "Security analyst log viewer scaffold with alerts and event search shape.",
        ("siem", "log viewer", "security monitoring"),
        render_enterprise_flask_service,
    ),
    ServiceTemplate(
        "attacker-workstation-ssh",
        "Linux learner workstation with SSH and common diagnostic tools.",
        ("attacker workstation", "linux learner workstation", "linux learner attack workstation", "linux-ssh-workstation"),
        render_attacker_workstation_ssh,
    ),
    ServiceTemplate(
        "controlled-drop",
        "Lab-scoped final submission receiver with resettable local state.",
        ("drop service", "controlled drop", "submission service", "controlled-drop-service"),
        render_controlled_drop,
    ),
)
