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
    files.setdefault("seed/records.json", render_default_records(artifact, getattr(blueprint, "role", template.template_id) if blueprint else template.template_id))
    files.setdefault("seed/clues.json", render_default_clues(artifact, getattr(blueprint, "role", template.template_id) if blueprint else template.template_id))
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
    role = normalize_template_id(str(getattr(artifact, "runtime", "service")))
    domain = business_domain_for_artifact(artifact, role)
    events = business_events(str(artifact.service), role, domain)
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
                "COPY noise /app/noise",
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
                "from flask import Flask, jsonify, request",
                "",
                f"SERVICE = {artifact.service!r}",
                f"PURPOSE = {artifact.purpose!r}",
                f"PORT = {port}",
                "SEED_DIR = Path('/app/seed')",
                "SEED_PATH = SEED_DIR / 'metadata.json'",
                "STATE_DIR = Path('/state')",
                "STATE_PATH = STATE_DIR / 'stage-state.json'",
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
                "def chain_data():",
                "    path = SEED_DIR / 'chain.json'",
                "    if path.exists():",
                "        return json.loads(path.read_text(encoding='utf-8'))",
                "    return {'service': SERVICE, 'stage_count': 0, 'stages': [], 'adjacent_stages': [], 'incoming': [], 'outgoing': []}",
                "",
                "",
                "def default_state():",
                "    path = SEED_DIR / 'stage-state.json'",
                "    if path.exists():",
                "        return json.loads(path.read_text(encoding='utf-8'))",
                "    return {'service': SERVICE, 'acquired_evidence': [], 'evidence_catalog': [], 'stages': [], 'events': []}",
                "",
                "",
                "def load_state():",
                "    if STATE_PATH.exists():",
                "        return json.loads(STATE_PATH.read_text(encoding='utf-8'))",
                "    state = default_state()",
                "    save_state(state)",
                "    return state",
                "",
                "",
                "def save_state(state):",
                "    STATE_DIR.mkdir(parents=True, exist_ok=True)",
                "    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')",
                "",
                "",
                "def recompute_unlocks(state):",
                "    acquired = set(state.get('acquired_evidence', []))",
                "    for stage in state.get('stages', []):",
                "        required = set(stage.get('required_inputs', []))",
                "        if required.issubset(acquired):",
                "            stage['status'] = 'unlocked'",
                "            stage['unlock_reason'] = 'required_evidence_satisfied' if required else 'entrypoint'",
                "        else:",
                "            stage['status'] = 'locked'",
                "            stage['missing_evidence'] = sorted(required - acquired)",
                "    return state",
                "",
                "",
                "@app.get('/')",
                "def index():",
                "    return jsonify({'service': SERVICE, 'purpose': PURPOSE, 'endpoints': ['/', '/metadata', '/workflow', '/api/chain', '/api/state', '/api/evidence', '/api/stages/<stage_id>', '/healthz']})",
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
                "@app.get('/api/chain')",
                "def chain_route():",
                "    return jsonify(chain_data())",
                "",
                "",
                "@app.get('/api/stages/<stage_id>')",
                "def stage_route(stage_id):",
                "    chain = chain_data()",
                "    for stage in chain.get('stages', []) + chain.get('adjacent_stages', []):",
                "        if stage.get('stage_id') == stage_id:",
                "            return jsonify(stage)",
                "    return jsonify({'error': 'stage not found', 'stage_id': stage_id}), 404",
                "",
                "",
                "@app.get('/api/state')",
                "def state_route():",
                "    return jsonify(recompute_unlocks(load_state()))",
                "",
                "",
                "@app.get('/api/evidence')",
                "def evidence_get_route():",
                "    state = recompute_unlocks(load_state())",
                "    return jsonify({'service': SERVICE, 'acquired_evidence': state.get('acquired_evidence', []), 'evidence_catalog': state.get('evidence_catalog', [])})",
                "",
                "",
                "@app.post('/api/evidence')",
                "def evidence_post_route():",
                "    payload = request.get_json(silent=True) or {}",
                "    evidence = str(payload.get('evidence') or payload.get('id') or '').strip()",
                "    if not evidence:",
                "        return jsonify({'accepted': False, 'error': 'missing evidence'}), 400",
                "    state = load_state()",
                "    acquired = set(state.get('acquired_evidence', []))",
                "    if evidence not in acquired:",
                "        state.setdefault('acquired_evidence', []).append(evidence)",
                "        state.setdefault('events', []).append({'event': 'evidence.acquired', 'evidence': evidence, 'service': SERVICE})",
                "    state = recompute_unlocks(state)",
                "    save_state(state)",
                "    return jsonify({'accepted': True, 'evidence': evidence, 'state': state})",
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
                "COPY noise /app/noise",
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
                "from flask import Flask, jsonify, render_template_string, request",
                "",
                f"SERVICE = {artifact.service!r}",
                f"PURPOSE = {artifact.purpose!r}",
                f"ROLE = {role!r}",
                f"PORT = {port}",
                f"ROUTES = {json.dumps(route_payload, ensure_ascii=False)}",
                "SEED_DIR = Path('/app/seed')",
                "STATE_DIR = Path('/state')",
                "LOG_PATH = Path('/var/log/labforge/service-events.jsonl')",
                "STAGE_STATE_PATH = STATE_DIR / 'stage-state.json'",
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
                "def load_events():",
                "    path = SEED_DIR.parent / 'noise' / 'events.jsonl'",
                "    if not path.exists():",
                "        return []",
                "    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]",
                "",
                "",
                "def chain_data():",
                "    return load_json('chain.json', {'service': SERVICE, 'stage_count': 0, 'stages': [], 'adjacent_stages': [], 'incoming': [], 'outgoing': []})",
                "",
                "",
                "def default_stage_state():",
                "    return load_json('stage-state.json', {'service': SERVICE, 'acquired_evidence': [], 'evidence_catalog': [], 'stages': [], 'events': []})",
                "",
                "",
                "def load_stage_state():",
                "    if STAGE_STATE_PATH.exists():",
                "        return json.loads(STAGE_STATE_PATH.read_text(encoding='utf-8'))",
                "    state = default_stage_state()",
                "    save_stage_state(state)",
                "    return state",
                "",
                "",
                "def save_stage_state(state):",
                "    STATE_DIR.mkdir(parents=True, exist_ok=True)",
                "    STAGE_STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')",
                "",
                "",
                "def recompute_stage_unlocks(state):",
                "    acquired = set(state.get('acquired_evidence', []))",
                "    for stage in state.get('stages', []):",
                "        required = set(stage.get('required_inputs', []))",
                "        missing = sorted(required - acquired)",
                "        if not missing:",
                "            stage['status'] = 'unlocked'",
                "            stage['unlock_reason'] = 'required_evidence_satisfied' if required else 'entrypoint'",
                "            stage.pop('missing_evidence', None)",
                "        else:",
                "            stage['status'] = 'locked'",
                "            stage['missing_evidence'] = missing",
                "    return state",
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
                "    metadata = load_json('metadata.json', {'service': SERVICE, 'role': ROLE, 'purpose': PURPOSE})",
                "    workflow = load_json('workflow.json', {'normal_workflows': []})",
                "    records = load_json('records.json', {'items': []}).get('items', [])",
                "    clues = load_json('clues.json', {'items': []}).get('items', [])",
                "    chain = chain_data()",
                "    stage_state = recompute_stage_unlocks(load_stage_state())",
                "    events = load_events()[:8]",
                "    return render_template_string(DASHBOARD_TEMPLATE, service=SERVICE, role=ROLE, purpose=PURPOSE, metadata=metadata, routes=ROUTES, workflow=workflow, records=records, clues=clues, chain=chain, stage_state=stage_state, events=events)",
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
                "@app.get('/api/clues')",
                "def api_clues():",
                "    append_event('clues.queried')",
                "    return jsonify(load_json('clues.json', {'items': []}))",
                "",
                "",
                "@app.get('/api/records')",
                "def api_records():",
                "    append_event('records.queried', {'query': dict(request.args)})",
                "    return jsonify(load_json('records.json', {'items': []}))",
                "",
                "",
                "@app.get('/api/chain')",
                "def api_chain():",
                "    append_event('chain.queried')",
                "    return jsonify(chain_data())",
                "",
                "",
                "@app.get('/api/stages/<stage_id>')",
                "def api_stage(stage_id):",
                "    chain = chain_data()",
                "    for stage in chain.get('stages', []) + chain.get('adjacent_stages', []):",
                "        if stage.get('stage_id') == stage_id:",
                "            append_event('stage.queried', {'stage_id': stage_id})",
                "            return jsonify(stage)",
                "    return jsonify({'error': 'stage not found', 'stage_id': stage_id}), 404",
                "",
                "",
                "@app.get('/api/state')",
                "def api_state():",
                "    append_event('state.queried')",
                "    return jsonify(recompute_stage_unlocks(load_stage_state()))",
                "",
                "",
                "@app.get('/api/evidence')",
                "def api_evidence_get():",
                "    state = recompute_stage_unlocks(load_stage_state())",
                "    return jsonify({'service': SERVICE, 'acquired_evidence': state.get('acquired_evidence', []), 'evidence_catalog': state.get('evidence_catalog', [])})",
                "",
                "",
                "@app.post('/api/evidence')",
                "def api_evidence_post():",
                "    payload = request.get_json(silent=True) or {}",
                "    evidence = str(payload.get('evidence') or payload.get('id') or '').strip()",
                "    if not evidence:",
                "        return jsonify({'accepted': False, 'error': 'missing evidence'}), 400",
                "    state = load_stage_state()",
                "    acquired = set(state.get('acquired_evidence', []))",
                "    if evidence not in acquired:",
                "        state.setdefault('acquired_evidence', []).append(evidence)",
                "        state.setdefault('events', []).append({'event': 'evidence.acquired', 'evidence': evidence, 'service': SERVICE})",
                "        append_event('evidence.acquired', {'evidence': evidence})",
                "    state = recompute_stage_unlocks(state)",
                "    save_stage_state(state)",
                "    return jsonify({'accepted': True, 'evidence': evidence, 'state': state})",
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
                "        return jsonify({'items': load_events()})",
                "    generated = [json.loads(line) for line in LOG_PATH.read_text(encoding='utf-8').splitlines() if line.strip()]",
                "    return jsonify({'items': [*load_events(), *generated]})",
                "",
                "",
                "DASHBOARD_TEMPLATE = '''",
                "<!doctype html>",
                "<html lang=\"en\">",
                "<head>",
                "  <meta charset=\"utf-8\">",
                "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
                "  <title>{{ service }} - Operations</title>",
                "  <style>",
                "    :root { color-scheme: light; --ink:#18212f; --muted:#647084; --line:#d8dee8; --panel:#ffffff; --bg:#f3f6fa; --accent:#2254a3; --ok:#147a55; --warn:#9a5b00; }",
                "    * { box-sizing: border-box; }",
                "    body { margin:0; font-family: Inter, Segoe UI, Arial, sans-serif; background:var(--bg); color:var(--ink); }",
                "    header { background:#10233f; color:white; padding:18px 28px; display:flex; justify-content:space-between; gap:24px; align-items:center; }",
                "    header h1 { margin:0; font-size:20px; font-weight:650; letter-spacing:0; }",
                "    header .meta { color:#c8d4e6; font-size:13px; }",
                "    nav { background:#fff; border-bottom:1px solid var(--line); padding:0 28px; display:flex; gap:18px; }",
                "    nav a { color:#344258; text-decoration:none; padding:13px 0; font-size:14px; border-bottom:2px solid transparent; }",
                "    nav a.active { color:var(--accent); border-color:var(--accent); font-weight:650; }",
                "    main { max-width:1180px; margin:24px auto; padding:0 18px; display:grid; grid-template-columns:2fr 1fr; gap:18px; }",
                "    section { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; }",
                "    h2 { margin:0 0 12px; font-size:16px; }",
                "    .muted { color:var(--muted); font-size:13px; line-height:1.5; }",
                "    table { width:100%; border-collapse:collapse; font-size:13px; }",
                "    th, td { text-align:left; padding:10px 8px; border-bottom:1px solid #edf1f6; vertical-align:top; }",
                "    th { color:#536176; font-weight:650; background:#f8fafc; }",
                "    .pill { display:inline-block; border:1px solid var(--line); border-radius:999px; padding:3px 8px; font-size:12px; color:#40506a; background:#f8fafc; }",
                "    .ok { color:var(--ok); } .warn { color:var(--warn); }",
                "    .grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }",
                "    .tile { border:1px solid #edf1f6; border-radius:8px; padding:12px; background:#fbfcfe; }",
                "    code { font-family: Consolas, ui-monospace, monospace; font-size:12px; }",
                "    @media (max-width: 860px) { main { grid-template-columns:1fr; } .grid { grid-template-columns:1fr; } }",
                "  </style>",
                "</head>",
                "<body>",
                "  <header>",
                "    <div><h1>{{ service }}</h1><div class=\"meta\">{{ role }} - synthetic enterprise training environment</div></div>",
                "    <span class=\"pill\">{{ metadata.get('status', 'template-runtime') }}</span>",
                "  </header>",
                "  <nav><a class=\"active\" href=\"/\">Overview</a><a href=\"/workflow\">Workflow</a><a href=\"/api/records\">Records API</a><a href=\"/api/chain\">Chain Context</a><a href=\"/api/state\">Stage State</a><a href=\"/logs/events\">Events</a><a href=\"/api/routes\">Routes</a></nav>",
                "  <main>",
                "    <div>",
                "      <section><h2>Operational Summary</h2><p class=\"muted\">{{ purpose }}</p><div class=\"grid\">",
                "        <div class=\"tile\"><strong>Routes</strong><br><span class=\"muted\">{{ routes|length }} declared business/API surfaces</span></div>",
                "        <div class=\"tile\"><strong>Records</strong><br><span class=\"muted\">{{ records|length }} seeded business records</span></div>",
                "        <div class=\"tile\"><strong>Workflows</strong><br><span class=\"muted\">{{ workflow.get('normal_workflows', [])|length }} normal workflows</span></div>",
                "        <div class=\"tile\"><strong>Chain Context</strong><br><span class=\"muted\">{{ chain.get('stage_count', 0) }} related workflow stages</span></div>",
                "        <div class=\"tile\"><strong>Evidence State</strong><br><span class=\"muted\">{{ stage_state.get('acquired_evidence', [])|length }} acquired evidence items</span></div>",
                "      </div></section>",
                "      <section style=\"margin-top:18px\"><h2>Business Records</h2><table><tr><th>ID</th><th>Type</th><th>Status</th><th>Owner</th><th>Updated</th></tr>",
                "      {% for item in records %}<tr><td><code>{{ item.get('id') }}</code></td><td>{{ item.get('type') }}</td><td><span class=\"pill\">{{ item.get('status') }}</span></td><td>{{ item.get('owner', '-') }}</td><td>{{ item.get('updated_at', '-') }}</td></tr>{% endfor %}",
                "      </table></section>",
                "      <section style=\"margin-top:18px\"><h2>Route Catalog</h2><table><tr><th>Method</th><th>Path</th><th>Purpose</th><th>Auth</th></tr>",
                "      {% for route in routes %}<tr><td>{{ route.get('method') }}</td><td><code>{{ route.get('path') }}</code></td><td>{{ route.get('purpose') }}</td><td>{{ route.get('auth') }}</td></tr>{% endfor %}",
                "      </table></section>",
                "    </div>",
                "    <aside>",
                "      <section><h2>Related Workflow Context</h2>{% if chain.get('stages') %}{% for stage in chain.get('stages', []) %}<p class=\"muted\"><strong>{{ stage.get('stage_id') }} - {{ stage.get('title') }}</strong><br>{{ stage.get('learner_clue') }}</p>{% endfor %}{% else %}<p class=\"muted\">No scenario-specific workflow context is assigned to this service.</p>{% endif %}</section>",
                "      <section style=\"margin-top:18px\"><h2>Stage State</h2>{% for stage in stage_state.get('stages', [])[:6] %}<p class=\"muted\"><strong>{{ stage.get('stage_id') }}</strong> <span class=\"pill\">{{ stage.get('status') }}</span><br>{% if stage.get('missing_evidence') %}Waiting for {{ ', '.join(stage.get('missing_evidence', [])) }}{% else %}Required evidence satisfied{% endif %}</p>{% endfor %}</section>",
                "      <section style=\"margin-top:18px\"><h2>Evidence Links</h2>{% for link in chain.get('incoming', []) + chain.get('outgoing', []) %}<p class=\"muted\"><code>{{ link.get('from_stage') }} -> {{ link.get('to_stage') }}</code><br>{{ ', '.join(link.get('carried_evidence', [])) or 'No declared evidence' }}</p>{% endfor %}</section>",
                "      <section style=\"margin-top:18px\"><h2>Operations Notes</h2>{% for clue in clues %}<p class=\"muted\"><strong>{{ clue.get('title') }}</strong><br>{{ clue.get('detail') }}</p>{% endfor %}</section>",
                "      <section style=\"margin-top:18px\"><h2>Recent Events</h2>{% for event in events %}<p class=\"muted\"><code>{{ event.get('event') }}</code><br>{{ event.get('severity','info') }} - {{ event.get('source', event.get('role', service)) }}</p>{% endfor %}</section>",
                "    </aside>",
                "  </main>",
                "</body>",
                "</html>",
                "'''",
                "",
                "",
                "if __name__ == '__main__':",
                "    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', PORT)))",
                "",
            ]
        ),
        "seed/records.json": render_default_records(artifact, role),
        "seed/clues.json": render_default_clues(artifact, role),
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
            "rm -f /state/stage-state.json 2>/dev/null || true",
            "mkdir -p /state",
            "echo ok",
            "",
        ]
    )


def render_default_records(artifact: Any, role: str) -> str:
    domain = business_domain_for_artifact(artifact, role)
    service = str(artifact.service)
    data = {
        "items": business_records(service, role, domain)
    }
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def render_default_events(artifact: Any, role: str) -> str:
    domain = business_domain_for_artifact(artifact, role)
    events = business_events(str(artifact.service), role, domain)
    return "\n".join(json.dumps(item, ensure_ascii=False) for item in events) + "\n"


def render_default_clues(artifact: Any, role: str) -> str:
    domain = business_domain_for_artifact(artifact, role)
    data = {"items": business_clues(str(artifact.service), role, domain, artifact)}
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def business_domain_for_artifact(artifact: Any, role: str) -> str:
    blob = " ".join(
        [
            str(getattr(artifact, "service", "")),
            str(getattr(artifact, "runtime", "")),
            str(getattr(artifact, "purpose", "")),
            role,
            " ".join(str(item) for item in getattr(artifact, "attack_surface", []) or []),
        ]
    ).lower()
    if any(token in blob for token in ("loan", "bank", "deposit", "account", "payment", "wire", "aml", "fraud")):
        return "banking"
    if any(token in blob for token in ("trade", "trading", "investor", "market", "settlement", "brokerage", "compliance")):
        return "securities"
    if any(token in blob for token in ("patient", "ehr", "clinical", "appointment", "claims", "billing")):
        return "healthcare"
    if any(token in blob for token in ("mes", "factory", "plant", "ot", "scada", "historian", "production")):
        return "manufacturing"
    if any(token in blob for token in ("domain", "ldap", "kerberos", "windows", "active directory", "workstation")):
        return "active-directory"
    if any(token in blob for token in ("build", "release", "update", "artifact", "repo", "signing")):
        return "supply-chain"
    return "enterprise"


def business_records(service: str, role: str, domain: str) -> list[dict[str, str]]:
    common = {
        "classification": "synthetic-training-data",
        "source_service": service,
    }
    if domain == "banking":
        return [
            {**common, "id": "LN-2026-0418", "type": "loan-review-case", "status": "needs-document-review", "owner": "loan-ops", "updated_at": "2026-05-18T09:42:11Z"},
            {**common, "id": "AML-2026-1172", "type": "aml-case", "status": "analyst-review", "owner": "fincrime-ops", "updated_at": "2026-05-18T10:05:44Z"},
            {**common, "id": "PAY-BATCH-0518-A", "type": "payment-batch", "status": "reconciled-with-exceptions", "owner": "payments", "updated_at": "2026-05-18T10:31:09Z"},
        ]
    if domain == "securities":
        return [
            {**common, "id": "ORD-884210", "type": "trade-exception", "status": "operations-review", "owner": "trade-ops", "updated_at": "2026-05-18T08:58:02Z"},
            {**common, "id": "SURV-2026-229", "type": "surveillance-alert", "status": "open", "owner": "compliance", "updated_at": "2026-05-18T09:16:44Z"},
            {**common, "id": "SETTLE-EOD-0518", "type": "settlement-batch", "status": "pending-eod", "owner": "back-office", "updated_at": "2026-05-18T10:02:19Z"},
        ]
    if domain == "healthcare":
        return [
            {**common, "id": "APT-2026-2210", "type": "appointment-request", "status": "scheduled", "owner": "front-desk", "updated_at": "2026-05-18T08:22:15Z"},
            {**common, "id": "EHR-AUD-9042", "type": "privacy-audit-item", "status": "review-needed", "owner": "privacy-office", "updated_at": "2026-05-18T09:50:02Z"},
            {**common, "id": "CLM-661802", "type": "claims-case", "status": "payer-response-pending", "owner": "billing", "updated_at": "2026-05-18T10:44:30Z"},
        ]
    if domain == "manufacturing":
        return [
            {**common, "id": "WO-17-4552", "type": "work-order", "status": "released-to-line", "owner": "production", "updated_at": "2026-05-18T07:35:03Z"},
            {**common, "id": "ENG-CHG-902", "type": "engineering-change", "status": "awaiting-review", "owner": "engineering", "updated_at": "2026-05-18T09:09:25Z"},
            {**common, "id": "HIST-ALM-310", "type": "historian-alarm", "status": "acknowledged", "owner": "plant-ops", "updated_at": "2026-05-18T10:12:47Z"},
        ]
    if domain == "supply-chain":
        return [
            {**common, "id": "BR-4421", "type": "build-request", "status": "manager-review", "owner": "release-ops", "updated_at": "2026-05-18T08:41:00Z"},
            {**common, "id": "REL-2.6.4", "type": "release-channel", "status": "staged", "owner": "release-engineering", "updated_at": "2026-05-18T09:22:11Z"},
            {**common, "id": "CUST-PILOT-204", "type": "customer-integration", "status": "pilot", "owner": "customer-success", "updated_at": "2026-05-18T10:40:31Z"},
        ]
    if domain == "active-directory":
        return [
            {**common, "id": "USR-1042", "type": "directory-user", "status": "active", "owner": "identity-ops", "updated_at": "2026-05-18T08:18:44Z"},
            {**common, "id": "GRP-FIN-OPS", "type": "security-group", "status": "review-due", "owner": "iam", "updated_at": "2026-05-18T09:31:03Z"},
            {**common, "id": "SHARE-BOARD", "type": "file-share", "status": "restricted", "owner": "corp-it", "updated_at": "2026-05-18T10:20:56Z"},
        ]
    return [
        {**common, "id": f"{service}-case-001", "type": role, "status": "active", "owner": "operations", "updated_at": "2026-05-18T09:00:00Z"},
        {**common, "id": f"{service}-case-002", "type": role, "status": "pending-review", "owner": "support", "updated_at": "2026-05-18T09:45:00Z"},
        {**common, "id": f"{service}-archive-003", "type": "archive-record", "status": "archived", "owner": "records", "updated_at": "2026-05-18T10:30:00Z"},
    ]


def business_events(service: str, role: str, domain: str) -> list[dict[str, str]]:
    labels = {
        "banking": ("loan.document.received", "aml.case.queued", "payment.batch.reconciled"),
        "securities": ("trade.exception.opened", "marketdata.feed.refreshed", "surveillance.alert.queued"),
        "healthcare": ("appointment.updated", "ehr.access.reviewed", "claim.status.polled"),
        "manufacturing": ("workorder.released", "historian.alarm.acknowledged", "engineering.change.reviewed"),
        "supply-chain": ("build.request.reviewed", "artifact.metadata.indexed", "release.channel.checked"),
        "active-directory": ("directory.bind.success", "group.review.queued", "share.access.denied"),
        "enterprise": ("case.updated", "record.reviewed", "routine.healthcheck"),
    }
    selected = labels.get(domain, labels["enterprise"])
    return [
        {"service": service, "role": role, "event": "service.started", "severity": "info", "source": "labforge-runtime"},
        {"service": service, "role": role, "event": selected[0], "severity": "info", "source": "business-workflow"},
        {"service": service, "role": role, "event": selected[1], "severity": "info", "source": "operations-job"},
        {"service": service, "role": role, "event": selected[2], "severity": "warning", "source": "monitoring"},
    ]


def business_clues(service: str, role: str, domain: str, artifact: Any) -> list[dict[str, str]]:
    seed_inputs = ", ".join(str(item) for item in getattr(artifact, "seed_inputs", []) or []) or "baseline seed package"
    noise_inputs = ", ".join(str(item) for item in getattr(artifact, "noise_inputs", []) or []) or "routine operational noise"
    return [
        {
            "title": "Data lineage",
            "detail": f"This service consumes {seed_inputs}. Treat records as synthetic but business-shaped.",
        },
        {
            "title": "Operational noise",
            "detail": f"Routine context includes {noise_inputs}; not every event is part of the learner path.",
        },
        {
            "title": "Review posture",
            "detail": f"{service} is operated as a {domain} {role}; validate workflows through normal routes before testing edge cases.",
        },
    ]


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
