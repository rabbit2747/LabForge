from __future__ import annotations

from datetime import datetime
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from pydantic import BaseModel, ConfigDict, Field

from .agent_adapters import get_agent_adapter
from .design import (
    create_design_fix_task_packages,
    create_design_fix_tasks,
    create_design_workspace_from_prompt,
    review_design_fix_results,
    review_design_workspace,
)
from .intake import slugify
from .io import load_yaml


class StudioModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class StudioScenarioSummary(StudioModel):
    scenario_id: str
    title: str
    industry: str = "enterprise"
    status: str = "draft"
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
    title = path.name
    industry = "enterprise"
    status = "created"
    if scenario_yaml.exists():
        scenario = load_yaml(scenario_yaml)
        title = str(scenario.get("title", title))
        industry = str(scenario.get("target_industry", industry))
        status = "draft-lab"
    if review_yaml.exists():
        review = load_yaml(review_yaml)
        status = str(review.get("status", "reviewed"))
    updated_at = datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
    return StudioScenarioSummary(
        scenario_id=path.name,
        title=title,
        industry=industry,
        status=status,
        path=str(path),
        updated_at=updated_at,
        steps=scenario_steps(path),
    )


def scenario_steps(path: Path) -> list[dict[str, str | bool]]:
    checks = [
        ("Source prompt", path / "lab" / "scenario-prompt.md"),
        ("Draft lab", path / "lab" / "scenario.yaml"),
        ("Agent workspace", path / "agents" / ".ai" / "orchestration-plan.yaml"),
        ("Run packages", path / "agents" / ".ai" / "run" / "run-plan.yaml"),
        ("Design review", path / "review" / "design-review-report.md"),
        ("Fix tasks", path / "review" / "design-fix-tasks.md"),
        ("Fix packages", path / "review" / "fix-agent-package-report.md"),
        ("Fix result review", path / "review" / "fix-result-review.md"),
    ]
    return [{"name": name, "complete": item.exists(), "path": str(item)} for name, item in checks]


def create_scenario(workspace: Path, payload: dict) -> dict:
    prompt = str(payload.get("prompt", "")).strip()
    if not prompt:
        raise ValueError("prompt is required")
    title = str(payload.get("title", "")).strip() or None
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


def read_scenario_detail(workspace: Path, scenario_id: str) -> dict:
    path = safe_scenario_path(workspace, scenario_id)
    summary = summarize_scenario(path).model_dump()
    summary["reports"] = available_reports(path)
    summary["fix_tasks"] = read_fix_tasks(path)
    return summary


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
        ("Design Summary", "design-workspace-summary.md"),
        ("Design Review", "review/design-review-report.md"),
        ("Fix Tasks", "review/design-fix-tasks.md"),
        ("Fix Agent Packages", "review/fix-agent-package-report.md"),
        ("Fix Result Review", "review/fix-result-review.md"),
        ("Realism Report", "review/realism-report.md"),
        ("Lint Report", "review/lint-report.md"),
        ("Agent Review", "review/agent-review.md"),
    ]
    return [{"name": name, "path": rel} for name, rel in candidates if (path / rel).exists()]


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
          <button class="primary" id="createScenario">Create Design</button>
        </div>
        <div class="grid">
          <div><label>Title</label><input id="title" placeholder="Brokerage compliance export lab"></div>
          <div><label>Industry</label><select id="industry"><option value="">Auto</option><option>enterprise</option><option>securities</option><option>healthcare</option><option>manufacturing</option><option>active-directory</option><option>supply-chain</option></select></div>
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
          <div class="meta"><span>${escapeHtml(s.industry)}</span><span class="status ${escapeHtml(s.status)}">${escapeHtml(s.status)}</span></div>
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
              <div class="meta"><span>${escapeHtml(s.scenario_id)}</span><span>${escapeHtml(s.industry)}</span><span class="status ${escapeHtml(s.status)}">${escapeHtml(s.status)}</span></div>
            </div>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
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
          <h2>Fix Tasks</h2>
          <div id="fixTasks">${renderFixTasks(s.fix_tasks || [])}</div>
        </div>`;
      document.getElementById('runReview').onclick = () => runReview(s.scenario_id);
      document.getElementById('generateTasks').onclick = () => generateTasks(s.scenario_id);
      document.getElementById('packageTasks').onclick = () => packageTasks(s.scenario_id);
      document.getElementById('reviewFixResults').onclick = () => reviewFixResults(s.scenario_id);
      detail.querySelectorAll('[data-report]').forEach(btn => btn.onclick = () => loadReport(s.scenario_id, decodeURIComponent(btn.dataset.report)));
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

    async function loadReport(id, path) {
      const res = await fetch(`/api/scenarios/${encodeURIComponent(id)}/file?path=${encodeURIComponent(path)}`);
      document.getElementById('reportViewer').textContent = await res.text();
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
    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    loadScenarios();
  </script>
</body>
</html>"""


STUDIO_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "studio-state.schema.json": StudioState,
    "studio-scenario-summary.schema.json": StudioScenarioSummary,
}
