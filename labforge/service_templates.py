from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class ServiceTemplate:
    template_id: str
    description: str
    aliases: tuple[str, ...]
    renderer: Callable[[Any, int], dict[str, str]]


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
    if not template_id:
        return None
    for template in SERVICE_TEMPLATES:
        candidates = {template.template_id, *template.aliases}
        if template_id in {normalize_template_id(item) for item in candidates}:
            return template
    return None


def list_service_templates() -> list[ServiceTemplate]:
    return list(SERVICE_TEMPLATES)


def render_template_files(artifact: Any, port: int) -> dict[str, str] | None:
    template = get_service_template(artifact)
    if not template:
        return None
    files = template.renderer(artifact, port)
    files.setdefault("seed/metadata.json", render_metadata(artifact, port, template.template_id))
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


def render_python_flask_web(artifact: Any, port: int) -> dict[str, str]:
    return {
        "Dockerfile": "\n".join(
            [
                "FROM python:3.12-alpine",
                "",
                "WORKDIR /app",
                "RUN pip install --no-cache-dir Flask==3.0.3",
                "COPY app.py /app/app.py",
                "COPY seed /app/seed",
                "RUN mkdir -p /var/log/labforge /state && chmod -R 755 /app /var/log/labforge /state",
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


def render_attacker_workstation_ssh(artifact: Any, port: int) -> dict[str, str]:
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
                "RUN chmod +x /usr/local/bin/labforge-workstation-info && chown -R attacker:attacker /home/attacker /state",
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


def render_controlled_drop(artifact: Any, port: int) -> dict[str, str]:
    return {
        "Dockerfile": "\n".join(
            [
                "FROM python:3.12-alpine",
                "",
                "WORKDIR /app",
                "RUN pip install --no-cache-dir Flask==3.0.3",
                "COPY app.py /app/app.py",
                "COPY seed /app/seed",
                "RUN mkdir -p /state /var/log/labforge && chmod -R 755 /app /state /var/log/labforge",
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
            f"curl -fsS http://127.0.0.1:${{PORT:-{port}}}/healthz",
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


SERVICE_TEMPLATES: tuple[ServiceTemplate, ...] = (
    ServiceTemplate(
        "python-flask-web",
        "Generic Flask HTTP service with metadata and healthcheck endpoints.",
        ("flask", "python web application", "python-flask", "python flask web"),
        render_python_flask_web,
    ),
    ServiceTemplate(
        "attacker-workstation-ssh",
        "Linux learner workstation with SSH and common diagnostic tools.",
        ("attacker workstation", "linux learner workstation", "linux learner attack workstation"),
        render_attacker_workstation_ssh,
    ),
    ServiceTemplate(
        "controlled-drop",
        "Lab-scoped final submission receiver with resettable local state.",
        ("drop service", "controlled drop", "submission service"),
        render_controlled_drop,
    ),
)
