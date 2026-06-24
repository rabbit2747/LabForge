from __future__ import annotations

import json
from pathlib import Path


def write_verified_mvp_manifest(path: Path, detail: dict) -> dict:
    release_gate = detail.get("release_gate") or {}
    manifest = {
        "scenario_id": detail.get("scenario_id"),
        "title": detail.get("title"),
        "industry": detail.get("industry"),
        "status": "verified" if release_gate.get("release_ready") else "not-ready",
        "pipeline_gate": detail.get("pipeline_gate", {}),
        "release_gate": release_gate,
        "playtest": detail.get("playtest", {}),
        "endpoints": detail.get("endpoints", {}),
        "learner_entrypoints": learner_entrypoints_from_manifest(detail.get("endpoints", {})),
        "reports": detail.get("reports", []),
        "next_commands": (detail.get("pipeline_gate") or {}).get("next_commands", []),
    }
    out_dir = path / "mvp"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "verified-mvp.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    (out_dir / "verified-mvp.md").write_text(render_verified_mvp_markdown(manifest), encoding="utf-8", newline="\n")
    return manifest


def learner_entrypoints_from_manifest(endpoint_manifest: dict) -> list[dict]:
    if not isinstance(endpoint_manifest, dict):
        return []
    entries: list[dict] = []
    for item in endpoint_manifest.get("published_endpoints", []):
        if not isinstance(item, dict):
            continue
        entries.append(
            {
                "service": item.get("service", ""),
                "role": item.get("role", ""),
                "protocol": item.get("protocol", ""),
                "connect": item.get("connect") or item.get("url") or "",
                "health_url": item.get("health_url", ""),
            }
        )
    return entries


def render_verified_mvp_markdown(manifest: dict) -> str:
    pipeline_gate = manifest.get("pipeline_gate") or {}
    release_gate = manifest.get("release_gate") or {}
    lines = [
        f"# Verified MVP - {manifest.get('title') or manifest.get('scenario_id')}",
        "",
        f"- Scenario ID: `{manifest.get('scenario_id')}`",
        f"- Industry: `{manifest.get('industry')}`",
        f"- Status: `{manifest.get('status')}`",
        f"- Pipeline decision: `{pipeline_gate.get('decision', '-')}`",
        f"- Release ready: `{str(release_gate.get('release_ready', False)).lower()}`",
        "",
        "## Learner Entrypoints",
        "",
    ]
    entrypoints = manifest.get("learner_entrypoints") or []
    if entrypoints:
        lines.extend(["| Service | Role | Protocol | Connect | Health |", "|---|---|---|---|---|"])
        for item in entrypoints:
            lines.append(
                f"| `{item.get('service', '')}` | {item.get('role', '') or '-'} | `{item.get('protocol', '')}` | "
                f"`{item.get('connect', '') or '-'}` | `{item.get('health_url', '') or '-'}` |"
            )
    else:
        lines.append("No learner-facing endpoints were published.")
    lines.extend(["", "## Release Gate Checks", ""])
    checks = release_gate.get("checks") or []
    if checks:
        lines.extend(["| Check | Status | Messages |", "|---|---|---|"])
        for check in checks:
            messages = "<br>".join(check.get("messages", [])) if isinstance(check, dict) else "-"
            lines.append(f"| `{check.get('name', '-')}` | {check.get('status', '-')} | {messages or '-'} |")
    else:
        lines.append("No release gate checks were recorded.")
    playtest = manifest.get("playtest") or {}
    lines.extend(["", "## Learner Playtest", ""])
    if playtest:
        lines.append(f"- Status: `{playtest.get('status', 'unknown')}`")
        lines.append(f"- Learner entrypoints: `{len(playtest.get('learner_entrypoints') or [])}`")
        lines.append(f"- Attacker entrypoints: `{len(playtest.get('attacker_entrypoints') or [])}`")
        lines.append(f"- Final submission endpoints: `{len(playtest.get('final_submission_endpoints') or [])}`")
        if playtest.get("report"):
            lines.append(f"- Report: `{playtest.get('report')}`")
        if playtest.get("access"):
            lines.append(f"- Access: `{playtest.get('access')}`")
    else:
        lines.append("No learner playtest report was recorded.")
    commands = manifest.get("next_commands") or []
    lines.extend(["", "## Next Commands", ""])
    if commands:
        lines.extend(f"```bash\n{command}\n```" for command in commands)
    else:
        lines.append("No next command suggested.")
    lines.append("")
    return "\n".join(lines)
