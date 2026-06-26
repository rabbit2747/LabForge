from __future__ import annotations

import json
from pathlib import Path


def write_verified_mvp_manifest(path: Path, detail: dict) -> dict:
    release_gate = detail.get("release_gate") or {}
    live_execution = live_execution_summary(release_gate)
    verification_level = verification_level_for(release_gate, live_execution)
    manifest = {
        "scenario_id": detail.get("scenario_id"),
        "title": detail.get("title"),
        "industry": detail.get("industry"),
        "status": verified_status(release_gate, live_execution),
        "verification_level": verification_level,
        "playable_by_learner": verification_level == "live",
        "requires_live_playtest": True,
        "live_blockers": live_blockers(live_execution),
        "live_execution": live_execution,
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


def release_gate_checks(release_gate: dict) -> list[dict]:
    checks = release_gate.get("checks") if isinstance(release_gate, dict) else []
    if not isinstance(checks, list):
        return []
    return [check for check in checks if isinstance(check, dict)]


def find_check(checks: list[dict], name: str) -> dict | None:
    for check in checks:
        if check.get("name") == name:
            return check
    return None


def check_messages(check: dict | None) -> list[str]:
    if not isinstance(check, dict):
        return []
    messages = check.get("messages") or []
    if not isinstance(messages, list):
        return []
    return [str(message) for message in messages]


def parse_key_value_messages(messages: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for message in messages:
        if "=" not in message:
            continue
        key, value = message.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def parse_bool(value: str | None) -> bool:
    return str(value or "").lower() in {"1", "true", "yes", "on"}


def parse_int(value: str | None) -> int:
    try:
        return int(str(value or "0"))
    except ValueError:
        return 0


def live_execution_summary(release_gate: dict) -> dict:
    checks = release_gate_checks(release_gate)
    e2e_check = find_check(checks, "e2e-solver-evidence")
    messages = check_messages(e2e_check)
    parsed = parse_key_value_messages(messages)
    requirements = parse_live_requirement_messages(messages)
    execute = parse_bool(parsed.get("execute"))
    executed_access_passed = parse_int(parsed.get("executed_access_passed"))
    executed_solver_passed = parse_int(parsed.get("executed_solver_passed"))
    live_ready = parsed.get("live_readiness") == "passed"
    check_passed = bool(e2e_check and e2e_check.get("status") == "passed")
    if e2e_check is None:
        status = "missing"
    elif check_passed and execute and live_ready and executed_access_passed > 0 and executed_solver_passed > 0:
        status = "passed"
    elif not execute:
        status = "planned"
    else:
        status = "failed"
    return {
        "status": status,
        "mode": parsed.get("mode", "unknown"),
        "execute": execute,
        "browser_engine": parsed.get("browser_engine", ""),
        "execute_tunnels": parse_bool(parsed.get("execute_tunnels")),
        "live_readiness": parsed.get("live_readiness", "unknown"),
        "executed_access_passed": executed_access_passed,
        "executed_solver_passed": executed_solver_passed,
        "requirements": requirements,
        "messages": messages,
    }


def parse_live_requirement_messages(messages: list[str]) -> list[dict]:
    requirements: list[dict] = []
    for message in messages:
        if not message.startswith("live_requirement="):
            continue
        payload = message.split("=", 1)[1]
        parts = payload.split(":")
        if not parts:
            continue
        item = {"name": parts[0], "required": 0, "passed": 0, "status": "unknown"}
        for part in parts[1:]:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            if key in {"required", "passed"}:
                item[key] = parse_int(value)
            elif key == "status":
                item[key] = value
        requirements.append(item)
    return requirements


def verification_level_for(release_gate: dict, live_execution: dict) -> str:
    if not release_gate.get("release_ready"):
        return "not-ready"
    if live_execution.get("status") == "passed":
        return "live"
    return "scaffold"


def live_blockers(live_execution: dict) -> list[str]:
    if live_execution.get("status") == "passed":
        return []
    blockers: list[str] = []
    if not live_execution.get("execute"):
        blockers.append("live e2e execution was not enabled")
    if live_execution.get("browser_engine") in {"", None, "none"}:
        blockers.append("no browser probing engine was recorded")
    if not live_execution.get("execute_tunnels"):
        blockers.append("persistent tunnel execution was not enabled")
    for item in live_execution.get("requirements") or []:
        if not isinstance(item, dict):
            continue
        if item.get("status") != "passed":
            blockers.append(
                f"{item.get('name', 'unknown')} required={item.get('required', 0)} passed={item.get('passed', 0)}"
            )
    if not blockers and live_execution.get("status") != "passed":
        blockers.append(f"live execution status is {live_execution.get('status', 'unknown')}")
    return blockers


def verified_status(release_gate: dict, live_execution: dict) -> str:
    level = verification_level_for(release_gate, live_execution)
    if level == "live":
        return "live-verified"
    if level == "scaffold":
        return "verified-scaffold"
    return "not-ready"


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
        f"- Verification level: `{manifest.get('verification_level')}`",
        f"- Playable by learner: `{str(manifest.get('playable_by_learner', False)).lower()}`",
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
    live_execution = manifest.get("live_execution") or {}
    lines.extend(["", "## Live Execution Evidence", ""])
    lines.append(f"- Status: `{live_execution.get('status', 'unknown')}`")
    lines.append(f"- Mode: `{live_execution.get('mode', 'unknown')}`")
    lines.append(f"- Execute enabled: `{str(live_execution.get('execute', False)).lower()}`")
    lines.append(f"- Browser engine: `{live_execution.get('browser_engine') or '-'}`")
    lines.append(f"- Tunnel execution: `{str(live_execution.get('execute_tunnels', False)).lower()}`")
    lines.append(f"- Live readiness: `{live_execution.get('live_readiness', 'unknown')}`")
    lines.append(f"- Access checks passed: `{live_execution.get('executed_access_passed', 0)}`")
    lines.append(f"- Solver checks passed: `{live_execution.get('executed_solver_passed', 0)}`")
    requirement_rows = live_execution.get("requirements") or []
    lines.extend(["", "| Requirement | Required | Passed | Status |", "|---|---:|---:|---|"])
    if requirement_rows:
        for item in requirement_rows:
            lines.append(
                f"| `{item.get('name', '-')}` | `{item.get('required', 0)}` | "
                f"`{item.get('passed', 0)}` | {item.get('status', '-')} |"
            )
    else:
        lines.append("| `-` | `0` | `0` | not-recorded |")
    if live_execution.get("status") != "passed":
        lines.append("")
        blockers = manifest.get("live_blockers") or []
        if blockers:
            lines.append("### Live Blockers")
            lines.append("")
            lines.extend(f"- {blocker}" for blocker in blockers)
            lines.append("")
        lines.append(
            "This package is not yet live-verified. Run the release gate with live browser, terminal, "
            "and tunnel execution before presenting it as a learner-playable lab."
        )
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
