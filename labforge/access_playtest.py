from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, write_text


AccessCheckStatus = Literal["planned", "passed", "warning", "failed", "skipped"]


class AccessPlaytestModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class AccessPlaytestItem(AccessPlaytestModel):
    check_id: str
    service: str
    kind: str
    command: str
    status: AccessCheckStatus
    expected: str = ""
    stdout: str = ""
    stderr: str = ""
    message: str = ""


class AccessPlaytestReport(AccessPlaytestModel):
    lab_id: str
    title: str
    mode: Literal["dry-run", "execute"]
    status: Literal["planned", "passed", "warning", "failed"]
    access_manifest: str
    browser_targets: list[str] = Field(default_factory=list)
    terminal_targets: list[str] = Field(default_factory=list)
    items: list[AccessPlaytestItem] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)


def run_access_playtest(
    access_manifest: Path,
    out: Path,
    *,
    execute: bool = False,
    timeout_seconds: int = 5,
) -> AccessPlaytestReport:
    access_manifest = access_manifest.resolve()
    out.mkdir(parents=True, exist_ok=True)
    data = load_access_manifest(access_manifest)
    items: list[AccessPlaytestItem] = []
    browser_targets = [
        str(item.get("connect", ""))
        for item in data.get("learner_entrypoints", [])
        if str(item.get("protocol", "")) == "http" and item.get("connect")
    ]
    terminal_targets = [
        str(item.get("connect", ""))
        for item in [*data.get("attacker_entrypoints", []), *data.get("learner_entrypoints", [])]
        if str(item.get("protocol", "")) == "ssh" and item.get("connect")
    ]
    for index, entrypoint in enumerate(data.get("learner_entrypoints", []) or [], start=1):
        if isinstance(entrypoint, dict) and str(entrypoint.get("protocol", "")) == "http" and entrypoint.get("connect"):
            items.append(
                run_http_entrypoint_check(
                    f"browser-{index:02d}",
                    entrypoint,
                    kind="browser-http",
                    expected="browser landing page returns reachable HTML or API content",
                    execute=execute,
                    timeout_seconds=timeout_seconds,
                )
            )
    for index, entrypoint in enumerate(data.get("final_submission_endpoints", []) or [], start=1):
        if isinstance(entrypoint, dict) and str(entrypoint.get("protocol", "")) == "http" and entrypoint.get("connect"):
            items.append(
                run_http_entrypoint_check(
                    f"final-{index:02d}",
                    entrypoint,
                    kind="final-http",
                    expected="final submission endpoint returns reachable HTTP content",
                    execute=execute,
                    timeout_seconds=timeout_seconds,
                )
            )
    for index, check in enumerate(data.get("health_checks", []) or [], start=1):
        if isinstance(check, dict):
            items.append(run_check(f"health-{index:02d}", check, execute=execute, timeout_seconds=timeout_seconds))
    for index, check in enumerate(data.get("terminal_checks", []) or [], start=1):
        if isinstance(check, dict):
            items.append(run_check(f"terminal-{index:02d}", check, execute=execute, timeout_seconds=timeout_seconds))

    mode: Literal["dry-run", "execute"] = "execute" if execute else "dry-run"
    status = aggregate_status(items, execute=execute)
    report = AccessPlaytestReport(
        lab_id=str(data.get("lab_id", "")),
        title=str(data.get("title", "")),
        mode=mode,
        status=status,
        access_manifest=str(access_manifest),
        browser_targets=browser_targets,
        terminal_targets=terminal_targets,
        items=items,
        next_actions=next_actions(data, browser_targets, terminal_targets, execute=execute),
    )
    write_text(out / "access-playtest.yaml", dump_yaml(report.model_dump()))
    write_text(out / "access-playtest.json", report.model_dump_json(indent=2))
    write_text(out / "access-playtest.md", render_access_playtest_markdown(report))
    return report


def load_access_manifest(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"learner access manifest not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"learner access manifest is not an object: {path}")
    for key in ("learner_entrypoints", "attacker_entrypoints", "final_submission_endpoints", "health_checks", "terminal_checks"):
        data.setdefault(key, [])
    return data


def run_http_entrypoint_check(
    check_id: str,
    entrypoint: dict,
    *,
    kind: str,
    expected: str,
    execute: bool,
    timeout_seconds: int,
) -> AccessPlaytestItem:
    url = str(entrypoint.get("connect", "")).strip()
    service = str(entrypoint.get("service", ""))
    if not url:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind=kind,
            command="GET",
            status="failed",
            expected=expected,
            message="missing HTTP URL",
        )
    command = f"GET {url}"
    if not execute:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind=kind,
            command=command,
            status="planned",
            expected=expected,
            message="dry-run",
        )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "LabForgeAccessPlaytest/1.0 (+browser-entrypoint-probe)",
            "Accept": "text/html,application/json,text/plain;q=0.9,*/*;q=0.8",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - lab-contained generated target.
            status_code = int(response.status)
            content_type = str(response.headers.get("Content-Type", ""))
            body = response.read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status_code = int(exc.code)
        content_type = str(exc.headers.get("Content-Type", ""))
        body = exc.read(4096).decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind=kind,
            command=command,
            status="failed",
            expected=expected,
            stderr=str(exc.reason),
            message=f"HTTP target unreachable: {exc.reason}",
        )
    except TimeoutError:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind=kind,
            command=command,
            status="failed",
            expected=expected,
            message=f"HTTP target timed out after {timeout_seconds}s",
        )

    body_sample = body[:500].strip()
    looks_like_browser_content = bool(body_sample) and (
        "<html" in body_sample.lower()
        or "application/json" in content_type.lower()
        or "text/plain" in content_type.lower()
        or "text/html" in content_type.lower()
    )
    if 200 <= status_code < 400 and looks_like_browser_content:
        status: AccessCheckStatus = "passed"
        message = f"http_status={status_code}; content_type={content_type or 'unknown'}; body_bytes={len(body)}"
    elif 400 <= status_code < 500 and body_sample:
        status = "warning"
        message = f"http_status={status_code}; target responded with client error page"
    else:
        status = "failed"
        message = f"http_status={status_code}; browser landing content missing or unusable"

    return AccessPlaytestItem(
        check_id=check_id,
        service=service,
        kind=kind,
        command=command,
        status=status,
        expected=expected,
        stdout=body_sample,
        message=message,
    )


def run_check(check_id: str, check: dict, *, execute: bool, timeout_seconds: int) -> AccessPlaytestItem:
    command = str(check.get("command", "")).strip()
    kind = str(check.get("kind", "command"))
    service = str(check.get("service", ""))
    expected = str(check.get("expected", ""))
    if not command:
        return AccessPlaytestItem(check_id=check_id, service=service, kind=kind, command="", status="failed", expected=expected, message="missing command")
    if not execute:
        return AccessPlaytestItem(check_id=check_id, service=service, kind=kind, command=command, status="planned", expected=expected, message="dry-run")
    argv = command_to_argv(command, kind)
    if not argv:
        return AccessPlaytestItem(check_id=check_id, service=service, kind=kind, command=command, status="skipped", expected=expected, message="unsupported command")
    executable = shutil.which(argv[0])
    if not executable:
        return AccessPlaytestItem(check_id=check_id, service=service, kind=kind, command=command, status="skipped", expected=expected, message=f"missing executable: {argv[0]}")
    try:
        completed = subprocess.run(
            argv,
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
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind=kind,
            command=command,
            status="failed",
            expected=expected,
            stdout=stdout,
            stderr=stderr,
            message=f"command timed out after {timeout_seconds}s",
        )
    ok = completed.returncode == 0
    return AccessPlaytestItem(
        check_id=check_id,
        service=service,
        kind=kind,
        command=command,
        status="passed" if ok else "failed",
        expected=expected,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
        message=f"exit_code={completed.returncode}",
    )


def command_to_argv(command: str, kind: str) -> list[str]:
    if command.startswith("curl "):
        return command.split()
    if kind == "ssh-connect" and command.startswith("ssh "):
        parts = command.split()
        if "-o" not in parts:
            parts[1:1] = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
        return parts
    return []


def aggregate_status(items: list[AccessPlaytestItem], *, execute: bool) -> Literal["planned", "passed", "warning", "failed"]:
    if not execute:
        return "planned"
    if any(item.status == "failed" for item in items):
        return "failed"
    if any(item.status in {"warning", "skipped"} for item in items):
        return "warning"
    return "passed"


def next_actions(data: dict, browser_targets: list[str], terminal_targets: list[str], *, execute: bool) -> list[str]:
    actions = [
        "Start the generated provider output before executing access checks.",
        *[f"Open browser target: {target}" for target in browser_targets],
        *[f"Open terminal target: {target}" for target in terminal_targets],
    ]
    if not execute:
        actions.append("Re-run access playtest with --execute after the provider is running to validate health and SSH checks.")
    if first_action := str(data.get("first_action", "")).strip():
        actions.append(f"Suggested first learner action: {first_action}")
    return actions


def render_access_playtest_markdown(report: AccessPlaytestReport) -> str:
    lines = [
        f"# Access Playtest - {report.title or report.lab_id}",
        "",
        f"- Lab ID: `{report.lab_id}`",
        f"- Mode: `{report.mode}`",
        f"- Status: `{report.status}`",
        f"- Access manifest: `{report.access_manifest}`",
        "",
        "## Browser Targets",
        "",
    ]
    lines.extend(f"- `{target}`" for target in report.browser_targets) if report.browser_targets else lines.append("- None")
    lines.extend(["", "## Terminal Targets", ""])
    lines.extend(f"- `{target}`" for target in report.terminal_targets) if report.terminal_targets else lines.append("- None")
    lines.extend(["", "## Checks", "", "| Check | Service | Kind | Status | Command | Message |", "|---|---|---|---|---|---|"])
    for item in report.items:
        lines.append(
            f"| `{item.check_id}` | `{item.service}` | `{item.kind}` | {item.status} | "
            f"`{item.command.replace('|', '\\|')}` | {item.message.replace('|', '\\|') or '-'} |"
        )
    lines.extend(["", "## Next Actions", ""])
    lines.extend(f"- {item}" for item in report.next_actions)
    lines.append("")
    return "\n".join(lines)
