from __future__ import annotations

import json
import shlex
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, write_text


AccessCheckStatus = Literal["planned", "passed", "warning", "failed", "skipped"]
BrowserProbeEngine = Literal["http", "playwright"]


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
    browser_engine: BrowserProbeEngine = "http",
    execute_tunnels: bool = False,
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
                    browser_engine=browser_engine,
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
                    browser_engine=browser_engine,
                )
            )
    for index, check in enumerate(data.get("health_checks", []) or [], start=1):
        if isinstance(check, dict):
            items.append(run_check(f"health-{index:02d}", check, execute=execute, timeout_seconds=timeout_seconds))
    for index, check in enumerate(data.get("terminal_checks", []) or [], start=1):
        if isinstance(check, dict):
            items.append(run_check(f"terminal-{index:02d}", check, execute=execute, timeout_seconds=timeout_seconds))
    for index, check in enumerate(data.get("terminal_sequences", []) or [], start=1):
        if isinstance(check, dict):
            items.append(run_terminal_sequence_check(f"terminal-seq-{index:02d}", check, execute=execute, timeout_seconds=timeout_seconds))
    for index, check in enumerate(data.get("tunnel_commands", []) or [], start=1):
        if isinstance(check, dict):
            items.append(
                run_tunnel_command_check(
                    f"tunnel-{index:02d}",
                    check,
                    execute=execute,
                    execute_tunnel=execute_tunnels,
                    timeout_seconds=timeout_seconds,
                )
            )
    for index, check in enumerate(data.get("plugin_checks", []) or [], start=1):
        if isinstance(check, dict):
            items.append(run_plugin_evidence_check(f"plugin-evidence-{index:02d}", check, execute=execute, timeout_seconds=timeout_seconds))

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
    for key in (
        "learner_entrypoints",
        "attacker_entrypoints",
        "final_submission_endpoints",
        "health_checks",
        "terminal_checks",
        "terminal_sequences",
        "tunnel_commands",
        "plugin_checks",
    ):
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
    browser_engine: BrowserProbeEngine = "http",
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
    expected_texts = normalize_expected_texts(entrypoint)
    expected_selectors = normalize_expected_selectors(entrypoint)
    if execute and browser_engine == "playwright":
        return run_playwright_entrypoint_check(
            check_id,
            service,
            url,
            expected,
            expected_texts,
            expected_selectors,
            timeout_seconds=timeout_seconds,
        )
    if not execute:
        expected_detail = expected
        if expected_texts:
            expected_detail = f"{expected}; expected text: {', '.join(expected_texts)}"
        if expected_selectors:
            expected_detail = f"{expected_detail}; expected selectors: {', '.join(expected_selectors)}"
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind=kind,
            command=command,
            status="planned",
            expected=expected_detail,
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
        missing_texts = [text for text in expected_texts if text not in body]
        if missing_texts:
            status: AccessCheckStatus = "warning"
            message = (
                f"http_status={status_code}; content_type={content_type or 'unknown'}; "
                f"body_bytes={len(body)}; missing_expected_text={','.join(missing_texts)}"
            )
        else:
            status = "passed"
            text_note = f"; matched_expected_text={len(expected_texts)}" if expected_texts else ""
            message = f"http_status={status_code}; content_type={content_type or 'unknown'}; body_bytes={len(body)}{text_note}"
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


def run_playwright_entrypoint_check(
    check_id: str,
    service: str,
    url: str,
    expected: str,
    expected_texts: list[str],
    expected_selectors: list[str],
    *,
    timeout_seconds: int,
) -> AccessPlaytestItem:
    executable = shutil.which("npx")
    command = f"playwright chromium GET {url}"
    if not executable:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="browser-playwright",
            command=command,
            status="failed",
            expected=expected,
            message="missing executable: npx",
        )
    script = """
const { chromium } = require('playwright');
const target = process.argv[1];
const expected = JSON.parse(process.argv[2] || '[]');
const selectors = JSON.parse(process.argv[3] || '[]');
const timeoutMs = Number(process.argv[4] || '5000');
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto(target, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
  const bodyText = await page.locator('body').innerText({ timeout: timeoutMs }).catch(() => '');
  const title = await page.title().catch(() => '');
  const finalUrl = page.url();
  const missingSelectors = [];
  const selectorCounts = {};
  for (const selector of selectors) {
    const count = await page.locator(selector).count().catch(() => 0);
    selectorCounts[selector] = count;
    if (count < 1) missingSelectors.push(selector);
  }
  await browser.close();
  const missing = expected.filter((value) => !bodyText.includes(value) && !title.includes(value));
  console.log(JSON.stringify({ ok: missing.length === 0 && missingSelectors.length === 0, url: finalUrl, title, text: bodyText.slice(0, 2000), missing, missingSelectors, selectorCounts }));
})().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(2);
});
""".strip()
    argv = [
        executable,
        "--yes",
        "--package",
        "playwright",
        "node",
        "-e",
        script,
        url,
        json.dumps(expected_texts),
        json.dumps(expected_selectors),
        str(max(timeout_seconds, 1) * 1000),
    ]
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(timeout_seconds + 10, 15),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="browser-playwright",
            command=command,
            status="failed",
            expected=expected,
            stdout=stdout.strip(),
            stderr=stderr.strip(),
            message=f"Playwright probe timed out after {timeout_seconds}s",
        )
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    if completed.returncode != 0:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="browser-playwright",
            command=command,
            status="failed",
            expected=expected,
            stdout=stdout[:500],
            stderr=stderr[:500],
            message=f"playwright_exit_code={completed.returncode}",
        )
    try:
        data = json.loads(stdout.splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="browser-playwright",
            command=command,
            status="failed",
            expected=expected,
            stdout=stdout[:500],
            stderr=stderr[:500],
            message=f"could not parse Playwright probe output: {exc}",
        )
    missing = [str(item) for item in data.get("missing", [])]
    missing_selectors = [str(item) for item in data.get("missingSelectors", [])]
    text_sample = str(data.get("text", ""))[:500].strip()
    if missing:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="browser-playwright",
            command=command,
            status="warning",
            expected=expected,
            stdout=text_sample,
            message=f"browser_loaded=true; missing_expected_text={','.join(missing)}",
        )
    if missing_selectors:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="browser-playwright",
            command=command,
            status="warning",
            expected=expected,
            stdout=text_sample,
            message=f"browser_loaded=true; missing_expected_selector={','.join(missing_selectors)}",
        )
    return AccessPlaytestItem(
        check_id=check_id,
        service=service,
        kind="browser-playwright",
        command=command,
        status="passed",
        expected=expected,
        stdout=text_sample,
        message=(
            f"browser_loaded=true; matched_expected_text={len(expected_texts)}; "
            f"matched_expected_selector={len(expected_selectors)}; title={data.get('title', '')}"
        ),
    )


def normalize_expected_texts(entrypoint: dict) -> list[str]:
    values: list[str] = []
    single = str(entrypoint.get("expected_text", "")).strip()
    if single:
        values.append(single)
    raw_many = entrypoint.get("expected_texts", [])
    if isinstance(raw_many, list):
        values.extend(str(item).strip() for item in raw_many if str(item).strip())
    return list(dict.fromkeys(values))


def normalize_expected_selectors(entrypoint: dict) -> list[str]:
    values: list[str] = []
    single = str(entrypoint.get("expected_selector", "")).strip()
    if single:
        values.append(single)
    raw_many = entrypoint.get("expected_selectors", [])
    if isinstance(raw_many, list):
        values.extend(str(value).strip() for value in raw_many if str(value).strip())
    return list(dict.fromkeys(values))


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


def run_terminal_sequence_check(check_id: str, check: dict, *, execute: bool, timeout_seconds: int) -> AccessPlaytestItem:
    service = str(check.get("service", ""))
    connect = str(check.get("connect") or check.get("command") or "").strip()
    commands = [str(item).strip() for item in check.get("commands", []) or [] if str(item).strip()]
    expected_texts = [str(item).strip() for item in check.get("expected_texts", []) or [] if str(item).strip()]
    expected = str(check.get("expected", "remote command sequence completes and expected output is visible"))
    if not connect:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-command-sequence",
            command="",
            status="failed",
            expected=expected,
            message="missing SSH connect command",
        )
    if not commands:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-command-sequence",
            command=connect,
            status="failed",
            expected=expected,
            message="missing remote commands",
        )
    remote_script = " && ".join(commands)
    display_command = f"{connect} {shlex.quote(remote_script)}"
    if not execute:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-command-sequence",
            command=display_command,
            status="planned",
            expected=expected,
            message="dry-run",
        )
    argv = ssh_sequence_argv(connect, remote_script)
    if not argv:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-command-sequence",
            command=display_command,
            status="skipped",
            expected=expected,
            message="unsupported SSH command sequence",
        )
    executable = shutil.which(argv[0])
    if not executable:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-command-sequence",
            command=display_command,
            status="skipped",
            expected=expected,
            message=f"missing executable: {argv[0]}",
        )
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
            kind="ssh-command-sequence",
            command=display_command,
            status="failed",
            expected=expected,
            stdout=stdout.strip(),
            stderr=stderr.strip(),
            message=f"remote command sequence timed out after {timeout_seconds}s",
        )
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    if completed.returncode != 0:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-command-sequence",
            command=display_command,
            status="failed",
            expected=expected,
            stdout=stdout,
            stderr=stderr,
            message=f"exit_code={completed.returncode}",
        )
    missing = [text for text in expected_texts if text not in stdout and text not in stderr]
    if missing:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-command-sequence",
            command=display_command,
            status="warning",
            expected=expected,
            stdout=stdout,
            stderr=stderr,
            message=f"exit_code=0; missing_expected_text={','.join(missing)}",
        )
    return AccessPlaytestItem(
        check_id=check_id,
        service=service,
        kind="ssh-command-sequence",
        command=display_command,
        status="passed",
        expected=expected,
        stdout=stdout,
        stderr=stderr,
        message=f"exit_code=0; commands={len(commands)}; matched_expected_text={len(expected_texts)}",
    )


def run_tunnel_command_check(check_id: str, check: dict, *, execute: bool, execute_tunnel: bool = False, timeout_seconds: int = 5) -> AccessPlaytestItem:
    service = str(check.get("service", ""))
    command = str(check.get("command", "")).strip()
    expected = "SSH local-forward command is well-formed and matches the declared internal target."
    if not command:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-local-forward",
            command="",
            status="failed",
            expected=expected,
            message="missing tunnel command",
        )
    parsed = parse_ssh_local_forward(command)
    if not parsed:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-local-forward",
            command=command,
            status="failed",
            expected=expected,
            message="unsupported SSH local-forward syntax; expected `ssh -L local:host:port destination`",
        )
    messages = tunnel_consistency_messages(check, parsed)
    if messages:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-local-forward",
            command=command,
            status="failed",
            expected=expected,
            message="; ".join(messages),
        )
    if not execute:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-local-forward",
            command=command,
            status="planned",
            expected=expected,
            message=f"dry-run; local={parsed['local_port']}; target={parsed['target_host']}:{parsed['target_port']}",
        )
    if not shutil.which("ssh"):
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-local-forward",
            command=command,
            status="skipped",
            expected=expected,
            message="missing executable: ssh",
        )
    if execute_tunnel:
        return run_live_tunnel_probe(check_id, check, parsed, expected, timeout_seconds=timeout_seconds)
    return AccessPlaytestItem(
        check_id=check_id,
        service=service,
        kind="ssh-local-forward",
        command=command,
        status="passed",
        expected=expected,
        message=(
            "syntax_valid=true; "
            f"local={parsed['local_port']}; target={parsed['target_host']}:{parsed['target_port']}; "
            "execution_noninvasive=true"
        ),
    )


def run_live_tunnel_probe(check_id: str, check: dict, parsed: dict[str, str], expected: str, *, timeout_seconds: int) -> AccessPlaytestItem:
    service = str(check.get("service", ""))
    command = str(check.get("command", "")).strip()
    argv = ssh_tunnel_argv(command)
    if not argv:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-local-forward",
            command=command,
            status="failed",
            expected=expected,
            message="could not build non-interactive SSH tunnel argv",
        )
    process = None
    try:
        process = subprocess.Popen(  # noqa: S603 - lab-scoped SSH command parsed with shlex and executed without shell.
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        local_port = int(parsed["local_port"])
        if wait_for_tcp_port("127.0.0.1", local_port, timeout_seconds):
            return AccessPlaytestItem(
                check_id=check_id,
                service=service,
                kind="ssh-local-forward",
                command=command,
                status="passed",
                expected=expected,
                message=(
                    "tunnel_open=true; "
                    f"local={parsed['local_port']}; target={parsed['target_host']}:{parsed['target_port']}; "
                    "terminated_after_probe=true"
                ),
            )
        stdout, stderr = collect_process_output(process)
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-local-forward",
            command=command,
            status="failed",
            expected=expected,
            stdout=stdout,
            stderr=stderr,
            message=f"tunnel did not open on 127.0.0.1:{parsed['local_port']} within {timeout_seconds}s",
        )
    except (OSError, ValueError) as exc:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="ssh-local-forward",
            command=command,
            status="failed",
            expected=expected,
            message=f"tunnel execution failed: {exc}",
        )
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()


def ssh_tunnel_argv(command: str) -> list[str]:
    try:
        parts = shlex.split(command)
    except ValueError:
        return []
    if not parts or parts[0] != "ssh":
        return []
    options = [
        "-N",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ConnectTimeout=5",
    ]
    return [parts[0], *options, *parts[1:]]


def wait_for_tcp_port(host: str, port: int, timeout_seconds: int) -> bool:
    deadline = time.monotonic() + max(timeout_seconds, 1)
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def collect_process_output(process: subprocess.Popen) -> tuple[str, str]:
    try:
        stdout, stderr = process.communicate(timeout=0.5)
    except subprocess.TimeoutExpired:
        return "", ""
    return (stdout or "").strip(), (stderr or "").strip()


def parse_ssh_local_forward(command: str) -> dict[str, str] | None:
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts or parts[0] != "ssh":
        return None
    forward = ""
    for index, part in enumerate(parts):
        if part == "-L" and index + 1 < len(parts):
            forward = parts[index + 1]
            break
        if part.startswith("-L") and len(part) > 2:
            forward = part[2:]
            break
    if not forward:
        return None
    pieces = forward.split(":")
    if len(pieces) < 3:
        return None
    local_port, target_host, target_port = pieces[0], pieces[1], pieces[2]
    if not local_port.isdigit() or not target_host or not target_port:
        return None
    return {"local_port": local_port, "target_host": target_host, "target_port": target_port}


def tunnel_consistency_messages(check: dict, parsed: dict[str, str]) -> list[str]:
    messages: list[str] = []
    expected_local = str(check.get("local_port", "")).strip()
    expected_dns = str(check.get("dns", "")).strip()
    expected_port = str(check.get("internal_port", "")).strip()
    if expected_local and expected_local != parsed["local_port"]:
        messages.append(f"local_port mismatch expected={expected_local} command={parsed['local_port']}")
    if expected_dns and expected_dns != parsed["target_host"]:
        messages.append(f"dns mismatch expected={expected_dns} command={parsed['target_host']}")
    if expected_port and expected_port != parsed["target_port"]:
        messages.append(f"internal_port mismatch expected={expected_port} command={parsed['target_port']}")
    return messages


def run_plugin_evidence_check(check_id: str, check: dict, *, execute: bool, timeout_seconds: int) -> AccessPlaytestItem:
    service = str(check.get("service", ""))
    plugin = str(check.get("plugin", ""))
    state_url = str(check.get("state_url", "")).strip()
    expected_evidence = [str(item).strip() for item in check.get("expected_evidence", []) or [] if str(item).strip()]
    command = f"GET {state_url}" if state_url else str(check.get("state_verification", "")).strip()
    expected = f"acquired_evidence contains {', '.join(expected_evidence)}" if expected_evidence else "stage state is reachable"
    if not state_url:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="plugin-evidence",
            command=command,
            status="skipped" if execute else "planned",
            expected=expected,
            message="plugin evidence has no published HTTP state URL",
        )
    if not execute:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="plugin-evidence",
            command=command,
            status="planned",
            expected=expected,
            message=f"dry-run; plugin={plugin}",
        )
    status, data, body = http_json_get(state_url, timeout_seconds)
    if status == 0:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="plugin-evidence",
            command=command,
            status="failed",
            expected=expected,
            stderr=body,
            message=f"state URL unreachable; plugin={plugin}",
        )
    if status != 200:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="plugin-evidence",
            command=command,
            status="failed",
            expected=expected,
            stdout=body[:500],
            message=f"state HTTP status={status}; plugin={plugin}",
        )
    acquired = data.get("acquired_evidence", []) if isinstance(data, dict) else []
    if not isinstance(acquired, list):
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="plugin-evidence",
            command=command,
            status="failed",
            expected=expected,
            stdout=body[:500],
            message=f"state shape missing acquired_evidence list; plugin={plugin}",
        )
    acquired_text = {str(item) for item in acquired}
    missing = [item for item in expected_evidence if item not in acquired_text]
    if missing:
        return AccessPlaytestItem(
            check_id=check_id,
            service=service,
            kind="plugin-evidence",
            command=command,
            status="failed",
            expected=expected,
            stdout=body[:500],
            message=f"missing_expected_evidence={','.join(missing)}; acquired_evidence={len(acquired_text)}; plugin={plugin}",
        )
    return AccessPlaytestItem(
        check_id=check_id,
        service=service,
        kind="plugin-evidence",
        command=command,
        status="passed",
        expected=expected,
        stdout=body[:500],
        message=f"expected_evidence_present={len(expected_evidence)}; acquired_evidence={len(acquired_text)}; plugin={plugin}",
    )


def http_json_get(url: str, timeout_seconds: int) -> tuple[int, dict, str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "LabForgeAccessPlaytest/1.0 (+plugin-evidence-probe)", "Accept": "application/json,text/plain;q=0.8,*/*;q=0.5"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - lab-contained generated target.
            body = response.read(16384).decode("utf-8", "replace")
            return int(response.status), parse_json_body(body), body
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(4096).decode("utf-8", "replace")
        finally:
            exc.close()
        return int(exc.code), parse_json_body(body), body
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, {}, str(exc)


def parse_json_body(body: str) -> dict:
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def command_to_argv(command: str, kind: str) -> list[str]:
    if command.startswith("curl "):
        return command.split()
    if kind == "ssh-connect" and command.startswith("ssh "):
        parts = command.split()
        if "-o" not in parts:
            parts[1:1] = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
        return parts
    return []


def ssh_sequence_argv(connect: str, remote_script: str) -> list[str]:
    if not connect.startswith("ssh "):
        return []
    parts = connect.split()
    if "-o" not in parts:
        parts[1:1] = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
    return [*parts, remote_script]


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
