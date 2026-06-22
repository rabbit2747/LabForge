from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.error
import urllib.request
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .agent_orchestration import AgentExecutionPackageSpec
from .io import load_yaml, write_text


class AgentAdapterError(RuntimeError):
    pass


class AdapterModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class AgentAdapterCapability(AdapterModel):
    name: str
    status: Literal["available", "not-implemented"]
    description: str
    live_execution: bool = False
    requires: list[str] = Field(default_factory=list)


class AgentAdapterPrepareResult(AdapterModel):
    adapter: str
    task_id: str
    status: Literal["prepared", "not-implemented"]
    package_file: str
    invocation_file: str | None = None
    message: str


class AgentAdapterExecutionResult(AdapterModel):
    adapter: str
    task_id: str
    status: Literal["complete", "failed", "not-implemented"]
    package_file: str
    output_file: str | None = None
    transcript_file: str | None = None
    message: str


class AgentAdapter:
    name = "base"
    status: Literal["available", "not-implemented"] = "not-implemented"
    description = "Base adapter contract"
    live_execution = False
    requires: list[str] = []

    def capability(self) -> AgentAdapterCapability:
        return AgentAdapterCapability(
            name=self.name,
            status=self.status,
            description=self.description,
            live_execution=self.live_execution,
            requires=self.requires,
        )

    def prepare(self, package_path: Path) -> AgentAdapterPrepareResult:
        raise NotImplementedError

    def execute(self, package_path: Path) -> AgentAdapterExecutionResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        return AgentAdapterExecutionResult(
            adapter=self.name,
            task_id=package.task_id,
            status="not-implemented",
            package_file=str(package_path),
            message=f"Adapter `{self.name}` does not support live execution.",
        )


class ManualAdapter(AgentAdapter):
    name = "manual"
    status: Literal["available", "not-implemented"] = "available"
    description = "Prepare copy/paste-ready instructions for a human-operated LLM session."
    live_execution = False
    requires: list[str] = []

    def prepare(self, package_path: Path) -> AgentAdapterPrepareResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        invocation_path = package_path.with_suffix(".manual.md")
        write_text(invocation_path, render_manual_invocation(package, package_path))
        return AgentAdapterPrepareResult(
            adapter=self.name,
            task_id=package.task_id,
            status="prepared",
            package_file=str(package_path),
            invocation_file=str(invocation_path),
            message="Manual invocation file created. No LLM was called.",
        )


class OpenAiAdapter(AgentAdapter):
    name = "openai"
    status: Literal["available", "not-implemented"] = "available"
    description = "Execute agent packages through the OpenAI Responses API and write LabForge result YAML."
    live_execution = True
    requires = ["OPENAI_API_KEY", "optional LABFORGE_OPENAI_MODEL"]

    def prepare(self, package_path: Path) -> AgentAdapterPrepareResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        invocation_path = package_path.with_suffix(".openai.json")
        write_text(invocation_path, json.dumps(openai_request_payload(package), ensure_ascii=False, indent=2) + "\n")
        return AgentAdapterPrepareResult(
            adapter=self.name,
            task_id=package.task_id,
            status="prepared",
            package_file=str(package_path),
            invocation_file=str(invocation_path),
            message="OpenAI request payload created. No LLM was called.",
        )

    def execute(self, package_path: Path) -> AgentAdapterExecutionResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return execution_failure(self.name, package, package_path, "OPENAI_API_KEY is not set.")

        payload = openai_request_payload(package)
        request = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=int(os.environ.get("LABFORGE_LLM_TIMEOUT", "120"))) as response:
                response_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return execution_failure(self.name, package, package_path, f"OpenAI API error {exc.code}: {body}")
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return execution_failure(self.name, package, package_path, f"OpenAI API request failed: {exc}")

        text = extract_openai_text(response_data)
        return write_live_execution_outputs(self.name, package, package_path, text, response_data)


class ClaudeCliAdapter(AgentAdapter):
    name = "claude-cli"
    status: Literal["available", "not-implemented"] = "available"
    description = "Execute agent packages through a local Claude CLI command and write LabForge result YAML."
    live_execution = True
    requires = ["claude CLI on PATH", "optional LABFORGE_CLAUDE_ARGS"]

    def prepare(self, package_path: Path) -> AgentAdapterPrepareResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        invocation_path = package_path.with_suffix(".claude.prompt.md")
        write_text(invocation_path, render_live_prompt(package))
        return AgentAdapterPrepareResult(
            adapter=self.name,
            task_id=package.task_id,
            status="prepared",
            package_file=str(package_path),
            invocation_file=str(invocation_path),
            message="Claude CLI prompt file created. No LLM was called.",
        )

    def execute(self, package_path: Path) -> AgentAdapterExecutionResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        claude = shutil.which(os.environ.get("LABFORGE_CLAUDE_BIN", "claude"))
        if not claude:
            return execution_failure(self.name, package, package_path, "Claude CLI was not found on PATH.")

        args = [claude, *split_optional_args(os.environ.get("LABFORGE_CLAUDE_ARGS"))]
        prompt = render_live_prompt(package)
        try:
            completed = subprocess.run(
                args,
                input=prompt,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=int(os.environ.get("LABFORGE_LLM_TIMEOUT", "300")),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return execution_failure(self.name, package, package_path, f"Claude CLI execution failed: {exc}")

        transcript = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "command": args,
        }
        if completed.returncode != 0:
            return write_live_execution_outputs(
                self.name,
                package,
                package_path,
                completed.stdout,
                transcript,
                status="failed",
                message=f"Claude CLI returned {completed.returncode}: {completed.stderr.strip()}",
            )
        return write_live_execution_outputs(self.name, package, package_path, completed.stdout, transcript)


class CodexCliAdapter(AgentAdapter):
    name = "codex"
    status: Literal["available", "not-implemented"] = "available"
    description = "Execute agent packages through Codex CLI (`codex exec`) and write LabForge result YAML."
    live_execution = True
    requires = [
        "codex CLI on PATH",
        "optional LABFORGE_CODEX_MODEL",
        "optional LABFORGE_CODEX_REASONING_EFFORT",
        "optional LABFORGE_CODEX_SANDBOX",
    ]

    def prepare(self, package_path: Path) -> AgentAdapterPrepareResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        prompt_path = package_path.with_suffix(".codex.prompt.md")
        command_path = package_path.with_suffix(".codex.command.ps1")
        write_text(prompt_path, render_live_prompt(package))
        write_text(command_path, render_codex_command(package, prompt_path))
        return AgentAdapterPrepareResult(
            adapter=self.name,
            task_id=package.task_id,
            status="prepared",
            package_file=str(package_path),
            invocation_file=str(command_path),
            message="Codex CLI prompt and command files created. No LLM was called.",
        )

    def execute(self, package_path: Path) -> AgentAdapterExecutionResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        codex = shutil.which(os.environ.get("LABFORGE_CODEX_BIN", "codex"))
        if not codex:
            return execution_failure(self.name, package, package_path, "Codex CLI was not found on PATH.")

        args = codex_command_args(codex, package)
        prompt = render_live_prompt(package)
        try:
            completed = subprocess.run(
                args,
                input=prompt,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=int(os.environ.get("LABFORGE_LLM_TIMEOUT", "300")),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return execution_failure(self.name, package, package_path, f"Codex CLI execution failed: {exc}")

        transcript = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "command": args,
        }
        if completed.returncode != 0:
            return write_live_execution_outputs(
                self.name,
                package,
                package_path,
                completed.stdout,
                transcript,
                status="failed",
                message=f"Codex CLI returned {completed.returncode}: {completed.stderr.strip()}",
            )
        return write_live_execution_outputs(self.name, package, package_path, completed.stdout, transcript)


class ClaudeCodeAdapter(AgentAdapter):
    name = "claude-code"
    status: Literal["available", "not-implemented"] = "available"
    description = "Execute agent packages through Claude Code non-interactive CLI mode and write LabForge result YAML."
    live_execution = True
    requires = ["claude CLI on PATH", "optional LABFORGE_CLAUDE_CODE_ARGS"]

    def prepare(self, package_path: Path) -> AgentAdapterPrepareResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        prompt_path = package_path.with_suffix(".claude-code.prompt.md")
        command_path = package_path.with_suffix(".claude-code.command.ps1")
        write_text(prompt_path, render_live_prompt(package))
        write_text(command_path, render_claude_code_command(prompt_path))
        return AgentAdapterPrepareResult(
            adapter=self.name,
            task_id=package.task_id,
            status="prepared",
            package_file=str(package_path),
            invocation_file=str(command_path),
            message="Claude Code prompt and command files created. No LLM was called.",
        )

    def execute(self, package_path: Path) -> AgentAdapterExecutionResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        claude = shutil.which(os.environ.get("LABFORGE_CLAUDE_CODE_BIN", "claude"))
        if not claude:
            return execution_failure(self.name, package, package_path, "Claude Code CLI was not found on PATH.")

        default_args = ["--print"]
        configured_args = split_optional_args(os.environ.get("LABFORGE_CLAUDE_CODE_ARGS"))
        args = [claude, *(configured_args or default_args)]
        prompt = render_live_prompt(package)
        try:
            completed = subprocess.run(
                args,
                input=prompt,
                text=True,
                encoding="utf-8",
                capture_output=True,
                cwd=package.context_root,
                timeout=int(os.environ.get("LABFORGE_LLM_TIMEOUT", "300")),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return execution_failure(self.name, package, package_path, f"Claude Code execution failed: {exc}")

        transcript = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "command": args,
            "cwd": package.context_root,
        }
        if completed.returncode != 0:
            return write_live_execution_outputs(
                self.name,
                package,
                package_path,
                completed.stdout,
                transcript,
                status="failed",
                message=f"Claude Code returned {completed.returncode}: {completed.stderr.strip()}",
            )
        return write_live_execution_outputs(self.name, package, package_path, completed.stdout, transcript)


class McpAdapter(AgentAdapter):
    name = "mcp"
    status: Literal["available", "not-implemented"] = "available"
    description = "Prepare MCP execution handoff files for an external MCP-capable orchestrator."
    live_execution = False
    requires = ["external MCP runner"]

    def prepare(self, package_path: Path) -> AgentAdapterPrepareResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        invocation_path = package_path.with_suffix(".mcp.json")
        write_text(
            invocation_path,
            json.dumps(
                {
                    "task_id": package.task_id,
                    "agent_id": package.agent_id,
                    "context_root": package.context_root,
                    "system_prompt": package.system_prompt,
                    "task_prompt": package.task_prompt,
                    "task_manifest": package.task_manifest,
                    "output_file": package.output_file,
                    "expected_result_schema": "agent-result.schema.json",
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
        )
        return AgentAdapterPrepareResult(
            adapter=self.name,
            task_id=package.task_id,
            status="prepared",
            package_file=str(package_path),
            invocation_file=str(invocation_path),
            message="MCP handoff file created for an external MCP runner.",
        )


class NotImplementedAdapter(AgentAdapter):
    def __init__(self, name: str, description: str, requires: list[str]) -> None:
        self.name = name
        self.description = description
        self.requires = requires

    def prepare(self, package_path: Path) -> AgentAdapterPrepareResult:
        package = AgentExecutionPackageSpec.model_validate(load_yaml(package_path))
        return AgentAdapterPrepareResult(
            adapter=self.name,
            task_id=package.task_id,
            status="not-implemented",
            package_file=str(package_path),
            message=f"Adapter `{self.name}` is registered as a future integration but is not implemented yet.",
        )


def openai_request_payload(package: AgentExecutionPackageSpec) -> dict[str, Any]:
    return {
        "model": os.environ.get("LABFORGE_OPENAI_MODEL", "gpt-4.1-mini"),
        "input": [
            {
                "role": "system",
                "content": [{"type": "input_text", "text": package.system_prompt}],
            },
            {
                "role": "user",
                "content": [{"type": "input_text", "text": render_live_prompt(package, include_system=False)}],
            },
        ],
        "text": {"format": {"type": "text"}},
    }


def codex_command_args(codex: str, package: AgentExecutionPackageSpec) -> list[str]:
    model = os.environ.get("LABFORGE_CODEX_MODEL", "gpt-5.2")
    effort = os.environ.get("LABFORGE_CODEX_REASONING_EFFORT", "medium")
    sandbox = os.environ.get("LABFORGE_CODEX_SANDBOX", "read-only")
    args = [
        codex,
        "exec",
        "--skip-git-repo-check",
        "-m",
        model,
        "--config",
        f"model_reasoning_effort={effort}",
        "--sandbox",
        sandbox,
        "-C",
        package.context_root,
    ]
    if truthy_env("LABFORGE_CODEX_FULL_AUTO"):
        args.append("--full-auto")
    args.extend(split_optional_args(os.environ.get("LABFORGE_CODEX_ARGS")))
    return args


def render_codex_command(package: AgentExecutionPackageSpec, prompt_path: Path) -> str:
    codex = os.environ.get("LABFORGE_CODEX_BIN", "codex")
    args = codex_command_args(codex, package)
    escaped_args = " ".join(powershell_quote(arg) for arg in args)
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"Get-Content -Raw {powershell_quote(str(prompt_path))} | & {escaped_args}",
            "",
        ]
    )


def render_claude_code_command(prompt_path: Path) -> str:
    claude = os.environ.get("LABFORGE_CLAUDE_CODE_BIN", "claude")
    args = [claude, *(split_optional_args(os.environ.get("LABFORGE_CLAUDE_CODE_ARGS")) or ["--print"])]
    escaped_args = " ".join(powershell_quote(arg) for arg in args)
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"Get-Content -Raw {powershell_quote(str(prompt_path))} | & {escaped_args}",
            "",
        ]
    )


def render_live_prompt(package: AgentExecutionPackageSpec, *, include_system: bool = True) -> str:
    sections = []
    if include_system:
        sections += ["# System Prompt", "", package.system_prompt.rstrip(), ""]
    sections += [
        "# Task Prompt",
        "",
        package.task_prompt.rstrip(),
        "",
        "# Task Manifest",
        "",
        "```yaml",
        render_yaml_like(package.task_manifest),
        "```",
        "",
        "# Required Output",
        "",
        "Return only a YAML object that validates against this shape:",
        "",
        "```yaml",
        f"task_id: {package.task_id}",
        "status: draft",
        "summary: Short reviewable summary.",
        "findings: []",
        "artifacts: []",
        "open_questions: []",
        "```",
        "",
        f"Keep `task_id` exactly `{package.task_id}`.",
        f"The orchestrator will write your YAML to `{package.output_file}`.",
    ]
    return "\n".join(sections)


def extract_openai_text(response_data: dict[str, Any]) -> str:
    if isinstance(response_data.get("output_text"), str):
        return str(response_data["output_text"])
    chunks: list[str] = []
    for item in response_data.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if isinstance(text, str):
                chunks.append(text)
    return "\n".join(chunks).strip()


def write_live_execution_outputs(
    adapter: str,
    package: AgentExecutionPackageSpec,
    package_path: Path,
    text: str,
    transcript: dict[str, Any],
    *,
    status: Literal["complete", "failed"] = "complete",
    message: str = "Live adapter execution completed.",
) -> AgentAdapterExecutionResult:
    package_dir = package_path.parent
    transcript_path = package_path.with_suffix(f".{adapter}.transcript.json")
    write_text(transcript_path, json.dumps(transcript, ensure_ascii=False, indent=2) + "\n")
    output_path = resolve_package_output_path(package_path, package.output_file)
    parsed = extract_yaml_object(text)
    if not parsed:
        parsed = {
            "task_id": package.task_id,
            "status": "needs-review" if status == "complete" else "blocked",
            "summary": text.strip()[:1000] if text.strip() else message,
            "findings": [],
            "artifacts": [{"adapter": adapter, "transcript": str(transcript_path)}],
            "open_questions": ["Adapter output was not a YAML object and needs supervisor review."],
        }
    parsed.setdefault("task_id", package.task_id)
    parsed.setdefault("status", "needs-review")
    parsed.setdefault("summary", "")
    parsed.setdefault("findings", [])
    parsed.setdefault("artifacts", [])
    parsed.setdefault("open_questions", [])
    write_text(output_path, render_yaml_like(parsed) + "\n")
    return AgentAdapterExecutionResult(
        adapter=adapter,
        task_id=package.task_id,
        status=status,
        package_file=str(package_path),
        output_file=str(output_path),
        transcript_file=str(transcript_path),
        message=message,
    )


def execution_failure(adapter: str, package: AgentExecutionPackageSpec, package_path: Path, message: str) -> AgentAdapterExecutionResult:
    return AgentAdapterExecutionResult(
        adapter=adapter,
        task_id=package.task_id,
        status="failed",
        package_file=str(package_path),
        output_file=str(resolve_package_output_path(package_path, package.output_file)),
        message=message,
    )


def resolve_package_output_path(package_path: Path, output_file: str) -> Path:
    # Package files live under <workspace>/.ai/run or <workspace>/.ai/service-build.
    # Output files are expressed relative to <workspace>, usually `.ai/outputs/...`.
    workspace_root = package_path.parent.parent.parent
    return (workspace_root / output_file).resolve()


def extract_yaml_object(text: str) -> dict[str, Any] | None:
    candidates = [text.strip()]
    if "```" in text:
        parts = text.split("```")
        candidates.extend(part.strip().removeprefix("yaml").strip() for part in parts if part.strip())
    for candidate in candidates:
        if not candidate:
            continue
        try:
            import yaml
            value = yaml.safe_load(candidate)
        except Exception:  # noqa: BLE001 - candidate parsing is best-effort.
            continue
        if isinstance(value, dict):
            return value
    return None


def split_optional_args(value: str | None) -> list[str]:
    if not value:
        return []
    import shlex

    return shlex.split(value)


def truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def render_manual_invocation(package: AgentExecutionPackageSpec, package_path: Path) -> str:
    lines = [
        f"# Manual Agent Invocation - {package.task_id}",
        "",
        "## Adapter",
        "",
        "- Name: `manual`",
        "- Live LLM call: no",
        f"- Package file: `{package_path.as_posix()}`",
        "",
        "## How To Use",
        "",
        "1. Start the target LLM or agent runtime manually.",
        "2. Paste the system prompt from the `System Prompt` section as the system/developer instruction, depending on the runtime.",
        "3. Paste the task prompt and task manifest as the user task context.",
        f"4. Write the result to `{package.output_file}` using the LabForge agent result schema.",
        "5. Run `python -m labforge agents validate <workspace>` after writing the result.",
        "",
        "## Context Status",
        "",
        f"- Context root: `{package.context_root}`",
        f"- Missing context files: {', '.join(package.missing_context_files) if package.missing_context_files else 'none'}",
        "",
        "## System Prompt",
        "",
        "```markdown",
        package.system_prompt.rstrip(),
        "```",
        "",
        "## Task Prompt",
        "",
        "```markdown",
        package.task_prompt.rstrip(),
        "```",
        "",
        "## Task Manifest",
        "",
        "```yaml",
    ]
    lines.extend(render_yaml_like(package.task_manifest).splitlines())
    lines += [
        "```",
        "",
    ]
    return "\n".join(lines)


def render_yaml_like(value: dict[str, Any]) -> str:
    try:
        import yaml
    except ImportError as exc:
        raise SystemExit(
            "PyYAML is required. From the LabForge repository root, run: pip install -e ."
        ) from exc
    return yaml.safe_dump(value, sort_keys=False, allow_unicode=True).rstrip()


def adapter_registry() -> dict[str, AgentAdapter]:
    return {
        "manual": ManualAdapter(),
        "openai": OpenAiAdapter(),
        "codex": CodexCliAdapter(),
        "claude-cli": ClaudeCliAdapter(),
        "claude-code": ClaudeCodeAdapter(),
        "mcp": McpAdapter(),
    }


def get_agent_adapter(name: str) -> AgentAdapter:
    adapters = adapter_registry()
    if name not in adapters:
        known = ", ".join(sorted(adapters))
        raise AgentAdapterError(f"unknown agent adapter `{name}`. Available adapters: {known}")
    return adapters[name]


def list_agent_adapters() -> list[AgentAdapterCapability]:
    return [adapter.capability() for adapter in adapter_registry().values()]


def render_agent_adapter_list() -> str:
    lines = [
        "# LabForge Agent Adapters",
        "",
        "| Adapter | Status | Live Execution | Requires | Description |",
        "|---|---|---:|---|---|",
    ]
    for item in list_agent_adapters():
        requires = ", ".join(item.requires) if item.requires else "-"
        lines.append(
            f"| `{item.name}` | {item.status} | {str(item.live_execution).lower()} | {requires} | {item.description} |"
        )
    lines.append("")
    return "\n".join(lines)


ADAPTER_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "agent-adapter-capability.schema.json": AgentAdapterCapability,
    "agent-adapter-prepare-result.schema.json": AgentAdapterPrepareResult,
    "agent-adapter-execution-result.schema.json": AgentAdapterExecutionResult,
}
