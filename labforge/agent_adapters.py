from __future__ import annotations

from pathlib import Path
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
        "openai": NotImplementedAdapter(
            "openai",
            "Future OpenAI API adapter. It will consume execution packages and write schema-validated agent results.",
            ["OPENAI_API_KEY"],
        ),
        "claude-cli": NotImplementedAdapter(
            "claude-cli",
            "Future Claude CLI adapter. It will pass execution packages to a local Claude CLI workflow.",
            ["claude CLI"],
        ),
        "mcp": NotImplementedAdapter(
            "mcp",
            "Future MCP adapter. It will delegate execution packages to configured MCP-backed agents.",
            ["MCP configuration"],
        ),
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
}
