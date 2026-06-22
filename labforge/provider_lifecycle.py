from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LifecycleModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class ProviderLifecycleResult(LifecycleModel):
    provider: str
    action: Literal["deploy", "destroy", "status"]
    mode: Literal["dry-run", "execute"]
    status: Literal["planned", "completed", "failed", "not-implemented"]
    output_dir: str
    commands: list[list[str]] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    message: str = ""


def provider_lifecycle(
    output_dir: Path,
    *,
    provider: str,
    action: Literal["deploy", "destroy", "status"],
    execute: bool = False,
    remove_volumes: bool = False,
) -> ProviderLifecycleResult:
    output_dir = output_dir.resolve()
    mode: Literal["dry-run", "execute"] = "execute" if execute else "dry-run"
    if provider != "docker-compose":
        return ProviderLifecycleResult(
            provider=provider,
            action=action,
            mode=mode,
            status="not-implemented",
            output_dir=str(output_dir),
            message=f"Provider lifecycle action `{action}` is not implemented for `{provider}`.",
        )

    compose_file = output_dir / "docker-compose.yml"
    if not compose_file.exists():
        return ProviderLifecycleResult(
            provider=provider,
            action=action,
            mode=mode,
            status="failed",
            output_dir=str(output_dir),
            message=f"docker-compose.yml not found in generated output: {output_dir}",
        )

    commands = docker_compose_commands(action, compose_file, remove_volumes=remove_volumes)
    if not execute:
        return ProviderLifecycleResult(
            provider=provider,
            action=action,
            mode=mode,
            status="planned",
            output_dir=str(output_dir),
            commands=commands,
            message="Dry run only. Re-run with --execute to invoke Docker Compose.",
        )

    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=output_dir,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        stdout_parts.append(completed.stdout.strip())
        stderr_parts.append(completed.stderr.strip())
        if completed.returncode != 0:
            return ProviderLifecycleResult(
                provider=provider,
                action=action,
                mode=mode,
                status="failed",
                output_dir=str(output_dir),
                commands=commands,
                stdout="\n".join(part for part in stdout_parts if part),
                stderr="\n".join(part for part in stderr_parts if part),
                message=f"Command failed with exit code {completed.returncode}: {' '.join(command)}",
            )

    return ProviderLifecycleResult(
        provider=provider,
        action=action,
        mode=mode,
        status="completed",
        output_dir=str(output_dir),
        commands=commands,
        stdout="\n".join(part for part in stdout_parts if part),
        stderr="\n".join(part for part in stderr_parts if part),
    )


def docker_compose_commands(
    action: Literal["deploy", "destroy", "status"],
    compose_file: Path,
    *,
    remove_volumes: bool = False,
) -> list[list[str]]:
    compose = ["docker", "compose", "-f", str(compose_file)]
    if action == "deploy":
        return [[*compose, "up", "--build", "-d"]]
    if action == "destroy":
        command = [*compose, "down"]
        if remove_volumes:
            command.append("-v")
        return [command]
    return [[*compose, "ps"]]


def render_lifecycle_result(result: ProviderLifecycleResult) -> str:
    lines = [
        "# Provider Lifecycle Result",
        "",
        f"- Provider: `{result.provider}`",
        f"- Action: `{result.action}`",
        f"- Mode: `{result.mode}`",
        f"- Status: `{result.status}`",
        f"- Output directory: `{result.output_dir}`",
        f"- Host OS: `{platform.system()}`",
        "",
        "## Commands",
        "",
    ]
    if result.commands:
        lines.extend(f"- `{' '.join(command)}`" for command in result.commands)
    else:
        lines.append("- No commands planned.")
    if result.message:
        lines += ["", "## Message", "", result.message]
    if result.stdout:
        lines += ["", "## Stdout", "", "```text", result.stdout, "```"]
    if result.stderr:
        lines += ["", "## Stderr", "", "```text", result.stderr, "```"]
    lines.append("")
    return "\n".join(lines)


PROVIDER_LIFECYCLE_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "provider-lifecycle-result.schema.json": ProviderLifecycleResult,
}
