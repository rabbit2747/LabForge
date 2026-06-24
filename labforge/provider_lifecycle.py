from __future__ import annotations

import os
import platform
import shlex
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .doctor import inspect_host


class LifecycleModel(BaseModel):
    model_config = ConfigDict(extra="allow")


ProviderLifecycleAction = Literal["validate", "deploy", "destroy", "status"]


class ProviderLifecycleResult(LifecycleModel):
    provider: str
    action: ProviderLifecycleAction
    mode: Literal["dry-run", "execute"]
    status: Literal["planned", "completed", "failed", "not-implemented"]
    output_dir: str
    commands: list[list[str]] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    message: str = ""


NON_DOCKER_PROVIDER_FILES: dict[str, list[str]] = {
    "ansible": ["README.md", "provider-plan.yaml", "inventory.yaml", "security-profile.md", "site.yml"],
    "terraform": ["README.md", "provider-plan.yaml", "inventory.yaml", "security-profile.md", "main.tf", "variables.tf"],
    "ludus": ["README.md", "provider-plan.yaml", "inventory.yaml", "security-profile.md", "range-config.yaml"],
    "hybrid": ["README.md", "provider-plan.yaml", "inventory.yaml", "security-profile.md", "orchestration-plan.yaml"],
}


def provider_lifecycle(
    output_dir: Path,
    *,
    provider: str,
    action: ProviderLifecycleAction,
    execute: bool = False,
    remove_volumes: bool = False,
    timeout_seconds: int = 60,
    env_overrides: dict[str, str] | None = None,
) -> ProviderLifecycleResult:
    output_dir = output_dir.resolve()
    mode: Literal["dry-run", "execute"] = "execute" if execute else "dry-run"
    if provider != "docker-compose":
        return non_docker_provider_lifecycle(output_dir, provider=provider, action=action, mode=mode, execute=execute)

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
    commands = adapt_docker_commands_for_host(commands, output_dir)
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
    child_env = os.environ.copy()
    if env_overrides:
        child_env.update(env_overrides)
    for command in commands:
        try:
            completed = subprocess.run(
                command,
                cwd=output_dir,
                env=child_env,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
        except OSError as exc:
            return ProviderLifecycleResult(
                provider=provider,
                action=action,
                mode=mode,
                status="failed",
                output_dir=str(output_dir),
                commands=commands,
                stdout="\n".join(part for part in stdout_parts if part),
                stderr="\n".join(part for part in stderr_parts if part),
                message=f"Command could not be started: {' '.join(command)} ({exc})",
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            stdout_parts.append(stdout.strip())
            stderr_parts.append(stderr.strip())
            return ProviderLifecycleResult(
                provider=provider,
                action=action,
                mode=mode,
                status="failed",
                output_dir=str(output_dir),
                commands=commands,
                stdout="\n".join(part for part in stdout_parts if part),
                stderr="\n".join(part for part in stderr_parts if part),
                message=f"Command timed out after {timeout_seconds}s: {' '.join(command)}",
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


def non_docker_provider_lifecycle(
    output_dir: Path,
    *,
    provider: str,
    action: ProviderLifecycleAction,
    mode: Literal["dry-run", "execute"],
    execute: bool,
) -> ProviderLifecycleResult:
    provider_root = resolve_provider_root(output_dir, provider)
    commands = non_docker_provider_commands(provider_root, provider, action)
    expected_files = NON_DOCKER_PROVIDER_FILES.get(provider, [])
    if provider not in NON_DOCKER_PROVIDER_FILES:
        return ProviderLifecycleResult(
            provider=provider,
            action=action,
            mode=mode,
            status="not-implemented",
            output_dir=str(provider_root),
            commands=commands,
            message=f"Provider lifecycle action `{action}` is not implemented for unknown provider `{provider}`.",
        )

    if not execute:
        return ProviderLifecycleResult(
            provider=provider,
            action=action,
            mode=mode,
            status="planned",
            output_dir=str(provider_root),
            commands=commands,
            message=(
                "Dry run only. Non-Docker providers emit operator-facing lifecycle plans. "
                "Use `validate --execute` to verify generated scaffold files before provider-specific deployment."
            ),
        )

    missing = [item for item in expected_files if not (provider_root / item).exists()]
    if missing:
        return ProviderLifecycleResult(
            provider=provider,
            action=action,
            mode=mode,
            status="failed",
            output_dir=str(provider_root),
            commands=commands,
            message=f"Generated `{provider}` provider output is missing required files: {', '.join(missing)}",
        )

    if action == "validate":
        return ProviderLifecycleResult(
            provider=provider,
            action=action,
            mode=mode,
            status="completed",
            output_dir=str(provider_root),
            commands=commands,
            stdout="\n".join(f"found {item}" for item in expected_files),
            message="Generated non-Docker provider scaffold is present. Provider-specific syntax checks remain an operator step.",
        )

    return ProviderLifecycleResult(
        provider=provider,
        action=action,
        mode=mode,
        status="not-implemented",
        output_dir=str(provider_root),
        commands=commands,
        message=(
            f"`{provider}` {action} requires an operator-approved external environment. "
            "LabForge generated the command plan but will not execute it automatically yet."
        ),
    )


def resolve_provider_root(output_dir: Path, provider: str) -> Path:
    nested = output_dir / provider
    if nested.exists():
        return nested.resolve()
    return output_dir.resolve()


def non_docker_provider_commands(output_dir: Path, provider: str, action: ProviderLifecycleAction) -> list[list[str]]:
    if provider == "ansible":
        if action == "validate":
            return [["ansible-inventory", "-i", "inventory.yaml", "--list"], ["ansible-playbook", "-i", "inventory.yaml", "site.yml", "--syntax-check"]]
        if action == "deploy":
            return [["ansible-playbook", "-i", "inventory.yaml", "site.yml"]]
        if action == "status":
            return [["ansible", "all", "-i", "inventory.yaml", "-m", "ping"]]
        return [["ansible-playbook", "-i", "inventory.yaml", "destroy.yml"]]
    if provider == "terraform":
        chdir = f"-chdir={output_dir}"
        if action == "validate":
            return [["terraform", chdir, "init", "-backend=false"], ["terraform", chdir, "validate"]]
        if action == "deploy":
            return [["terraform", chdir, "apply"]]
        if action == "status":
            return [["terraform", chdir, "state", "list"]]
        return [["terraform", chdir, "destroy"]]
    if provider == "ludus":
        if action == "validate":
            return [["ludus", "range", "config", "check", "-f", "range-config.yaml"]]
        if action == "deploy":
            return [["ludus", "range", "deploy", "-f", "range-config.yaml"]]
        if action == "status":
            return [["ludus", "range", "status"]]
        return [["ludus", "range", "destroy"]]
    if provider == "hybrid":
        if action == "validate":
            return [["labforge", "provider", "validate", str(output_dir), "--provider", "docker-compose"], ["ansible-inventory", "-i", "inventory.yaml", "--list"]]
        if action == "deploy":
            return [["sh", "scripts/start-docker-tier.sh"], ["ansible-playbook", "-i", "inventory.yaml", "site.yml"]]
        if action == "status":
            return [["sh", "scripts/status.sh"]]
        return [["sh", "scripts/destroy.sh"]]
    return []


def docker_compose_commands(
    action: ProviderLifecycleAction,
    compose_file: Path,
    *,
    remove_volumes: bool = False,
) -> list[list[str]]:
    output_dir = compose_file.parent
    script = lifecycle_script(output_dir, action, remove_volumes=remove_volumes)
    if script:
        return [script]
    compose = ["docker", "compose", "-f", str(compose_file)]
    if action == "validate":
        return [[*compose, "config"]]
    if action == "deploy":
        return [[*compose, "up", "--build", "-d"]]
    if action == "destroy":
        command = [*compose, "down"]
        if remove_volumes:
            command.append("-v")
        return [command]
    return [[*compose, "ps"]]


def adapt_docker_commands_for_host(commands: list[list[str]], output_dir: Path) -> list[list[str]]:
    if not commands:
        return commands
    if platform.system().lower() != "windows":
        return commands
    if any(command and command[0].lower() in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"} for command in commands):
        return commands
    if not all(command and command[0] == "docker" for command in commands):
        return commands

    report = inspect_host()
    if report.host_docker_server:
        return commands
    distro = next((item.name for item in report.wsl_distros if item.docker_server), "")
    if not distro:
        return commands
    return [wrap_command_for_wsl(command, output_dir, distro) for command in commands]


def windows_to_wsl_path(path: Path) -> str:
    resolved = str(path.resolve())
    if len(resolved) >= 3 and resolved[1:3] == ":\\":
        drive = resolved[0].lower()
        rest = resolved[3:].replace("\\", "/")
        return f"/mnt/{drive}/{rest}"
    return resolved.replace("\\", "/")


def translate_path_arg_for_wsl(value: str) -> str:
    if len(value) >= 3 and value[1:3] == ":\\":
        return windows_to_wsl_path(Path(value))
    return value


def wrap_command_for_wsl(command: list[str], output_dir: Path, distro: str) -> list[str]:
    wsl_cwd = windows_to_wsl_path(output_dir)
    translated = [translate_path_arg_for_wsl(item) for item in command]
    inner = "cd " + shlex.quote(wsl_cwd) + " && " + " ".join(shlex.quote(item) for item in translated)
    return ["wsl.exe", "-d", distro, "--", "bash", "-lc", inner]


def lifecycle_script(
    output_dir: Path,
    action: ProviderLifecycleAction,
    *,
    remove_volumes: bool = False,
) -> list[str] | None:
    if action == "validate":
        script_name = "validate"
    elif action == "deploy":
        script_name = "start"
    elif action == "status":
        script_name = "status"
    else:
        script_name = "destroy" if remove_volumes else "stop"
    if platform.system().lower() == "windows":
        script = output_dir / "scripts" / f"{script_name}.ps1"
        if script.exists():
            return [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
            ]
        return None
    script = output_dir / "scripts" / f"{script_name}.sh"
    if script.exists():
        return ["sh", str(script)]
    return None


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
