from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from labforge.io import dump_yaml, write_text
from labforge.model import LabSpec
from labforge.providers.base import Provider
from labforge.security_controls import control_placements, has_selected_category, selected_controls


class DockerComposeProvider(Provider):
    name = "docker-compose"

    def generate(self, spec: LabSpec, out: Path, **kwargs: Any) -> None:
        profile = str(kwargs.get("profile", "unprotected"))
        write_text(out / "docker-compose.yml", render_compose(spec, profile=profile))
        write_text(out / "docs" / "provider-security-plan.md", render_security_plan(spec, profile))
        write_text(out / "docs" / "provider-service-plan.md", render_provider_service_plan(spec))
        copy_service_sources(spec, out)
        write_runtime_scripts(out)
        endpoint_manifest = build_endpoint_manifest(spec)
        write_text(out / "endpoints.json", json.dumps(endpoint_manifest, ensure_ascii=False, indent=2) + "\n")
        write_text(out / "QUICKSTART.md", render_quickstart(spec, profile, endpoint_manifest))


def service_artifact_map(spec: LabSpec) -> dict[str, Any]:
    if not spec.artifacts_model:
        return {}
    return {artifact.service: artifact for artifact in spec.artifacts_model.service_artifacts}


def service_build_context(spec: LabSpec, service: dict[str, Any], artifacts: dict[str, Any]) -> str:
    name = str(service["name"])
    if service.get("build"):
        return str(service["build"])
    artifact = artifacts.get(name)
    if artifact:
        source = spec.root / artifact.source_path
        if source.exists():
            return f"./{artifact.source_path}"
    return f"./services/{name}"


def copy_service_sources(spec: LabSpec, out: Path) -> None:
    for artifact in service_artifact_map(spec).values():
        source = spec.root / artifact.source_path
        if not source.exists() or not source.is_dir():
            continue
        target = out / artifact.source_path
        shutil.copytree(
            source,
            target,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
        )


def render_compose(spec: LabSpec, profile: str = "unprotected") -> str:
    artifacts = service_artifact_map(spec)
    compose: dict[str, Any] = {
        "name": spec.lab_id,
        "networks": {},
        "volumes": {"labforge_state": {}},
        "services": {},
    }
    used_host_ports: set[int] = set()

    for network in spec.networks:
        name = str(network["name"])
        compose["networks"][name] = {"driver": "bridge"}
        if network.get("internal", False):
            compose["networks"][name]["internal"] = True
        if profile == "protected":
            compose["networks"][name]["labels"] = [
                f"labforge.profile={profile}",
                f"labforge.network={name}",
            ]

    for service in spec.services:
        name = str(service["name"])
        artifact = artifacts.get(name)
        entry: dict[str, Any] = {
            "build": service_build_context(spec, service, artifacts),
            "networks": service.get("networks", []),
            "restart": "unless-stopped",
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
            "pids_limit": 200,
            "labels": [
                f"labforge.profile={profile}",
                f"labforge.role={service.get('role', 'service')}",
            ],
        }
        if artifact:
            entry["labels"].extend(
                [
                    f"labforge.service.source={artifact.source_path}",
                    f"labforge.service.runtime={artifact.runtime}",
                    "labforge.service.contract=docs/service-artifact-contract.md",
                ]
            )
        if profile == "protected":
            entry["labels"].append("labforge.security-controls=enabled")
            if has_selected_category(spec, "siem"):
                entry["logging"] = {
                    "driver": "json-file",
                    "options": {
                        "max-size": "10m",
                        "max-file": "3",
                    },
                }
        if service.get("read_only", True):
            entry["read_only"] = True
            entry.setdefault("tmpfs", ["/tmp", "/state", "/var/log/labforge"])
        if "user" in service:
            entry["user"] = str(service["user"])
        if service.get("expose"):
            entry["expose"] = [str(port) for port in service["expose"]]
        if service.get("ports"):
            entry["ports"] = normalize_port_mappings(name, service["ports"], used_host_ports)
        if service.get("environment"):
            entry["environment"] = service["environment"]
        if service.get("volumes"):
            entry["volumes"] = service["volumes"]
        if artifact:
            add_service_environment(entry, "LABFORGE_STATE_DIR", "/labforge-state")
            volumes = list(entry.get("volumes", []))
            if "labforge_state:/labforge-state" not in volumes:
                volumes.append("labforge_state:/labforge-state")
            entry["volumes"] = volumes
        if service.get("depends_on"):
            entry["depends_on"] = service["depends_on"]
        if service.get("healthcheck"):
            entry["healthcheck"] = service["healthcheck"]
        compose["services"][name] = entry

    if profile == "protected":
        add_security_control_services(spec, compose)

    return dump_yaml(compose)


def add_service_environment(entry: dict[str, Any], key: str, value: str) -> None:
    environment = entry.get("environment")
    if environment is None:
        entry["environment"] = {key: value}
        return
    if isinstance(environment, dict):
        environment.setdefault(key, value)
        return
    if isinstance(environment, list):
        prefix = f"{key}="
        if not any(str(item).startswith(prefix) for item in environment):
            environment.append(f"{key}={value}")
        return
    entry["environment"] = {key: value}


def normalize_port_mappings(service_name: str, ports: list[Any], used_host_ports: set[int]) -> list[str]:
    return [item["compose_mapping"] for item in port_mapping_records(service_name, ports, used_host_ports)]


def port_mapping_records(service_name: str, ports: list[Any], used_host_ports: set[int]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    next_dynamic = 18080
    for item in ports:
        text = str(item)
        bind_ip = ""
        if ":" not in text:
            host = parse_port(text)
            container = text
        else:
            host_text, container = text.rsplit(":", maxsplit=1)
            host = parse_port(host_text)
        if host is None:
            records.append(
                {
                    "source": text,
                    "compose_mapping": text,
                    "container_port": container if ":" in text else text,
                    "default_host_port": None,
                    "env": None,
                    "bind_ip": bind_ip,
                }
            )
            continue
        if host in used_host_ports:
            while next_dynamic in used_host_ports:
                next_dynamic += 1
            host = next_dynamic
        used_host_ports.add(host)
        host_expr = f"${{{port_env_name(service_name, container)}:-{host}}}"
        if ":" in text and ":" in host_text:
            bind_ip = host_text.rsplit(":", maxsplit=1)[0]
            compose_mapping = f"{bind_ip}:{host_expr}:{container}"
        else:
            compose_mapping = f"{host_expr}:{container}"
        records.append(
            {
                "source": text,
                "compose_mapping": compose_mapping,
                "container_port": container,
                "default_host_port": host,
                "env": port_env_name(service_name, container),
                "bind_ip": bind_ip,
            }
        )
    return records


def parse_port(value: str) -> int | None:
    try:
        return int(value.rsplit(":", maxsplit=1)[-1])
    except ValueError:
        return None


def port_env_name(service_name: str, container_port: str) -> str:
    service_part = "".join(char.upper() if char.isalnum() else "_" for char in service_name).strip("_")
    port_part = "".join(char if char.isalnum() else "_" for char in container_port).strip("_")
    return f"LABFORGE_PORT_{service_part}_{port_part}"


def build_endpoint_manifest(spec: LabSpec) -> dict[str, Any]:
    used_host_ports: set[int] = set()
    published: list[dict[str, Any]] = []
    internal: list[dict[str, Any]] = []
    artifacts = service_artifact_map(spec)

    for service in spec.services:
        name = str(service["name"])
        role = str(service.get("role", "service"))
        networks = [str(item) for item in service.get("networks", [])]
        ports = service.get("ports") or []
        if ports:
            for record in port_mapping_records(name, ports, used_host_ports):
                container_port = str(record["container_port"])
                default_host_port = record["default_host_port"]
                protocol = endpoint_protocol(container_port)
                item: dict[str, Any] = {
                    "service": name,
                    "role": role,
                    "protocol": protocol,
                    "container_port": container_port,
                    "default_host_port": default_host_port,
                    "override_env": record["env"],
                    "compose_mapping": record["compose_mapping"],
                    "networks": networks,
                }
                if default_host_port is not None:
                    if protocol == "ssh":
                        item["connect"] = f"ssh {endpoint_user(name)}@127.0.0.1 -p {default_host_port}"
                    else:
                        item["url"] = f"http://127.0.0.1:{default_host_port}/"
                        item["health_url"] = f"http://127.0.0.1:{default_host_port}/healthz"
                        expected_texts = endpoint_expected_texts(artifacts.get(name))
                        if expected_texts:
                            item["expected_texts"] = expected_texts
                        expected_selectors = endpoint_expected_selectors(artifacts.get(name))
                        if expected_selectors:
                            item["expected_selectors"] = expected_selectors
                published.append(item)
        else:
            internal.append(
                {
                    "service": name,
                    "role": role,
                    "dns": name,
                    "networks": networks,
                    "expose": [str(item) for item in service.get("expose", [])],
                }
            )

    return {
        "lab_id": spec.lab_id,
        "title": spec.title,
        "provider": "docker-compose",
        "published_endpoints": published,
        "internal_services": internal,
    }


def endpoint_expected_texts(artifact: Any | None) -> list[str]:
    if artifact is None:
        return []
    values: list[str] = []
    template = normalize_artifact_template(artifact)
    template_texts = {
        "business-portal": ["Operational Summary"],
        "internal-admin-console": ["Operational Summary"],
        "identity-gateway": ["Operational Summary"],
        "data-api": ["Operational Summary"],
        "audit-log-service": ["Operational Summary"],
        "object-store": ["Operational Summary"],
        "siem-log-viewer": ["Operational Summary"],
    }
    values.extend(template_texts.get(template, []))
    plugin_texts = {
        "ssti-preview": ["Response Preview", "Approved Merge Fields"],
        "stored-xss-review": ["Review Intake", "Reviewer Inbox"],
        "idor-object-access": ["Business Object Catalog"],
        "sql-injection-reporting": ["Reporting Workbench", "Visible Report Catalog"],
        "ssrf-internal-fetch": ["Upstream Import Console"],
        "path-traversal-download": ["Document Library"],
        "unsafe-file-upload": ["Case Attachment Portal"],
        "diagnostic-command-injection": ["Operations Diagnostics Console"],
        "credential-exposure": ["Runtime Configuration", "Integration Bind Profile"],
        "solr-velocity-rce": ["Search Operations Console", "Core Status"],
        "build-pipeline-abuse": ["Release Build Console"],
        "signed-update-publish": ["Update Channel Console"],
        "customer-update-callback": ["Customer Agent Status"],
    }
    for plugin in artifact_vulnerability_plugins(artifact):
        values.extend(plugin_texts.get(plugin, []))
    return list(dict.fromkeys(values))


def endpoint_expected_selectors(artifact: Any | None) -> list[str]:
    if artifact is None:
        return []
    values: list[str] = []
    template = normalize_artifact_template(artifact)
    template_selectors = {
        "business-portal": ["main", "nav"],
        "internal-admin-console": ["main", "nav"],
        "identity-gateway": ["main"],
        "data-api": ["main"],
        "audit-log-service": ["main"],
        "object-store": ["main"],
        "siem-log-viewer": ["main"],
    }
    values.extend(template_selectors.get(template, []))
    plugin_selectors = {
        "ssti-preview": ["form", "textarea"],
        "stored-xss-review": ["form", "textarea"],
        "idor-object-access": ["a[href*='objects'], table"],
        "sql-injection-reporting": ["form", "input[name='q']"],
        "ssrf-internal-fetch": ["form", "input[name='url']"],
        "path-traversal-download": ["a[href*='download'], table"],
        "unsafe-file-upload": ["form", "input[type='file']"],
        "diagnostic-command-injection": ["form", "input[name='command']"],
        "credential-exposure": ["section", "code"],
        "solr-velocity-rce": ["form", "input[name='core']"],
        "build-pipeline-abuse": ["form", "button"],
        "signed-update-publish": ["form", "button"],
        "customer-update-callback": ["section", "code"],
    }
    for plugin in artifact_vulnerability_plugins(artifact):
        values.extend(plugin_selectors.get(plugin, []))
    return list(dict.fromkeys(values))


def normalize_artifact_template(artifact: Any) -> str:
    extra = getattr(artifact, "model_extra", None) or {}
    explicit = extra.get("template")
    if isinstance(explicit, dict):
        explicit = explicit.get("id")
    value = explicit or getattr(artifact, "runtime", "")
    return "".join(char.lower() if char.isalnum() else "-" for char in str(value)).strip("-")


def artifact_vulnerability_plugins(artifact: Any) -> list[str]:
    extra = getattr(artifact, "model_extra", None) or {}
    raw = extra.get("vulnerability_plugins", [])
    if not isinstance(raw, list):
        return []
    plugins: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            value = item.get("id", "")
        else:
            value = item
        plugin_id = "".join(char.lower() if char.isalnum() else "-" for char in str(value)).strip("-")
        if plugin_id:
            plugins.append(plugin_id)
    return plugins


def endpoint_protocol(container_port: str) -> str:
    port = parse_port(container_port)
    if port == 22:
        return "ssh"
    return "http"


def endpoint_user(service_name: str) -> str:
    if "attacker" in service_name or "workstation" in service_name:
        return "attacker"
    return "lab"


def render_quickstart(spec: LabSpec, profile: str, endpoint_manifest: dict[str, Any]) -> str:
    lines = [
        f"# Quickstart - {spec.title}",
        "",
        "This file is generated by the Docker Compose provider for supervisors and lab operators.",
        "It lists the commands and learner-visible endpoints needed to start and inspect this generated lab package.",
        "",
        "## Start",
        "",
        "PowerShell on Windows, with automatic WSL delegation when Docker is not reachable in the current shell:",
        "",
        "```powershell",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\start.ps1",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\status.ps1",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\services-healthcheck.ps1",
        "```",
        "",
        "Linux, macOS, or WSL:",
        "",
        "```sh",
        "./scripts/start.sh",
        "./scripts/status.sh",
        "./scripts/services-healthcheck.sh",
        "```",
        "",
        "## Reset And Stop",
        "",
        "```powershell",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\services-reset.ps1",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\reset.ps1",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\stop.ps1",
        "```",
        "",
        "```sh",
        "./scripts/services-reset.sh",
        "./scripts/reset.sh",
        "./scripts/stop.sh",
        "```",
        "",
        "## Published Endpoints",
        "",
        "| Service | Role | Protocol | Default | Override |",
        "|---|---|---|---|---|",
    ]
    endpoints = endpoint_manifest.get("published_endpoints", [])
    if endpoints:
        for item in endpoints:
            default = item.get("connect") or item.get("url") or "-"
            if item.get("health_url"):
                default = f"{default}<br>health: {item['health_url']}"
            lines.append(
                f"| `{item['service']}` | {item['role']} | `{item['protocol']}` | `{default}` | `{item.get('override_env') or '-'}` |"
            )
    else:
        lines.append("| - | - | - | - | - |")

    lines += [
        "",
        "Published ports can be changed before startup by setting the listed override variable.",
        "",
        "```powershell",
        "$env:LABFORGE_PORT_EXAMPLE_8080='19081'",
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\start.ps1",
        "```",
        "",
        "```sh",
        "LABFORGE_PORT_EXAMPLE_8080=19081 ./scripts/start.sh",
        "```",
        "",
        "## Internal DNS",
        "",
        "The following services are intentionally not published to the host. They are reachable by service name only from containers attached to the same generated lab networks.",
        "",
        "| Service | Role | Networks |",
        "|---|---|---|",
    ]
    internal_services = endpoint_manifest.get("internal_services", [])
    if internal_services:
        for item in internal_services:
            networks = ", ".join(item.get("networks") or [])
            lines.append(f"| `{item['service']}` | {item['role']} | {networks or '-'} |")
    else:
        lines.append("| - | - | - |")

    lines += [
        "",
        "## Generated Files",
        "",
        "- `endpoints.json`: machine-readable endpoint manifest.",
        "- `docker-compose.yml`: generated provider output.",
        "- `docs/`: architecture, MITRE, provider, and security-control documentation.",
        "- `scripts/`: runtime lifecycle scripts.",
        "",
        f"Active security profile: `{profile}`.",
        "",
    ]
    return "\n".join(lines)


def add_security_control_services(spec: LabSpec, compose: dict[str, Any]) -> None:
    controls = selected_controls(spec)
    if not controls:
        return

    compose["volumes"].setdefault("labforge_logs", {})
    networks = [str(network["name"]) for network in spec.networks]

    for control in controls:
        service_name = f"control-{control.category}-{control.control_id}"
        placement = next(
            (item for item in control_placements(spec) if item["id"] == control.control_id),
            {},
        )
        scope = placement.get("scope", {})
        entry: dict[str, Any] = {
            "image": "alpine:3.20",
            "command": [
                "sh",
                "-lc",
                "echo '[labforge] control container online'; while true; do sleep 3600; done",
            ],
            "restart": "unless-stopped",
            "networks": networks,
            "read_only": True,
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
            "pids_limit": 100,
            "environment": {
                "LABFORGE_CONTROL_ID": control.control_id,
                "LABFORGE_CONTROL_CATEGORY": control.category,
                "LABFORGE_CONTROL_MODE": control.mode,
                "LABFORGE_MONITORED_NETWORKS": ",".join(scope.get("networks") or networks),
                "LABFORGE_MONITORED_SERVICES": ",".join(scope.get("services") or []),
            },
            "labels": [
                "labforge.generated=true",
                "labforge.profile=protected",
                f"labforge.control.category={control.category}",
                f"labforge.control.id={control.control_id}",
                f"labforge.control.mode={control.mode}",
            ],
        }
        if control.category in {"siem", "ids", "edr"}:
            entry["volumes"] = ["labforge_logs:/var/log/labforge"]
        compose["services"][service_name] = entry


def render_security_plan(spec: LabSpec, profile: str) -> str:
    lines = [
        f"# Docker Compose Provider Security Plan - {spec.title}",
        "",
        f"- Active profile: `{profile}`",
        "",
    ]
    if profile != "protected":
        lines += [
            "The unprotected provider output keeps only the base scenario services.",
            "Security controls are documented but not materialized as Compose services.",
            "",
        ]
        return "\n".join(lines)

    controls = selected_controls(spec)
    placements = control_placements(spec)
    lines += [
        "The protected provider output materializes selected controls as Compose services.",
        "These services are safe scaffolds: they mark placement, networking, labels, and log volumes so a later implementation can replace them with real WAF/IDS/SIEM/EDR components.",
        "",
        "## Selected Controls",
        "",
    ]
    if not controls:
        lines.append("- No controls selected.")
    for control in controls:
        lines += [
            f"- `{control.control_id}` ({control.category}, mode: `{control.mode}`)",
            f"  - Compose service: `control-{control.category}-{control.control_id}`",
            f"  - Purpose: {control.description or control.name}",
        ]
    lines += [
        "",
        "## Placement Matrix",
        "",
        "| Control | Networks | Services | Effect |",
        "|---|---|---|---|",
    ]
    for placement in placements:
        scope = placement.get("scope", {})
        networks = ", ".join(scope.get("networks", [])) or "-"
        services = ", ".join(scope.get("services", [])) or "-"
        lines.append(f"| `{placement['id']}` | {networks} | {services} | {placement['effect']} |")
    lines += [
        "",
        "## Provider Effects",
        "",
        "- Adds `labforge.profile` and role labels to generated services.",
        "- Adds security-control labels to generated services in protected mode.",
        "- Adds safe control-plane services for selected controls.",
        "- Adds `labforge_logs` volume when selected controls need central log collection.",
        "- Adds Docker json-file log rotation when SIEM collection is selected.",
        "",
    ]
    return "\n".join(lines)


def render_provider_service_plan(spec: LabSpec) -> str:
    artifacts = service_artifact_map(spec)
    trusted_update_services = services_with_trusted_update_plugins(artifacts)
    lines = [
        f"# Docker Compose Provider Service Plan - {spec.title}",
        "",
        "This document explains how the Docker Compose provider uses service artifact contracts.",
        "",
        "## Provider Rules",
        "",
        "- If `topology.yaml` defines an explicit `build`, that build context wins.",
        "- Otherwise, if the service has a `service_artifacts` entry and its `source_path` exists, the provider uses that path as the build context.",
        "- If the source path does not exist yet, the provider keeps the conventional `./services/<service-name>` build context so the scaffold remains predictable.",
        "- Healthcheck and reset contracts are emitted in documentation. Compose labels point back to `docs/service-artifact-contract.md`.",
        "- Compose healthcheck commands still come from `topology.yaml`.",
        "",
        "## Services",
        "",
        "| Service | Build Context | Artifact Source | Runtime | Healthcheck Contract | Reset Contract | Evidence Logs |",
        "|---|---|---|---|---|---|---|",
    ]
    for service in spec.services:
        name = str(service["name"])
        artifact = artifacts.get(name)
        context = service_build_context(spec, service, artifacts)
        source = artifact.source_path if artifact else ""
        runtime = artifact.runtime if artifact else ""
        healthcheck = artifact.healthcheck if artifact else ""
        reset = artifact.reset if artifact else ""
        logs = "<br>".join(artifact.evidence_logs) if artifact and artifact.evidence_logs else ""
        lines.append(
            f"| `{name}` | `{context}` | `{source}` | `{runtime}` | {healthcheck} | {reset} | {logs} |"
        )
    lines += [
        "",
        "## Reset Notes",
        "",
        "The generated `scripts/reset.*` currently performs a Compose volume reset.",
        "The generated `scripts/services-reset.*` runs copied service `reset.sh` hooks.",
        "The generated `scripts/services-healthcheck.*` runs copied service `healthcheck.sh` hooks.",
        "Service-specific hooks should replace placeholders with deterministic implementation logic before the lab is treated as runnable.",
        "",
    ]
    if trusted_update_services:
        lines += [
            "## Trusted Update Shared State",
            "",
            "The following services participate in a trusted-update scaffold chain and must share the `labforge_state` volume mounted at `/labforge-state`:",
            "",
            *[f"- `{service}`: {', '.join(plugins)}" for service, plugins in trusted_update_services.items()],
            "",
            "This shared state allows build manifests, signed manifests, published channel state, and customer update state to flow between generated services without hidden hard-coded answers.",
            "",
        ]
    return "\n".join(lines)


def services_with_trusted_update_plugins(artifacts: dict[str, Any]) -> dict[str, list[str]]:
    trusted_plugins = {
        "build-pipeline-abuse",
        "signed-update-publish",
        "customer-update-callback",
    }
    services: dict[str, list[str]] = {}
    for service, artifact in artifacts.items():
        plugins = [plugin for plugin in artifact_vulnerability_plugins(artifact) if plugin in trusted_plugins]
        if plugins:
            services[service] = plugins
    return services


def write_runtime_scripts(out: Path) -> None:
    scripts = {
        "validate": ["config"],
        "start": ["up", "--build", "-d"],
        "status": ["ps"],
        "stop": ["down"],
        "destroy": ["down", "-v"],
        "reset": ["down", "-v", "&&", "up", "--build", "-d"],
    }
    for name, args in scripts.items():
        write_text(out / "scripts" / f"{name}.sh", render_shell_script(args))
        write_text(out / "scripts" / f"{name}.ps1", render_powershell_script(args))
    for hook in ("healthcheck", "reset"):
        write_text(out / "scripts" / f"services-{hook}.sh", render_service_hook_shell_script(hook))
        write_text(out / "scripts" / f"services-{hook}.ps1", render_service_hook_powershell_script(hook))
    write_text(out / "scripts" / "README.md", render_scripts_readme())


def render_shell_script(compose_args: list[str]) -> str:
    if "&&" in compose_args:
        first = compose_args[: compose_args.index("&&")]
        second = compose_args[compose_args.index("&&") + 1 :]
        body = "\n".join(
            [
                f"docker compose -f docker-compose.yml {' '.join(first)}",
                f"docker compose -f docker-compose.yml {' '.join(second)}",
            ]
        )
    else:
        body = f"docker compose -f docker-compose.yml {' '.join(compose_args)}"
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            "set -eu",
            'LAB_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"',
            'cd "$LAB_ROOT"',
            body,
            "",
        ]
    )


def render_service_hook_shell_script(hook: str) -> str:
    command_name = f"labforge-{hook}"
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            "set -eu",
            'LAB_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"',
            'cd "$LAB_ROOT"',
            "FOUND=0",
            "for service in $(docker compose -f docker-compose.yml config --services); do",
            "    FOUND=1",
            f"    echo \"[labforge] running {hook} hook in $service\"",
            f"    docker compose -f docker-compose.yml exec -T \"$service\" sh -lc 'if [ -x /usr/local/bin/{command_name} ]; then /usr/local/bin/{command_name}; else echo skip; fi'",
            "done",
            'if [ "$FOUND" -eq 0 ]; then',
            "    echo '[labforge] no compose services found'",
            "fi",
            "",
        ]
    )


def render_service_hook_powershell_script(hook: str) -> str:
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
            "$LabRoot = (Resolve-Path (Join-Path $ScriptDir '..')).Path",
            f"$HookScript = Join-Path $ScriptDir 'services-{hook}.sh'",
            "",
            "function ConvertTo-LabForgeWslPath([string]$Path) {",
            "    $FullPath = (Resolve-Path $Path).Path",
            "    if ($FullPath -match '^([A-Za-z]):\\\\(.*)$') {",
            "        $Drive = $Matches[1].ToLowerInvariant()",
            "        $Rest = $Matches[2] -replace '\\\\', '/'",
            "        return \"/mnt/$Drive/$Rest\"",
            "    }",
            "    return ($FullPath -replace '\\\\', '/')",
            "}",
            "",
            "if (Get-Command sh -ErrorAction SilentlyContinue) {",
            "    Push-Location $LabRoot",
            "    try {",
            "        & sh $HookScript",
            "        if ($LASTEXITCODE -ne 0) { throw \"service hook failed with exit code $LASTEXITCODE\" }",
            "    } finally {",
            "        Pop-Location",
            "    }",
            "    return",
            "}",
            "",
            "if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {",
            "    throw 'No POSIX shell found. Install sh/Git Bash/WSL to run service hooks on Windows.'",
            "}",
            "",
            "$DistroArgs = @()",
            "if ($env:LABFORGE_WSL_DISTRO) { $DistroArgs = @('-d', $env:LABFORGE_WSL_DISTRO) }",
            "$WslHook = ConvertTo-LabForgeWslPath $HookScript",
            "wsl.exe @DistroArgs -- sh $WslHook",
            "if ($LASTEXITCODE -ne 0) { throw \"WSL service hook failed with exit code $LASTEXITCODE\" }",
            "",
        ]
    )


def render_powershell_script(compose_args: list[str]) -> str:
    if "&&" in compose_args:
        first = compose_args[: compose_args.index("&&")]
        second = compose_args[compose_args.index("&&") + 1 :]
        command_lines = [
            f"Invoke-LabForgeCompose @({powershell_array(first)})",
            f"Invoke-LabForgeCompose @({powershell_array(second)})",
        ]
    else:
        command_lines = [f"Invoke-LabForgeCompose @({powershell_array(compose_args)})"]

    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
            "$LabRoot = (Resolve-Path (Join-Path $ScriptDir '..')).Path",
            "",
            "function Test-LabForgeDocker {",
            "    try {",
            "        docker compose version *> $null",
            "        return $LASTEXITCODE -eq 0",
            "    } catch {",
            "        return $false",
            "    }",
            "}",
            "",
            "function ConvertTo-LabForgeWslPath([string]$Path) {",
            "    $FullPath = (Resolve-Path $Path).Path",
            "    if ($FullPath -match '^([A-Za-z]):\\\\(.*)$') {",
            "        $Drive = $Matches[1].ToLowerInvariant()",
            "        $Rest = $Matches[2] -replace '\\\\', '/'",
            "        return \"/mnt/$Drive/$Rest\"",
            "    }",
            "    return ($FullPath -replace '\\\\', '/')",
            "}",
            "",
            "function Join-LabForgeShellArgs([string[]]$Items) {",
            "    return ($Items | ForEach-Object { \"'\" + ($_ -replace \"'\", \"'\\''\") + \"'\" }) -join ' '",
            "}",
            "",
            "function Join-LabForgeShellEnv {",
            "    $Pairs = @()",
            "    foreach ($Item in Get-ChildItem Env:LABFORGE_PORT_*) {",
            "        $Name = ($Item.Name -replace '[^A-Za-z0-9_]', '')",
            "        $Value = ($Item.Value -replace \"'\", \"'\\''\")",
            "        if ($Name) { $Pairs += \"$Name='$Value'\" }",
            "    }",
            "    if ($Pairs.Count -eq 0) { return '' }",
            "    return (($Pairs -join ' ') + ' ')",
            "}",
            "",
            "function Get-LabForgeWslDistros {",
            "    $Raw = wsl.exe -l -q 2>$null",
            "    if ($LASTEXITCODE -ne 0) { return @() }",
            "    $Distros = @()",
            "    foreach ($Line in $Raw) {",
            "        $Name = ($Line -replace \"`0\", '').Trim()",
            "        if ($Name) { $Distros += $Name }",
            "    }",
            "    return $Distros",
            "}",
            "",
            "function Test-LabForgeWslDocker([string]$Distro) {",
            "    wsl.exe -d $Distro -- docker version --format '{{.Server.Version}}' *> $null",
            "    return $LASTEXITCODE -eq 0",
            "}",
            "",
            "function Select-LabForgeWslDistro {",
            "    if ($env:LABFORGE_WSL_DISTRO) {",
            "        if (Test-LabForgeWslDocker $env:LABFORGE_WSL_DISTRO) { return $env:LABFORGE_WSL_DISTRO }",
            "        throw \"LABFORGE_WSL_DISTRO is set to '$env:LABFORGE_WSL_DISTRO', but Docker is not reachable there.\"",
            "    }",
            "    foreach ($Distro in Get-LabForgeWslDistros) {",
            "        if (Test-LabForgeWslDocker $Distro) { return $Distro }",
            "    }",
            "    throw 'Docker is not available in this shell and no WSL distro with a reachable Docker server was found.'",
            "}",
            "",
            "function Invoke-LabForgeCompose([string[]]$ComposeArgs) {",
            "    if (Test-LabForgeDocker) {",
            "        Push-Location $LabRoot",
            "        try {",
            "            & docker compose -f docker-compose.yml @ComposeArgs",
            "            if ($LASTEXITCODE -ne 0) { throw \"docker compose failed with exit code $LASTEXITCODE\" }",
            "        } finally {",
            "            Pop-Location",
            "        }",
            "        return",
            "    }",
            "",
            "    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {",
            "        throw 'Docker is not available in this shell and wsl.exe was not found.'",
            "    }",
            "",
            "    $Distro = Select-LabForgeWslDistro",
            "    $WslLabRoot = ConvertTo-LabForgeWslPath $LabRoot",
            "    $ArgString = Join-LabForgeShellArgs $ComposeArgs",
            "    $EnvPrefix = Join-LabForgeShellEnv",
            "    $Command = \"cd '$WslLabRoot' && ${EnvPrefix}docker compose -f docker-compose.yml $ArgString\"",
            "    wsl.exe -d $Distro -- bash -lc $Command",
            "    if ($LASTEXITCODE -ne 0) { throw \"WSL docker compose failed with exit code $LASTEXITCODE\" }",
            "}",
            "",
            *command_lines,
            "",
        ]
    )


def powershell_array(items: list[str]) -> str:
    return ", ".join("'" + item.replace("'", "''") + "'" for item in items)


def render_scripts_readme() -> str:
    return "\n".join(
        [
            "# Runtime Scripts",
            "",
            "These scripts are generated by the Docker Compose provider.",
            "",
            "| Script | Purpose |",
            "|---|---|",
            "| `validate.ps1` / `validate.sh` | Run `docker compose config`. |",
            "| `start.ps1` / `start.sh` | Build and start the lab. |",
            "| `status.ps1` / `status.sh` | Show current Compose service status. |",
            "| `stop.ps1` / `stop.sh` | Stop the lab without deleting volumes. |",
            "| `destroy.ps1` / `destroy.sh` | Stop the lab and delete Compose volumes. |",
            "| `reset.ps1` / `reset.sh` | Delete volumes and rebuild the lab. |",
            "| `services-healthcheck.ps1` / `services-healthcheck.sh` | Run service `healthcheck.sh` hooks copied into the generated lab. |",
            "| `services-reset.ps1` / `services-reset.sh` | Run service `reset.sh` hooks copied into the generated lab. |",
            "",
            "PowerShell scripts first try Docker in the current shell. If Docker is not available, they delegate to WSL.",
            "When WSL delegation is needed, the scripts auto-detect a WSL distro with a reachable Docker server.",
            "Set `LABFORGE_WSL_DISTRO` only when you want to force a specific distro.",
            "",
            "Published service ports are rendered with environment variable overrides.",
            "For example, a service named `support-portal` exposing container port `8080` uses `LABFORGE_PORT_SUPPORT_PORTAL_8080`.",
            "If a default port is already allocated, set the variable before running `start.*`, for example:",
            "",
            "```powershell",
            "$env:LABFORGE_PORT_SUPPORT_PORTAL_8080='19081'",
            ".\\scripts\\start.ps1",
            "```",
            "",
            "```sh",
            "LABFORGE_PORT_SUPPORT_PORTAL_8080=19081 ./scripts/start.sh",
            "```",
            "",
        ]
    )
