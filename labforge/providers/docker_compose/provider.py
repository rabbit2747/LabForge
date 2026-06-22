from __future__ import annotations

from pathlib import Path
from typing import Any

from labforge.io import dump_yaml, write_text
from labforge.model import LabSpec
from labforge.providers.base import Provider
from labforge.security_controls import has_selected_category, selected_controls


class DockerComposeProvider(Provider):
    name = "docker-compose"

    def generate(self, spec: LabSpec, out: Path, **kwargs: Any) -> None:
        profile = str(kwargs.get("profile", "unprotected"))
        write_text(out / "docker-compose.yml", render_compose(spec, profile=profile))
        write_text(out / "docs" / "provider-security-plan.md", render_security_plan(spec, profile))


def render_compose(spec: LabSpec, profile: str = "unprotected") -> str:
    compose: dict[str, Any] = {
        "name": spec.lab_id,
        "networks": {},
        "volumes": {},
        "services": {},
    }

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
        entry: dict[str, Any] = {
            "build": service.get("build", f"./services/{name}"),
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
        if "user" in service:
            entry["user"] = str(service["user"])
        if service.get("expose"):
            entry["expose"] = [str(port) for port in service["expose"]]
        if service.get("ports"):
            entry["ports"] = [str(port) for port in service["ports"]]
        if service.get("environment"):
            entry["environment"] = service["environment"]
        if service.get("volumes"):
            entry["volumes"] = service["volumes"]
        if service.get("depends_on"):
            entry["depends_on"] = service["depends_on"]
        if service.get("healthcheck"):
            entry["healthcheck"] = service["healthcheck"]
        compose["services"][name] = entry

    if profile == "protected":
        add_security_control_services(spec, compose)

    return dump_yaml(compose)


def add_security_control_services(spec: LabSpec, compose: dict[str, Any]) -> None:
    controls = selected_controls(spec)
    if not controls:
        return

    compose["volumes"].setdefault("labforge_logs", {})
    networks = [str(network["name"]) for network in spec.networks]

    for control in controls:
        service_name = f"control-{control.category}-{control.control_id}"
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
                "LABFORGE_MONITORED_NETWORKS": ",".join(networks),
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
        "## Provider Effects",
        "",
        "- Adds `labforge.profile` and role labels to generated services.",
        "- Adds security-control labels to generated services in protected mode.",
        "- Adds safe control placeholder services for selected controls.",
        "- Adds `labforge_logs` volume when selected controls need central log collection.",
        "- Adds Docker json-file log rotation when SIEM collection is selected.",
        "",
    ]
    return "\n".join(lines)
