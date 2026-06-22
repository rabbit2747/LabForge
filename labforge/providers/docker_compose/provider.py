from __future__ import annotations

from pathlib import Path
from typing import Any

from labforge.io import dump_yaml, write_text
from labforge.model import LabSpec
from labforge.providers.base import Provider


class DockerComposeProvider(Provider):
    name = "docker-compose"

    def generate(self, spec: LabSpec, out: Path) -> None:
        write_text(out / "docker-compose.yml", render_compose(spec))


def render_compose(spec: LabSpec) -> str:
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

    for service in spec.services:
        name = str(service["name"])
        entry: dict[str, Any] = {
            "build": service.get("build", f"./services/{name}"),
            "networks": service.get("networks", []),
            "restart": "unless-stopped",
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
            "pids_limit": 200,
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

    return dump_yaml(compose)

