from __future__ import annotations

from pathlib import Path
from typing import Any

from .diagrams import (
    render_architecture_diagrams_report,
    render_attack_flow_diagram,
    render_security_controls_diagram,
    render_topology_diagram,
)
from .io import dump_yaml, write_text
from .model import LabSpec


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


def render_readme(spec: LabSpec) -> str:
    lines = [
        f"# {spec.title}",
        "",
        "## Summary",
        "",
        str(spec.scenario.get("summary", "")),
        "",
        "## Final Objective",
        "",
        str(spec.scenario.get("final_objective", "")),
        "",
        "## Exposed Services",
        "",
    ]
    for service in spec.services:
        if service.get("exposed"):
            lines.append(f"- `{service['name']}`")
    lines += [
        "",
        "## Stages",
        "",
    ]
    for stage in spec.stage_list:
        mitre = stage.get("mitre", {})
        techniques = ", ".join(
            f"{item['id']} {item['name']}" for item in mitre.get("techniques", [])
        )
        lines += [
            f"### {stage['id']} - {stage['title']}",
            "",
            f"- Procedure: {stage.get('procedure', '')}",
            f"- MITRE Tactic: {mitre.get('tactic', '')}",
            f"- MITRE Techniques: {techniques}",
            "",
        ]
    return "\n".join(lines)


def render_mitre_report(spec: LabSpec) -> str:
    lines = [
        f"# MITRE Mapping - {spec.title}",
        "",
        "| Stage | Procedure | Tactic | Techniques |",
        "|---|---|---|---|",
    ]
    for stage in spec.stage_list:
        mitre = stage.get("mitre", {})
        techniques = "<br>".join(
            f"`{item['id']}` {item['name']}" for item in mitre.get("techniques", [])
        )
        lines.append(
            f"| {stage['id']} {stage['title']} | {stage.get('procedure', '')} | "
            f"{mitre.get('tactic', '')} | {techniques} |"
        )
    lines.append("")
    return "\n".join(lines)


def build_lab(spec: LabSpec, out: Path) -> None:
    write_text(out / "docker-compose.yml", render_compose(spec))
    write_text(out / "README.md", render_readme(spec))
    write_text(out / "docs" / "mitre-mapping.md", render_mitre_report(spec))
    write_text(out / "docs" / "implementation-checklist.md", render_checklist(spec))
    write_text(out / "docs" / "architecture-diagrams.md", render_architecture_diagrams_report(spec))
    write_text(out / "diagrams" / "topology.mmd", render_topology_diagram(spec))
    write_text(out / "diagrams" / "attack-flow.mmd", render_attack_flow_diagram(spec))
    write_text(out / "diagrams" / "security-controls.mmd", render_security_controls_diagram(spec))


def render_docs(spec: LabSpec, out: Path) -> None:
    write_text(out / "README.md", render_readme(spec))
    write_text(out / "mitre-mapping.md", render_mitre_report(spec))
    write_text(out / "implementation-checklist.md", render_checklist(spec))
    write_text(out / "architecture-diagrams.md", render_architecture_diagrams_report(spec))
    write_text(out / "diagrams" / "topology.mmd", render_topology_diagram(spec))
    write_text(out / "diagrams" / "attack-flow.mmd", render_attack_flow_diagram(spec))
    write_text(out / "diagrams" / "security-controls.mmd", render_security_controls_diagram(spec))


def render_checklist(spec: LabSpec) -> str:
    lines = [
        f"# Implementation Checklist - {spec.title}",
        "",
        "## Required Controls",
        "",
        "- [ ] External services are explicitly marked.",
        "- [ ] Internal services are not directly exposed.",
        "- [ ] Attacker Workstation is available.",
        "- [ ] Reset strategy is documented.",
        "- [ ] Seed data and noise data are separated.",
        "- [ ] Health checks exist for every service.",
        "- [ ] Dangerous behavior is constrained to lab networks.",
        "",
        "## Services",
        "",
    ]
    for service in spec.services:
        lines.append(f"- [ ] `{service['name']}` implemented and healthcheck passing")
    lines += ["", "## Stages", ""]
    for stage in spec.stage_list:
        lines.append(f"- [ ] `{stage['id']}` {stage['title']}")
    lines.append("")
    return "\n".join(lines)
