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
    write_text(out / "docs" / "deployment-requirements.md", render_deployment_requirements(spec))
    write_text(out / "diagrams" / "topology.mmd", render_topology_diagram(spec))
    write_text(out / "diagrams" / "attack-flow.mmd", render_attack_flow_diagram(spec))
    write_text(out / "diagrams" / "security-controls.mmd", render_security_controls_diagram(spec))


def render_docs(spec: LabSpec, out: Path) -> None:
    write_text(out / "README.md", render_readme(spec))
    write_text(out / "mitre-mapping.md", render_mitre_report(spec))
    write_text(out / "implementation-checklist.md", render_checklist(spec))
    write_text(out / "architecture-diagrams.md", render_architecture_diagrams_report(spec))
    write_text(out / "deployment-requirements.md", render_deployment_requirements(spec))
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


def _render_host_table(hosts: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Role | Count | OS | CPU | Memory | Storage | Software |",
        "|---|---:|---|---|---|---|---|",
    ]
    for host in hosts:
        software = "<br>".join(str(item) for item in host.get("software", []))
        lines.append(
            "| "
            f"{host.get('role', '')} | "
            f"{host.get('count', '')} | "
            f"{host.get('os', '')} | "
            f"{host.get('cpu', '')} | "
            f"{host.get('memory', '')} | "
            f"{host.get('storage', '')} | "
            f"{software} |"
        )
    return lines


def render_deployment_requirements(spec: LabSpec) -> str:
    deployment = spec.topology.get("deployment", {})
    if not isinstance(deployment, dict):
        deployment = {}

    recommended_model = deployment.get("recommended_model", "docker-compose")
    docker_only_supported = deployment.get("docker_only_supported", True)
    docker_support_text = "Yes" if docker_only_supported else "No"

    lines = [
        f"# Deployment Requirements - {spec.title}",
        "",
        "This document explains what physical or virtual environment is required to build this lab.",
        "It is intended for supervisors and infrastructure operators before the lab is provisioned.",
        "",
        "## Deployment Summary",
        "",
        f"- Recommended model: `{recommended_model}`",
        f"- Docker-only supported: `{docker_support_text}`",
        "",
    ]

    if deployment.get("docker_only_notes"):
        lines += [
            "## Docker-Only Notes",
            "",
            str(deployment["docker_only_notes"]),
            "",
        ]

    minimum = deployment.get("minimum_environment", {})
    if isinstance(minimum, dict) and minimum:
        lines += [
            "## Minimum Environment",
            "",
            str(minimum.get("description", "Minimum environment for prototype mode.")),
            "",
        ]
        hosts = minimum.get("hosts", [])
        if isinstance(hosts, list) and hosts:
            lines += _render_host_table(hosts)
            lines.append("")

    realistic = deployment.get("realistic_environment", {})
    if isinstance(realistic, dict) and realistic:
        lines += [
            "## Realistic Environment",
            "",
            str(realistic.get("description", "Recommended environment for realistic lab operation.")),
            "",
        ]
        hosts = realistic.get("hosts", [])
        if isinstance(hosts, list) and hosts:
            lines += _render_host_table(hosts)
            lines.append("")

    platforms = deployment.get("required_platforms", [])
    if isinstance(platforms, list) and platforms:
        lines += [
            "## Required Platforms and Tooling",
            "",
        ]
        for platform in platforms:
            lines.append(f"- {platform}")
        lines.append("")

    if not deployment:
        lines += [
            "## Default Assumption",
            "",
            "No explicit deployment requirements were provided. LabForge assumes a single Docker-capable host for prototype mode.",
            "",
            "| Role | Count | OS | CPU | Memory | Storage | Software |",
            "|---|---:|---|---|---|---|---|",
            "| training-host | 1 | Windows 11 or Linux | 8 cores recommended | 16 GB minimum | 80 GB free | Docker, Python 3.11+, Git |",
            "",
        ]

    lines += [
        "## Supervisor Review Questions",
        "",
        "- Can this lab run on one Docker host, or does it require VM-based infrastructure?",
        "- Does the scenario require Windows Server, Active Directory, Kerberos, SMB, RDP, or GPO behavior?",
        "- Is a hypervisor such as Proxmox, VMware, or Hyper-V required?",
        "- How many learner PCs and infrastructure hosts are required?",
        "- Are security sensors such as IDS, WAF, SIEM, or EDR part of the selected profile?",
        "- Is reset/snapshot support available for every host that stores lab state?",
        "",
    ]
    return "\n".join(lines)
