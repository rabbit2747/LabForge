from __future__ import annotations

from pathlib import Path
from typing import Any

from .diagrams import (
    render_architecture_diagrams_report,
    render_attack_flow_diagram,
    render_security_controls_diagram,
    render_topology_diagram,
)
from .io import write_text
from .model import LabSpec
from .providers.factory import get_provider
from .templating import render_template, template_context


def render_readme(spec: LabSpec) -> str:
    return render_template("docs/readme.md.j2", **template_context(spec))


def render_mitre_report(spec: LabSpec) -> str:
    return render_template("docs/mitre-mapping.md.j2", **template_context(spec))


def build_lab(
    spec: LabSpec,
    out: Path,
    provider_name: str = "docker-compose",
    profile: str = "unprotected",
) -> None:
    provider = get_provider(provider_name)
    provider_errors = provider.validate(spec)
    if provider_errors:
        joined = "\n".join(f"- {error}" for error in provider_errors)
        raise ValueError(f"Provider validation failed for {provider_name}:\n{joined}")
    provider.generate(spec, out)
    render_common_outputs(spec, out, profile=profile)


def render_docs(spec: LabSpec, out: Path, profile: str = "unprotected") -> None:
    render_common_outputs(spec, out, profile=profile, docs_root=out)


def render_common_outputs(
    spec: LabSpec,
    out: Path,
    profile: str = "unprotected",
    docs_root: Path | None = None,
) -> None:
    docs_base = docs_root if docs_root is not None else out / "docs"
    write_text(out / "README.md", render_readme(spec))
    write_text(docs_base / "mitre-mapping.md", render_mitre_report(spec))
    write_text(docs_base / "implementation-checklist.md", render_checklist(spec))
    write_text(docs_base / "architecture-diagrams.md", render_architecture_diagrams_report(spec))
    write_text(docs_base / "architecture-unprotected.md", render_profile_architecture(spec, "unprotected"))
    write_text(docs_base / "architecture-protected.md", render_profile_architecture(spec, "protected"))
    write_text(docs_base / "security-control-selection.md", render_security_control_selection(spec, profile))
    write_text(docs_base / "deployment-requirements.md", render_deployment_requirements(spec))
    write_text(out / "diagrams" / "topology.mmd", render_topology_diagram(spec))
    write_text(out / "diagrams" / "attack-flow.mmd", render_attack_flow_diagram(spec))
    write_text(out / "diagrams" / "security-controls.mmd", render_security_controls_diagram(spec))


def render_checklist(spec: LabSpec) -> str:
    return render_template("docs/implementation-checklist.md.j2", **template_context(spec))


def render_profile_architecture(spec: LabSpec, profile: str) -> str:
    protected = profile == "protected"
    lines = [
        f"# {profile.title()} Architecture - {spec.title}",
        "",
        "## Purpose",
        "",
    ]
    if protected:
        lines += [
            "This architecture overlays selectable security controls on top of the base lab topology.",
            "It is intended for realistic supervision, detection planning, and purple-team expansion.",
            "",
            "## Security Controls",
            "",
        ]
        controls = spec.topology.get("security_controls", {}).get("recommended", [])
        for control in controls:
            lines.append(f"- {control}")
        if not controls:
            lines.append("- No controls declared.")
        lines += [
            "",
            "## Expected Control Impact",
            "",
            "- Public entry points may be observed by WAF or reverse-proxy logging.",
            "- Internal east-west movement may be observed by IDS/NDR sensors.",
            "- Endpoint execution may be recorded by EDR-lite or host telemetry.",
            "- Central logging should preserve enough context for instructor review.",
            "",
        ]
    else:
        lines += [
            "This architecture shows the base learner path without enforcement-oriented security controls.",
            "It is intended for validating that the red-team scenario can be completed end to end.",
            "",
            "## Base Exposure",
            "",
        ]
        for service in spec.services:
            if service.get("exposed"):
                lines.append(f"- `{service['name']}` is externally reachable.")
        lines += [
            "",
            "## Expected Learner Flow",
            "",
        ]
        for stage in spec.stage_list:
            lines.append(f"- `{stage['id']}` {stage['title']}")
        lines.append("")
    return "\n".join(lines)


def render_security_control_selection(spec: LabSpec, profile: str) -> str:
    selection = spec.supervisor_selection.get("selected_controls", {})
    lines = [
        f"# Security Control Selection - {spec.title}",
        "",
        f"- Active profile: `{profile}`",
        "",
        "## Recommended Controls",
        "",
    ]
    for control in spec.topology.get("security_controls", {}).get("recommended", []):
        lines.append(f"- {control}")
    if not spec.topology.get("security_controls", {}).get("recommended", []):
        lines.append("- No recommended controls declared.")
    lines += ["", "## Supervisor Selection", ""]
    if isinstance(selection, dict) and selection:
        for category, controls in selection.items():
            values = controls or []
            joined = ", ".join(f"`{item}`" for item in values) if values else "_none_"
            lines.append(f"- {category}: {joined}")
    else:
        lines.append("- No supervisor selection file provided.")
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
