from __future__ import annotations

import re
from typing import Any

from .model import LabSpec


def _node_id(prefix: str, value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value)
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return f"{prefix}_{cleaned or 'item'}"


def _label(value: Any) -> str:
    return str(value).replace('"', "'")


def render_topology_diagram(spec: LabSpec) -> str:
    lines = [
        "flowchart LR",
        f"  %% Infrastructure topology for {spec.lab_id}",
        "  supervisor[Supervisor / Instructor]",
        "  learner[Learner / Attacker]",
        "",
        "  subgraph networks[Network Zones]",
    ]

    for network in spec.networks:
        name = str(network["name"])
        node = _node_id("net", name)
        suffix = "internal" if network.get("internal", False) else "external"
        lines.append(f'    {node}["{_label(name)} ({suffix})"]')

    lines += [
        "  end",
        "",
        "  subgraph assets[Lab Assets]",
    ]

    for service in spec.services:
        name = str(service["name"])
        role = service.get("role", "service")
        exposed = "public" if service.get("exposed") else "internal"
        node = _node_id("svc", name)
        lines.append(f'    {node}["{_label(name)}<br/>{_label(role)}<br/>{exposed}"]')

    lines += ["  end", ""]

    for service in spec.services:
        service_node = _node_id("svc", str(service["name"]))
        for network in service.get("networks", []):
            network_node = _node_id("net", str(network))
            lines.append(f"  {network_node} --- {service_node}")

    exposed_services = [svc for svc in spec.services if svc.get("exposed")]
    for service in exposed_services:
        lines.append(f"  learner --> {_node_id('svc', str(service['name']))}")

    lines += [
        "  supervisor -. reviews .-> networks",
        "",
        "  classDef exposed fill:#fff1f2,stroke:#be123c,stroke-width:2px,color:#111827",
        "  classDef internal fill:#eef2ff,stroke:#4338ca,color:#111827",
        "  classDef zone fill:#ecfeff,stroke:#0891b2,color:#111827",
    ]
    for network in spec.networks:
        lines.append(f"  class {_node_id('net', str(network['name']))} zone")
    for service in spec.services:
        class_name = "exposed" if service.get("exposed") else "internal"
        lines.append(f"  class {_node_id('svc', str(service['name']))} {class_name}")

    return "\n".join(lines) + "\n"


def render_attack_flow_diagram(spec: LabSpec) -> str:
    lines = [
        "flowchart TD",
        f"  %% Learner attack flow for {spec.lab_id}",
        '  start(["Start"])',
    ]
    previous = "start"
    for stage in spec.stage_list:
        node = _node_id("stage", str(stage["id"]))
        tactic = stage.get("mitre", {}).get("tactic", "")
        title = f"{stage['id']}<br/>{stage['title']}"
        if tactic:
            title += f"<br/>{tactic}"
        lines.append(f'  {node}["{_label(title)}"]')
        lines.append(f"  {previous} --> {node}")
        previous = node
    lines.append('  finish(["Final Objective"])')
    lines.append(f"  {previous} --> finish")
    lines += [
        "",
        "  classDef stage fill:#f8fafc,stroke:#334155,color:#0f172a",
        "  classDef terminal fill:#f0fdf4,stroke:#15803d,color:#052e16",
        "  class start,finish terminal",
    ]
    for stage in spec.stage_list:
        lines.append(f"  class {_node_id('stage', str(stage['id']))} stage")
    return "\n".join(lines) + "\n"


def render_security_controls_diagram(spec: LabSpec) -> str:
    controls = spec.topology.get("security_controls", {})
    if not isinstance(controls, dict):
        controls = {}

    control_names = controls.get(
        "recommended",
        [
            "Firewall / Segmentation",
            "WAF",
            "IDS Sensor",
            "Central Logging",
            "EDR Lite",
        ],
    )

    lines = [
        "flowchart LR",
        f"  %% Protected architecture control overlay for {spec.lab_id}",
        "  learner[Learner / Attacker]",
        "  public[Public Entry]",
        "  dmz[DMZ Services]",
        "  internal[Internal Services]",
        "  target[Final Objective]",
        "",
        "  learner --> public --> dmz --> internal --> target",
        "",
        "  subgraph controls[Selectable Security Controls]",
    ]
    for item in control_names:
        node = _node_id("ctrl", str(item))
        lines.append(f'    {node}["{_label(item)}"]')
    lines.append("  end")
    lines.append("")

    attach_targets = ["public", "dmz", "internal"]
    for index, item in enumerate(control_names):
        node = _node_id("ctrl", str(item))
        target = attach_targets[index % len(attach_targets)]
        lines.append(f"  {node} -. observes / enforces .-> {target}")

    lines += [
        "",
        "  classDef path fill:#f8fafc,stroke:#334155,color:#0f172a",
        "  classDef control fill:#fef9c3,stroke:#ca8a04,color:#422006",
        "  class learner,public,dmz,internal,target path",
    ]
    for item in control_names:
        lines.append(f"  class {_node_id('ctrl', str(item))} control")
    return "\n".join(lines) + "\n"


def render_architecture_diagrams_report(spec: LabSpec) -> str:
    topology = render_topology_diagram(spec).rstrip()
    attack_flow = render_attack_flow_diagram(spec).rstrip()
    security = render_security_controls_diagram(spec).rstrip()

    return "\n".join(
        [
            f"# Architecture Diagrams - {spec.title}",
            "",
            "This document is generated for supervisors. It shows the lab from three views:",
            "",
            "- Infrastructure topology",
            "- Learner attack flow",
            "- Protected architecture control overlay",
            "",
            "## Infrastructure Topology",
            "",
            "```mermaid",
            topology,
            "```",
            "",
            "## Learner Attack Flow",
            "",
            "```mermaid",
            attack_flow,
            "```",
            "",
            "## Protected Architecture Control Overlay",
            "",
            "```mermaid",
            security,
            "```",
            "",
        ]
    )

