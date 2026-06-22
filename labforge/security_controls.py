from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .model import LabSpec


@dataclass(frozen=True)
class SelectedControl:
    category: str
    control_id: str
    name: str
    mode: str
    description: str


def selected_control_ids(spec: LabSpec) -> dict[str, list[str]]:
    selected = spec.supervisor_selection.get("selected_controls", {})
    if not isinstance(selected, dict):
        return {}
    normalized: dict[str, list[str]] = {}
    for category, values in selected.items():
        if isinstance(values, list):
            normalized[str(category)] = [str(value) for value in values]
    return normalized


def selected_controls(spec: LabSpec) -> list[SelectedControl]:
    selected = selected_control_ids(spec)
    catalog = spec.security_controls.get("controls", {})
    if not isinstance(catalog, dict):
        catalog = {}

    controls: list[SelectedControl] = []
    for category, ids in selected.items():
        catalog_items = catalog.get(category, [])
        by_id = {
            str(item.get("id")): item
            for item in catalog_items
            if isinstance(item, dict) and item.get("id")
        }
        for control_id in ids:
            item: dict[str, Any] = by_id.get(control_id, {})
            controls.append(
                SelectedControl(
                    category=category,
                    control_id=control_id,
                    name=str(item.get("name", control_id)),
                    mode=str(item.get("mode", "document")),
                    description=str(item.get("description", "")),
                )
            )
    return controls


def has_selected_category(spec: LabSpec, category: str) -> bool:
    return any(control.category == category for control in selected_controls(spec))


def control_placements(spec: LabSpec) -> list[dict[str, Any]]:
    placements: list[dict[str, Any]] = []
    networks = [str(network.get("name")) for network in spec.networks]
    exposed_services = [
        str(service.get("name"))
        for service in spec.services
        if service.get("exposed") or service.get("ports")
    ]
    all_services = [str(service.get("name")) for service in spec.services]
    internal_networks = [
        str(network.get("name"))
        for network in spec.networks
        if network.get("internal", False)
    ]

    for control in selected_controls(spec):
        if control.category == "firewall":
            scope = {"networks": list(networks), "services": []}
            effect = "segment networks and constrain traffic according to lab profile"
        elif control.category == "waf":
            scope = {"networks": [], "services": list(exposed_services)}
            effect = "observe or filter externally exposed web entry points"
        elif control.category == "ids":
            scope = {"networks": list(internal_networks or networks), "services": []}
            effect = "observe east-west traffic on internal lab segments"
        elif control.category == "siem":
            scope = {"networks": list(networks), "services": list(all_services)}
            effect = "collect service, proxy, control, and host telemetry"
        elif control.category == "edr":
            scope = {"networks": [], "services": list(all_services)}
            effect = "collect endpoint process and execution telemetry"
        else:
            scope = {"networks": list(networks), "services": list(all_services)}
            effect = "document selected control placement for provider implementation"
        placements.append(
            {
                "id": control.control_id,
                "category": control.category,
                "mode": control.mode,
                "name": control.name,
                "scope": scope,
                "effect": effect,
            }
        )
    return placements
