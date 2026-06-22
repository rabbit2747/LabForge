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
