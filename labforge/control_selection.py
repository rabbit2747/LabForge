from __future__ import annotations

from pathlib import Path
from typing import Any

from .io import dump_yaml, load_yaml, write_text
from .model import LabSpec


def render_control_catalog(spec: LabSpec) -> str:
    catalog = spec.security_controls.get("controls", {})
    selected = spec.supervisor_selection.get("selected_controls", {})
    lines = [
        f"# Security Control Catalog - {spec.title}",
        "",
        "| Category | ID | Name | Mode | Selected | Description |",
        "|---|---|---|---|---:|---|",
    ]
    if not isinstance(catalog, dict) or not catalog:
        lines.append("| - | - | - | - | false | No controls declared. |")
        lines.append("")
        return "\n".join(lines)

    for category, controls in catalog.items():
        selected_ids = selected.get(category, []) if isinstance(selected, dict) else []
        if not isinstance(controls, list):
            continue
        for control in controls:
            if not isinstance(control, dict):
                continue
            control_id = str(control.get("id", ""))
            lines.append(
                "| "
                f"`{category}` | "
                f"`{control_id}` | "
                f"{control.get('name', control_id)} | "
                f"`{control.get('mode', 'document')}` | "
                f"{str(control_id in selected_ids).lower()} | "
                f"{control.get('description', '')} |"
            )
    lines.append("")
    return "\n".join(lines)


def apply_control_selection(
    lab_root: Path,
    selections: list[str],
    *,
    clear: bool = False,
    profile: str | None = None,
    detection_feedback: str | None = None,
    allow_student_log_access: bool | None = None,
) -> dict[str, Any]:
    spec = LabSpec.load(lab_root)
    selection_path = lab_root / "supervisor-selection.yaml"
    data = load_yaml(selection_path) if selection_path.exists() else {}
    selected_controls = {} if clear else dict(data.get("selected_controls", {}) or {})

    available = available_control_ids(spec)
    for selection in selections:
        category, control_id = parse_selection(selection)
        if category not in available:
            raise ValueError(f"Unknown control category `{category}`. Available categories: {', '.join(sorted(available))}")
        if control_id not in available[category]:
            available_ids = ", ".join(sorted(available[category]))
            raise ValueError(f"Unknown control `{control_id}` for category `{category}`. Available controls: {available_ids}")
        values = list(selected_controls.get(category, []) or [])
        if control_id not in values:
            values.append(control_id)
        selected_controls[category] = values

    data["selected_controls"] = selected_controls
    training_mode = dict(data.get("training_mode", {}) or {})
    if profile:
        training_mode["profile"] = profile
    if detection_feedback:
        training_mode["detection_feedback"] = detection_feedback
    if allow_student_log_access is not None:
        training_mode["allow_student_log_access"] = allow_student_log_access
    if training_mode:
        data["training_mode"] = training_mode

    write_text(selection_path, dump_yaml(data))
    return data


def available_control_ids(spec: LabSpec) -> dict[str, set[str]]:
    catalog = spec.security_controls.get("controls", {})
    if not isinstance(catalog, dict):
        return {}
    available: dict[str, set[str]] = {}
    for category, controls in catalog.items():
        if not isinstance(controls, list):
            continue
        ids = {
            str(control.get("id"))
            for control in controls
            if isinstance(control, dict) and control.get("id")
        }
        available[str(category)] = ids
    return available


def parse_selection(selection: str) -> tuple[str, str]:
    if "=" not in selection:
        raise ValueError("Control selections must use CATEGORY=CONTROL_ID format.")
    category, control_id = selection.split("=", 1)
    category = category.strip()
    control_id = control_id.strip()
    if not category or not control_id:
        raise ValueError("Control selections must include both category and control id.")
    return category, control_id
