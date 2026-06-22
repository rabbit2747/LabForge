from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .model import LabSpec


def template_root() -> Path:
    return Path(__file__).resolve().parent / "templates"


def environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(template_root())),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
    )


def render_template(name: str, **context: Any) -> str:
    template = environment().get_template(name)
    return template.render(**context).rstrip() + "\n"


def stage_techniques(stage: dict[str, Any], separator: str = ", ") -> str:
    mitre = stage.get("mitre", {})
    return separator.join(
        f"{item['id']} {item['name']}" for item in mitre.get("techniques", [])
    )


def template_context(spec: LabSpec, **extra: Any) -> dict[str, Any]:
    exposed_services = [service for service in spec.services if service.get("exposed")]
    context: dict[str, Any] = {
        "spec": spec,
        "scenario": spec.scenario,
        "topology": spec.topology,
        "stages": spec.stage_list,
        "services": spec.services,
        "networks": spec.networks,
        "exposed_services": exposed_services,
        "stage_techniques": stage_techniques,
    }
    context.update(extra)
    return context
