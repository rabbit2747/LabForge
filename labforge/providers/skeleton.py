from __future__ import annotations

from typing import Any

from labforge.io import dump_yaml
from labforge.model import LabSpec
from labforge.security_controls import selected_controls


def provider_plan(spec: LabSpec, provider: str, profile: str, status: str) -> dict[str, Any]:
    deployment = spec.topology.get("deployment", {})
    return {
        "provider": provider,
        "profile": profile,
        "status": status,
        "lab_id": spec.lab_id,
        "title": spec.title,
        "recommended_model": deployment.get("recommended_model", "unspecified"),
        "docker_only_supported": deployment.get("docker_only_supported", True),
        "required_platforms": deployment.get("required_platforms", []),
        "networks": [network.get("name") for network in spec.networks],
        "services": [
            {
                "name": service.get("name"),
                "role": service.get("role", "service"),
                "exposed": service.get("exposed", False),
                "networks": service.get("networks", []),
            }
            for service in spec.services
        ],
        "selected_controls": [
            {
                "id": control.control_id,
                "category": control.category,
                "mode": control.mode,
                "name": control.name,
            }
            for control in selected_controls(spec)
        ],
    }


def provider_inventory(spec: LabSpec) -> dict[str, Any]:
    assets = spec.environment.get("assets", []) if isinstance(spec.environment, dict) else []
    zones = spec.environment.get("zones", []) if isinstance(spec.environment, dict) else []
    return {
        "zones": zones,
        "assets": assets,
        "services": spec.services,
        "networks": spec.networks,
    }


def render_provider_readme(spec: LabSpec, provider: str, profile: str, status: str, purpose: str) -> str:
    deployment = spec.topology.get("deployment", {})
    lines = [
        f"# {provider} Provider - {spec.title}",
        "",
        f"- Provider: `{provider}`",
        f"- Profile: `{profile}`",
        f"- Status: `{status}`",
        f"- Purpose: {purpose}",
        "",
        "## Deployment Model",
        "",
        f"- Recommended model: `{deployment.get('recommended_model', 'unspecified')}`",
        f"- Docker-only supported: `{deployment.get('docker_only_supported', True)}`",
        f"- Required platforms: {', '.join(deployment.get('required_platforms', [])) or 'none declared'}",
        "",
    ]
    notes = deployment.get("docker_only_notes")
    if notes:
        lines += ["## Docker Notes", "", notes, ""]
    lines += [
        "## Generated Files",
        "",
        "- `provider-plan.yaml`: provider-facing service, network, and control summary",
        "- `inventory.yaml`: logical assets, zones, services, and networks",
        "- `security-profile.md`: selected control placement and expected provider behavior",
        "",
        "This provider output is deterministic scaffold material. It must be reviewed and completed before real deployment.",
        "",
    ]
    return "\n".join(lines)


def render_security_profile(spec: LabSpec, provider: str, profile: str) -> str:
    controls = selected_controls(spec)
    lines = [
        f"# {provider} Security Profile - {spec.title}",
        "",
        f"- Profile: `{profile}`",
        "",
    ]
    if profile != "protected":
        lines += [
            "Security controls are documented but not materialized in unprotected profile output.",
            "",
        ]
        return "\n".join(lines)

    lines += [
        "## Selected Controls",
        "",
    ]
    if not controls:
        lines.append("- No selected controls were found.")
    for control in controls:
        lines += [
            f"- `{control.control_id}`",
            f"  - Category: `{control.category}`",
            f"  - Mode: `{control.mode}`",
            f"  - Purpose: {control.description or control.name}",
        ]
    lines += [
        "",
        "## Provider Expectations",
        "",
        "- Preserve lab containment and explicit egress boundaries.",
        "- Keep protected controls observable and reviewable by supervisors.",
        "- Do not turn documentation-only controls into blocking controls without supervisor selection.",
        "",
    ]
    return "\n".join(lines)


def render_yaml(data: dict[str, Any]) -> str:
    return dump_yaml(data)
