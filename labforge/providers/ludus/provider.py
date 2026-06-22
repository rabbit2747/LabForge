from __future__ import annotations

from pathlib import Path
from typing import Any

from labforge.io import write_text
from labforge.model import LabSpec
from labforge.providers.base import Provider
from labforge.providers.skeleton import (
    provider_inventory,
    provider_plan,
    render_provider_readme,
    render_security_profile,
    render_yaml,
)


class LudusProvider(Provider):
    name = "ludus"

    def generate(self, spec: LabSpec, out: Path, **kwargs: Any) -> None:
        profile = str(kwargs.get("profile", "unprotected"))
        root = out / "ludus"
        write_text(root / "README.md", render_provider_readme(spec, self.name, profile, "skeleton", "Generate Proxmox-backed range scaffolds for realistic Windows AD and enterprise network labs."))
        write_text(root / "provider-plan.yaml", render_yaml(provider_plan(spec, self.name, profile, "skeleton")))
        write_text(root / "inventory.yaml", render_yaml(provider_inventory(spec)))
        write_text(root / "security-profile.md", render_security_profile(spec, self.name, profile))
        write_text(root / "range-config.yaml", render_range_config(spec, profile))


def render_range_config(spec: LabSpec, profile: str) -> str:
    data: dict[str, Any] = {
        "lab": spec.lab_id,
        "profile": profile,
        "provider": "ludus",
        "status": "skeleton",
        "range": {
            "networks": spec.networks,
            "hosts": [],
        },
        "notes": [
            "Map Windows AD assets to real Windows Server and workstation templates.",
            "Map Linux prototype services to containers or Linux VMs as appropriate.",
            "Review generated security controls before enabling enforcement.",
        ],
    }
    for asset in spec.environment.get("assets", []):
        data["range"]["hosts"].append(
            {
                "name": asset.get("id"),
                "role": asset.get("type"),
                "os": asset.get("os", "unspecified"),
                "zone": asset.get("zone"),
                "exposure": asset.get("exposure", "internal"),
            }
        )
    return render_yaml(data)
