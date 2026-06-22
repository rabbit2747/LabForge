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


class HybridProvider(Provider):
    name = "hybrid"

    def generate(self, spec: LabSpec, out: Path, **kwargs: Any) -> None:
        profile = str(kwargs.get("profile", "unprotected"))
        root = out / "hybrid"
        write_text(root / "README.md", render_provider_readme(spec, self.name, profile, "skeleton", "Split lab services across Docker-hosted components and VM-hosted enterprise assets."))
        write_text(root / "provider-plan.yaml", render_yaml(provider_plan(spec, self.name, profile, "skeleton")))
        write_text(root / "inventory.yaml", render_yaml(provider_inventory(spec)))
        write_text(root / "security-profile.md", render_security_profile(spec, self.name, profile))
        write_text(root / "orchestration-plan.yaml", render_hybrid_orchestration(spec, profile))


def render_hybrid_orchestration(spec: LabSpec, profile: str) -> str:
    docker_services: list[str] = []
    vm_assets: list[dict[str, Any]] = []
    asset_hints = {
        str(asset.get("id")): {
            "os": str(asset.get("os", "")),
            "type": str(asset.get("type", "")),
        }
        for asset in spec.environment.get("assets", [])
    }
    for service in spec.services:
        name = str(service.get("name"))
        hints = asset_hints.get(name, {})
        os_hint = str(hints.get("os", ""))
        type_hint = str(hints.get("type", ""))
        combined_hint = f"{os_hint} {type_hint} {name}".lower()
        if any(token in combined_hint for token in ("windows", " ad", "directory", "domain_controller")):
            vm_assets.append(
                {
                    "name": name,
                    "os": os_hint or "windows-or-vm-required",
                    "type": type_hint or service.get("role", "vm-required"),
                }
            )
        else:
            docker_services.append(name)
    data = {
        "lab": spec.lab_id,
        "profile": profile,
        "provider": "hybrid",
        "status": "skeleton",
        "docker_services": docker_services,
        "vm_assets": vm_assets,
        "operator_steps": [
            "Provision VM assets first when identity, Windows, or AD semantics are required.",
            "Start Docker-hosted services after VM network addresses are known.",
            "Bind generated security controls to the correct Docker or VM segment.",
            "Run LabForge service health checks before learner access is opened.",
        ],
    }
    return render_yaml(data)
