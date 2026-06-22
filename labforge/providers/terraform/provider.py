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


class TerraformProvider(Provider):
    name = "terraform"

    def generate(self, spec: LabSpec, out: Path, **kwargs: Any) -> None:
        profile = str(kwargs.get("profile", "unprotected"))
        root = out / "terraform"
        write_text(root / "README.md", render_provider_readme(spec, self.name, profile, "skeleton", "Generate infrastructure-as-code scaffolds for VM, network, and security-control placement."))
        write_text(root / "provider-plan.yaml", render_yaml(provider_plan(spec, self.name, profile, "skeleton")))
        write_text(root / "inventory.yaml", render_yaml(provider_inventory(spec)))
        write_text(root / "security-profile.md", render_security_profile(spec, self.name, profile))
        write_text(root / "main.tf", render_main_tf(spec))
        write_text(root / "variables.tf", render_variables_tf())


def render_main_tf(spec: LabSpec) -> str:
    lines = [
        'terraform {',
        '  required_version = ">= 1.6.0"',
        '}',
        '',
        f'locals {{',
        f'  lab_id = "{spec.lab_id}"',
        '  services = [',
    ]
    lines.extend(f'    "{service.get("name")}",' for service in spec.services)
    lines += [
        '  ]',
        '}',
        '',
        '# Provider-specific resources should be added by the provider engineer.',
        '# This scaffold intentionally avoids assuming AWS, Azure, GCP, Proxmox, or VMware.',
        '',
    ]
    return "\n".join(lines)


def render_variables_tf() -> str:
    return "\n".join(
        [
            'variable "labforge_profile" {',
            '  type        = string',
            '  description = "LabForge security profile: unprotected or protected."',
            '  default     = "unprotected"',
            '}',
            '',
        ]
    )
