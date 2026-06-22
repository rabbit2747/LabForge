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


class AnsibleProvider(Provider):
    name = "ansible"

    def generate(self, spec: LabSpec, out: Path, **kwargs: Any) -> None:
        profile = str(kwargs.get("profile", "unprotected"))
        root = out / "ansible"
        write_text(root / "README.md", render_provider_readme(spec, self.name, profile, "skeleton", "Generate inventory and playbook scaffolds for Linux and hybrid lab hosts."))
        write_text(root / "provider-plan.yaml", render_yaml(provider_plan(spec, self.name, profile, "skeleton")))
        write_text(root / "inventory.yaml", render_yaml(provider_inventory(spec)))
        write_text(root / "security-profile.md", render_security_profile(spec, self.name, profile))
        write_text(root / "site.yml", render_site_playbook(spec))


def render_site_playbook(spec: LabSpec) -> str:
    service_names = [str(service.get("name")) for service in spec.services]
    lines = [
        "---",
        "- name: Prepare LabForge lab hosts",
        "  hosts: all",
        "  become: true",
        "  vars:",
        f"    labforge_lab_id: {spec.lab_id}",
        "    labforge_services:",
    ]
    lines.extend(f"      - {name}" for name in service_names)
    lines += [
        "  tasks:",
        "    - name: Show planned LabForge services",
        "      ansible.builtin.debug:",
        "        var: labforge_services",
        "",
    ]
    return "\n".join(lines)
