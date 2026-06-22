from __future__ import annotations

from pathlib import Path
from typing import Any

from labforge.io import write_text
from labforge.model import LabSpec
from labforge.providers.base import Provider


class AnsibleProvider(Provider):
    name = "ansible"

    def generate(self, spec: LabSpec, out: Path, **kwargs: Any) -> None:
        profile = str(kwargs.get("profile", "unprotected"))
        write_text(
            out / "ansible" / "README.md",
            f"# Ansible Provider - {spec.title}\n\nProfile: `{profile}`\n\nThis provider skeleton is planned.\n",
        )
