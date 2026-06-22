from __future__ import annotations

from pathlib import Path

from labforge.io import write_text
from labforge.model import LabSpec
from labforge.providers.base import Provider


class TerraformProvider(Provider):
    name = "terraform"

    def generate(self, spec: LabSpec, out: Path) -> None:
        write_text(
            out / "terraform" / "README.md",
            f"# Terraform Provider - {spec.title}\n\nThis provider skeleton is planned.\n",
        )

