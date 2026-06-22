from __future__ import annotations

from pathlib import Path

from labforge.io import write_text
from labforge.model import LabSpec
from labforge.providers.base import Provider


class LudusProvider(Provider):
    name = "ludus"

    def generate(self, spec: LabSpec, out: Path) -> None:
        write_text(
            out / "ludus" / "README.md",
            f"# Ludus Provider - {spec.title}\n\nThis provider skeleton is planned for Proxmox-backed AD ranges.\n",
        )

