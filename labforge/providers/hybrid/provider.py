from __future__ import annotations

from pathlib import Path

from labforge.io import write_text
from labforge.model import LabSpec
from labforge.providers.base import Provider


class HybridProvider(Provider):
    name = "hybrid"

    def generate(self, spec: LabSpec, out: Path) -> None:
        write_text(
            out / "hybrid" / "README.md",
            f"# Hybrid Provider - {spec.title}\n\nThis provider skeleton is planned for Docker plus VM labs.\n",
        )

