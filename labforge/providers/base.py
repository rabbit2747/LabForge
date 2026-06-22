from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from labforge.model import LabSpec


class Provider(ABC):
    name: str

    def validate(self, spec: LabSpec) -> list[str]:
        return []

    @abstractmethod
    def generate(self, spec: LabSpec, out: Path) -> None:
        """Generate provider-specific infrastructure artifacts."""

    def plan(self, spec: LabSpec, out: Path) -> None:
        self.generate(spec, out)

    def deploy(self, spec: LabSpec, out: Path) -> None:
        raise NotImplementedError(f"{self.name} deploy is not implemented yet")

    def destroy(self, spec: LabSpec, out: Path) -> None:
        raise NotImplementedError(f"{self.name} destroy is not implemented yet")

