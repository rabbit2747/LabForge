from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .io import load_yaml


REQUIRED_FILES = ("scenario.yaml", "topology.yaml", "stages.yaml")


@dataclass(frozen=True)
class LabSpec:
    root: Path
    scenario: dict[str, Any]
    topology: dict[str, Any]
    stages: dict[str, Any]

    @classmethod
    def load(cls, root: Path) -> "LabSpec":
        root = root.resolve()
        missing = [name for name in REQUIRED_FILES if not (root / name).exists()]
        if missing:
            joined = ", ".join(missing)
            raise FileNotFoundError(f"Missing required files in {root}: {joined}")
        return cls(
            root=root,
            scenario=load_yaml(root / "scenario.yaml"),
            topology=load_yaml(root / "topology.yaml"),
            stages=load_yaml(root / "stages.yaml"),
        )

    @property
    def lab_id(self) -> str:
        return str(self.scenario.get("id", self.root.name))

    @property
    def title(self) -> str:
        return str(self.scenario.get("title", self.lab_id))

    @property
    def services(self) -> list[dict[str, Any]]:
        services = self.topology.get("services", [])
        if not isinstance(services, list):
            raise ValueError("topology.yaml services must be a list")
        return services

    @property
    def networks(self) -> list[dict[str, Any]]:
        networks = self.topology.get("networks", [])
        if not isinstance(networks, list):
            raise ValueError("topology.yaml networks must be a list")
        return networks

    @property
    def stage_list(self) -> list[dict[str, Any]]:
        stages = self.stages.get("stages", [])
        if not isinstance(stages, list):
            raise ValueError("stages.yaml stages must be a list")
        return stages

