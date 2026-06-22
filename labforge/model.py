from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .io import load_yaml
from .spec_models import (
    ArtifactSpec,
    EnvironmentSpec,
    LabMetadata,
    ScenarioSpec,
    SecurityControlsSpec,
    StagesSpec,
    SupervisorSelectionSpec,
    TopologySpec,
)


REQUIRED_FILES = ("scenario.yaml", "topology.yaml", "stages.yaml")
OPTIONAL_FILES = {
    "lab": "lab.yaml",
    "environment": "environment.yaml",
    "artifacts": "artifacts.yaml",
    "security_controls": "security-controls.yaml",
    "supervisor_selection": "supervisor-selection.yaml",
}


@dataclass(frozen=True)
class LabSpec:
    root: Path
    scenario: dict[str, Any]
    topology: dict[str, Any]
    stages: dict[str, Any]
    lab: dict[str, Any]
    environment: dict[str, Any]
    artifacts: dict[str, Any]
    security_controls: dict[str, Any]
    supervisor_selection: dict[str, Any]
    scenario_model: ScenarioSpec
    topology_model: TopologySpec
    stages_model: StagesSpec
    lab_model: LabMetadata | None = None
    environment_model: EnvironmentSpec | None = None
    artifacts_model: ArtifactSpec | None = None
    security_controls_model: SecurityControlsSpec | None = None
    supervisor_selection_model: SupervisorSelectionSpec | None = None

    @classmethod
    def load(cls, root: Path) -> "LabSpec":
        root = root.resolve()
        missing = [name for name in REQUIRED_FILES if not (root / name).exists()]
        if missing:
            joined = ", ".join(missing)
            raise FileNotFoundError(f"Missing required files in {root}: {joined}")
        scenario = load_yaml(root / "scenario.yaml")
        topology = load_yaml(root / "topology.yaml")
        stages = load_yaml(root / "stages.yaml")

        optional: dict[str, dict[str, Any]] = {}
        for key, filename in OPTIONAL_FILES.items():
            path = root / filename
            optional[key] = load_yaml(path) if path.exists() else {}

        scenario_model = ScenarioSpec.model_validate(scenario)
        topology_model = TopologySpec.model_validate(topology)
        stages_model = StagesSpec.model_validate(stages)

        lab_model = LabMetadata.model_validate(optional["lab"]) if optional["lab"] else None
        environment_model = (
            EnvironmentSpec.model_validate(optional["environment"])
            if optional["environment"]
            else None
        )
        artifacts_model = (
            ArtifactSpec.model_validate(optional["artifacts"]) if optional["artifacts"] else None
        )
        security_controls_model = (
            SecurityControlsSpec.model_validate(optional["security_controls"])
            if optional["security_controls"]
            else None
        )
        supervisor_selection_model = (
            SupervisorSelectionSpec.model_validate(optional["supervisor_selection"])
            if optional["supervisor_selection"]
            else None
        )

        return cls(
            root=root,
            scenario=scenario,
            topology=topology,
            stages=stages,
            lab=optional["lab"],
            environment=optional["environment"],
            artifacts=optional["artifacts"],
            security_controls=optional["security_controls"],
            supervisor_selection=optional["supervisor_selection"],
            scenario_model=scenario_model,
            topology_model=topology_model,
            stages_model=stages_model,
            lab_model=lab_model,
            environment_model=environment_model,
            artifacts_model=artifacts_model,
            security_controls_model=security_controls_model,
            supervisor_selection_model=supervisor_selection_model,
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
