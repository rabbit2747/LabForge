from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


ENTERPRISE_TACTICS = {
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
}


class LabForgeModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class LabMetadata(LabForgeModel):
    id: str
    title: str
    version: str = "0.2"
    difficulty: str | None = None
    mode: str = "red-team"
    default_provider: str = "docker-compose"
    supported_providers: list[str] = Field(default_factory=lambda: ["docker-compose"])


class ScenarioSpec(LabForgeModel):
    id: str
    title: str
    summary: str
    final_objective: str
    learner_entrypoint: str | None = None
    target_industry: str | None = None
    target_organization_type: str | None = None
    realism_notes: list[str] = Field(default_factory=list)


class NetworkSpec(LabForgeModel):
    name: str
    internal: bool = False


class HealthcheckSpec(LabForgeModel):
    test: list[str]
    interval: str | None = None
    timeout: str | None = None
    retries: int | None = None


class ServiceSpec(LabForgeModel):
    name: str
    role: str = "service"
    exposed: bool = False
    networks: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)
    expose: list[str] = Field(default_factory=list)
    user: str | None = None
    build: str | None = None
    read_only: bool = True
    environment: dict[str, Any] | None = None
    volumes: list[str] | None = None
    depends_on: list[str] | None = None
    healthcheck: HealthcheckSpec | dict[str, Any] | None = None


class HostRequirement(LabForgeModel):
    role: str
    count: int = 1
    os: str
    cpu: str | None = None
    memory: str | None = None
    storage: str | None = None
    software: list[str] = Field(default_factory=list)


class EnvironmentRequirement(LabForgeModel):
    description: str
    hosts: list[HostRequirement] = Field(default_factory=list)


class DeploymentSpec(LabForgeModel):
    recommended_model: str = "docker-compose"
    docker_only_supported: bool = True
    docker_only_notes: str | None = None
    minimum_environment: EnvironmentRequirement | None = None
    realistic_environment: EnvironmentRequirement | None = None
    required_platforms: list[str] = Field(default_factory=list)


class SecurityControlsSpec(LabForgeModel):
    recommended: list[str] = Field(default_factory=list)


class TopologySpec(LabForgeModel):
    networks: list[NetworkSpec] = Field(default_factory=list)
    services: list[ServiceSpec] = Field(default_factory=list)
    security_controls: SecurityControlsSpec = Field(default_factory=SecurityControlsSpec)
    deployment: DeploymentSpec = Field(default_factory=DeploymentSpec)

    @model_validator(mode="after")
    def validate_references(self) -> "TopologySpec":
        network_names = {item.name for item in self.networks}
        for service in self.services:
            for network in service.networks:
                if network not in network_names:
                    raise ValueError(f"service {service.name} references unknown network: {network}")
        return self


class TechniqueSpec(LabForgeModel):
    id: str
    name: str


class MitreStageMapping(LabForgeModel):
    tactic: str
    techniques: list[TechniqueSpec] = Field(default_factory=list)

    @field_validator("tactic")
    @classmethod
    def tactic_must_be_enterprise(cls, value: str) -> str:
        if value not in ENTERPRISE_TACTICS:
            raise ValueError(f"invalid MITRE Enterprise tactic: {value}")
        return value


class StageSpec(LabForgeModel):
    id: str
    title: str
    procedure: str
    evidence: list[str] = Field(default_factory=list)
    mitre: MitreStageMapping
    required_findings: list[str] = Field(default_factory=list)
    next_stage: str | None = None


class StagesSpec(LabForgeModel):
    stages: list[StageSpec] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_stage_ids(self) -> "StagesSpec":
        seen: set[str] = set()
        for stage in self.stages:
            if stage.id in seen:
                raise ValueError(f"duplicate stage id: {stage.id}")
            seen.add(stage.id)
        return self


class AssetSpec(LabForgeModel):
    id: str
    type: str
    zone: str | None = None
    os: str | None = None
    exposure: Literal["public", "internal", "restricted"] | str = "internal"


class EnvironmentSpec(LabForgeModel):
    zones: list[dict[str, Any]] = Field(default_factory=list)
    assets: list[AssetSpec] = Field(default_factory=list)


class ServiceArtifactSpec(LabForgeModel):
    service: str
    source_path: str
    runtime: str = "unspecified"
    purpose: str
    attack_surface: list[str] = Field(default_factory=list)
    seed_inputs: list[str] = Field(default_factory=list)
    noise_inputs: list[str] = Field(default_factory=list)
    healthcheck: str
    reset: str
    evidence_logs: list[str] = Field(default_factory=list)
    safety_boundaries: list[str] = Field(default_factory=list)


class ArtifactSpec(LabForgeModel):
    seed: list[dict[str, Any]] = Field(default_factory=list)
    noise: list[dict[str, Any]] = Field(default_factory=list)
    learner_handouts: list[dict[str, Any]] = Field(default_factory=list)
    instructor_only: list[dict[str, Any]] = Field(default_factory=list)
    service_artifacts: list[ServiceArtifactSpec] = Field(default_factory=list)


class SupervisorSelectionSpec(LabForgeModel):
    selected_controls: dict[str, list[str]] = Field(default_factory=dict)
    training_mode: dict[str, Any] = Field(default_factory=dict)


SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "lab.schema.json": LabMetadata,
    "scenario.schema.json": ScenarioSpec,
    "topology.schema.json": TopologySpec,
    "stages.schema.json": StagesSpec,
    "environment.schema.json": EnvironmentSpec,
    "artifacts.schema.json": ArtifactSpec,
    "security-controls.schema.json": SecurityControlsSpec,
    "supervisor-selection.schema.json": SupervisorSelectionSpec,
}
