from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .io import dump_yaml, write_text
from .model import LabSpec


class ChainModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class ChainNode(ChainModel):
    stage_id: str
    title: str
    tactic: str = ""
    techniques: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    required_inputs: list[str] = Field(default_factory=list)
    produces: list[str] = Field(default_factory=list)
    unlocks: str | None = None
    learner_clue: str = ""
    supervisor_note: str = ""


class ChainLink(ChainModel):
    from_stage: str
    to_stage: str
    carried_evidence: list[str] = Field(default_factory=list)
    status: Literal["explicit", "inferred", "missing"] = "inferred"


class ChainManifest(ChainModel):
    lab_id: str
    title: str
    status: Literal["passed", "warning", "failed"]
    nodes: list[ChainNode] = Field(default_factory=list)
    links: list[ChainLink] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)


def build_chain_manifest(spec: LabSpec) -> ChainManifest:
    stages = spec.stage_list
    services = [str(service.get("name", "")) for service in spec.services if service.get("name")]
    nodes: list[ChainNode] = []
    links: list[ChainLink] = []
    warnings: list[str] = []
    failures: list[str] = []

    if not stages:
        return ChainManifest(
            lab_id=spec.lab_id,
            title=spec.title,
            status="failed",
            failures=["No stages were declared."],
        )

    stage_ids = [str(stage.get("id", "")) for stage in stages]
    for index, stage in enumerate(stages):
        stage_id = str(stage.get("id", f"stage-{index + 1:02d}"))
        next_id = explicit_or_inferred_next(stage, stages, index)
        mitre = stage.get("mitre", {}) if isinstance(stage.get("mitre"), dict) else {}
        techniques = [
            f"{technique.get('id', '')} {technique.get('name', '')}".strip()
            for technique in mitre.get("techniques", []) or []
            if isinstance(technique, dict)
        ]
        produces = [str(item) for item in stage.get("evidence", []) or []]
        required_inputs = [str(item) for item in stage.get("required_findings", []) or []]
        if not required_inputs and index > 0:
            required_inputs = [str(item) for item in stages[index - 1].get("evidence", []) or []]
        node = ChainNode(
            stage_id=stage_id,
            title=str(stage.get("title", "")),
            tactic=str(mitre.get("tactic", "")),
            techniques=techniques,
            services=infer_stage_services(stage, services),
            required_inputs=required_inputs,
            produces=produces,
            unlocks=next_id,
            learner_clue=learner_clue_for_stage(stage, index),
            supervisor_note=supervisor_note_for_stage(stage, required_inputs, produces, next_id),
        )
        nodes.append(node)

        if index < len(stages) - 1:
            target = next_id or str(stages[index + 1].get("id", ""))
            status: Literal["explicit", "inferred", "missing"] = "explicit" if stage.get("next_stage") else "inferred"
            if target not in stage_ids:
                status = "missing"
                failures.append(f"{stage_id} unlocks unknown stage `{target}`.")
            if not produces:
                warnings.append(f"{stage_id} does not declare evidence produced for the next stage.")
            links.append(
                ChainLink(
                    from_stage=stage_id,
                    to_stage=target,
                    carried_evidence=produces,
                    status=status,
                )
            )

    if len(stages) < 2:
        failures.append("A hands-on lab chain requires at least two stages.")
    continuity_failures, continuity_warnings = validate_chain_continuity(nodes)
    failures.extend(continuity_failures)
    warnings.extend(continuity_warnings)
    orphaned = [node.stage_id for node in nodes[1:] if not node.required_inputs]
    if orphaned:
        warnings.append(f"Stages without required inputs or inferred previous evidence: {', '.join(orphaned)}")
    service_gaps = [node.stage_id for node in nodes if not node.services]
    if service_gaps:
        warnings.append(f"Stages without inferred service touchpoints: {', '.join(service_gaps)}")
    status: Literal["passed", "warning", "failed"] = "failed" if failures else ("warning" if warnings else "passed")
    return ChainManifest(
        lab_id=spec.lab_id,
        title=spec.title,
        status=status,
        nodes=nodes,
        links=links,
        warnings=warnings,
        failures=failures,
    )


def validate_chain_continuity(nodes: list[ChainNode]) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    produced_so_far: set[str] = set()
    produced_by_stage: dict[str, list[str]] = {}
    for index, node in enumerate(nodes):
        missing = sorted([item for item in node.required_inputs if item not in produced_so_far])
        if missing and index > 0:
            failures.append(
                f"{node.stage_id} requires evidence not produced by earlier stages: {', '.join(missing)}"
            )
        if index == 0 and node.required_inputs:
            warnings.append(
                f"{node.stage_id} is an entry stage but declares required inputs: {', '.join(node.required_inputs)}"
            )
        duplicate = sorted([item for item in node.produces if item in produced_so_far])
        if duplicate:
            warnings.append(
                f"{node.stage_id} produces evidence already produced earlier: {', '.join(duplicate)}"
            )
        produced_by_stage[node.stage_id] = list(node.produces)
        produced_so_far.update(node.produces)
    final_stage_id = nodes[-1].stage_id if nodes else ""
    unused = sorted(
        evidence
        for stage_id, produced in produced_by_stage.items()
        if stage_id != final_stage_id
        for evidence in produced
        if not any(evidence in node.required_inputs for node in nodes if node.stage_id != stage_id)
    )
    if unused and len(nodes) > 1:
        warnings.append(f"Produced evidence not used by another stage: {', '.join(unused[:10])}")
    return failures, warnings


def explicit_or_inferred_next(stage: dict[str, Any], stages: list[dict[str, Any]], index: int) -> str | None:
    explicit = stage.get("next_stage")
    if explicit:
        return str(explicit)
    if index + 1 < len(stages):
        return str(stages[index + 1].get("id", ""))
    return None


def infer_stage_services(stage: dict[str, Any], service_names: list[str]) -> list[str]:
    blob = " ".join(
        [
            str(stage.get("id", "")),
            str(stage.get("title", "")),
            str(stage.get("procedure", "")),
            " ".join(str(item) for item in stage.get("evidence", []) or []),
            " ".join(str(item) for item in stage.get("required_findings", []) or []),
            " ".join(str(item) for item in stage.get("infrastructure_touched", []) or []),
        ]
    ).lower()
    matches = []
    for service in service_names:
        service_text = service.lower()
        service_words = service_text.replace("-", " ")
        if service_text in blob or service_words in blob:
            matches.append(service)
    heuristic_matches = infer_services_from_common_terms(blob, service_names)
    for service in heuristic_matches:
        if service not in matches:
            matches.append(service)
    return matches


def infer_services_from_common_terms(blob: str, service_names: list[str]) -> list[str]:
    service_blob = {service: service.lower().replace("-", " ") for service in service_names}
    rules: list[tuple[tuple[str, ...], tuple[str, ...]]] = [
        (("hr ", "profile preview", "employee", "human resources"), ("hr", "portal", "employee")),
        (("command execution", "foothold", "current user", "hostname", "internal dns"), ("portal", "edge", "entry", "web")),
        (("ldap", "bind", "domain", "spn", "kerberoast", "kerberos", "directory"), ("ldap", "ad", "domain", "identity", "directory")),
        (("reporting", "report", "server-side maintenance"), ("reporting", "report")),
        (("backup", "run-as", "operator token", "maintenance script"), ("backup", "reporting")),
        (("file share", "fileserver", "archive", "board share", "network shared"), ("file", "fileserver", "share", "object", "archive")),
        (("stage the final", "manifest", "source path", "hash"), ("file", "staging", "drop", "object")),
        (("controlled drop", "submit", "submission"), ("drop", "submit", "controlled")),
        (("build", "artifact", "release", "signed", "update"), ("build", "artifact", "release", "sign", "update")),
        (("customer", "agent", "tenant", "integration"), ("customer", "agent", "tenant")),
        (("siem", "alert", "event", "audit", "log"), ("siem", "log", "audit", "monitor")),
    ]
    matches: list[str] = []
    for stage_terms, service_terms in rules:
        if not any(term in blob for term in stage_terms):
            continue
        for service, normalized in service_blob.items():
            if any(term in normalized for term in service_terms):
                matches.append(service)
    return matches


def learner_clue_for_stage(stage: dict[str, Any], index: int) -> str:
    title = str(stage.get("title", f"stage {index + 1}"))
    procedure = str(stage.get("procedure", ""))
    if not procedure:
        return f"Review normal business behavior related to {title} and collect evidence before moving on."
    return procedure


def supervisor_note_for_stage(stage: dict[str, Any], required_inputs: list[str], produces: list[str], next_id: str | None) -> str:
    inputs = ", ".join(required_inputs) or "no declared input"
    outputs = ", ".join(produces) or "no declared output"
    next_text = next_id or "final stage"
    return f"Requires {inputs}; produces {outputs}; unlocks {next_text}."


def write_chain_manifest(spec: LabSpec, out: Path) -> ChainManifest:
    manifest = build_chain_manifest(spec)
    out.mkdir(parents=True, exist_ok=True)
    write_text(out / "stage-chain.yaml", dump_yaml(manifest.model_dump()))
    write_text(out / "stage-chain.json", manifest.model_dump_json(indent=2))
    write_text(out / "stage-chain.md", render_chain_markdown(manifest))
    return manifest


def service_chain_view(manifest: ChainManifest, service: str) -> dict[str, Any]:
    """Return the part of a stage chain that is relevant to one service runtime."""
    stage_ids = {node.stage_id for node in manifest.nodes if service in node.services}
    incoming = [link for link in manifest.links if link.to_stage in stage_ids]
    outgoing = [link for link in manifest.links if link.from_stage in stage_ids]
    adjacent_ids = {
        *stage_ids,
        *[link.from_stage for link in incoming],
        *[link.to_stage for link in outgoing],
    }
    stage_by_id = {node.stage_id: node for node in manifest.nodes}
    adjacent = [stage_by_id[stage_id] for stage_id in sorted(adjacent_ids) if stage_id in stage_by_id and stage_id not in stage_ids]
    stages = [node for node in manifest.nodes if node.stage_id in stage_ids]
    return {
        "lab_id": manifest.lab_id,
        "title": manifest.title,
        "service": service,
        "chain_status": manifest.status,
        "stage_count": len(stages),
        "stages": [node.model_dump() for node in stages],
        "adjacent_stages": [node.model_dump() for node in adjacent],
        "incoming": [link.model_dump() for link in incoming],
        "outgoing": [link.model_dump() for link in outgoing],
        "warnings": manifest.warnings,
        "failures": manifest.failures,
    }


def stage_state_seed(manifest: ChainManifest, service: str) -> dict[str, Any]:
    """Build initial evidence/unlock state for generated service runtimes."""
    evidence_catalog = sorted({evidence for node in manifest.nodes for evidence in [*node.required_inputs, *node.produces]})
    stages = []
    for node in manifest.nodes:
        unlocked = not node.required_inputs
        stages.append(
            {
                "stage_id": node.stage_id,
                "title": node.title,
                "services": node.services,
                "required_inputs": node.required_inputs,
                "produces": node.produces,
                "unlocks": node.unlocks,
                "status": "unlocked" if unlocked else "locked",
                "unlock_reason": "entrypoint" if unlocked else "waiting_for_evidence",
            }
        )
    return {
        "lab_id": manifest.lab_id,
        "service": "lab-wide",
        "local_service": service,
        "state_scope": "shared",
        "chain_status": manifest.status,
        "acquired_evidence": [],
        "evidence_catalog": evidence_catalog,
        "stages": stages,
        "events": [],
    }


def apply_evidence_to_stage_state(state: dict[str, Any], evidence: str) -> dict[str, Any]:
    evidence = str(evidence).strip()
    if not evidence:
        return recompute_stage_state(state)
    acquired = state.setdefault("acquired_evidence", [])
    if evidence not in acquired:
        acquired.append(evidence)
        state.setdefault("events", []).append({"event": "evidence.acquired", "evidence": evidence})
    return recompute_stage_state(state)


def recompute_stage_state(state: dict[str, Any]) -> dict[str, Any]:
    acquired = set(state.get("acquired_evidence", []))
    for stage in state.get("stages", []):
        required = set(stage.get("required_inputs", []))
        missing = sorted(required - acquired)
        if not missing:
            stage["status"] = "unlocked"
            stage["unlock_reason"] = "required_evidence_satisfied" if required else "entrypoint"
            stage.pop("missing_evidence", None)
        else:
            stage["status"] = "locked"
            stage["missing_evidence"] = missing
    return state


def render_chain_markdown(manifest: ChainManifest) -> str:
    lines = [
        f"# Stage Chain - {manifest.title}",
        "",
        f"- Lab ID: `{manifest.lab_id}`",
        f"- Status: `{manifest.status}`",
        f"- Stages: `{len(manifest.nodes)}`",
        f"- Links: `{len(manifest.links)}`",
        "",
        "## Chain",
        "",
        "| Stage | Tactic | Services | Requires | Produces | Unlocks | Learner Clue |",
        "|---|---|---|---|---|---|---|",
    ]
    for node in manifest.nodes:
        lines.append(
            f"| `{node.stage_id}` {escape_cell(node.title)} | {escape_cell(node.tactic or '-')} | "
            f"{escape_cell(', '.join(node.services) or '-')} | {escape_cell(', '.join(node.required_inputs) or '-')} | "
            f"{escape_cell(', '.join(node.produces) or '-')} | `{node.unlocks or '-'}` | {escape_cell(node.learner_clue)} |"
        )
    lines += ["", "## Links", "", "| From | To | Evidence | Status |", "|---|---|---|---|"]
    for link in manifest.links:
        lines.append(
            f"| `{link.from_stage}` | `{link.to_stage}` | {escape_cell(', '.join(link.carried_evidence) or '-')} | {link.status} |"
        )
    if manifest.failures:
        lines += ["", "## Failures", "", *[f"- {item}" for item in manifest.failures]]
    if manifest.warnings:
        lines += ["", "## Warnings", "", *[f"- {item}" for item in manifest.warnings]]
    lines.append("")
    return "\n".join(lines)


def escape_cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def chain_manifest_to_json(manifest: ChainManifest) -> str:
    return json.dumps(manifest.model_dump(), ensure_ascii=False, indent=2) + "\n"
