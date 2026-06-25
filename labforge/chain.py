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


class EvidenceHandoff(ChainModel):
    evidence: str
    producer_stage: str
    consumer_stage: str
    distance: int = 1
    status: Literal["direct", "skipped-stage", "missing-producer"] = "direct"


class EvidenceRuntimeSource(ChainModel):
    evidence: str
    producer_stage: str = ""
    required_by_stages: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    plugin_emitters: list[str] = Field(default_factory=list)
    runtime_paths: list[str] = Field(default_factory=list)
    status: Literal["plugin-backed", "runtime-backed", "final-only", "unmapped"] = "unmapped"


class ChainManifest(ChainModel):
    lab_id: str
    title: str
    status: Literal["passed", "warning", "failed"]
    nodes: list[ChainNode] = Field(default_factory=list)
    links: list[ChainLink] = Field(default_factory=list)
    evidence_handoffs: list[EvidenceHandoff] = Field(default_factory=list)
    evidence_runtime_sources: list[EvidenceRuntimeSource] = Field(default_factory=list)
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
    evidence_handoffs, handoff_failures, handoff_warnings = build_evidence_handoffs(nodes)
    failures.extend(handoff_failures)
    warnings.extend(handoff_warnings)
    links = refine_links_with_consumed_evidence(links, nodes, evidence_handoffs)
    evidence_runtime_sources, runtime_warnings = build_evidence_runtime_sources(spec, nodes)
    warnings.extend(runtime_warnings)
    clue_failures, clue_warnings = validate_clue_quality(nodes)
    failures.extend(clue_failures)
    warnings.extend(clue_warnings)
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
        evidence_handoffs=evidence_handoffs,
        evidence_runtime_sources=evidence_runtime_sources,
        warnings=warnings,
        failures=failures,
    )


def build_evidence_handoffs(nodes: list[ChainNode]) -> tuple[list[EvidenceHandoff], list[str], list[str]]:
    handoffs: list[EvidenceHandoff] = []
    failures: list[str] = []
    warnings: list[str] = []
    latest_producer: dict[str, tuple[str, int]] = {}

    for index, node in enumerate(nodes):
        for evidence in node.required_inputs:
            producer = latest_producer.get(evidence)
            if not producer:
                future_producers = [
                    later.stage_id
                    for later in nodes[index + 1 :]
                    if evidence in later.produces
                ]
                if future_producers:
                    failures.append(
                        f"{node.stage_id} requires `{evidence}` before it is produced by later stage(s): {', '.join(future_producers)}"
                    )
                handoffs.append(
                    EvidenceHandoff(
                        evidence=evidence,
                        producer_stage="",
                        consumer_stage=node.stage_id,
                        distance=0,
                        status="missing-producer",
                    )
                )
                continue
            producer_stage, producer_index = producer
            distance = index - producer_index
            status: Literal["direct", "skipped-stage", "missing-producer"] = "direct" if distance == 1 else "skipped-stage"
            if distance > 1:
                warnings.append(
                    f"{node.stage_id} consumes `{evidence}` from {producer_stage} across {distance - 1} intermediate stage(s)."
                )
            handoffs.append(
                EvidenceHandoff(
                    evidence=evidence,
                    producer_stage=producer_stage,
                    consumer_stage=node.stage_id,
                    distance=distance,
                    status=status,
                )
            )

        for evidence in node.produces:
            latest_producer[evidence] = (node.stage_id, index)

    return handoffs, failures, warnings


def refine_links_with_consumed_evidence(
    links: list[ChainLink], nodes: list[ChainNode], handoffs: list[EvidenceHandoff]
) -> list[ChainLink]:
    node_by_stage = {node.stage_id: node for node in nodes}
    consumed_by_pair: dict[tuple[str, str], list[str]] = {}
    for handoff in handoffs:
        if not handoff.producer_stage:
            continue
        consumed_by_pair.setdefault((handoff.producer_stage, handoff.consumer_stage), []).append(handoff.evidence)

    refined: list[ChainLink] = []
    for link in links:
        evidence = consumed_by_pair.get((link.from_stage, link.to_stage))
        if evidence is None:
            source = node_by_stage.get(link.from_stage)
            target = node_by_stage.get(link.to_stage)
            if source and target and target.required_inputs:
                evidence = [item for item in source.produces if item in target.required_inputs]
            elif source:
                evidence = list(source.produces)
            else:
                evidence = list(link.carried_evidence)
        refined.append(link.model_copy(update={"carried_evidence": sorted(dict.fromkeys(evidence))}))
    return refined


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


def build_evidence_runtime_sources(spec: LabSpec, nodes: list[ChainNode]) -> tuple[list[EvidenceRuntimeSource], list[str]]:
    produced_by_stage: dict[str, str] = {}
    required_by_evidence: dict[str, list[str]] = {}
    services_by_evidence: dict[str, set[str]] = {}
    for node in nodes:
        for evidence in node.produces:
            produced_by_stage.setdefault(evidence, node.stage_id)
            services_by_evidence.setdefault(evidence, set()).update(node.services)
        for evidence in node.required_inputs:
            required_by_evidence.setdefault(evidence, []).append(node.stage_id)

    plugin_emitters = declared_plugin_evidence_emitters(spec)
    runtime_paths = declared_runtime_evidence_paths(spec)
    should_warn_unmapped = has_declared_vulnerability_plugins(spec)
    final_stage = nodes[-1].stage_id if nodes else ""
    sources: list[EvidenceRuntimeSource] = []
    warnings: list[str] = []
    for evidence in sorted(produced_by_stage):
        emitters = sorted(plugin_emitters.get(evidence, []))
        paths = sorted(runtime_paths.get(evidence, []))
        producer_stage = produced_by_stage[evidence]
        if emitters:
            status: Literal["plugin-backed", "runtime-backed", "final-only", "unmapped"] = "plugin-backed"
        elif paths:
            status = "runtime-backed"
        elif producer_stage == final_stage:
            status = "final-only"
        else:
            status = "unmapped"
            if should_warn_unmapped:
                warnings.append(
                    f"{producer_stage} evidence `{evidence}` has no declared plugin emitter or explicit runtime evidence path."
                )
        sources.append(
            EvidenceRuntimeSource(
                evidence=evidence,
                producer_stage=producer_stage,
                required_by_stages=sorted(required_by_evidence.get(evidence, [])),
                services=sorted(services_by_evidence.get(evidence, set())),
                plugin_emitters=emitters,
                runtime_paths=paths,
                status=status,
            )
        )
    return sources, warnings


def has_declared_vulnerability_plugins(spec: LabSpec) -> bool:
    artifacts_model = getattr(spec, "artifacts_model", None)
    if not artifacts_model:
        return False
    for artifact in getattr(artifacts_model, "service_artifacts", []) or []:
        extra = getattr(artifact, "model_extra", None) or {}
        plugins = extra.get("vulnerability_plugins") or extra.get("vulnerabilities") or []
        if plugins:
            return True
    return False


def declared_plugin_evidence_emitters(spec: LabSpec) -> dict[str, list[str]]:
    emitters: dict[str, list[str]] = {}
    artifacts_model = getattr(spec, "artifacts_model", None)
    if not artifacts_model:
        return emitters
    for artifact in getattr(artifacts_model, "service_artifacts", []) or []:
        service = str(getattr(artifact, "service", ""))
        extra = getattr(artifact, "model_extra", None) or {}
        plugins = extra.get("vulnerability_plugins") or extra.get("vulnerabilities") or []
        if isinstance(plugins, str):
            plugins = [{"id": plugins}]
        for plugin in plugins if isinstance(plugins, list) else []:
            if isinstance(plugin, str):
                plugin = {"id": plugin}
            if not isinstance(plugin, dict):
                continue
            plugin_id = normalize_plugin_id(str(plugin.get("id", "")))
            values = plugin.get("emits_evidence") or plugin.get("evidence") or plugin.get("produces") or []
            if isinstance(values, str):
                values = [values]
            for value in values if isinstance(values, list) else []:
                evidence = str(value).strip()
                if not evidence:
                    continue
                emitter = f"{service}:{plugin_id}" if plugin_id else service
                emitters.setdefault(evidence, [])
                if emitter not in emitters[evidence]:
                    emitters[evidence].append(emitter)
    return emitters


def declared_runtime_evidence_paths(spec: LabSpec) -> dict[str, list[str]]:
    paths: dict[str, list[str]] = {}
    artifacts_model = getattr(spec, "artifacts_model", None)
    if not artifacts_model:
        return paths
    for artifact in getattr(artifacts_model, "service_artifacts", []) or []:
        service = str(getattr(artifact, "service", ""))
        for path in getattr(artifact, "evidence_logs", []) or []:
            path_text = str(path).strip()
            if not path_text:
                continue
            for token in evidence_like_tokens(path_text):
                paths.setdefault(token, [])
                source = f"{service}:{path_text}"
                if source not in paths[token]:
                    paths[token].append(source)
    return paths


def evidence_like_tokens(value: str) -> list[str]:
    normalized = normalize_clue_text(value).replace(" ", "_")
    tokens = [normalized] if normalized else []
    if normalized.endswith("_log"):
        tokens.append(normalized[:-4])
    if normalized.endswith("_events"):
        tokens.append(normalized[:-7])
    return [token for token in tokens if token]


def normalize_plugin_id(value: str) -> str:
    chars = [ch.lower() if ch.isalnum() else "-" for ch in value.strip()]
    return "-".join(part for part in "".join(chars).split("-") if part)


def validate_clue_quality(nodes: list[ChainNode]) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    direct_answer_terms = (
        "flag",
        "ctf",
        "answer key",
        "copy paste",
        "copy/paste",
        "정답",
        "플래그",
    )
    weak_phrases = {
        "continue",
        "continue.",
        "next",
        "start.",
        "proceed",
        "go next",
        "do it",
    }
    for index, node in enumerate(nodes):
        clue = " ".join(node.learner_clue.split())
        normalized = clue.lower()
        if not clue:
            failures.append(f"{node.stage_id} has no learner clue.")
            continue
        if len(clue) < 24 or normalized in weak_phrases:
            warnings.append(f"{node.stage_id} learner clue is too thin to guide a human learner.")
        if normalized.startswith("review normal business behavior related to"):
            warnings.append(f"{node.stage_id} learner clue is a generic fallback rather than a scenario-specific clue.")
        if any(term in normalized for term in direct_answer_terms):
            warnings.append(f"{node.stage_id} learner clue contains CTF or answer-key wording.")
        thin_clue = len(clue) < 32
        if thin_clue and not (clue_references_any(clue, node.required_inputs) or clue_references_any(clue, node.services)):
            warnings.append(f"{node.stage_id} learner clue is short and lacks an evidence or service anchor.")
        if len(nodes) > 1 and not clue_references_any(clue, stage_clue_anchor_values(node)):
            warnings.append(f"{node.stage_id} learner clue does not reference evidence, service, or stage context.")
    return failures, warnings


def stage_clue_anchor_values(node: ChainNode) -> list[str]:
    values = [
        *node.required_inputs,
        *node.produces,
        *node.services,
        node.title,
        node.tactic,
        *node.techniques,
    ]
    return [value for value in values if not is_generic_clue_anchor(value)]


def is_generic_clue_anchor(value: str) -> bool:
    normalized = normalize_clue_text(value)
    if not normalized:
        return True
    return normalized in GENERIC_CLUE_ANCHORS


GENERIC_CLUE_ANCHORS = {
    "entry",
    "next",
    "stage",
    "step",
    "review",
    "internal workflow",
    "external workflow",
    "final",
    "finish",
}


def clue_references_any(clue: str, values: list[str]) -> bool:
    normalized = normalize_clue_text(clue)
    for value in values:
        text = normalize_clue_text(value)
        if not text:
            continue
        if text in normalized:
            return True
        parts = [part for part in text.split() if len(part) >= 4]
        if parts and any(part in normalized for part in parts):
            return True
    return False


def normalize_clue_text(value: str) -> str:
    chars = [ch.lower() if ch.isalnum() else " " for ch in str(value)]
    return " ".join("".join(chars).split())


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
        "evidence_handoffs": [
            handoff.model_dump()
            for handoff in manifest.evidence_handoffs
            if handoff.producer_stage in stage_ids or handoff.consumer_stage in stage_ids
        ],
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
    lines += [
        "",
        "## Evidence Handoffs",
        "",
        "| Evidence | Producer | Consumer | Distance | Status |",
        "|---|---|---|---|---|",
    ]
    if not manifest.evidence_handoffs:
        lines.append("| - | - | - | - | - |")
    for handoff in manifest.evidence_handoffs:
        lines.append(
            f"| `{handoff.evidence}` | `{handoff.producer_stage or '-'}` | `{handoff.consumer_stage}` | "
            f"{handoff.distance} | {handoff.status} |"
        )
    lines += [
        "",
        "## Evidence Runtime Sources",
        "",
        "| Evidence | Producer Stage | Required By | Services | Runtime Source | Status |",
        "|---|---|---|---|---|---|",
    ]
    if not manifest.evidence_runtime_sources:
        lines.append("| - | - | - | - | - | - |")
    for source in manifest.evidence_runtime_sources:
        runtime_source = ", ".join([*source.plugin_emitters, *source.runtime_paths]) or "-"
        lines.append(
            f"| `{source.evidence}` | `{source.producer_stage or '-'}` | "
            f"{escape_cell(', '.join(source.required_by_stages) or '-')} | "
            f"{escape_cell(', '.join(source.services) or '-')} | {escape_cell(runtime_source)} | {source.status} |"
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
