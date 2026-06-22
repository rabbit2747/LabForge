# LabForge

LabForge is a small framework for building ROOT14-style hands-on security labs
from declarative scenario specifications.

The goal is to let authors describe:

- scenario story and final objective
- infrastructure topology
- services and networks
- MITRE ATT&CK stage mappings
- seed artifacts and noise data
- reset/build/documentation behavior

Then LabForge generates a repeatable lab scaffold:

- `docker-compose.yml`
- generated documentation
- stage/MITRE report
- supervisor architecture diagrams
- reset notes
- implementation checklist

LabForge intentionally does not replace Docker Compose, Ansible, or Terraform.
It sits above them as a lab-specific content and topology layer.

## MVP Commands

```powershell
python -m labforge validate examples/scenario-02-ad-domain-compromise
python -m labforge build examples/scenario-02-ad-domain-compromise --out output/scenario-02
python -m labforge docs examples/scenario-02-ad-domain-compromise --out output/scenario-02-docs
```

Generated documentation includes Mermaid diagrams:

- `docs/architecture-diagrams.md`
- `diagrams/topology.mmd`
- `diagrams/attack-flow.mmd`
- `diagrams/security-controls.mmd`

## Scenario Layout

```text
scenario-root/
|-- scenario.yaml
|-- topology.yaml
|-- stages.yaml
|-- artifacts/
`-- services/
```

## Required Design Principles

- External exposure must be explicit.
- Internal services must not be directly exposed by default.
- Attacker Workstation should be present for interactive learner work.
- Reset behavior must be planned.
- MITRE tactic and technique mapping is required for each stage.
- Seed data and noise data should be separated.
- Health checks are required for generated services.
- Dangerous behavior must be constrained to the lab network.

## Current Status

This is an MVP scaffold. It can validate a scenario bundle and generate a Docker
Compose scaffold plus documentation. It does not yet generate full vulnerable
service source code.
