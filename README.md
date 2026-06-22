# LabForge

LabForge is a declarative framework for designing, reviewing, and generating
ROOT14-style hands-on security lab infrastructure.

It is not intended to be only a Docker Compose generator. Docker Compose is the
first implemented provider, but the framework is being shaped so that future
labs can target Docker, virtual machines, Ansible, Terraform, Vagrant, Proxmox,
VMware, or hybrid environments.

## What It Does

LabForge lets an author describe a lab as structured scenario files:

- the story and final objective
- the logical infrastructure and network zones
- services, exposed entry points, and internal assets
- stage-by-stage learner flow
- MITRE ATT&CK tactic and technique mappings
- selectable security controls such as firewall, WAF, IDS, logging, and EDR
- supervisor-facing architecture diagrams
- deployment requirements for Docker, VM, Proxmox, and hybrid lab models

From those files, LabForge currently generates:

- `docker-compose.yml`
- student/supervisor README
- MITRE mapping report
- implementation checklist
- Mermaid architecture diagrams
- deployment requirements for supervisors
- raw `.mmd` diagram files for rendering or review

## Quick Start

```powershell
cd C:\dev\LabForge

python -m labforge validate examples/scenario-02-ad-domain-compromise
python -m labforge build examples/scenario-02-ad-domain-compromise --out output/scenario-02 --force
python -m labforge docs examples/scenario-02-ad-domain-compromise --out output/scenario-02-docs
```

Expected result:

```text
Validation passed
Built lab scaffold: C:\dev\LabForge\output\scenario-02
Rendered docs: C:\dev\LabForge\output\scenario-02-docs
```

## Detailed Review Guide

For the complete explanation, usage model, file format, generated outputs,
security-control concept, and current limitations, see:

[`docs/labforge-review-guide-ko.md`](docs/labforge-review-guide-ko.md)

For a broader catalog of Docker, VM, AD, Proxmox, IDS, SIEM, Kubernetes, and
hybrid deployment environment requirements, see:

[`docs/environment-requirements-catalog-ko.md`](docs/environment-requirements-catalog-ko.md)

For an analysis of reusable open-source tools, MCP/Skill candidates, provider
backends, and license risks from the local `reference/` directory, see:

[`docs/reference-tooling-analysis-ko.md`](docs/reference-tooling-analysis-ko.md)

## Current Status

LabForge is currently an MVP. It can validate a scenario bundle and generate
Docker Compose scaffolding plus documentation. It does not yet generate full
vulnerable service source code, VM infrastructure, Ansible roles, Terraform
modules, or final production-grade protected/unprotected architecture variants.
