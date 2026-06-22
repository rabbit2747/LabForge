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
- Docker Compose security-control scaffolds for selected protected controls
- student/supervisor README
- MITRE mapping report
- implementation checklist
- Mermaid architecture diagrams
- deployment requirements for supervisors
- raw `.mmd` diagram files for rendering or review

LabForge can also inspect the local build host before real deployment work:

- local OS detection: Windows, Linux, macOS, WSL Linux
- WSL availability and distro list
- Docker CLI/server reachability from host and WSL
- recommended execution location such as host shell, WSL, or VM/hybrid prerequisites

## Quick Start

```powershell
cd C:\dev\LabForge

python -m labforge validate examples/scenario-02-ad-domain-compromise
python -m labforge doctor --lab examples/scenario-02-ad-domain-compromise
python -m labforge build examples/scenario-02-ad-domain-compromise --out output/scenario-02 --provider docker-compose --profile unprotected --force
python -m labforge docs examples/scenario-02-ad-domain-compromise --out output/scenario-02-docs --profile protected
python -m labforge schema export --out schemas
```

Expected result:

```text
Validation passed
# LabForge Host Doctor
Built lab scaffold with provider docker-compose and profile unprotected: C:\dev\LabForge\output\scenario-02
Rendered docs with profile protected: C:\dev\LabForge\output\scenario-02-docs
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
Docker Compose scaffolding plus documentation. The v0.2 spec model is now
validated through pydantic and can export JSON Schema files. The provider
interface has a working `docker-compose` provider plus skeleton `ansible`,
`terraform`, `ludus`, and `hybrid` providers. Documentation rendering now uses
Jinja2 templates and can emit `unprotected` and `protected` architecture views.
The Docker Compose provider can materialize selected protected controls as safe
control scaffold services with labels, networks, and log volumes. It does not
yet generate full vulnerable service source code, VM infrastructure, Ansible
roles, Terraform modules, Ludus range files, or production-grade enforcement
logic for WAF, IDS, SIEM, or EDR controls.

The `doctor` command now detects whether the current machine should run lab
work directly from the host shell or from WSL. This is important for Windows
training PCs where the source tree is on Windows but Docker is configured inside
WSL.
