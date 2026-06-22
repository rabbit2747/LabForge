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
- Docker Compose runtime scripts for validate, start, stop, and reset
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
- host-aware execution plans that combine lab requirements, provider choice, profile, and local runtime state
- dry-run agent orchestration scaffolds for future Orchestrator LLM and specialist agents
- generated system prompts and per-agent task prompts for future LLM execution

## Quick Start

```powershell
cd <LabForge repository root>

python -m labforge validate examples/scenario-02-ad-domain-compromise
python -m labforge doctor --lab examples/scenario-02-ad-domain-compromise
python -m labforge plan examples/scenario-02-ad-domain-compromise --provider docker-compose --profile protected
python -m labforge agents scaffold examples/scenario-02-ad-domain-compromise --out output/scenario-02-agents
python -m labforge agents validate output/scenario-02-agents
python -m labforge services scaffold examples/scenario-02-ad-domain-compromise
python -m labforge services check examples/scenario-02-ad-domain-compromise
python -m labforge services healthcheck examples/scenario-02-ad-domain-compromise
python -m labforge services reset examples/scenario-02-ad-domain-compromise --service hr-portal
python -m labforge build examples/scenario-02-ad-domain-compromise --out output/scenario-02 --provider docker-compose --profile unprotected --force
python -m labforge docs examples/scenario-02-ad-domain-compromise --out output/scenario-02-docs --profile protected
python -m labforge schema export --out schemas
```

Expected result:

```text
Validation passed
# LabForge Host Doctor
# Execution Plan - Scenario 02 - Active Directory Domain Compromise
Scaffolded agent workspace: <repo>\output\scenario-02-agents\.ai
Agent workspace validation passed
Scaffolded service artifact files under: <repo>\examples\scenario-02-ad-domain-compromise
Service artifact check passed
[passed] edge-proxy healthcheck: <repo>\examples\scenario-02-ad-domain-compromise\services\edge-proxy\healthcheck.sh
[passed] hr-portal reset: <repo>\examples\scenario-02-ad-domain-compromise\services\hr-portal\reset.sh
Built lab scaffold with provider docker-compose and profile unprotected: <repo>\output\scenario-02
Rendered docs with profile protected: <repo>\output\scenario-02-docs
```

## Detailed Review Guide

For the complete explanation, usage model, file format, generated outputs,
security-control concept, and current limitations, see:

[`docs/labforge-review-guide-ko.md`](docs/labforge-review-guide-ko.md)

For the portability and open-source design rules that every LabForge change
must follow, see:

[`docs/open-source-constitution.md`](docs/open-source-constitution.md)

For the service implementation contract used by scenario authors, service
builders, providers, QA agents, and supervisors, see:

[`docs/service-artifact-standard.md`](docs/service-artifact-standard.md)

For a broader catalog of Docker, VM, AD, Proxmox, IDS, SIEM, Kubernetes, and
hybrid deployment environment requirements, see:

[`docs/environment-requirements-catalog-ko.md`](docs/environment-requirements-catalog-ko.md)

For an analysis of reusable open-source tools, MCP/Skill candidates, provider
backends, and license risks from the local `reference/` directory, see:

[`docs/reference-tooling-analysis-ko.md`](docs/reference-tooling-analysis-ko.md)

For the revised Orchestrator LLM and specialist-agent development plan, see:

[`docs/agent-orchestration-plan-ko.md`](docs/agent-orchestration-plan-ko.md)

## Current Status

LabForge is currently an MVP. It can validate a scenario bundle and generate
Docker Compose scaffolding plus documentation. The v0.2 spec model is now
validated through pydantic and can export JSON Schema files. The provider
interface has a working `docker-compose` provider plus skeleton `ansible`,
`terraform`, `ludus`, and `hybrid` providers. Documentation rendering now uses
Jinja2 templates and can emit `unprotected` and `protected` architecture views.
The Docker Compose provider can materialize selected protected controls as safe
control scaffold services with labels, networks, and log volumes. It also emits
PowerShell and shell runtime scripts for validation, start, stop, and reset;
PowerShell scripts automatically detect whether Docker is available in the
current shell or in any WSL distro on Windows, then run through the first usable
runtime. The provider also consumes `service_artifacts` contracts to document
service build contexts, reset behavior, healthchecks, evidence logs, and safety
boundaries. It does not yet generate full vulnerable service source code, VM infrastructure, Ansible
roles, Terraform modules, Ludus range files, or production-grade enforcement
logic for WAF, IDS, SIEM, or EDR controls.

The `doctor` command now detects whether the current machine should run lab
work directly from the host shell, from WSL, or through a VM/hybrid provider.
This is important because training PCs may be Windows, Linux, macOS, WSL-based,
or backed by a separate virtualization host.

The `plan` command turns that diagnosis into concrete execution steps. For
example, on a Windows PC where Docker is only reachable inside WSL, the plan
selects the detected WSL distro with Docker instead of assuming a fixed distro
name.

The `agents` command creates a dry-run orchestration workspace. It does not call
an LLM yet. It defines the future Orchestrator LLM and specialist agent system
prompts, per-agent task prompts, task contracts, output contracts, and decision
logs first, then later adapters can connect OpenAI, Claude CLI, or MCP.

```powershell
python -m labforge agents scaffold examples/scenario-02-ad-domain-compromise --out output/scenario-02-agents
python -m labforge agents validate output/scenario-02-agents
python -m labforge agents adapters
python -m labforge agents plan-run output/scenario-02-agents --context-root examples/scenario-02-ad-domain-compromise
python -m labforge agents run output/scenario-02-agents --dry-run --adapter manual --context-root examples/scenario-02-ad-domain-compromise
python -m labforge agents review output/scenario-02-agents --write
python -m labforge agents decide output/scenario-02-agents --decision accepted --task-id 02-mitre-mapper --reason "Reviewed mapping output."
```

`agents plan-run` reports execution readiness without calling an LLM.
`agents run --dry-run` writes `.ai/run/*.package.yaml` files that bundle the
system prompt, task prompt, task manifest, output contract, and context status
for each specialist agent. The first available adapter is `manual`, which also
writes `.manual.md` invocation files for human-operated LLM sessions. `openai`,
`claude-cli`, and `mcp` are registered as future adapter slots but do not perform
live execution yet.

`agents review` aggregates `.ai/outputs/*.result.yaml` files into
`.ai/reviews/agent-review.{yaml,md}` and returns a non-zero status when the
workspace is not ready for supervisor approval. `agents decide` appends explicit
supervisor decisions to `.ai/decisions/`.

Non-Docker providers currently generate deterministic scaffold artifacts rather
than deploying infrastructure directly. `ansible`, `terraform`, `ludus`, and
`hybrid` outputs include provider plans, inventory files, security profiles, and
provider-specific starter files so provider engineers can complete the runnable
implementation without reverse-engineering the scenario spec.
