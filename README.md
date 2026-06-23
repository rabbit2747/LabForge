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

python -m labforge intake from-prompt --prompt "Create a realistic enterprise red-team lab for a brokerage firm where the learner starts from a public investor portal and reaches a controlled compliance export through internal service discovery and trust abuse." --out output/intake-brokerage-lab --industry securities --provider auto --force
python -m labforge intake scaffold --from output/intake-brokerage-lab/scenario-intake.yaml --out output/brokerage-lab-draft --force
python -m labforge design from-prompt --prompt "Create a realistic enterprise red-team lab for a brokerage firm where the learner starts from a public investor portal and reaches a controlled compliance export through internal service discovery and trust abuse." --out output/brokerage-design-workspace --industry securities --adapter manual --force
python -m labforge intake template --out output/intake-scenario-02 --lab-id scenario-02-ad-domain-compromise --title "Scenario 02 - Active Directory Domain Compromise"
python -m labforge intake scaffold --from output/intake-scenario-02/scenario-intake.yaml --out output/intake-scenario-02-lab --force
python -m labforge validate examples/scenario-02-ad-domain-compromise
python -m labforge doctor --lab examples/scenario-02-ad-domain-compromise
python -m labforge plan examples/scenario-02-ad-domain-compromise --provider docker-compose --profile protected
python -m labforge realism profiles
python -m labforge realism check examples/scenario-02-ad-domain-compromise --industry enterprise --out output/scenario-02-realism.md
python -m labforge controls list examples/scenario-02-ad-domain-compromise
python -m labforge package examples/scenario-02-ad-domain-compromise --out output/scenario-02-package --provider docker-compose --profile protected --all-profiles --materialize --force
python -m labforge workflow status examples/scenario-02-ad-domain-compromise --provider docker-compose --profile protected
python -m labforge agents scaffold examples/scenario-02-ad-domain-compromise --out output/scenario-02-agents
python -m labforge agents validate output/scenario-02-agents
python -m labforge services scaffold examples/scenario-02-ad-domain-compromise
python -m labforge services check examples/scenario-02-ad-domain-compromise
python -m labforge services templates
python -m labforge services vulnerability-plugins
python -m labforge services verify examples/scenario-02-ad-domain-compromise
python -m labforge services plan examples/scenario-02-ad-domain-compromise --out output/scenario-02-service-plan
python -m labforge services agent-packages examples/scenario-02-ad-domain-compromise --out output/scenario-02-service-agents --adapter manual
python -m labforge services run-agents output/scenario-02-service-agents --adapter codex --dry-run --service hr-portal
python -m labforge services review-results examples/scenario-02-ad-domain-compromise --results output/scenario-02-service-agents/.ai/outputs --force
python -m labforge services apply-results examples/scenario-02-ad-domain-compromise --results output/scenario-02-service-agents/.ai/outputs
python -m labforge workflow plan examples/scenario-02-ad-domain-compromise --results output/scenario-02-service-agents/.ai/outputs --provider docker-compose --profile protected
python -m labforge services review-result examples/scenario-02-ad-domain-compromise --result output/scenario-02-service-agents/.ai/outputs/service-build-<service>.result.yaml --force
python -m labforge services apply-result examples/scenario-02-ad-domain-compromise --result output/scenario-02-service-agents/.ai/outputs/service-build-<service>.result.yaml --dry-run
python -m labforge services healthcheck examples/scenario-02-ad-domain-compromise
python -m labforge services reset examples/scenario-02-ad-domain-compromise --service hr-portal
python -m labforge qa release-gate examples/scenario-02-ad-domain-compromise --out output/scenario-02-release-gate --provider docker-compose --profile protected --agent-results output/scenario-02-agents/.ai/outputs --materialize --force
python -m labforge build examples/scenario-02-ad-domain-compromise --out output/scenario-02 --provider docker-compose --profile unprotected --force
python -m labforge docs examples/scenario-02-ad-domain-compromise --out output/scenario-02-docs --profile protected
python -m labforge schema export --out schemas
```

Expected result:

```text
Created natural-language scenario intake package: <repo>\output\intake-brokerage-lab
Scaffolded LabForge lab from intake: <repo>\output\brokerage-lab-draft
Created LabForge design workspace: <repo>\output\brokerage-design-workspace
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

For the rule that service templates must generate reusable infrastructure parts
rather than reusable puzzles, see:

[`docs/service-template-principles.md`](docs/service-template-principles.md)

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
boundaries. `services materialize` can generate safe runnable Docker service
runtimes from built-in infrastructure templates such as `python-flask-web`,
`attacker-workstation-ssh`, and `controlled-drop`, or fall back to a generic
safe runtime when no template is selected. LabForge does not yet generate full
scenario-specific vulnerable service source code, production VM infrastructure,
complete Ansible roles, complete Terraform modules, or production-grade
enforcement logic for WAF, IDS, SIEM, or EDR controls.

The `doctor` command now detects whether the current machine should run lab
work directly from the host shell, from WSL, or through a VM/hybrid provider.
This is important because training PCs may be Windows, Linux, macOS, WSL-based,
or backed by a separate virtualization host.

The `plan` command turns that diagnosis into concrete execution steps. For
example, on a Windows PC where Docker is only reachable inside WSL, the plan
selects the detected WSL distro with Docker instead of assuming a fixed distro
name.

The `intake from-prompt` command starts from a natural-language scenario idea.
It preserves the original prompt, infers a conservative `scenario-intake.yaml`,
and writes an LLM transformation brief for the scenario, MITRE, infrastructure,
industry-realism, safety, provider, and service-builder agents. This is the
first handoff step, not a claim that the lab is fully implemented.

The `design from-prompt` command performs the first full design handoff in one
step. It creates the intake package, scaffolds a draft lab, copies the source
prompt into the lab context, scaffolds the agent workspace, and prepares dry-run
agent execution packages for the selected adapter.

The `agents` command creates a dry-run orchestration workspace. It does not call
an LLM yet. It defines the future Orchestrator LLM and specialist agent system
prompts, per-agent task prompts, task contracts, output contracts, and decision
logs first, then later adapters can connect OpenAI, Claude CLI, or MCP.

```powershell
python -m labforge intake from-prompt --prompt-file .\my-scenario-prompt.md --out output\my-scenario-intake --industry securities --provider auto --force
python -m labforge intake scaffold --from output\my-scenario-intake\scenario-intake.yaml --out output\my-scenario-draft --force
python -m labforge design from-prompt --prompt-file .\my-scenario-prompt.md --out output\my-scenario-design --industry securities --adapter manual --force
python -m labforge intake template --out output/new-intake --lab-id new-lab --title "New Lab"
python -m labforge intake scaffold --from output/new-intake/scenario-intake.yaml --out output/new-lab --force
python -m labforge validate output/new-lab
python -m labforge lint output/new-lab
python -m labforge controls apply output/new-lab --clear --select firewall=fw-basic-segmentation --select ids=ids-east-west --profile protected
python -m labforge workflow status output/new-lab --provider docker-compose --profile protected
python -m labforge services scaffold output/new-lab
python -m labforge services materialize output/new-lab --force
python -m labforge services verify output/new-lab
python -m labforge services plan output/new-lab --out output/new-lab-service-plan
python -m labforge services agent-packages output/new-lab --out output/new-lab-service-agents --adapter manual
python -m labforge services run-agents output/new-lab-service-agents --adapter claude-code --dry-run
python -m labforge services review-results output/new-lab --results output/new-lab-service-agents/.ai/outputs --force
python -m labforge services apply-results output/new-lab --results output/new-lab-service-agents/.ai/outputs
python -m labforge workflow plan output/new-lab --results output/new-lab-service-agents/.ai/outputs --provider docker-compose --profile protected
python -m labforge services review-result output/new-lab --result output/new-lab-service-agents/.ai/outputs/service-build-entry-service.result.yaml --force
python -m labforge services apply-result output/new-lab --result output/new-lab-service-agents/.ai/outputs/service-build-entry-service.result.yaml --dry-run
python -m labforge agents scaffold examples/scenario-02-ad-domain-compromise --out output/scenario-02-agents
python -m labforge agents validate output/scenario-02-agents
python -m labforge agents adapters
python -m labforge agents smoke-adapters examples/scenario-02-ad-domain-compromise --out output/scenario-02-adapter-smoke --force --report output/scenario-02-adapter-smoke.md
python -m labforge agents plan-run output/scenario-02-agents --context-root examples/scenario-02-ad-domain-compromise
python -m labforge agents run output/scenario-02-agents --dry-run --adapter manual --context-root examples/scenario-02-ad-domain-compromise
python -m labforge agents run output/scenario-02-agents --dry-run --adapter openai --agent scenario-designer --context-root examples/scenario-02-ad-domain-compromise
python -m labforge agents run output/scenario-02-agents --dry-run --adapter codex --agent scenario-designer --context-root examples/scenario-02-ad-domain-compromise
python -m labforge agents run output/scenario-02-agents --dry-run --adapter claude-code --agent mitre-mapper --context-root examples/scenario-02-ad-domain-compromise
python -m labforge agents run output/scenario-02-agents --dry-run --adapter manual --agent industry-realism-reviewer --context-root examples/scenario-02-ad-domain-compromise
python -m labforge agents result-stub output/scenario-02-agents --task-id 02-mitre-mapper --status needs-review --summary "Draft mapping is ready for supervisor review."
python -m labforge agents review output/scenario-02-agents --write
python -m labforge workflow status examples/scenario-02-ad-domain-compromise --agent-results output/scenario-02-agents/.ai/outputs --provider docker-compose --profile protected
python -m labforge agents decide output/scenario-02-agents --decision accepted --task-id 02-mitre-mapper --reason "Reviewed mapping output."
```

`agents plan-run` reports execution readiness without calling an LLM.
`agents run --dry-run` writes `.ai/run/*.package.yaml` files that bundle the
system prompt, task prompt, task manifest, output contract, and context status
for each specialist agent. The `manual` adapter writes `.manual.md` invocation
files for human-operated LLM sessions. The `openai` and `claude-cli` adapters
support live execution only when `--execute` is explicitly provided. The `codex`
and `claude-code` adapters support Codex CLI and Claude Code CLI workflows. The
`mcp` adapter writes a JSON handoff file for an external MCP-capable
orchestrator. See `docs/live-agent-adapters.md`.

`agents review` aggregates `.ai/outputs/*.result.yaml` files into
`.ai/reviews/agent-review.{yaml,md}` and returns a non-zero status when the
workspace is not ready for supervisor approval. `agents result-stub` helps
manual workflows write schema-valid result files. `agents decide` appends
explicit supervisor decisions to `.ai/decisions/`.

`services review-result` checks a completed service-builder result before any
file is modified. `services review-results` and `services apply-results` provide
the same supervisor workflow across a directory of service-builder outputs.
Batch apply is dry-run by default; pass `--execute` only after review. The apply
commands accept schema-valid result YAML with `service_changes`, verify that
every target path stays inside the declared service directory, block overwrites
unless `--force` is set, and can run without changing files first.

`workflow status` and `workflow plan` summarize the current build state and show
the next LabForge commands a supervisor should run. They do not modify files.
Pass `--results <service-agent-output-dir>` after service-builder packages exist
so the workflow can include review/apply readiness in the report. Pass
`--agent-results <agent-output-dir>` after specialist agent results exist so the
workflow can enforce the independent `industry-realism-reviewer` gate.
See `docs/workflow-orchestration.md` for the workflow phases and report
contract.

`realism check` is a fast static pre-check for industry-specific enterprise
texture. For example, a securities-firm scenario should include public investor
channels, customer authentication, trading/order flow, market data, settlement,
compliance, data stores, monitoring, and realistic business noise. It is not the
final realism decision. The `industry-realism-reviewer` specialist agent reviews
infrastructure, services, UI, workflows, data, security controls, and operational
noise before a supervisor accepts the lab. See `docs/realism-profiles.md` and
`docs/industry-realism-reviewer.md`.

Non-Docker providers currently generate deterministic scaffold artifacts rather
than deploying infrastructure directly. `ansible`, `terraform`, `ludus`, and
`hybrid` outputs include provider plans, inventory files, security profiles, and
provider-specific starter files so provider engineers can complete the runnable
implementation without reverse-engineering the scenario spec.

QA smoke checks can validate the current lab definition, service artifact
contracts, optional service runtime materialization, and provider build in one
pass:

```powershell
python -m labforge qa smoke examples/scenario-02-ad-domain-compromise --out output/qa-smoke --provider docker-compose --profile protected --materialize --force
python -m labforge provider deploy output/qa-smoke/provider-output --provider docker-compose
python -m labforge provider status output/qa-smoke/provider-output --provider docker-compose
python -m labforge provider destroy output/qa-smoke/provider-output --provider docker-compose --volumes
```

Release gates are stricter than smoke checks. Warnings from lint or service
verification fail the gate, which is useful before a lab is handed to learners:

```powershell
python -m labforge qa release-gate examples/scenario-02-ad-domain-compromise --out output/release-gate --provider docker-compose --profile protected --agent-results output/scenario-02-agents/.ai/outputs --materialize --force
```

The current example scenario is still a scaffold, so the release gate is
expected to fail until service placeholders, tests, seed data, and reset logic
are implemented.

Provider lifecycle commands are dry-run by default. Add `--execute` only when
you intentionally want LabForge to invoke the provider command.
