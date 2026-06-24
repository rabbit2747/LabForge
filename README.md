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
- Docker Compose runtime scripts for validate, start, status, stop, and reset
- Docker Compose `QUICKSTART.md` and `endpoints.json` for startup commands,
  URLs, SSH commands, and port overrides
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
python -m labforge pipeline create --prompt "Create a realistic enterprise red-team lab for a brokerage firm where the learner starts from a public investor portal and reaches a controlled compliance export through internal service discovery and trust abuse." --out output/brokerage-pipeline --industry securities --provider auto --adapter manual --force
python -m labforge pipeline verified-mvp --prompt "Create a realistic enterprise red-team lab for a brokerage firm where the learner starts from a public investor portal and reaches a controlled compliance export through internal service discovery and trust abuse." --out output/brokerage-verified-mvp --industry securities --provider auto --adapter manual --force
python -m labforge pipeline gate output/brokerage-pipeline
python -m labforge design from-prompt --prompt "Create a realistic enterprise red-team lab for a brokerage firm where the learner starts from a public investor portal and reaches a controlled compliance export through internal service discovery and trust abuse." --out output/brokerage-design-workspace --industry securities --adapter manual --force
python -m labforge design review output/brokerage-design-workspace --out output/brokerage-design-review --force
python -m labforge design tasks output/brokerage-design-workspace
python -m labforge design package-tasks output/brokerage-design-workspace --adapter manual --prepare
python -m labforge design run-task output/brokerage-design-workspace --task fix-001 --adapter manual
python -m labforge design review-fix-results output/brokerage-design-workspace
python -m labforge design apply-fix-results output/brokerage-design-workspace --task fix-001
python -m labforge studio serve --workspace output/studio --host 127.0.0.1 --port 8765
python -m labforge intake template --out output/intake-scenario-02 --lab-id scenario-02-ad-domain-compromise --title "Scenario 02 - Active Directory Domain Compromise"
python -m labforge intake scaffold --from output/intake-scenario-02/scenario-intake.yaml --out output/intake-scenario-02-lab --force
python -m labforge validate examples/scenario-02-ad-domain-compromise
python -m labforge guard framework-hooks .
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
python -m labforge services blueprints examples/scenario-02-ad-domain-compromise --out output/scenario-02-service-blueprints
python -m labforge services status examples/scenario-02-ad-domain-compromise
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
python -m labforge qa playtest examples/scenario-02-ad-domain-compromise --out output/scenario-02-playtest --provider docker-compose --profile protected --materialize --force
python -m labforge qa mvp-matrix --out output/mvp-matrix --provider docker-compose --profile protected --force
python -m labforge build examples/scenario-02-ad-domain-compromise --out output/scenario-02 --provider docker-compose --profile unprotected --force
python -m labforge docs examples/scenario-02-ad-domain-compromise --out output/scenario-02-docs --profile protected
python -m labforge schema export --out schemas
```

Expected result:

```text
Created natural-language scenario intake package: <repo>\output\intake-brokerage-lab
Scaffolded LabForge lab from intake: <repo>\output\brokerage-lab-draft
# LabForge Pipeline Result
# LabForge Pipeline Gate
Created LabForge design workspace: <repo>\output\brokerage-design-workspace
# LabForge Design Review Report
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

For the natural-language to reviewable-workspace pipeline, see:

[`docs/pipeline-workflow.md`](docs/pipeline-workflow.md)

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
PowerShell and shell runtime scripts for validation, start, status, stop, and reset;
PowerShell scripts automatically detect whether Docker is available in the
current shell or in any WSL distro on Windows, then run through the first usable
runtime. The Docker Compose provider also emits a generated `QUICKSTART.md`
and `endpoints.json` so supervisors can see published URLs, SSH connection
commands, health URLs, internal DNS names, and `LABFORGE_PORT_*` override
variables without reading `docker-compose.yml` by hand. The provider also
consumes `service_artifacts` contracts to document service build contexts, reset
behavior, healthchecks, evidence logs, and safety boundaries. `services
blueprints` now generates service-builder blueprints that
describe each service's role, API surface, data stores, normal workflows,
healthcheck/reset contract, evidence logs, and safety boundaries. `services
materialize` can generate safe runnable Docker service runtimes from built-in
infrastructure templates such as `python-flask-web`, `business-portal`,
`internal-admin-console`, `identity-gateway`, `data-api`, `audit-log-service`,
`message-broker-stub`, `object-store`, `siem-log-viewer`,
`attacker-workstation-ssh`, and `controlled-drop`, or fall back to a generic
safe runtime when no template is selected. `services status` reports whether
each service is missing, scaffolded, blueprinted, materialized as a runtime, or
tested. Materialized service runtimes now include a business-shaped HTML
dashboard, route catalog, `/api/records`, `/api/clues`, `/logs/events`,
deterministic seed records, operational clues, and noise events. The generated
data is synthetic and scenario-derived, but it is shaped around the target
business domain when possible: banking labs get loan, payment, AML, and
fraud-like records; securities labs get trade, market-data, settlement, and
compliance records; healthcare and manufacturing labs get their own
workflow-shaped records. LabForge does not yet generate full
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

The `guard framework-hooks` command checks LabForge framework code, templates,
and schemas for named-scenario markers. It keeps examples such as Orion Echo as
scenario inputs or regression fixtures, not as hidden branches in framework
core.

## Post-MVP Development Priorities

The MVP proves that a natural-language scenario can become a verified runnable
package. The next work is ordered by the current product priority:

1. Expand vulnerability and attack-technique scaffolds. Supported scaffolds
   should move from generic starters toward realistic, lab-scoped service
   behavior with believable routes, data, operational noise, reset hooks, and
   evidence logs.
2. Improve LLM agent orchestration. The Orchestrator LLM and specialist agents
   should be separated into explicit scenario, MITRE, industry-realism,
   security-control, infrastructure, provider, implementation, and QA roles with
   reviewable contracts.
3. Strengthen lab quality verification. A generated lab must be tested for
   runtime behavior, learner reachability, solution-path plausibility, industry
   realism, anti-CTF wording, and reset reliability before learner delivery.
4. Deepen industry-specific realism review. Specialist reviewers must judge the
   actual infrastructure, services, UI, workflows, data, security controls, and
   deployment model for the declared industry. For example, a securities lab
   should account for trading channels, order management, market data,
   settlement, compliance, and security monitoring, while a banking lab should
   account for digital banking, accounts, loan operations, payments, fraud/FDS,
   AML, batch operations, and security monitoring instead of accepting a few
   finance keywords.
5. Extend non-Docker providers. AD, Windows Server, Proxmox, Terraform,
   Ansible, Ludus, and hybrid VM environments must become practical provider
   targets when Docker alone cannot represent the scenario.

The `intake from-prompt` command starts from a natural-language scenario idea.
It preserves the original prompt, infers a conservative `scenario-intake.yaml`,
analyzes prompt clues into `prompt-analysis.yaml` and `prompt-analysis.md`, and
writes an LLM transformation brief for the scenario, MITRE, infrastructure,
industry-realism, safety, provider, and service-builder agents. This is the
first handoff step, not a claim that the lab is fully implemented.

The `design from-prompt` command performs the first full design handoff in one
step. It creates the intake package, scaffolds a draft lab, copies the source
prompt into the lab context, scaffolds the agent workspace, and prepares dry-run
agent execution packages for the selected adapter.

The `pipeline create` command is the opinionated product path for starting from
natural language. It creates the design workspace, runs the first supervisor
review, packages design correction tasks for specialist agents, scaffolds
service artifacts, renders service blueprints, creates the service
implementation plan, materializes safe starter runtimes, packages
service-builder agent tasks, reviews whether service-builder results are ready
to apply, verifies service quality gates, executes supported plugin runtime
smoke checks, creates the runnable supervisor package, and writes
`pipeline-summary.md`, `pipeline-result.yaml`, and `pipeline-result.json`.
It also writes a supervisor gate bundle: `pipeline-gate.md`,
`pipeline-gate.yaml`, and `pipeline-gate.json`, plus
`supervisor-package/generated/` with provider output such as Docker Compose and
`supervisor-package/lifecycle/` with executed validation evidence plus dry-run
deploy/status/destroy command plans.

The `pipeline verified-mvp` command is the one-command CLI path for automation.
It runs the full natural-language pipeline, runs the strict release gate, and
writes `mvp/verified-mvp.md` plus `mvp/verified-mvp.json` in the selected
workspace. Use it when a CI job, script, or non-web workflow needs the same
result as Studio's **Create Verified MVP** button.

The `pipeline gate` command can be rerun at any time to classify the workspace
as `draft`, `blocked`, `needs-agent-work`, `ready-for-supervisor`, or
`release-candidate`. Use `--strict` when automation should fail unless the
workspace is ready for supervisor or release-gate work.

The `design review` command collects the first supervisor-facing design review.
It runs validation, lint, an industry realism pre-check, and an agent-output
readiness review, then writes a review bundle with `design-review-report.md`,
`lint-report.md`, `realism-report.md`, and `agent-review.md`.

The `design tasks` command converts design review findings into a concrete fix
queue. It maps realism, lint, security-control, service, and agent-readiness
findings to the specialist agent that should handle each correction.

The `design package-tasks` command turns each fix task into a standard LabForge
agent execution package. With `--prepare`, it also creates adapter-specific
invocation files, such as manual copy/paste prompts for human-operated LLM
sessions.

The `design run-task` command prepares or executes one packaged design fix task
through the selected adapter. Without `--execute`, it only creates the
adapter-specific invocation artifact. With a live adapter and `--execute`, it
expects the adapter to write a LabForge agent result YAML.

The `design review-fix-results` command reads the fix-agent result YAML files,
validates them against the agent result schema, updates task status, and writes
a supervisor-facing `fix-result-review.md` report.

The `design apply-fix-results` command applies approved fix-agent artifacts to
the draft `lab/` directory. It is a dry-run by default. Real writes require
`--execute`, and overwriting existing lab files additionally requires `--force`
so a supervisor has to make that decision explicitly.

When `pipeline create` materializes runtime scaffolds, it also writes baseline
MVP service-builder results from those generated files. These baseline results
make the first package reviewable and applicable without pretending that the lab
is final: live service-builder agents can still replace or deepen the generated
service code, UI, data, and vulnerability behavior before supervisor approval.

The `studio serve` command starts a local web console for scenario authors and
supervisors. Studio can create scenarios from natural-language text, load a
prompt from a local file into the form, list multiple scenario workspaces, show
which design step is complete, run design review, generate fix tasks, package
fix tasks, review fix-agent results, dry-run fix-result application, display
generated reports, show generated endpoint manifests with learner-visible URLs,
SSH commands, health URLs, internal DNS names, and port override variables, and
run safe provider lifecycle actions for the generated supervisor package:
validate, start, service healthcheck, status, and stop. Studio uses the
generated `LABFORGE_PORT_*` variables to avoid occupied default ports when it
starts a Docker Compose lab, then updates the endpoint panel with the effective
runtime URLs and SSH ports actually used for that run. Studio also surfaces the
pipeline supervisor gate decision, blocking items, and next commands, then can
run the strict release gate for the selected scenario and display the release
readiness checks beside the runtime controls. A supervisor can move from
natural-language intake to runnable package validation and final readiness
review in one web console. Use **Create Verified MVP** when you want Studio to
run the full natural-language pipeline and the strict release gate in one action.
That flow also writes `mvp/verified-mvp.md` and `mvp/verified-mvp.json` as a
handoff manifest with the gate status, learner entrypoints, reports, and next
commands.

The `agents` command creates a dry-run orchestration workspace. It does not call
an LLM yet. It defines the future Orchestrator LLM and specialist agent system
prompts, per-agent task prompts, task contracts, output contracts, and decision
logs first, then later adapters can connect OpenAI, Claude CLI, or MCP.

```powershell
python -m labforge intake from-prompt --prompt-file .\my-scenario-prompt.md --out output\my-scenario-intake --industry securities --provider auto --force
python -m labforge intake scaffold --from output\my-scenario-intake\scenario-intake.yaml --out output\my-scenario-draft --force
python -m labforge design from-prompt --prompt-file .\my-scenario-prompt.md --out output\my-scenario-design --industry securities --adapter manual --force
python -m labforge design review output\my-scenario-design --out output\my-scenario-design-review --force
python -m labforge design tasks output\my-scenario-design
python -m labforge design package-tasks output\my-scenario-design --adapter manual --prepare
python -m labforge design run-task output\my-scenario-design --task fix-001 --adapter manual
python -m labforge design review-fix-results output\my-scenario-design
python -m labforge design apply-fix-results output\my-scenario-design --task fix-001
python -m labforge studio serve --workspace output\studio --host 127.0.0.1 --port 8765
python -m labforge intake template --out output/new-intake --lab-id new-lab --title "New Lab"
python -m labforge intake scaffold --from output/new-intake/scenario-intake.yaml --out output/new-lab --force
python -m labforge validate output/new-lab
python -m labforge lint output/new-lab
python -m labforge guard framework-hooks .
python -m labforge controls apply output/new-lab --clear --select firewall=fw-basic-segmentation --select ids=ids-east-west --profile protected
python -m labforge workflow status output/new-lab --provider docker-compose --profile protected
python -m labforge services scaffold output/new-lab
python -m labforge services materialize output/new-lab --force
python -m labforge services verify output/new-lab
python -m labforge services vulnerability-plugins
python -m labforge services blueprints output/new-lab --out output/new-lab-service-blueprints
python -m labforge services status output/new-lab
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
texture. It now emits an overall score plus infrastructure, service,
workflow/UI, data/noise, security-control, and attack-path sub-scores. It also
flags CTF-like wording such as `flag`, `ctf`, `foothold shell`, or `exploit
here`, and writes concrete remediation text that `design tasks` can convert into
specialist-agent fix tasks. For example, a securities-firm scenario should
include public investor channels, customer authentication, trading/order flow,
market data, settlement, compliance, data stores, monitoring, and realistic
business noise. It is not the final realism decision. The
`industry-realism-reviewer` specialist agent reviews infrastructure, services,
UI, workflows, data, security controls, and operational noise before a
supervisor accepts the lab. See `docs/realism-profiles.md` and
`docs/industry-realism-reviewer.md`.

Non-Docker providers generate deterministic provider artifacts and lifecycle
plans rather than silently deploying infrastructure. `ansible`, `terraform`,
`ludus`, and `hybrid` outputs include provider plans, inventory files, security
profiles, and provider-specific starter files so provider engineers can complete
the runnable implementation without reverse-engineering the scenario spec.
`labforge provider validate --execute` checks that the generated scaffold is
complete, while deploy/status/destroy produce operator-facing command plans
until an approved external range environment is attached.

QA smoke checks can validate the current lab definition, service artifact
contracts, scenario-derived MVP runtime materialization, supported lab-scoped
vulnerability scaffolds, generated plugin runtime behavior, and provider build
in one pass:

```powershell
python -m labforge qa smoke examples/scenario-02-ad-domain-compromise --out output/qa-smoke --provider docker-compose --profile protected --materialize --force
python -m labforge provider validate output/qa-smoke/provider-output --provider docker-compose --execute
python -m labforge provider deploy output/qa-smoke/provider-output --provider docker-compose
python -m labforge provider status output/qa-smoke/provider-output --provider docker-compose
python -m labforge provider destroy output/qa-smoke/provider-output --provider docker-compose --volumes
python -m labforge provider validate output/non-docker-package --provider ansible --execute
python -m labforge provider deploy output/non-docker-package --provider terraform
```

Supported minimum-runnable vulnerability scaffolds include web-entry behaviors
(`ssti-preview`, `stored-xss-review`, `idor-object-access`,
`ssrf-internal-fetch`, `path-traversal-download`, `unsafe-file-upload`,
`diagnostic-command-injection`) and supply-chain workflow behaviors
(`build-pipeline-abuse`, `signed-update-publish`, `customer-update-callback`).
These are generic lab-scoped starters: scenario authors and service-builder
agents still adapt UI, data, noise, and stage logic for the specific target
organization.

Release gates are stricter than smoke checks. Warnings from lint or service
verification fail the gate, which is useful before a lab is handed to learners:

```powershell
python -m labforge qa release-gate examples/scenario-02-ad-domain-compromise --out output/release-gate --provider docker-compose --profile protected --agent-results output/scenario-02-agents/.ai/outputs --materialize --force
```

The same strict gate is available in Studio through **Run Release Gate** on a
scenario detail page. Studio writes `release-gate/release-gate-report.md` and
`release-gate/release-gate-report.yaml`, then shows each check result in the
Release Gate panel.

Release gates also run `vulnerability-coverage-strict`. This framework-level
gate fails if a runnable vulnerability plugin lacks a registered scaffold,
runtime smoke sequence, solver-runner sequence, learner guidance, or browser
expected-text contract. The gate writes
`release-gate/vulnerability-coverage/vulnerability-coverage.md` and `.json` so
supervisors can see exactly which attack-technique scaffolds are not ready for
learner delivery.

Release gates also include a learner-experience check. It reads generated
provider output such as `endpoints.json` and fails release when no learner
entrypoint, learner-visible URL or SSH command, endpoint health URL, attacker
workstation, or controlled-drop path is available.

`qa playtest` creates learner-path evidence from the generated lab. It builds
provider output, reads learner-visible URLs and SSH commands, runs supported
plugin runtime checks, writes a connected stage-chain manifest, verifies that
the scenario has a multi-stage chain, and writes:

- `learner-access.md`: supervisor-facing access sheet with URLs, SSH commands,
  attacker workstation access, final submission endpoint, and high-level
  learner path.
- `learner-access.json`: machine-readable access manifest with start/status/stop
  commands, learner browser targets, attacker SSH targets, health checks,
  terminal checks, and first learner action.
- `access-playtest/access-playtest.md`: browser/terminal access verification
  plan generated from `learner-access.json`. Re-run it with
  `python -m labforge qa access-playtest <playtest/learner-access.json> --out <out>`
  for dry-run planning, or add `--execute` after the provider is running to run
  supported `curl` and SSH batch checks.
- `solver-plan.md/json`: ordered, supervisor-facing solver-agent plan derived
  from learner access, stage-chain checks, plugin runtime evidence, and final
  submission endpoints. It is designed for automated playtest agents and avoids
  hard-coding named-scenario exploit scripts into the framework.
- `solver-run/solver-run.md`: dry-run or executed solver-agent report generated
  from `solver-plan.json`. Re-run it with
  `python -m labforge qa solver-run <playtest/solver-plan.json> --access-manifest <playtest/learner-access.json> --out <out>`,
  and add `--execute` after provider startup to probe supported browser and SSH
  access steps.
- `e2e-solver.md/yaml/json`: launch-oriented supervisor report generated by
  `python -m labforge qa e2e-solver <provider-output> --solver-plan <playtest/solver-plan.json> --access-manifest <playtest/learner-access.json> --out <out>`.
  In dry-run mode it plans provider lifecycle, access checks, and solver probes.
  Add `--execute` to validate/start/status the provider and run supported
  HTTP/SSH probes, and `--cleanup` to stop the provider afterward.
- `host-preflight.md/json`: E2E solver host readiness evidence, including OS,
  WSL availability, Docker reachability, and recommended execution path before
  provider lifecycle commands are executed.
- `playtest-report.md`: evidence that the generated lab has a reachable start,
  runnable lab-scoped vulnerability behavior, ordered stages, and a completion
  path.
- `stage-chain/stage-chain.md`: machine-checked stage graph showing each stage's
  required inputs, produced evidence, touched services, unlock target, and
  learner clue.
- `playtest-walkthrough.md`: supervisor-facing copy/paste walkthrough for
  starting provider output, opening access points, checking generated behavior,
  and stopping the lab.
- `playtest-report.yaml/json`: machine-readable playtest status for Studio,
  verified MVP manifests, and later browser/terminal automation.

The MVP matrix checks the natural-language product path across multiple built-in
industry profiles. It creates pipeline workspaces for supply-chain, securities,
banking, healthcare, and manufacturing prompts, then runs each workspace through
the pipeline gate and strict release gate:

```powershell
python -m labforge qa mvp-matrix --out output/mvp-matrix --provider docker-compose --profile protected --force
```

The current example scenario can materialize runnable MVP services. A release
gate still requires real vulnerability behavior and reviewed service-builder
outputs before learner delivery.

Provider lifecycle commands are dry-run by default. Add `--execute` only when
you intentionally want LabForge to invoke the provider command.
