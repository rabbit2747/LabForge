# LabForge Pipeline Workflow

`labforge pipeline create` is the opinionated end-to-end entrypoint for turning
a natural-language lab idea into a reviewable LabForge workspace.

It does not replace supervisor review or specialist-agent implementation. It
creates the first coherent bundle that a supervisor can inspect before assigning
deeper scenario, provider, security-control, and service-builder work.

## Command

```bash
python -m labforge pipeline create \
  --prompt "Create a realistic securities red-team lab..." \
  --out output/my-lab-pipeline \
  --industry securities \
  --provider auto \
  --adapter manual \
  --force
```

The same workflow is available in LabForge Studio through **Create Full
Pipeline**. Studio also provides **Create Verified MVP**, which runs the full
pipeline and immediately runs the strict release gate against the generated lab
workspace.

After generation, evaluate the supervisor gate:

```bash
python -m labforge pipeline gate output/my-lab-pipeline
python -m labforge pipeline gate output/my-lab-pipeline --strict
```

## Pipeline Stages

| Stage | Output | Purpose |
| --- | --- | --- |
| Design workspace | `intake/`, `lab/`, `agents/` | Preserve the source prompt, write prompt analysis, infer the first LabForge spec, and prepare specialist-agent packages. |
| Baseline specialist evidence | `agents/.ai/outputs/` and `agents/.ai/reviews/` | Write deterministic baseline agent result files so the draft can pass structural review before live specialist agents refine it. |
| Design review | `review/` | Run validation, lint, industry realism pre-check, and agent readiness review. |
| Design fix tasks | `review/design-fix-tasks.*` | Convert review and realism findings into concrete specialist-agent correction tasks. |
| Design fix packages | `review/fix-agent-packages/` and `review/fix-agent-results/` | Prepare correction task prompts and schema-valid result stubs so the supervisor can immediately dispatch agent work. |
| Service scaffold | `lab/services/<service>/` | Create service contracts, hooks, seed/noise/test folders, and plugin contracts. |
| Service blueprints | `service-blueprints/` and per-service `blueprint.yaml` | Describe each service role, API surface, data stores, workflows, and safety boundaries. |
| Service plan | `service-plan/` | Split service implementation into agent-ready tasks. |
| Runtime materialization | per-service runtime files | Create safe starter service runtimes for early provider and QA testing. |
| Service agent packages | `service-agents/.ai/service-build/` | Package service-builder prompts and result stubs. |
| Service result review | `service-result-review/` | Review service-builder result stubs or outputs and report whether they are ready to apply. |
| Service verification | `service-verification/` | Check runtime, blueprint, scaffold, tests, and hook readiness. |
| Plugin runtime smoke | `plugin-runtime-smoke/` | Import generated MVP services and execute supported lab-scoped plugin routes with Flask test clients. |
| Service status | `service-status/` | Summarize whether each service is missing, scaffolded, blueprinted, runtime-ready, or tested. |
| Supervisor package | `supervisor-package/` | Render the runnable provider package, protected/unprotected profile outputs, lifecycle command plans, documentation, execution plan, and QA evidence. |
| Workflow report | `workflow/` | Report the next actionable build step. |

## Output Manifest

The pipeline always writes:

- `pipeline-summary.md`
- `pipeline-result.yaml`
- `pipeline-result.json`
- `pipeline-gate.md`
- `pipeline-gate.yaml`
- `pipeline-gate.json`
- `supervisor-package/package-report.md`
- `supervisor-package/generated/`
- `supervisor-package/generated/QUICKSTART.md`
- `supervisor-package/generated/endpoints.json`

These files are the supervisor-facing manifest for the generated workspace.
They list every step, its status, produced artifacts, warnings, and next
commands.

The intake directory also includes `prompt-analysis.yaml` and
`prompt-analysis.md`. These files record detected industry evidence, provider
pressure, likely entrypoints, likely final objectives, named assets, requested
attack themes, security-control hints, realism risks, and supervisor questions.
They are evidence for review, not an approved final design.

Generated `environment.yaml` and `topology.yaml` use industry-aware zones and
networks where LabForge has a profile. For example, supply-chain scenarios use
public edge, corporate, development, build, release, customer, and security
monitoring zones instead of a single generic internal network.

`plugin-runtime-smoke/` proves that supported generated plugin scaffolds are not
only present on disk but executable. The smoke runner imports each generated
Flask service, isolates its state in a temporary directory, and exercises routes
for the supported plugin contracts such as SSTI preview, stored review content,
IDOR object access, SSRF policy checks, diagnostic command execution, build
pipeline creation, signed update publishing, and customer update callbacks.

`supervisor-package/` is the first runnable handoff bundle. For Docker Compose
labs it includes `generated/docker-compose.yml`, `generated/QUICKSTART.md`,
`generated/endpoints.json`, rendered service directories, architecture
documentation, diagrams, protected and unprotected profile outputs, host
diagnostics, execution plans, QA smoke reports, service verification reports,
and `lifecycle/*-plan.md` files. The package executes provider validation
during creation when the provider supports it, then records dry-run deploy,
status, and destroy commands for the supervisor.
Generated Docker Compose packages support `LABFORGE_PORT_*` environment
variable overrides for published ports, and their service healthcheck/reset
scripts execute inside the running containers so Windows-to-WSL delegated
starts can still validate the live lab.
The endpoint manifest records learner-visible URLs, SSH connection commands,
health URLs, override variable names, and internal DNS names in a
machine-readable form for Studio or external orchestration tools.
Studio can run safe lifecycle actions against this generated package:
validate, start, service healthcheck, status, and stop. These actions are fixed
buttons, not arbitrary shell input. Their last results are written under
`supervisor-package/lifecycle/studio-*-last.md`, and Studio uses generated
`LABFORGE_PORT_*` override variables when default published ports are already
occupied. The active runtime state is written to
`supervisor-package/lifecycle/studio-runtime.json`, so the endpoint panel can
show the effective URLs and SSH ports for the current run instead of only the
default manifest values.

Studio can also run the strict release gate from the scenario detail page. The
web action uses the selected lab workspace, materializes safe runtime scaffolds
when needed, requires the generated industry-realism reviewer evidence, writes
`release-gate/release-gate-report.md` and
`release-gate/release-gate-report.yaml`, and displays the individual readiness
checks in the Release Gate panel. This keeps the human supervisor workflow in
one place: create the full pipeline, inspect the Supervisor Gate decision,
blocking items, and next commands, inspect generated endpoints, start and
healthcheck the lab, then run the final release readiness gate before learner
delivery.

When runtime materialization is enabled, the pipeline writes baseline MVP
service-builder result files from the generated service code and reviews them in
`service-result-review/`. These results prove the generated scaffold is
reviewable and applicable; specialist agents should still refine realism,
scenario-specific vulnerable behavior, UI, data, and noise before release.

The pipeline also writes baseline specialist-agent evidence for the design
agents. This evidence is intentionally deterministic: it proves the generated
draft is structurally reviewable, while preserving the option for live Codex,
Claude Code, OpenAI, MCP, or human reviewers to replace the baseline files with
deeper analysis before publication.

## Supervisor Gate

The pipeline gate classifies a workspace into one of five decisions:

| Decision | Meaning |
| --- | --- |
| `draft` | The pipeline is incomplete or required artifacts are missing. |
| `blocked` | A structural failure prevents safe continuation. |
| `needs-agent-work` | The workspace is usable, but design, service, or realism warnings require specialist-agent work. |
| `ready-for-supervisor` | The workspace is ready for human supervisor review before live agent execution or release gate. |
| `release-candidate` | The workspace has the expected generated evidence, supervisor package, and validation plans to run the stricter QA release gate. |

By default, `pipeline gate` is a reporting command and exits successfully after
writing the gate files. Use `--strict` in CI or automation when the command
should fail unless the workspace is ready for supervisor or release-gate work.

## MVP Matrix

`qa mvp-matrix` is the regression command for the natural-language product
path. It creates fresh pipeline workspaces from built-in scenario prompts for
supply-chain, securities, healthcare, and manufacturing profiles, then runs the
pipeline gate and strict release gate for each case.

```bash
python -m labforge qa mvp-matrix \
  --out output/mvp-matrix \
  --provider docker-compose \
  --profile protected \
  --force
```

The command passes only when every case reaches `release-candidate` and the
release gate reports `release_ready: true`. It is intentionally broader than a
single scenario test so changes to intake profiles, plugin compatibility,
realism checks, service materialization, or provider output cannot quietly
collapse different industries back into one generic lab shape.

## Status Semantics

- `complete`: all pipeline steps completed without blocking warnings.
- `warning`: the pipeline produced a usable workspace, but supervisor or agent
  review is still needed.
- `failed`: a required stage failed and the workspace should not be used as a
  build source until corrected.

`warning` is expected for most first-pass natural-language scenarios because
LabForge intentionally keeps the original prompt as untrusted draft intent until
reviewed.

## Boundaries

The pipeline may generate safe starter services, but it does not claim that
scenario-specific vulnerable behavior is complete. Vulnerability behavior,
industry-grade UI, realistic data, and final learner chain quality still require
specialist-agent implementation and supervisor acceptance.
