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
Pipeline**.

After generation, evaluate the supervisor gate:

```bash
python -m labforge pipeline gate output/my-lab-pipeline
python -m labforge pipeline gate output/my-lab-pipeline --strict
```

## Pipeline Stages

| Stage | Output | Purpose |
| --- | --- | --- |
| Design workspace | `intake/`, `lab/`, `agents/` | Preserve the source prompt, write prompt analysis, infer the first LabForge spec, and prepare specialist-agent packages. |
| Design review | `review/` | Run validation, lint, industry realism pre-check, and agent readiness review. |
| Service scaffold | `lab/services/<service>/` | Create service contracts, hooks, seed/noise/test folders, and plugin contracts. |
| Service blueprints | `service-blueprints/` and per-service `blueprint.yaml` | Describe each service role, API surface, data stores, workflows, and safety boundaries. |
| Service plan | `service-plan/` | Split service implementation into agent-ready tasks. |
| Runtime materialization | per-service runtime files | Create safe starter service runtimes for early provider and QA testing. |
| Service agent packages | `service-agents/.ai/service-build/` | Package service-builder prompts and result stubs. |
| Service verification | `service-verification/` | Check runtime, blueprint, scaffold, tests, and hook readiness. |
| Service status | `service-status/` | Summarize whether each service is missing, scaffolded, blueprinted, runtime-ready, or tested. |
| Workflow report | `workflow/` | Report the next actionable build step. |

## Output Manifest

The pipeline always writes:

- `pipeline-summary.md`
- `pipeline-result.yaml`
- `pipeline-result.json`
- `pipeline-gate.md`
- `pipeline-gate.yaml`
- `pipeline-gate.json`

These files are the supervisor-facing manifest for the generated workspace.
They list every step, its status, produced artifacts, warnings, and next
commands.

The intake directory also includes `prompt-analysis.yaml` and
`prompt-analysis.md`. These files record detected industry evidence, provider
pressure, likely entrypoints, likely final objectives, named assets, requested
attack themes, security-control hints, realism risks, and supervisor questions.
They are evidence for review, not an approved final design.

## Supervisor Gate

The pipeline gate classifies a workspace into one of five decisions:

| Decision | Meaning |
| --- | --- |
| `draft` | The pipeline is incomplete or required artifacts are missing. |
| `blocked` | A structural failure prevents safe continuation. |
| `needs-agent-work` | The workspace is usable, but design, service, or realism warnings require specialist-agent work. |
| `ready-for-supervisor` | The workspace is ready for human supervisor review before live agent execution or release gate. |
| `release-candidate` | The workspace has the expected evidence to run the stricter QA release gate. |

By default, `pipeline gate` is a reporting command and exits successfully after
writing the gate files. Use `--strict` in CI or automation when the command
should fail unless the workspace is ready for supervisor or release-gate work.

## Status Semantics

- `complete`: all pipeline steps completed without warnings.
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
