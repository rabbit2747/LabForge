# LabForge Workflow Orchestration

LabForge workflow commands report where a lab is in the build lifecycle and
which command a supervisor should run next. They do not deploy infrastructure,
modify service source files, or call an LLM.

## Commands

```powershell
python -m labforge workflow status <lab-root> --provider docker-compose --profile protected
python -m labforge workflow plan <lab-root> --provider docker-compose --profile protected
python -m labforge workflow status <lab-root> --results <service-agent-output-dir>
python -m labforge workflow status <lab-root> --format json --out output/workflow-report.json
```

`status` and `plan` currently render the same report. The distinction is
intentional: future versions can make `plan` more prescriptive while keeping
`status` focused on evidence.

## Lifecycle

The workflow report tracks these phases:

1. Validate Lab Specification
2. Render Architecture And Execution Plan
3. Validate Service Contracts
4. Materialize Or Implement Service Runtimes
5. Create Service Implementation Plan
6. Create Service Builder Agent Packages
7. Review Service Builder Results
8. Apply Service Builder Results
9. Verify Service Implementations
10. Render Provider Output
11. Run Release Gate
12. Create Supervisor Package

Each phase has a status:

- `done`: The required evidence is present.
- `ready`: The phase can run now.
- `pending`: The phase needs an earlier artifact, such as service-builder
  result files.
- `warning`: The phase found reviewable issues, but the lab may still be
  inspectable.
- `blocked`: The phase found an issue that prevents safe continuation.

## Service Builder Results

Pass `--results` after creating service-builder packages:

```powershell
python -m labforge services agent-packages <lab-root> --out output/my-lab-service-agents --adapter manual
python -m labforge workflow status <lab-root> --results output/my-lab-service-agents/.ai/outputs
python -m labforge agents scaffold <lab-root> --out output/my-lab-agents
python -m labforge agents run output/my-lab-agents --dry-run --adapter manual --agent industry-realism-reviewer --context-root <lab-root>
python -m labforge workflow status <lab-root> --agent-results output/my-lab-agents/.ai/outputs
```

The `industry-realism-review` step is a required workflow gate for release
readiness. It is separate from static `realism check`: the reviewer must judge
infrastructure, services, UI, workflows, data/noise, security controls, and
deployment realism before a supervisor accepts the lab.

Release gates require the same evidence:

```powershell
python -m labforge qa release-gate <lab-root> --out output/my-lab-release-gate --provider docker-compose --profile protected --agent-results output/my-lab-agents/.ai/outputs --materialize --force
```

The workflow then includes batch review and batch apply readiness. If result
files are still `needs-review`, the apply phase is blocked and the report points
back to:

```powershell
python -m labforge services review-results <lab-root> --results <service-agent-output-dir> --force
```

When all results are ready, the next command becomes:

```powershell
python -m labforge services apply-results <lab-root> --results <service-agent-output-dir> --execute --force
```

## Output Contract

Workflow reports are available as Markdown or JSON. The JSON output follows
`schemas/workflow-report.schema.json`, so an external UI or orchestration layer
can consume the report without scraping CLI text.
