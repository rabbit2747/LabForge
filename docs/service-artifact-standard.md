# LabForge Service Artifact Standard

Service artifacts define how a logical service becomes a runnable lab component.
They are the contract between scenario authors, service builders, provider
engineers, QA agents, and supervisors.

## Why This Exists

`topology.yaml` says that a service exists.

`artifacts.yaml` must explain how that service is implemented, seeded, reset,
observed, and constrained.

Without this contract, a generated lab may have a realistic architecture diagram
but no reliable way to build, verify, reset, or review each service.

## Required `artifacts.yaml` Section

```yaml
service_artifacts:
  - service: hr-portal
    source_path: services/hr-portal
    runtime: Python web application
    purpose: Externally reachable business application used for initial access.
    attack_surface:
      - Business workflow endpoint
      - Deliberately vulnerable preview endpoint
    seed_inputs:
      - hr-portal-cases
    noise_inputs:
      - stale-support-notes
    healthcheck: GET /healthz must return 200 and confirm seed data is loaded.
    reset: Restore seeded cases and remove learner-created temporary files.
    evidence_logs:
      - application.log
      - security-audit.log
    safety_boundaries:
      - Vulnerable behavior must be lab-scoped and documented.
      - Outbound callbacks may reach only declared lab services.
```

## Field Meaning

| Field | Meaning |
|---|---|
| `service` | Must match a service name in `topology.yaml`. |
| `source_path` | Relative path to the service implementation directory. |
| `runtime` | Runtime family such as Python, Node.js, nginx, Windows VM, LDAP, or provider-managed service. |
| `purpose` | Why this service exists in the scenario. |
| `attack_surface` | Intended learner-facing or internal behaviors that matter to the scenario. |
| `seed_inputs` | Seed artifact IDs consumed by this service. |
| `noise_inputs` | Noise artifact IDs consumed by this service. |
| `healthcheck` | Human-readable contract for readiness. Provider code may translate this into Compose, Ansible, or VM checks. |
| `reset` | How learner state is cleared and baseline data is restored. |
| `evidence_logs` | Logs or event streams used by QA, instructors, graders, or detection controls. |
| `safety_boundaries` | Constraints that keep the behavior lab-scoped and safe. |

## Recommended Service Directory

```text
services/<service-name>/
|-- README.md
|-- blueprint.yaml
|-- Dockerfile or provider-specific build files
|-- src/ or app/
|-- seed/
|-- noise/
|-- tests/
|-- healthcheck.sh
|-- reset.sh
`-- labforge-service.yaml
```

The exact files can differ by provider. For example, a Windows VM service may
use PowerShell DSC or Ansible tasks instead of a Dockerfile. The contract must
still explain healthcheck, reset, seed/noise data, evidence logs, and safety
boundaries.

## CLI Workflow

Create service builder blueprints:

```powershell
python -m labforge services blueprints <lab-root>
python -m labforge services blueprints <lab-root> --out output/service-blueprints
```

Blueprints describe each service's role, template, API surface, data stores,
normal workflows, seed/noise expectations, evidence logs, healthcheck/reset
contract, and safety boundaries. `services scaffold` also writes
`services/<service>/blueprint.yaml` for each service.

Create placeholder service directories and hooks:

```powershell
python -m labforge services scaffold <lab-root>
```

Create runnable service runtimes from service contracts. If a built-in service
template is selected, LabForge uses that infrastructure template. Otherwise it
falls back to a safe generic runtime:

```powershell
python -m labforge services materialize <lab-root>
python -m labforge services materialize <lab-root> --force
```

`services materialize` writes runtime files such as `Dockerfile`, `app.py`,
`healthcheck.sh`, `reset.sh`, `blueprint.yaml`, `seed/metadata.json`,
`seed/blueprint.json`, realistic starter records/noise where the selected
template supports them, and smoke tests for each declared service artifact.
Built-in templates provide reusable infrastructure parts only.
Scenario-specific vulnerable behavior, clues, final objects, and solution paths
still belong in scenario-specific service code or instructor-only artifacts.

Report service implementation status:

```powershell
python -m labforge services status <lab-root>
python -m labforge services status <lab-root> --format json
```

Status levels:

- `missing`: service directory is absent.
- `scaffolded`: contract files exist.
- `blueprinted`: `blueprint.yaml` exists.
- `runtime`: runtime files exist.
- `tested`: runtime files and at least one substantive test exist.

When `vulnerability_plugins` are declared, materialization also writes reviewable
contract files under `services/<service>/plugins/*.contract.yaml`. These files
describe the scenario-specific behavior that service builders must implement;
they do not generate final answers or fixed exploit chains.

Each declared plugin must include its required scenario configuration keys. For
example, `ssti-preview` requires `workflow`, `template_engine`,
`execution_boundary`, and `post_exploitation_objective`. LabForge copies those
requirements into the plugin contract file and `services verify` warns when a
scenario omits them.

Review available plugin contracts:

```powershell
python -m labforge services vulnerability-plugins
```

The command also shows scaffold coverage:

- `minimum-runnable`: `services materialize` adds starter runtime routes, seed
  metadata, and smoke tests.
- `contract-only`: LabForge writes the reviewable contract, but a service
  builder must implement the runtime behavior for that scenario.

Validate that every declared service artifact has a matching implementation
directory and required files:

```powershell
python -m labforge services check <lab-root>
```

Run healthcheck hooks:

```powershell
python -m labforge services healthcheck <lab-root>
python -m labforge services healthcheck <lab-root> --service hr-portal
```

Run reset hooks:

```powershell
python -m labforge services reset <lab-root>
python -m labforge services reset <lab-root> --service hr-portal
```

The scaffold and materialize commands are intentionally conservative. They do
not generate real vulnerable service code. They create contract files and safe
runtime placeholders that service builders and agents replace with actual
implementation.

Docker Compose provider outputs also include:

- `scripts/services-healthcheck.sh`
- `scripts/services-healthcheck.ps1`
- `scripts/services-reset.sh`
- `scripts/services-reset.ps1`

## Provider Expectations

Docker Compose providers should:

- map `source_path` to build context when applicable
- surface healthcheck and reset expectations in generated docs/scripts
- keep logs in declared evidence paths or volumes where possible

VM or hybrid providers should:

- translate service artifacts into VM roles, provisioners, or playbooks
- implement reset through snapshot revert or deterministic provisioning
- preserve evidence logs for supervisor review

Agent workflows should:

- create or review service code against this contract
- reject services that lack reset or safety boundaries
- produce QA results tied to each `service_artifacts` entry

## Applying Service Builder Results

Service builders may return implementation changes through a schema-valid
service result file. LabForge can apply those changes to exactly one declared
service directory.

```yaml
task_id: service-build-entry-service
status: complete
service: entry-service
summary: Implemented the entry service runtime, healthcheck, reset hook, and tests.
implemented_routes:
  - GET /healthz
  - GET /metadata
data_model:
  - metadata.json
normal_workflows:
  - operator opens metadata and submits a business request
vulnerable_paths: []
detection_evidence:
  - application.log records normal and abnormal requests
healthcheck_behavior: GET /healthz returns 200 when seed data is present.
reset_behavior: Remove transient state and restore deterministic seed data.
service_changes:
  - target_path: app.py
    content: |
      print("implemented service")
  - target_path: healthcheck.sh
    executable: true
    content: |
      #!/usr/bin/env sh
      set -eu
      curl -fsS http://127.0.0.1:8080/healthz
findings: []
open_questions: []
```

`services agent-packages` creates initial service-builder result stubs in this
shape with `status: needs-review`, the target `service`, empty implementation
summary fields, and an empty `service_changes` list. A service result becomes
applyable only after the builder changes `status` to `complete`, describes
implemented routes/data/workflows/evidence/reset behavior, and provides
concrete `service_changes`.

Apply the result:

```powershell
python -m labforge services review-result <lab-root> --result service-build-entry-service.result.yaml
python -m labforge services review-results <lab-root> --results <service-agent-output-dir> --force
python -m labforge services apply-result <lab-root> --result service-build-entry-service.result.yaml --dry-run
python -m labforge services apply-result <lab-root> --result service-build-entry-service.result.yaml --force
python -m labforge services apply-results <lab-root> --results <service-agent-output-dir>
python -m labforge services apply-results <lab-root> --results <service-agent-output-dir> --execute --force
```

Safety rules:

- `service` must match a declared `service_artifacts` item.
- `target_path` is always relative to that service's `source_path`.
- absolute paths and `..` traversal are rejected.
- existing files are not overwritten unless `--force` is provided.
- `source_path`, when used instead of inline `content`, is relative to the
  result file directory.
- only the selected service directory can be modified.

This creates the missing link between manual or LLM-assisted service
implementation and deterministic LabForge verification:

```powershell
python -m labforge services review-result <lab-root> --result <agent-result.yaml> --force
python -m labforge services apply-result <lab-root> --result <agent-result.yaml> --force
python -m labforge services verify <lab-root> --strict
python -m labforge qa release-gate <lab-root> --out output/release-gate --provider docker-compose --profile protected
```

`review-result` should run before `apply-result` in supervised workflows. It
does not modify files. It checks the result schema, service name, completion
status, open questions, target paths, source files, and overwrite risk. It
returns success only when the result is ready to apply.

`review-results` performs the same review across a directory of
`*.result.yaml` files and reports how many services are ready, still need review,
or failed validation. It is intended for supervisor batch review before applying
service-builder outputs.

`apply-results` applies every ready `*.result.yaml` file in a directory. It is
dry-run by default; use `--execute` to write files. Results that still need
review are skipped rather than partially applied, so a supervisor can rerun the
command after individual service-builder agents fix their output.
