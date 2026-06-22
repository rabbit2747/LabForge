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

Create placeholder service directories and hooks:

```powershell
python -m labforge services scaffold <lab-root>
```

Validate that every declared service artifact has a matching implementation
directory and required files:

```powershell
python -m labforge services check <lab-root>
```

The scaffold command is intentionally conservative. It does not generate real
vulnerable service code. It creates the contract files that service builders and
agents replace with actual implementation.

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
