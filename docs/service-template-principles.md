# LabForge Service Template Principles

LabForge service templates are reusable infrastructure parts, not reusable
puzzles.

This distinction keeps generated labs from becoming repetitive. A template may
save implementation time, but it must not decide the learner's full attack path,
final answer, or scenario-specific exploit chain.

## Core Rule

Templates generate reusable service structure. Scenarios define the training
problem.

## Allowed Template Responsibilities

A service template may provide:

- runtime skeletons such as Flask, Express, nginx, Linux workstation, LDAP, or
  object storage stubs
- healthcheck and reset hooks
- seed and noise data loaders
- logging and evidence paths
- default UI layout or API structure
- provider-specific build files
- safety controls such as lab-only egress restrictions

## Scenario-Specific Responsibilities

The scenario must define:

- learner objective and final target
- stage sequence
- MITRE ATT&CK tactic and technique mapping
- vulnerable behavior and its boundaries
- realistic clues, noise, and documents
- credentials, tokens, object keys, or final proof material
- exploit path, lateral movement path, and final submission logic

## Anti-Patterns

Do not put these in reusable templates:

- final flags or final object values
- answer keys
- exact exploit commands
- fixed magic strings required for scoring
- scenario-specific credentials
- hard-coded CVE-to-solution walkthroughs
- hidden grader-only names that learners cannot infer
- one fixed chain such as web bug -> internal API -> object store -> drop

## Good Template Metadata

```yaml
template:
  id: python-flask-web
  role: infrastructure-part
  provides:
    - http-runtime
    - healthcheck
    - reset-hook
    - seed-loader
  scenario_must_define:
    - vulnerable behavior
    - learner-facing workflow
    - seed and noise records
    - solution evidence
```

## Bad Template Metadata

```yaml
template:
  id: python-flask-ssti-to-flag
  answer_key: ANRC_Q2_facility_audit
  exploit_command: "{{ cycler.__init__.__globals__.os.popen(...) }}"
  solution_path:
    - submit body parameter
    - get shell
    - read final object
```

## Verification Expectations

LabForge verification should warn when service contracts or template metadata
contain puzzle-like markers such as:

- `answer_key`
- `ctf_flag`
- `exploit_command`
- `final_flag`
- `hardcoded_payload`
- `magic_string`
- `solution_path`

These values may exist in instructor-only artifacts when needed, but they should
not live inside reusable template metadata.

## Design Goal

Two labs may both use `python-flask-web`, but they should still feel different
because their business workflows, data, attack surfaces, internal topology,
security controls, and final objectives are scenario-specific.

## Built-In Infrastructure Templates

Initial built-in templates:

- `python-flask-web`: generic Flask HTTP service with `/`, `/metadata`, and
  `/healthz`.
- `attacker-workstation-ssh`: Linux learner workstation with SSH and common
  diagnostic tools.
- `controlled-drop`: lab-scoped submission receiver with resettable local state.

Use them from `artifacts.yaml`:

```yaml
service_artifacts:
  - service: entry-service
    source_path: services/entry-service
    runtime: Python web application
    template:
      id: python-flask-web
    purpose: First learner-facing business service.
    attack_surface:
      - Scenario-specific workflow endpoint.
    healthcheck: GET /healthz must return 200.
    reset: Restore baseline data.
    evidence_logs:
      - application.log
    safety_boundaries:
      - Vulnerable behavior must remain lab-scoped.
```

Materialize the selected templates:

```powershell
python -m labforge services templates
python -m labforge services materialize <lab-root> --force
python -m labforge services verify <lab-root>
```

## Vulnerability Plugin Contracts

Vulnerability plugins describe scenario-specific vulnerable behavior that may be
implemented on top of reusable infrastructure templates. They are contracts, not
complete generated exploits or answer keys.

Initial built-in plugin contracts:

- `ssti-preview`
- `stored-xss-review`
- `idor-object-access`
- `ssrf-internal-fetch`
- `diagnostic-command-injection`

Use them from `artifacts.yaml`:

```yaml
service_artifacts:
  - service: entry-service
    source_path: services/entry-service
    runtime: Python web application
    template:
      id: python-flask-web
    vulnerability_plugins:
      - id: ssti-preview
        workflow: document preview
        template_engine: jinja2
        execution_boundary: lab container only
    purpose: First learner-facing business service.
    attack_surface:
      - Scenario-specific preview endpoint.
    healthcheck: GET /healthz must return 200.
    reset: Restore baseline data.
    evidence_logs:
      - application.log
    safety_boundaries:
      - Vulnerable behavior must remain lab-scoped.
```

Materialization writes plugin contract files under the service directory:

```text
services/<service>/plugins/ssti-preview.contract.yaml
```

The plugin contract tells service builders what the scenario must define, which
MITRE techniques are commonly involved, and which safety boundaries must be
preserved. It does not generate the final vulnerable route or the learner's
solution path by itself.
