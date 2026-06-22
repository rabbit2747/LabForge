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
