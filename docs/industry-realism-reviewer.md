# Industry Realism Reviewer Agent

The `industry-realism-reviewer` is an independent specialist agent. Its job is
to decide whether a lab genuinely resembles the declared target industry.

This reviewer exists because keyword-based checks are not enough. A scenario can
mention "trading", "market data", or "compliance" and still be unrealistic if
the actual services, UI, data, workflows, and security architecture do not match
how a securities firm, hospital, manufacturer, or enterprise would operate.

## Review Scope

The reviewer must inspect:

- Declared industry and organization type.
- Scenario narrative and final objective.
- Network zones, trust boundaries, and deployment model.
- Service inventory, service roles, exposed ports, and internal-only systems.
- Service source, UI screenshots, frontend routes, labels, forms, errors, and
  dashboards when available.
- Business workflows implemented by the services.
- Seed data, noise data, logs, tickets, documents, and object names.
- Security controls, telemetry, SIEM/IDS/EDR placement, and protected profile
  behavior.
- Provider constraints, such as whether Docker is only a prototype and whether
  VM, AD, endpoint, OT, or hypervisor realism is required.

## Verdicts

Use one of three verdicts:

- `pass`: The lab is plausible for the declared industry. Minor polish issues
  may remain, but no major architecture, service, UI, workflow, data, or
  monitoring gap exists.
- `conditional-pass`: The core industry model is plausible, but specific
  changes are required before learner release.
- `fail`: The lab feels like a generic CTF or generic enterprise with industry
  labels attached, or a critical industry system/workflow is missing.

## Required Review Dimensions

The result must include a verdict for each dimension:

- Infrastructure realism.
- Service realism.
- UI realism.
- Workflow realism.
- Data and noise realism.
- Security-control realism.
- Deployment realism.

If UI screenshots or service source are unavailable, mark UI realism as
`not-reviewable` and request the missing material.

## Common Failure Cases

Fail or conditionally pass when:

- Services are named after attack stages rather than business systems.
- A page, menu, API route, or document leaks the intended solution path.
- A securities-firm lab lacks trading/order flow, market data, settlement,
  compliance, customer authentication, and realistic financial records.
- A healthcare lab lacks patient, clinical, billing, identity, audit, or privacy
  workflows.
- A manufacturing lab lacks production, engineering, historian, vendor access,
  or IT/OT segmentation.
- An AD lab claims realism while using only an LDAP-like placeholder without
  stating prototype limitations or hybrid/VM requirements.
- UI text uses CTF terms such as "foothold", "stage", "flag", "exploit here",
  or "next step".
- Noise data is random clutter rather than normal business records.
- Security controls are diagram-only but the protected profile claims enforced
  detection or blocking.

## Relationship to `realism check`

`python -m labforge realism check` is a static pre-check. It can identify
missing zones, obvious missing capabilities, and absent noise inputs. The
industry reviewer may use that report as one input, but must not treat it as
final evidence.

The reviewer is the realism gate that protects LabForge from producing
same-shaped labs with different industry labels.
