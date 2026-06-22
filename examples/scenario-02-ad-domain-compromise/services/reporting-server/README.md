# reporting-server

Internal discovery and lateral movement target.

## Runtime

- Internal Linux or Windows application server

## Attack Surface

- Internal HTTP or service endpoint
- Misconfiguration or delegated access path

## Healthcheck Contract

Internal readiness endpoint or service status check must pass.

## Reset Contract

Remove learner-created files and restore baseline internal notes.

## Evidence Logs

- `service.log`
- `access.log`

## Safety Boundaries

- Must be reachable only from declared internal networks.
- Any exploit path must remain inside lab services.
