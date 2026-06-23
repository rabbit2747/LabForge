# siem-lite

Provides realistic enterprise security telemetry and optional detection feedback.

## Runtime

- Central logging and security monitoring prototype

## Attack Surface

- Internal log search interface
- Alert review workflow

## Healthcheck Contract

GET /healthz or equivalent local readiness check must return ready.

## Reset Contract

Restore seeded event stream and clear learner-generated alerts.

## Evidence Logs

- `events.log`
- `alerts.log`

## Safety Boundaries

- Learner-visible logs must not reveal instructor-only solution data.
- Detection events must be synthetic and scoped to declared lab services.
