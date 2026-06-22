# hr-portal

Externally reachable business application used for initial access.

## Runtime

- Python web application

## Attack Surface

- Authenticated or unauthenticated web workflow
- Deliberately vulnerable preview or business logic endpoint

## Healthcheck Contract

GET /healthz must return 200 and verify the application can read its seed data.

## Reset Contract

Restore seeded cases and remove learner-created temporary files.

## Evidence Logs

- `application.log`
- `access.log`
- `security-audit.log`

## Safety Boundaries

- Vulnerable behavior must be lab-scoped and documented.
- Outbound callbacks may reach only the attacker-workstation or declared internal services.
