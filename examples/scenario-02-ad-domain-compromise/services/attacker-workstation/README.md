# attacker-workstation

Learner-controlled workstation for authorized lab activity.

## Runtime

- Linux SSH workstation

## Attack Surface

- SSH access for learner terminal
- Lab-scoped tools and handout files

## Healthcheck Contract

SSH service or shell readiness check must confirm the attacker home exists.

## Reset Contract

Recreate learner home from baseline files and remove transient sessions, tunnels, and callbacks.

## Evidence Logs

- `shell command transcript when training mode requires it`
- `callback listener logs`

## Safety Boundaries

- Tools must be scoped to lab networks.
- No privileged Docker socket mount.
- No default route to unintended external targets unless explicitly selected by supervisor.
