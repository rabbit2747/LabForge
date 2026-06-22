# backup-server

Privilege escalation and sensitive operations target.

## Runtime

- Internal backup service prototype

## Attack Surface

- Backup metadata
- Restore workflow or credential handling path

## Healthcheck Contract

Backup API or local status command must report ready.

## Reset Contract

Restore backup catalog and delete learner-generated restore jobs.

## Evidence Logs

- `backup-audit.log`
- `restore-jobs.log`

## Safety Boundaries

- Restore operations must not write outside declared lab volumes.
- Credentials must be synthetic lab secrets only.
