# ldap-ad

Prototype directory service for identity, group, and service account data.

## Runtime

- LDAP directory prototype or Windows AD provider replacement

## Attack Surface

- Directory queries
- Credential and group discovery paths

## Healthcheck Contract

Directory bind or equivalent query must succeed with a low-privilege test account.

## Reset Contract

Reimport baseline directory objects and rotate any generated lab credentials.

## Evidence Logs

- `directory-query.log`
- `auth.log`

## Safety Boundaries

- Prototype mode must not claim full Kerberos or GPO fidelity.
- Realistic AD mode must be implemented by VM or hybrid provider.
