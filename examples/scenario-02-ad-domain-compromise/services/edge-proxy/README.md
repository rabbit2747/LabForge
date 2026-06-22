# edge-proxy

Public ingress that exposes only approved learner entrypoints.

## Runtime

- nginx or equivalent reverse proxy

## Attack Surface

- HTTP routing and access logging
- Optional WAF or reverse-proxy control placement

## Healthcheck Contract

GET /healthz must return 200 from inside the container.

## Reset Contract

Stateless; restart container and clear generated access logs when reset profile requires it.

## Evidence Logs

- `access.log`
- `error.log`

## Safety Boundaries

- Must not proxy arbitrary internal hostnames.
- Must expose only topology-declared public ports.
