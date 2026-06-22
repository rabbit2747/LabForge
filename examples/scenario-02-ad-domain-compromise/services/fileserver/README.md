# fileserver

Stores the final controlled collection object.

## Runtime

- Internal file or object service

## Attack Surface

- Internal file listing or object retrieval workflow
- Access proof validation

## Healthcheck Contract

Object listing or file existence check for seeded non-secret object must pass.

## Reset Contract

Restore final object and remove temporary learner downloads or proofs.

## Evidence Logs

- `object-access.log`

## Safety Boundaries

- Final data must be synthetic and training-only.
- Object retrieval must require the intended lab proof or access condition.
