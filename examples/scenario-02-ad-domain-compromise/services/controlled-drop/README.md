# controlled-drop

Receives the final object proof and records completion.

## Runtime

- Submission API

## Attack Surface

- Final submission endpoint
- Optional supervisor status endpoint

## Healthcheck Contract

GET /healthz or equivalent status endpoint must return ready.

## Reset Contract

Clear submissions and restore initial scoreboard state.

## Evidence Logs

- `submissions.log`
- `completion-events.log`

## Safety Boundaries

- Must accept only lab-defined final object proofs.
- Must not expose instructor-only answer data to learners.
