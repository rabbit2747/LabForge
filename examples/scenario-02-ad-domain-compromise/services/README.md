# Services

Place service implementation directories here.

Each service listed in `topology.yaml` is expected to have a matching directory
under this folder when the lab moves from design scaffold to runnable lab.

Each directory should follow the LabForge service artifact contract declared in
`../artifacts.yaml`.

Recommended structure:

```text
services/<service-name>/
|-- README.md
|-- Dockerfile or provider-specific build files
|-- src/ or app/
|-- seed/
|-- noise/
|-- tests/
|-- healthcheck.sh
|-- reset.sh
`-- labforge-service.yaml
```

`labforge-service.yaml` should mirror the service contract:

- service name
- runtime
- healthcheck behavior
- reset behavior
- seed and noise inputs
- evidence log paths
- safety boundaries

Provider-specific implementations may add files, but they should not remove the
contract fields required by `artifacts.yaml`.
