# LabForge Open Source Constitution

LabForge is an open-source framework, not a one-off local setup script.
Every feature, provider, generated artifact, and document should be designed so
it can work across different learner, supervisor, and infrastructure machines.

## Core Rules

1. Do not hard-code one developer's machine.

   Avoid fixed user paths, private directories, personal hostnames, fixed WSL
   distro names, or assumptions such as `C:\Users\...`, `/home/ubuntu/...`, or
   one specific Docker Desktop setup.

2. Detect before deciding.

   Use `labforge doctor` and provider checks to identify OS, shell, Docker,
   WSL, hypervisor, and required runtime capabilities before generating an
   execution plan.

3. Prefer portable defaults with explicit overrides.

   Generated scripts should work on Windows, Linux, macOS, and WSL when the
   required runtime exists. Environment variables may override auto-detection,
   but they must not be required for the common path.

4. Keep providers independent.

   Docker Compose is one provider. AD, Windows VM, Proxmox, Ludus, Ansible,
   Terraform, Vagrant, and hybrid environments must remain valid provider
   targets.

5. Separate scenario intent from implementation.

   Scenario files describe learning objectives, topology, stages, assets, and
   security controls. Provider code decides how to realize that design on the
   selected platform.

6. Generate supervisor-readable decisions.

   LabForge must explain what it detected, what it selected, why it selected
   it, and what the supervisor must review before deployment.

7. Keep examples generic.

   Documentation examples should use placeholders such as `<repo>`,
   `<lab-root>`, `<output-dir>`, and `<detected-distro>` unless a concrete value
   is part of a generated example.

8. Treat security controls as first-class design inputs.

   Protected and unprotected architectures must be documented separately. WAF,
   IDS, firewall, SIEM, EDR, logging, and segmentation choices should be visible
   in diagrams and provider outputs when supported.

9. Make generated labs resettable.

   Every provider should define how a lab starts, stops, validates, resets, and
   preserves or destroys learner state.

10. Keep open-source users in mind.

    Installation, validation, testing, and contribution paths should not depend
    on private repositories, local reference folders, proprietary services, or a
    single operating system.

11. Templates are infrastructure parts, not puzzles.

    Reusable service templates may provide runtime skeletons, healthchecks,
    reset hooks, seed/noise loaders, logging, and safety boundaries. They must
    not hard-code final answers, exact exploit commands, magic scoring strings,
    or one fixed learner solution path.

## Review Checklist

Before merging a change, check:

- Are there any private absolute paths or user-specific names?
- Does the feature work on more than one OS, or clearly document provider
  limitations?
- Does `doctor` or the provider detect the needed runtime instead of assuming it?
- Can a supervisor understand the generated architecture and required hardware?
- Are security controls documented and reflected in generated outputs where
  applicable?
- Do templates provide reusable infrastructure parts rather than reusable
  puzzle answers?
- Are local-only reference materials excluded from commits?
