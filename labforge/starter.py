from __future__ import annotations

from pathlib import Path

from .io import dump_yaml, write_text


STARTER_FILES = (
    "lab.yaml",
    "scenario.yaml",
    "topology.yaml",
    "stages.yaml",
    "environment.yaml",
    "artifacts.yaml",
    "security-controls.yaml",
    "supervisor-selection.yaml",
    "providers/docker-compose.yaml",
    "providers/hybrid.yaml",
    "services/README.md",
)


def init_lab(out: Path, *, lab_id: str, title: str, force: bool = False) -> list[Path]:
    written: list[Path] = []
    files = starter_file_map(lab_id, title)
    for filename, content in files.items():
        path = out / filename
        if path.exists() and not force:
            continue
        write_text(path, content)
        written.append(path)
    return written


def starter_file_map(lab_id: str, title: str) -> dict[str, str]:
    return {
        "lab.yaml": dump_yaml(
            {
                "id": lab_id,
                "title": title,
                "version": "0.2",
                "difficulty": "draft",
                "mode": "red-team",
                "default_provider": "docker-compose",
                "supported_providers": ["docker-compose", "hybrid", "ansible", "terraform", "ludus"],
            }
        ),
        "scenario.yaml": dump_yaml(
            {
                "id": lab_id,
                "title": title,
                "summary": "Replace this with the scenario narrative and enterprise context.",
                "final_objective": "Replace this with the learner's final objective.",
                "learner_entrypoint": "Replace this with the first reachable service or access method.",
                "target_industry": "Replace with an industry profile such as securities, healthcare, or manufacturing.",
                "target_organization_type": "Replace with the type of company being modeled.",
                "realism_notes": [
                    "List the business systems, data flows, and operational noise that make this lab feel like the target industry."
                ],
            }
        ),
        "topology.yaml": dump_yaml(starter_topology()),
        "stages.yaml": dump_yaml(starter_stages()),
        "environment.yaml": dump_yaml(starter_environment()),
        "artifacts.yaml": dump_yaml(starter_artifacts()),
        "security-controls.yaml": dump_yaml(starter_security_controls()),
        "supervisor-selection.yaml": dump_yaml(starter_supervisor_selection()),
        "providers/docker-compose.yaml": dump_yaml(
            {
                "provider": "docker-compose",
                "profile_support": ["unprotected", "protected"],
                "purpose": "Prototype the lab as local containers before moving to a realistic provider.",
                "limitations": [
                    "Replace placeholder services with realistic lab-scoped implementations.",
                    "Use hybrid or VM provider when the scenario requires Windows, AD, ICS, or endpoint realism.",
                ],
            }
        ),
        "providers/hybrid.yaml": dump_yaml(
            {
                "provider": "hybrid",
                "status": "planned",
                "purpose": "Combine Docker services with VM-backed enterprise assets when required.",
                "expected_assets": [
                    "Docker host for prototype services",
                    "Linux attacker workstation",
                    "Optional Windows or domain assets",
                ],
            }
        ),
        "services/README.md": "\n".join(
            [
                "# Services",
                "",
                "Run `python -m labforge services scaffold <lab-root>` after filling `artifacts.yaml`.",
                "Run `python -m labforge services materialize <lab-root>` only when safe placeholder Docker runtimes are useful.",
                "",
            ]
        ),
    }


def starter_topology() -> dict:
    return {
        "networks": [
            {"name": "public_net"},
            {"name": "dmz_net", "internal": True},
            {"name": "corp_net", "internal": True},
        ],
        "security_controls": {
            "recommended": [
                "Firewall / Segmentation",
                "WAF on public web entry points",
                "IDS east-west sensor",
                "Central log collection",
            ]
        },
        "deployment": {
            "recommended_model": "docker-compose",
            "docker_only_supported": True,
            "docker_only_notes": "Update this when the scenario requires VM, Windows, AD, cloud, ICS, or endpoint realism.",
            "minimum_environment": {
                "description": "Single training PC for prototype mode.",
                "hosts": [
                    {
                        "role": "training-host",
                        "count": 1,
                        "os": "Windows, Linux, or macOS with a Docker-capable runtime",
                        "cpu": "8 cores recommended",
                        "memory": "16 GB minimum",
                        "storage": "80 GB free",
                        "software": ["Docker-compatible runtime", "Python 3.11+", "Git"],
                    }
                ],
            },
            "realistic_environment": {
                "description": "Update this with real infrastructure requirements.",
                "hosts": [],
            },
            "required_platforms": ["Docker Compose for prototype services"],
        },
        "services": [
            {
                "name": "attacker-workstation",
                "role": "learner attack workstation",
                "exposed": True,
                "networks": ["public_net", "dmz_net"],
                "ports": ["2222:22"],
                "healthcheck": {
                    "test": ["CMD", "sh", "-lc", "test -d /home/attacker"],
                    "interval": "10s",
                    "timeout": "3s",
                    "retries": 10,
                },
            },
            {
                "name": "entry-service",
                "role": "first learner-facing business service",
                "exposed": True,
                "networks": ["public_net", "dmz_net"],
                "expose": ["8080"],
                "healthcheck": {
                    "test": ["CMD", "sh", "-lc", "true"],
                    "interval": "10s",
                    "timeout": "3s",
                    "retries": 10,
                },
            },
        ],
    }


def starter_stages() -> dict:
    return {
        "stages": [
            {
                "id": "stage-01",
                "title": "Replace with first learner action",
                "procedure": "Describe what the learner must discover and do in this stage.",
                "evidence": ["Replace with observable evidence for QA or instructor review."],
                "mitre": {
                    "tactic": "Initial Access",
                    "techniques": [{"id": "T0000", "name": "Replace with ATT&CK Enterprise technique"}],
                },
                "required_findings": ["Replace with the finding needed to advance."],
                "next_stage": "stage-02",
            },
            {
                "id": "stage-02",
                "title": "Replace with second learner action",
                "procedure": "Describe the next step in the chain.",
                "evidence": ["Replace with evidence."],
                "mitre": {
                    "tactic": "Discovery",
                    "techniques": [{"id": "T0000", "name": "Replace with ATT&CK Enterprise technique"}],
                },
                "required_findings": ["Replace with the finding needed to advance."],
            },
        ]
    }


def starter_environment() -> dict:
    return {
        "zones": [
            {"id": "public", "name": "Learner reachable zone"},
            {"id": "dmz", "name": "Externally reachable service zone"},
            {"id": "corp", "name": "Internal corporate zone"},
        ],
        "assets": [
            {
                "id": "attacker-workstation",
                "type": "learner_workstation",
                "zone": "public",
                "os": "linux",
                "exposure": "public",
            },
            {
                "id": "entry-service",
                "type": "web_app",
                "zone": "dmz",
                "os": "linux",
                "exposure": "public",
            },
        ],
    }


def starter_artifacts() -> dict:
    return {
        "seed": [],
        "noise": [],
        "learner_handouts": [],
        "instructor_only": [],
        "service_artifacts": [
            {
                "service": "attacker-workstation",
                "source_path": "services/attacker-workstation",
                "runtime": "Linux learner workstation",
                "purpose": "Learner-controlled workstation for authorized lab activity.",
                "attack_surface": [],
                "seed_inputs": [],
                "noise_inputs": [],
                "healthcheck": "Confirm the learner account or workspace exists.",
                "reset": "Clear learner-created temporary files.",
                "evidence_logs": [],
                "safety_boundaries": ["Do not allow uncontrolled external callbacks."],
            },
            {
                "service": "entry-service",
                "source_path": "services/entry-service",
                "runtime": "Replace with service runtime",
                "purpose": "First learner-facing service.",
                "attack_surface": ["Replace with intended lab-scoped attack surface."],
                "seed_inputs": [],
                "noise_inputs": [],
                "healthcheck": "GET /healthz must return 200.",
                "reset": "Restore baseline data.",
                "evidence_logs": ["application.log"],
                "safety_boundaries": ["Vulnerable behavior must remain lab-scoped."],
            },
        ],
    }


def starter_security_controls() -> dict:
    return {
        "recommended": ["Firewall / Segmentation", "WAF", "IDS", "SIEM"],
        "controls": {
            "firewall": [
                {
                    "id": "fw-basic-segmentation",
                    "name": "Basic segmentation",
                    "mode": "enforce",
                    "description": "Separates public, DMZ, and internal networks.",
                }
            ],
            "waf": [
                {
                    "id": "waf-entry-service",
                    "name": "Entry service WAF",
                    "mode": "alert",
                    "description": "Records suspicious web requests.",
                }
            ],
            "ids": [
                {
                    "id": "ids-east-west",
                    "name": "East-west IDS",
                    "mode": "alert",
                    "description": "Observes movement between internal zones.",
                }
            ],
            "siem": [
                {
                    "id": "siem-central-logs",
                    "name": "Central log collection",
                    "mode": "collect",
                    "description": "Collects service and control logs.",
                }
            ],
        },
    }


def starter_supervisor_selection() -> dict:
    return {
        "selected_controls": {
            "firewall": ["fw-basic-segmentation"],
            "waf": [],
            "ids": ["ids-east-west"],
            "siem": ["siem-central-logs"],
        },
        "training_mode": {
            "mode": "red-team",
            "profile": "unprotected",
            "detection_feedback": "instructor_only",
            "allow_student_log_access": False,
        },
    }
