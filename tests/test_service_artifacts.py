from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from labforge.implementation_plan import create_service_agent_packages
from labforge.io import dump_yaml, load_yaml, write_text
from labforge.model import LabSpec
from labforge.service_artifacts import review_service_result


class ServiceArtifactLiveReadinessTests(unittest.TestCase):
    def test_service_agent_package_carries_live_readiness_tasks_into_result_stub(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_lab(root)
            readiness_path = root / "live-readiness-tasks.json"
            write_text(readiness_path, json.dumps({"tasks": [live_task()]}, indent=2) + "\n")

            out = root / "service-agents"
            create_service_agent_packages(LabSpec.load(root), out, live_readiness_tasks_path=readiness_path)

            result_path = out / ".ai" / "outputs" / "service-build-support-portal.result.yaml"
            result = load_yaml(result_path)

            self.assertEqual(result["live_readiness_tasks"][0]["task_id"], "live-readiness-001")
            self.assertEqual(result["live_readiness_evidence"], [])
            self.assertIn("Live readiness tasks are attached", "\n".join(result["findings"]))

    def test_service_result_review_requires_live_readiness_evidence_when_tasks_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_lab(root)
            result_path = root / "service-result.yaml"
            result = complete_service_result(root, live_readiness_evidence=[])
            write_text(result_path, dump_yaml(result))

            review = review_service_result(LabSpec.load(root), result_path, force=True)

            self.assertEqual(review.status, "needs-review")
            self.assertFalse(review.ready_to_apply)
            messages = "\n".join(item.message for item in review.items)
            self.assertIn("no live_readiness_evidence", messages)

    def test_service_result_review_accepts_live_readiness_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_lab(root)
            result_path = root / "service-result.yaml"
            result = complete_service_result(
                root,
                live_readiness_evidence=[
                    {
                        "task_id": "live-readiness-001",
                        "artifact": "learner-access.json",
                        "evidence": "attacker_workstation_ssh command and solver terminal step generated",
                    }
                ],
            )
            write_text(result_path, dump_yaml(result))

            review = review_service_result(LabSpec.load(root), result_path, force=True)

            self.assertEqual(review.status, "ready")
            self.assertTrue(review.ready_to_apply)
            self.assertTrue(any("live readiness evidence supplied" in item.message for item in review.items))


def live_task() -> dict:
    return {
        "task_id": "live-readiness-001",
        "assigned_agent": "service-builder",
        "severity": "warning",
        "required_action": "publish an SSH-capable attacker workstation and terminal command sequence",
        "expected_artifact": "learner-access.json and solver-plan.json evidence",
    }


def complete_service_result(root: Path, *, live_readiness_evidence: list[dict]) -> dict:
    return {
        "task_id": "service-build-support-portal",
        "status": "complete",
        "service": "support-portal",
        "summary": "Implemented support portal runtime and live learner access updates.",
        "implemented_routes": [{"method": "GET", "path": "/healthz"}],
        "data_model": ["seed/metadata.json"],
        "normal_workflows": ["Support case review"],
        "vulnerable_paths": [],
        "detection_evidence": ["logs/service-events.jsonl"],
        "live_readiness_tasks": [live_task()],
        "live_readiness_evidence": live_readiness_evidence,
        "healthcheck_behavior": "GET /healthz",
        "reset_behavior": "reset.sh clears state",
        "service_changes": [{"target_path": "app.py", "content": "print('updated')\n"}],
        "findings": [],
        "open_questions": [],
    }


def write_lab(root: Path) -> None:
    write_text(
        root / "scenario.yaml",
        json.dumps(
            {
                "id": "service-live-readiness",
                "title": "Service Live Readiness",
                "summary": "Enterprise support lab.",
                "final_objective": "Collect synthetic evidence.",
                "target_industry": "enterprise",
            },
            indent=2,
        )
        + "\n",
    )
    write_text(
        root / "topology.yaml",
        json.dumps(
            {
                "networks": [{"name": "dmz"}],
                "services": [{"name": "support-portal", "role": "support portal", "networks": ["dmz"], "exposed": True}],
                "deployment": {"recommended_model": "docker-compose", "docker_only_supported": True},
            },
            indent=2,
        )
        + "\n",
    )
    write_text(
        root / "stages.yaml",
        json.dumps(
            {
                "stages": [
                    {
                        "id": "stage-01",
                        "title": "Review support portal.",
                        "procedure": "Review support case notes and diagnostics workflow.",
                        "evidence": ["support_context"],
                        "mitre": {"tactic": "Discovery", "techniques": [{"id": "T1082", "name": "System Information Discovery"}]},
                    }
                ]
            },
            indent=2,
        )
        + "\n",
    )
    write_text(
        root / "artifacts.yaml",
        json.dumps(
            {
                "service_artifacts": [
                    {
                        "service": "support-portal",
                        "source_path": "services/support-portal",
                        "runtime": "business-portal",
                        "purpose": "Support diagnostics workflow.",
                        "seed_inputs": ["support cases"],
                        "noise_inputs": ["routine diagnostics"],
                        "healthcheck": "GET /healthz",
                        "reset": "reset.sh",
                        "evidence_logs": ["logs/service-events.jsonl"],
                        "safety_boundaries": ["synthetic data only"],
                    }
                ]
            },
            indent=2,
        )
        + "\n",
    )
    service_root = root / "services" / "support-portal"
    (service_root / "seed").mkdir(parents=True)
    (service_root / "noise").mkdir(parents=True)
    (service_root / "tests").mkdir(parents=True)
    write_text(service_root / "README.md", "Support portal service.\n")
    write_text(service_root / "labforge-service.yaml", "service: support-portal\n")
    write_text(service_root / "healthcheck.sh", "#!/bin/sh\nexit 0\n")
    write_text(service_root / "reset.sh", "#!/bin/sh\nexit 0\n")
    write_text(service_root / "Dockerfile", "FROM python:3.12-slim\n")
    write_text(service_root / "app.py", "print('support portal')\n")
    write_text(service_root / "blueprint.yaml", "service: support-portal\n")


if __name__ == "__main__":
    unittest.main()
