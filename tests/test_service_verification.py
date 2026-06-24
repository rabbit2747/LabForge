import json
import tempfile
import unittest
from pathlib import Path

from labforge.model import LabSpec
from labforge.service_verification import verify_services


class ServiceVerificationTests(unittest.TestCase):
    def test_learner_visible_service_content_flags_solver_language(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_lab(root)
            service_root = root / "services" / "support-portal"
            write_service_runtime(service_root)
            (service_root / "templates").mkdir(parents=True, exist_ok=True)
            (service_root / "templates" / "diagnostics.html").write_text(
                "<h1>Foothold shell</h1><p>Exploit here to submit flag.</p>",
                encoding="utf-8",
            )
            (service_root / "seed").mkdir(parents=True, exist_ok=True)
            (service_root / "seed" / "runbook.json").write_text(
                json.dumps({"note": "The admin password is stored in the answer key."}),
                encoding="utf-8",
            )

            report = verify_services(LabSpec.load(root))
            findings = [item for item in report.findings if item.category == "learner-facing-language"]
            messages = "\n".join(item.message for item in findings)

            self.assertEqual(report.status, "warning")
            self.assertTrue(findings)
            self.assertIn("foothold shell", messages)
            self.assertIn("exploit here", messages)
            self.assertIn("submit flag", messages)
            self.assertIn("admin password", messages)
            self.assertIn("answer key", messages)

    def test_learner_visible_service_content_accepts_business_language(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_lab(root)
            service_root = root / "services" / "support-portal"
            write_service_runtime(service_root)
            (service_root / "templates").mkdir(parents=True, exist_ok=True)
            (service_root / "templates" / "diagnostics.html").write_text(
                "<h1>Support Diagnostics Console</h1><p>Review approved runtime checks and support case notes.</p>",
                encoding="utf-8",
            )
            (service_root / "seed").mkdir(parents=True, exist_ok=True)
            (service_root / "seed" / "runbook.json").write_text(
                json.dumps({"note": "Vault reference and startup diagnostic entries require correlation."}),
                encoding="utf-8",
            )

            report = verify_services(LabSpec.load(root))
            findings = [item for item in report.findings if item.category == "learner-facing-language"]

            self.assertFalse(findings)

    def test_stage_chain_context_flags_thin_or_unanchored_clues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_lab(root)
            service_root = root / "services" / "support-portal"
            write_service_runtime(service_root)
            (service_root / "seed" / "chain.json").write_text(
                json.dumps(
                    {
                        "service": "support-portal",
                        "stage_count": 2,
                        "stages": [
                            {
                                "stage_id": "stage-01",
                                "title": "Support review",
                                "services": ["support-portal"],
                                "required_inputs": [],
                                "produces": ["support_context"],
                                "learner_clue": "Continue.",
                            },
                            {
                                "stage_id": "stage-02",
                                "title": "Internal workflow",
                                "services": ["support-portal"],
                                "required_inputs": ["support_context"],
                                "produces": ["internal_context"],
                                "learner_clue": "Review the ordinary business process and look around carefully.",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = verify_services(LabSpec.load(root))
            findings = [item for item in report.findings if item.category == "stage-clue-context"]
            messages = "\n".join(item.message for item in findings)

            self.assertTrue(findings)
            self.assertIn("stage-01 learner clue is too thin", messages)
            self.assertIn("stage-02 learner clue does not mention its service, evidence, or required input anchors", messages)

    def test_stage_chain_context_accepts_anchored_business_clue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_lab(root)
            service_root = root / "services" / "support-portal"
            write_service_runtime(service_root)
            (service_root / "seed" / "chain.json").write_text(
                json.dumps(
                    {
                        "service": "support-portal",
                        "stage_count": 1,
                        "stages": [
                            {
                                "stage_id": "stage-01",
                                "title": "Support review",
                                "services": ["support-portal"],
                                "required_inputs": [],
                                "produces": ["support_context"],
                                "learner_clue": "Use support-portal case notes to correlate support_context with approved diagnostics records.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = verify_services(LabSpec.load(root))
            findings = [item for item in report.findings if item.category == "stage-clue-context"]

            self.assertFalse(findings)


def write_lab(root: Path) -> None:
    (root / "scenario.yaml").write_text(
        json.dumps(
            {
                "id": "service-language",
                "title": "Service Language",
                "summary": "Enterprise support lab.",
                "final_objective": "Collect synthetic evidence.",
                "target_industry": "enterprise",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (root / "topology.yaml").write_text(
        json.dumps(
            {
                "networks": [{"name": "dmz"}],
                "services": [{"name": "support-portal", "role": "support portal", "networks": ["dmz"], "exposed": True}],
                "deployment": {"recommended_model": "docker-compose", "docker_only_supported": True},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (root / "stages.yaml").write_text(
        json.dumps(
            {
                "stages": [
                    {
                        "id": "stage-01",
                        "title": "Review support portal.",
                        "procedure": "Review support case notes and diagnostics workflow.",
                        "evidence": ["support_context"],
                        "mitre": {
                            "tactic": "Discovery",
                            "techniques": [{"id": "T1082", "name": "System Information Discovery"}],
                        },
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (root / "artifacts.yaml").write_text(
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
                        "evidence_logs": ["service-events.jsonl"],
                        "safety_boundaries": ["synthetic data only"],
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def write_service_runtime(service_root: Path) -> None:
    service_root.mkdir(parents=True, exist_ok=True)
    (service_root / "README.md").write_text("Support portal service.\n", encoding="utf-8")
    (service_root / "labforge-service.yaml").write_text("service: support-portal\n", encoding="utf-8")
    (service_root / "healthcheck.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (service_root / "reset.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (service_root / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    (service_root / "app.py").write_text("print('support portal')\n", encoding="utf-8")
    (service_root / "seed").mkdir(parents=True, exist_ok=True)
    (service_root / "noise").mkdir(parents=True, exist_ok=True)
    (service_root / "noise" / "events.jsonl").write_text('{"event":"routine"}\n', encoding="utf-8")
    (service_root / "tests").mkdir(parents=True, exist_ok=True)
    (service_root / "tests" / "test_smoke.py").write_text("def test_smoke():\n    assert True\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
