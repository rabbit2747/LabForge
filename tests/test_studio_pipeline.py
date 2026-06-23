from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from labforge.cli import main
from labforge.studio import (
    create_pipeline_scenario,
    create_verified_mvp_scenario,
    read_scenario_detail,
    run_release_gate_for_scenario,
    studio_state,
)


class StudioPipelineTest(unittest.TestCase):
    def test_natural_language_pipeline_can_reach_release_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            detail = create_pipeline_scenario(
                workspace,
                {
                    "title": "Studio Securities Smoke",
                    "industry": "securities",
                    "adapter": "manual",
                    "provider": "auto",
                    "prompt": (
                        "Create a realistic brokerage red-team lab where a learner starts from "
                        "a public investor portal, reaches internal trade operations, abuses a "
                        "review workflow, and retrieves a controlled compliance export."
                    ),
                },
            )

            scenario_id = str(detail["scenario_id"])
            state = studio_state(workspace).model_dump()
            self.assertEqual([item["scenario_id"] for item in state["scenarios"]], [scenario_id])
            self.assertTrue(any(step["name"] == "Supervisor package" and step["complete"] for step in detail["steps"]))
            self.assertTrue(any(report["name"] == "Quickstart" for report in detail["reports"]))
            self.assertTrue(any(report["name"] == "Endpoint Manifest" for report in detail["reports"]))
            self.assertEqual(detail["pipeline_gate"]["decision"], "release-candidate")
            self.assertTrue(detail["pipeline_gate"]["ready_for_supervisor"])
            self.assertTrue(detail["pipeline_gate"]["ready_for_release_gate"])
            self.assertTrue(detail["pipeline_gate"]["next_commands"])

            release_detail = run_release_gate_for_scenario(workspace, scenario_id, {})
            gate = release_detail["last_release_gate"]
            self.assertEqual(gate["status"], "passed")
            self.assertTrue(gate["release_ready"])
            self.assertEqual(
                {check["name"]: check["status"] for check in gate["checks"]},
                {
                    "schema-validation": "passed",
                    "quality-lint-strict": "passed",
                    "service-verification-strict": "passed",
                    "plugin-runtime-smoke-strict": "passed",
                    "industry-realism-review": "passed",
                    "provider-build": "passed",
                    "learner-experience-strict": "passed",
                },
            )

            reread = read_scenario_detail(workspace, scenario_id)
            self.assertEqual(reread["release_gate"]["status"], "passed")
            self.assertTrue(any(step["name"] == "Release gate" and step["complete"] for step in reread["steps"]))
            self.assertTrue(any(report["name"] == "Release Gate" for report in reread["reports"]))

    def test_verified_mvp_endpoint_runs_pipeline_and_release_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            detail = create_verified_mvp_scenario(
                workspace,
                {
                    "title": "Verified MVP Smoke",
                    "industry": "manufacturing",
                    "adapter": "manual",
                    "provider": "auto",
                    "prompt": (
                        "Create a realistic manufacturing red-team lab where a learner starts "
                        "from a supplier portal, reaches engineering documentation, discovers "
                        "MES and historian services, and retrieves a controlled production report."
                    ),
                },
            )

            self.assertEqual(detail["pipeline_gate"]["decision"], "release-candidate")
            self.assertEqual(detail["last_release_gate"]["status"], "passed")
            self.assertTrue(detail["last_release_gate"]["release_ready"])
            self.assertTrue(any(step["name"] == "Release gate" and step["complete"] for step in detail["steps"]))
            self.assertTrue(any(step["name"] == "Verified MVP" and step["complete"] for step in detail["steps"]))
            self.assertTrue(any(report["name"] == "Release Gate" for report in detail["reports"]))
            self.assertTrue(any(report["name"] == "Verified MVP" for report in detail["reports"]))
            self.assertTrue((workspace / str(detail["scenario_id"]) / "mvp" / "verified-mvp.json").exists())
            self.assertTrue((workspace / str(detail["scenario_id"]) / "mvp" / "verified-mvp.md").exists())

    def test_verified_mvp_cli_creates_handoff_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "verified-cli"
            code = main(
                [
                    "pipeline",
                    "verified-mvp",
                    "--prompt",
                    (
                        "Create a realistic healthcare red-team lab where a learner starts from "
                        "a patient portal, discovers identity and EHR systems, abuses a clinical "
                        "workflow, and retrieves a controlled synthetic audit export."
                    ),
                    "--out",
                    str(out),
                    "--industry",
                    "healthcare",
                    "--provider",
                    "auto",
                    "--adapter",
                    "manual",
                    "--force",
                ]
            )

            self.assertEqual(code, 0)
            self.assertTrue((out / "mvp" / "verified-mvp.json").exists())
            self.assertTrue((out / "mvp" / "verified-mvp.md").exists())
            self.assertTrue((out / "release-gate" / "release-gate-report.yaml").exists())

    def test_verified_mvp_cli_accepts_banking_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "banking-cli"
            code = main(
                [
                    "pipeline",
                    "verified-mvp",
                    "--prompt",
                    (
                        "Create a realistic regional bank red-team lab where a learner starts "
                        "from a public loan application portal, discovers internal document "
                        "processing services, abuses an operations review workflow, and "
                        "retrieves a controlled synthetic suspicious-activity export."
                    ),
                    "--out",
                    str(out),
                    "--industry",
                    "banking",
                    "--provider",
                    "auto",
                    "--adapter",
                    "manual",
                    "--force",
                ]
            )

            self.assertEqual(code, 0)
            self.assertTrue((out / "mvp" / "verified-mvp.json").exists())
            self.assertTrue((out / "release-gate" / "release-gate-report.yaml").exists())


if __name__ == "__main__":
    unittest.main()
