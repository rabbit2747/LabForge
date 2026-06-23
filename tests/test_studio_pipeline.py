from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from labforge.studio import create_pipeline_scenario, read_scenario_detail, run_release_gate_for_scenario, studio_state


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
                },
            )

            reread = read_scenario_detail(workspace, scenario_id)
            self.assertEqual(reread["release_gate"]["status"], "passed")
            self.assertTrue(any(step["name"] == "Release gate" and step["complete"] for step in reread["steps"]))
            self.assertTrue(any(report["name"] == "Release Gate" for report in reread["reports"]))


if __name__ == "__main__":
    unittest.main()
