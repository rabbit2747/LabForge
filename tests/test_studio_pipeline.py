from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from labforge.cli import main
from labforge.qa import QaCheck, ReleaseGateReport
from labforge.studio import (
    create_pipeline_scenario,
    create_verified_mvp_scenario,
    read_scenario_detail,
    run_release_gate_for_scenario,
    studio_state,
)
from labforge.verified_mvp import write_verified_mvp_manifest


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
            self.assertTrue(any(report["name"] == "Learner Access" for report in detail["reports"]))
            self.assertTrue(any(report["name"] == "Learner Access JSON" for report in detail["reports"]))
            self.assertTrue(any(report["name"] == "Solver Plan" for report in detail["reports"]))
            self.assertTrue(any(report["name"] == "Learner Playtest" for report in detail["reports"]))
            self.assertTrue(any(report["name"] == "Playtest Walkthrough" for report in detail["reports"]))
            self.assertIn(detail["playtest"]["status"], {"passed", "warning"})
            self.assertTrue(detail["playtest"]["learner_entrypoints"])
            self.assertEqual(detail["pipeline_gate"]["decision"], "release-candidate")
            self.assertTrue(detail["pipeline_gate"]["ready_for_supervisor"])
            self.assertTrue(detail["pipeline_gate"]["ready_for_release_gate"])
            self.assertEqual(
                {item["name"]: item["status"] for item in detail["pipeline_gate"]["items"]}.get("human-playability"),
                "passed",
            )
            self.assertTrue(detail["pipeline_gate"]["next_commands"])
            solver_plan_path = workspace / scenario_id / "playtest" / "solver-plan.json"
            self.assertTrue(solver_plan_path.exists())
            solver_data = json.loads(solver_plan_path.read_text(encoding="utf-8"))
            self.assertTrue(any(step["action_type"] == "vulnerability-behavior" for step in solver_data["steps"]))

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
                    "vulnerability-coverage-strict": "passed",
                    "industry-realism-review": "passed",
                    "provider-build": "passed",
                    "learner-experience-strict": "passed",
                    "learner-playtest-evidence": "passed",
                    "e2e-solver-evidence": "passed",
                },
            )
            self.assertTrue((workspace / scenario_id / "release-gate" / "learner-playtest" / "solver-run" / "solver-run.yaml").exists())
            self.assertTrue((workspace / scenario_id / "release-gate" / "learner-playtest" / "access-playtest" / "access-playtest.yaml").exists())
            self.assertTrue((workspace / scenario_id / "release-gate" / "vulnerability-coverage" / "vulnerability-coverage.md").exists())
            self.assertTrue((workspace / scenario_id / "release-gate" / "vulnerability-coverage" / "vulnerability-coverage.json").exists())
            self.assertTrue((workspace / scenario_id / "release-gate" / "e2e-solver" / "e2e-solver.md").exists())
            self.assertTrue((workspace / scenario_id / "release-gate" / "e2e-solver" / "host-preflight.json").exists())

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

    def test_verified_mvp_manifest_marks_scaffold_when_live_e2e_is_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            manifest = write_verified_mvp_manifest(
                out,
                {
                    "scenario_id": "dry-run-smoke",
                    "title": "Dry Run Smoke",
                    "industry": "enterprise",
                    "release_gate": {
                        "release_ready": True,
                        "checks": [
                            {
                                "name": "e2e-solver-evidence",
                                "status": "passed",
                                "messages": [
                                    "mode=dry-run",
                                    "execute=false",
                                    "browser_engine=none",
                                    "execute_tunnels=false",
                                    "live_readiness=not-run",
                                    "executed_access_passed=0",
                                    "executed_solver_passed=0",
                                ],
                            }
                        ],
                    },
                },
            )

            self.assertEqual(manifest["status"], "verified-scaffold")
            self.assertEqual(manifest["verification_level"], "scaffold")
            self.assertFalse(manifest["playable_by_learner"])
            self.assertEqual(manifest["live_execution"]["status"], "planned")
            markdown = (out / "mvp" / "verified-mvp.md").read_text(encoding="utf-8")
            self.assertIn("This package is not yet live-verified", markdown)

    def test_verified_mvp_manifest_marks_live_when_browser_terminal_solver_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            manifest = write_verified_mvp_manifest(
                out,
                {
                    "scenario_id": "live-smoke",
                    "title": "Live Smoke",
                    "industry": "enterprise",
                    "release_gate": {
                        "release_ready": True,
                        "checks": [
                            {
                                "name": "e2e-solver-evidence",
                                "status": "passed",
                                "messages": [
                                    "mode=execute",
                                    "execute=true",
                                    "browser_engine=playwright",
                                    "execute_tunnels=true",
                                    "live_readiness=passed",
                                    "executed_access_passed=3",
                                    "executed_solver_passed=8",
                                ],
                            }
                        ],
                    },
                },
            )

            self.assertEqual(manifest["status"], "live-verified")
            self.assertEqual(manifest["verification_level"], "live")
            self.assertTrue(manifest["playable_by_learner"])
            self.assertEqual(manifest["live_execution"]["status"], "passed")
            self.assertEqual(manifest["live_execution"]["browser_engine"], "playwright")

    def test_studio_release_gate_forwards_live_e2e_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            scenario = workspace / "live-options"
            lab = scenario / "lab"
            lab.mkdir(parents=True)
            (lab / "scenario.yaml").write_text(
                "lab_id: live-options\n"
                "title: Live Options\n"
                "target_industry: enterprise\n"
                "services: []\n"
                "stages: []\n",
                encoding="utf-8",
            )

            def fake_release_gate(*_args, **kwargs):
                self.assertTrue(kwargs["execute_e2e"])
                self.assertTrue(kwargs["cleanup_e2e"])
                self.assertTrue(kwargs["execute_tunnels"])
                self.assertEqual(kwargs["browser_engine"], "playwright")
                return ReleaseGateReport(
                    lab_id="live-options",
                    provider=kwargs["provider"],
                    profile=kwargs["profile"],
                    status="passed",
                    release_ready=True,
                    output_dir=str(scenario / "release-gate"),
                    checks=[
                        QaCheck(
                            name="e2e-solver-evidence",
                            status="passed",
                            messages=[
                                "mode=execute",
                                "execute=true",
                                "browser_engine=playwright",
                                "execute_tunnels=true",
                                "live_readiness=passed",
                                "executed_access_passed=3",
                                "executed_solver_passed=8",
                            ],
                        )
                    ],
                )

            with patch("labforge.studio.run_release_gate", side_effect=fake_release_gate):
                detail = run_release_gate_for_scenario(
                    workspace,
                    "live-options",
                    {
                        "execute_e2e": True,
                        "cleanup_e2e": True,
                        "execute_tunnels": True,
                        "browser_engine": "playwright",
                    },
                )

            gate = detail["last_release_gate"]
            self.assertEqual(gate["status"], "passed")
            self.assertEqual(gate["checks"][0]["messages"][4], "live_readiness=passed")


if __name__ == "__main__":
    unittest.main()
