from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from labforge.cli import command_pipeline_verified_mvp
from labforge.cli import main
from labforge.implementation_plan import create_service_agent_packages
from labforge.io import dump_yaml, load_yaml, write_text
from labforge.model import LabSpec
from labforge.pipeline import live_access_readiness_gate_item, live_readiness_tasks_from_gate, PipelineGateReport, PipelineGateItem
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
    def test_live_access_readiness_gate_item_warns_without_core_browser_or_solver(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "lab-access-bundle.json"
            write_text(
                bundle,
                dump_yaml(
                    {
                        "live_readiness_requirements": [
                            {"name": "browser", "required": 0, "status": "missing"},
                            {"name": "final-submission", "required": 0, "status": "missing"},
                            {"name": "solver", "required": 0, "status": "missing"},
                        ]
                    }
                ),
            )

            item = live_access_readiness_gate_item(bundle)

            self.assertEqual(item.name, "live-access-readiness")
            self.assertEqual(item.status, "warning")
            self.assertIn("browser", item.required_action)
            self.assertIn("solver", item.required_action)
            self.assertTrue(any("controlled-drop" in evidence for evidence in item.evidence))

    def test_live_readiness_tasks_from_gate_convert_fix_hints_to_service_tasks(self) -> None:
        report = PipelineGateReport(
            workspace="C:/tmp/labforge-workspace",
            lab_dir="C:/tmp/labforge-workspace/lab",
            decision="needs-agent-work",
            items=[
                PipelineGateItem(
                    name="live-access-readiness",
                    status="warning",
                    evidence=[
                        "browser:required=1:status=declared",
                        "fix_hint=add a controlled-drop or submission service and expose its learner URL",
                    ],
                )
            ],
        )

        payload = live_readiness_tasks_from_gate(report)

        self.assertEqual(payload["status"], "pending")
        self.assertEqual(payload["tasks"][0]["assigned_agent"], "service-builder")
        self.assertIn("controlled-drop", payload["tasks"][0]["required_action"])
        self.assertTrue(any("--live-readiness-tasks" in command for command in payload["next_commands"]))

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
            self.assertTrue(any(report["name"] == "Live Readiness Tasks" for report in detail["reports"]))
            self.assertTrue((workspace / scenario_id / "live-readiness-tasks.json").exists())
            self.assertTrue((workspace / scenario_id / "live-readiness-tasks.md").exists())
            self.assertIn("live_readiness_tasks", detail)
            self.assertIn(detail["live_readiness_tasks"]["status"], {"pending", "no-tasks"})
            readiness_path = workspace / scenario_id / "live-readiness-tasks.json"
            readiness_payload = load_yaml(readiness_path)
            readiness_payload["tasks"] = [
                {
                    "task_id": "live-readiness-001",
                    "assigned_agent": "service-builder",
                    "severity": "warning",
                    "required_action": "publish an SSH-capable attacker workstation and terminal command sequence",
                    "expected_artifact": "learner-access.json and solver-plan.json evidence",
                }
            ]
            write_text(readiness_path, dump_yaml(readiness_payload))
            lab_dir = workspace / scenario_id / "lab"
            service_agent_dir = workspace / scenario_id / "service-agents-live"
            create_service_agent_packages(
                LabSpec.load(lab_dir),
                service_agent_dir,
                live_readiness_tasks_path=readiness_path,
            )
            package_file = next((service_agent_dir / ".ai" / "service-build").glob("*.package.yaml"))
            package = load_yaml(package_file)
            self.assertTrue(package["task_manifest"]["live_readiness_tasks"])
            self.assertIn("Live Readiness Tasks", package["task_prompt"])
            self.assertTrue(any(str(item).endswith("live-readiness-tasks.json") for item in package["context_files"]))
            workflow = json.loads((workspace / scenario_id / "workflow" / "workflow-report.json").read_text(encoding="utf-8"))
            self.assertIn("live-readiness-tasks", {step["id"] for step in workflow["steps"]})
            self.assertIn(detail["playtest"]["status"], {"passed", "warning"})
            self.assertTrue(detail["playtest"]["learner_entrypoints"])
            self.assertEqual(detail["pipeline_gate"]["decision"], "release-candidate")
            self.assertTrue(detail["pipeline_gate"]["ready_for_supervisor"])
            self.assertTrue(detail["pipeline_gate"]["ready_for_release_gate"])
            self.assertEqual(
                {item["name"]: item["status"] for item in detail["pipeline_gate"]["items"]}.get("human-playability"),
                "passed",
            )
            self.assertEqual(
                {item["name"]: item["status"] for item in detail["pipeline_gate"]["items"]}.get("live-access-readiness"),
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
            self.assertEqual(gate["verification_level"], "scaffold")
            self.assertFalse(gate["live_verified"])
            self.assertEqual(gate["live_execution"]["status"], "planned")
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

    def test_verified_mvp_cli_forwards_live_e2e_options_to_release_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "live-cli"
            lab = out / "lab"
            lab.mkdir(parents=True)

            pipeline_result = SimpleNamespace(
                lab_dir=str(lab),
                status="complete",
                model_dump=lambda: {"status": "complete", "lab_dir": str(lab)},
            )
            release_gate = SimpleNamespace(
                status="passed",
                release_ready=True,
                verification_level="live",
                live_verified=True,
                model_dump=lambda: {"status": "passed", "release_ready": True},
            )

            def fake_release_gate(*_args, **kwargs):
                self.assertTrue(kwargs["execute_e2e"])
                self.assertTrue(kwargs["cleanup_e2e"])
                self.assertTrue(kwargs["execute_tunnels"])
                self.assertEqual(kwargs["e2e_timeout_seconds"], 321)
                self.assertEqual(kwargs["browser_engine"], "playwright")
                return release_gate

            args = SimpleNamespace(
                prompt="Create a realistic enterprise lab.",
                prompt_file=None,
                out=str(out),
                lab_id=None,
                title=None,
                industry="enterprise",
                difficulty="intermediate",
                provider="auto",
                release_provider="",
                profile="protected",
                adapter="manual",
                no_materialize=False,
                no_service_agents=False,
                execute_e2e=True,
                cleanup_e2e=True,
                execute_tunnels=True,
                e2e_timeout=321,
                browser_engine="playwright",
                require_live=False,
                force=True,
                format="text",
            )

            with (
                patch("labforge.cli.create_lab_pipeline", return_value=pipeline_result),
                patch("labforge.cli.run_release_gate", side_effect=fake_release_gate),
                patch("labforge.studio.read_scenario_detail", return_value={"scenario_id": "live-cli"}),
                patch("labforge.cli.write_verified_mvp_manifest", return_value={"status": "live-verified"}),
            ):
                code = command_pipeline_verified_mvp(args)

            self.assertEqual(code, 0)

    def test_verified_mvp_cli_require_live_fails_for_scaffold_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scaffold-cli"
            lab = out / "lab"
            lab.mkdir(parents=True)

            pipeline_result = SimpleNamespace(
                lab_dir=str(lab),
                status="complete",
                model_dump=lambda: {"status": "complete", "lab_dir": str(lab)},
            )
            release_gate = SimpleNamespace(
                status="passed",
                release_ready=True,
                verification_level="scaffold",
                live_verified=False,
                model_dump=lambda: {"status": "passed", "release_ready": True},
            )
            args = SimpleNamespace(
                prompt="Create a realistic enterprise lab.",
                prompt_file=None,
                out=str(out),
                lab_id=None,
                title=None,
                industry="enterprise",
                difficulty="intermediate",
                provider="auto",
                release_provider="",
                profile="protected",
                adapter="manual",
                no_materialize=False,
                no_service_agents=False,
                execute_e2e=False,
                cleanup_e2e=False,
                execute_tunnels=False,
                e2e_timeout=120,
                browser_engine="http",
                require_live=True,
                force=True,
                format="text",
            )

            with (
                patch("labforge.cli.create_lab_pipeline", return_value=pipeline_result),
                patch("labforge.cli.run_release_gate", return_value=release_gate),
                patch("labforge.studio.read_scenario_detail", return_value={"scenario_id": "scaffold-cli"}),
                patch(
                    "labforge.cli.write_verified_mvp_manifest",
                    return_value={
                        "status": "verified-scaffold",
                        "verification_level": "scaffold",
                        "live_blockers": ["live e2e execution was not enabled"],
                    },
                ),
            ):
                code = command_pipeline_verified_mvp(args)

            self.assertEqual(code, 1)

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
            self.assertIn("live e2e execution was not enabled", manifest["live_blockers"])
            markdown = (out / "mvp" / "verified-mvp.md").read_text(encoding="utf-8")
            self.assertIn("### Live Blockers", markdown)
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
            self.assertEqual(manifest["live_blockers"], [])

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
                    verification_level="live",
                    live_verified=True,
                    live_execution={
                        "status": "passed",
                        "mode": "execute",
                        "execute": True,
                        "browser_engine": "playwright",
                        "execute_tunnels": True,
                        "live_readiness": "passed",
                        "executed_access_passed": 3,
                        "executed_solver_passed": 8,
                    },
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
            self.assertTrue(gate["live_verified"])
            self.assertEqual(gate["verification_level"], "live")
            self.assertEqual(gate["checks"][0]["messages"][4], "live_readiness=passed")


if __name__ == "__main__":
    unittest.main()
