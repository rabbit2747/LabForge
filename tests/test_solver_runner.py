from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from labforge.solver_runner import run_solver_plan, ssh_batch_argv


class SolverRunnerTests(unittest.TestCase):
    def test_solver_runner_creates_dry_run_report_from_plan_and_access(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solver_plan = root / "solver-plan.json"
            access_manifest = root / "learner-access.json"
            solver_plan.write_text(
                json.dumps(
                    {
                        "lab_id": "solver-smoke",
                        "title": "Solver Smoke",
                        "provider": "docker-compose",
                        "profile": "protected",
                        "learner_start": "http://127.0.0.1:18081/",
                        "attacker_shell": "ssh attacker@127.0.0.1 -p 2222",
                        "final_submission": "http://127.0.0.1:18082/",
                        "steps": [
                            {
                                "order": 1,
                                "step_id": "access-01",
                                "action_type": "access",
                                "learner_action": "Open the portal.",
                                "expected_result": "Portal loads.",
                                "evidence": ["investor-portal: http://127.0.0.1:18081/"],
                            },
                            {
                                "order": 2,
                                "step_id": "plugin-investor-portal-ssti-preview",
                                "action_type": "vulnerability-behavior",
                                "service": "investor-portal",
                                "plugin": "ssti-preview",
                                "learner_action": "Test preview rendering.",
                                "expected_result": "Expression is rendered.",
                                "evidence": ["/labforge/scaffold/ssti-preview"],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            access_manifest.write_text(
                json.dumps(
                    {
                        "learner_entrypoints": [
                            {"service": "investor-portal", "protocol": "http", "connect": "http://127.0.0.1:18081/"}
                        ],
                        "attacker_entrypoints": [
                            {"service": "attacker-workstation", "protocol": "ssh", "connect": "ssh attacker@127.0.0.1 -p 2222"}
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = run_solver_plan(solver_plan, root / "solver-run", access_manifest=access_manifest, execute=False)

            self.assertEqual(report.status, "planned")
            self.assertEqual(report.browser_targets, ["http://127.0.0.1:18081/"])
            self.assertEqual(report.terminal_targets, ["ssh attacker@127.0.0.1 -p 2222"])
            self.assertEqual([step.status for step in report.steps], ["planned", "planned"])
            self.assertTrue((root / "solver-run" / "solver-run.md").exists())
            self.assertTrue((root / "solver-run" / "solver-run.yaml").exists())
            self.assertTrue((root / "solver-run" / "solver-run.json").exists())

    def test_ssh_batch_argv_adds_safe_noninteractive_options(self) -> None:
        argv = ssh_batch_argv("ssh attacker@127.0.0.1 -p 2222")

        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("StrictHostKeyChecking=no", argv)
        self.assertEqual(argv[-1], "true")


if __name__ == "__main__":
    unittest.main()
