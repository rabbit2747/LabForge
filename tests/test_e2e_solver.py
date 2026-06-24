from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from labforge.e2e_solver import run_e2e_solver


class E2ESolverTests(unittest.TestCase):
    def test_e2e_solver_dry_run_plans_lifecycle_access_and_solver(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_output = root / "provider-output"
            provider_output.mkdir()
            (provider_output / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            solver_plan = root / "solver-plan.json"
            access_manifest = root / "learner-access.json"
            solver_plan.write_text(
                json.dumps(
                    {
                        "lab_id": "e2e-smoke",
                        "title": "E2E Smoke",
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
                                "learner_action": "Open learner portal.",
                                "expected_result": "Portal responds.",
                                "evidence": ["portal"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            access_manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "e2e-smoke",
                        "title": "E2E Smoke",
                        "learner_entrypoints": [
                            {"service": "portal", "protocol": "http", "connect": "http://127.0.0.1:18081/"}
                        ],
                        "attacker_entrypoints": [
                            {"service": "attacker-workstation", "protocol": "ssh", "connect": "ssh attacker@127.0.0.1 -p 2222"}
                        ],
                        "health_checks": [
                            {
                                "service": "portal",
                                "kind": "http-health",
                                "command": "curl -i http://127.0.0.1:18081/healthz",
                                "expected": "healthy",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = run_e2e_solver(provider_output, solver_plan, access_manifest, root / "e2e", execute=False)

            self.assertEqual(report.status, "planned")
            self.assertEqual([item.action for item in report.lifecycle], ["validate", "deploy", "status"])
            self.assertEqual(report.access_playtest.status, "planned")
            self.assertEqual(report.solver_run.status, "planned")
            self.assertTrue((root / "e2e" / "e2e-solver.md").exists())
            self.assertTrue((root / "e2e" / "e2e-solver.yaml").exists())
            self.assertTrue((root / "e2e" / "e2e-solver.json").exists())


if __name__ == "__main__":
    unittest.main()
