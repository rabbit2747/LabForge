from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from labforge.doctor import HostDoctorReport
from labforge.e2e_solver import run_e2e_solver
from labforge.qa import e2e_solver_release_check


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

            report = run_e2e_solver(
                provider_output,
                solver_plan,
                access_manifest,
                root / "e2e",
                execute=False,
                host_preflight=HostDoctorReport(
                    host_os="linux",
                    platform="test",
                    architecture="x86_64",
                    shell_hint="sh",
                    cwd=str(root),
                    wsl_available=False,
                    host_docker_cli=True,
                    host_docker_server=True,
                    recommended_execution="host",
                ),
            )

            self.assertEqual(report.status, "planned")
            self.assertIn("host_os", report.host_preflight)
            self.assertIn("recommended_execution", report.host_preflight)
            self.assertEqual([item.action for item in report.lifecycle], ["validate", "deploy", "status"])
            self.assertEqual(report.access_playtest.status, "planned")
            self.assertEqual(report.solver_run.status, "planned")
            self.assertTrue((root / "e2e" / "e2e-solver.md").exists())
            self.assertTrue((root / "e2e" / "e2e-solver.yaml").exists())
            self.assertTrue((root / "e2e" / "e2e-solver.json").exists())
            self.assertTrue((root / "e2e" / "host-preflight.md").exists())
            self.assertTrue((root / "e2e" / "host-preflight.json").exists())

    def test_release_gate_execute_e2e_requires_passed_solver_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_output = root / "provider-output"
            playtest = root / "learner-playtest"
            out = root / "e2e"
            provider_output.mkdir()
            playtest.mkdir()
            (provider_output / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (provider_output / "endpoints.json").write_text("{}\n", encoding="utf-8")
            (playtest / "solver-plan.json").write_text("{}\n", encoding="utf-8")
            (playtest / "learner-access.json").write_text("{}\n", encoding="utf-8")

            def fake_e2e(*_args, **_kwargs):
                for relative in (
                    "e2e-solver.md",
                    "e2e-solver.yaml",
                    "e2e-solver.json",
                    "host-preflight.md",
                    "host-preflight.json",
                    "access-playtest/access-playtest.yaml",
                    "solver-run/solver-run.yaml",
                ):
                    path = out / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("ok\n", encoding="utf-8")
                return SimpleNamespace(
                    status="warning",
                    mode="execute",
                    preflight_ready=True,
                    lifecycle=[],
                    access_playtest=SimpleNamespace(status="passed"),
                    solver_run=SimpleNamespace(status="warning"),
                )

            with patch("labforge.qa.run_e2e_solver", side_effect=fake_e2e):
                check = e2e_solver_release_check(
                    provider_output,
                    playtest,
                    out,
                    provider="docker-compose",
                    execute=True,
                )

            self.assertEqual(check.name, "e2e-solver-evidence")
            self.assertEqual(check.status, "failed")
            self.assertIn("execute=true", check.messages)


if __name__ == "__main__":
    unittest.main()
