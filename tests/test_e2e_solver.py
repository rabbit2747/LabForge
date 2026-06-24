from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from labforge.access_playtest import AccessPlaytestReport
from labforge.doctor import HostDoctorReport
from labforge.e2e_solver import run_e2e_solver
from labforge.provider_lifecycle import ProviderLifecycleResult
from labforge.qa import e2e_solver_release_check
from labforge.solver_runner import SolverRunReport


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

            def fake_e2e(*_args, **kwargs):
                self.assertEqual(kwargs.get("browser_engine"), "playwright")
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
                    browser_engine="playwright",
                )

            self.assertEqual(check.name, "e2e-solver-evidence")
            self.assertEqual(check.status, "failed")
            self.assertIn("execute=true", check.messages)
            self.assertIn("browser_engine=playwright", check.messages)

    def test_e2e_solver_execute_runs_lifecycle_access_solver_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_output = root / "provider-output"
            playtest = root / "playtest"
            out = root / "e2e"
            provider_output.mkdir()
            playtest.mkdir()
            solver_plan = playtest / "solver-plan.json"
            access_manifest = playtest / "learner-access.json"
            (provider_output / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            solver_plan.write_text(
                json.dumps(
                    {
                        "lab_id": "execute-smoke",
                        "title": "Execute Smoke",
                        "steps": [],
                    }
                ),
                encoding="utf-8",
            )
            access_manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "execute-smoke",
                        "title": "Execute Smoke",
                        "learner_entrypoints": [],
                        "attacker_entrypoints": [],
                        "health_checks": [],
                    }
                ),
                encoding="utf-8",
            )
            calls: list[tuple[str, bool]] = []

            def fake_lifecycle(*_args, **kwargs):
                calls.append((kwargs["action"], kwargs["execute"]))
                return ProviderLifecycleResult(
                    provider=kwargs["provider"],
                    action=kwargs["action"],
                    mode="execute",
                    status="completed",
                    output_dir=str(provider_output),
                    commands=[],
                    stdout="",
                    stderr="",
                    message="",
                )

            def fake_access(*_args, **kwargs):
                self.assertTrue(kwargs["execute"])
                return AccessPlaytestReport(
                    lab_id="execute-smoke",
                    title="Execute Smoke",
                    mode="execute",
                    status="passed",
                    access_manifest=str(access_manifest),
                    browser_targets=[],
                    terminal_targets=[],
                    items=[],
                )

            def fake_solver(*_args, **kwargs):
                self.assertTrue(kwargs["execute"])
                return SolverRunReport(
                    lab_id="execute-smoke",
                    title="Execute Smoke",
                    mode="execute",
                    status="passed",
                    solver_plan=str(solver_plan),
                    steps=[],
                )

            with patch("labforge.e2e_solver.provider_lifecycle", side_effect=fake_lifecycle), patch(
                "labforge.e2e_solver.run_access_playtest",
                side_effect=fake_access,
            ), patch("labforge.e2e_solver.run_solver_plan", side_effect=fake_solver):
                report = run_e2e_solver(
                    provider_output,
                    solver_plan,
                    access_manifest,
                    out,
                    execute=True,
                    cleanup=True,
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

            self.assertEqual(report.status, "passed")
            self.assertEqual(calls, [("validate", True), ("deploy", True), ("status", True), ("destroy", True)])
            self.assertTrue((out / "e2e-solver.md").exists())


if __name__ == "__main__":
    unittest.main()
