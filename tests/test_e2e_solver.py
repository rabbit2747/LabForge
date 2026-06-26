from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from labforge.access_playtest import AccessPlaytestItem, AccessPlaytestReport
from labforge.doctor import HostDoctorReport
from labforge.e2e_solver import run_e2e_solver, validate_access_bundle, validate_execution_depth, validate_plugin_check_alignment
from labforge.provider_lifecycle import ProviderLifecycleResult
from labforge.qa import e2e_solver_release_check
from labforge.solver_runner import SolverRunReport, SolverRunStep


class FakeTunnelProcess:
    def __init__(self) -> None:
        self.terminated = False
        self.killed = False

    def poll(self):
        return None if not self.terminated and not self.killed else 0

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self) -> None:
        self.killed = True

    def communicate(self, timeout=None):
        return ("", "")


class E2ESolverTests(unittest.TestCase):
    def test_access_bundle_validation_flags_missing_playability_material(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_output = root / "provider-output"
            provider_output.mkdir()
            (provider_output / "endpoints.json").write_text("{}\n", encoding="utf-8")
            solver_plan = root / "solver-plan.json"
            access_manifest = root / "learner-access.json"
            access_bundle = root / "lab-access-bundle.json"
            solver_plan.write_text(
                json.dumps(
                    {
                        "steps": [
                            {
                                "step_id": "plugin-support-portal-ssti-preview",
                                "action_type": "vulnerability-behavior",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            access_manifest.write_text(
                json.dumps(
                    {
                        "attacker_entrypoints": [
                            {
                                "service": "attacker-workstation",
                                "protocol": "ssh",
                                "connect": "ssh attacker@127.0.0.1 -p 2222",
                            }
                        ],
                        "internal_targets": [
                            {"service": "wiki", "dns": "wiki", "expose": ["6000"]}
                        ],
                        "terminal_sequences": [],
                        "tunnel_commands": [],
                        "plugin_checks": [],
                    }
                ),
                encoding="utf-8",
            )
            access_bundle.write_text(
                json.dumps(
                    {
                        "generated_files": {
                            "provider_endpoints": str((provider_output / "endpoints.json").resolve()),
                            "learner_access_json": str(access_manifest.resolve()),
                            "solver_plan_json": str(solver_plan.resolve()),
                        },
                        "learner_urls": [],
                        "attacker_ssh": ["ssh attacker@127.0.0.1 -p 2222"],
                        "final_submission_urls": [],
                        "terminal_sequences": [
                            {
                                "service": "attacker-workstation",
                                "connect": "ssh attacker@127.0.0.1 -p 2222",
                                "commands": ["echo labforge-terminal-ready", "pwd"],
                                "expected_texts": ["labforge-terminal-ready"],
                            }
                        ],
                        "published_endpoints": [
                            {
                                "service": "attacker-workstation",
                                "protocol": "ssh",
                                "connect": "ssh attacker@127.0.0.1 -p 2222",
                            }
                        ],
                        "internal_targets": [{"service": "wiki", "dns": "wiki", "expose": ["6000"]}],
                        "tunnel_commands": [],
                        "plugin_checks": [],
                        "solver_ready": True,
                    }
                ),
                encoding="utf-8",
            )

            findings = validate_access_bundle(access_bundle, provider_output, solver_plan, access_manifest)

            joined = " ".join(findings)
            self.assertIn("missing=terminal_sequences_for_attacker_ssh", joined)
            self.assertIn("missing=tunnel_commands_for_internal_targets", joined)
            self.assertIn("missing=plugin_checks_for_vulnerability_steps", joined)

    def test_e2e_solver_dry_run_plans_lifecycle_access_and_solver(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_output = root / "provider-output"
            provider_output.mkdir()
            (provider_output / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            solver_plan = root / "solver-plan.json"
            access_manifest = root / "learner-access.json"
            access_bundle = root / "lab-access-bundle.json"
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
            access_bundle.write_text(
                json.dumps(
                    {
                        "lab_id": "e2e-smoke",
                        "title": "E2E Smoke",
                        "provider_output_dir": str(provider_output.resolve()),
                        "learner_urls": ["http://127.0.0.1:18081/"],
                        "attacker_ssh": ["ssh attacker@127.0.0.1 -p 2222"],
                        "final_submission_urls": [],
                        "published_endpoints": [
                            {
                                "service": "portal",
                                "protocol": "http",
                                "connect": "http://127.0.0.1:18081/",
                                "default_host_port": None,
                                "container_port": "",
                                "override_env": "",
                            },
                            {
                                "service": "attacker-workstation",
                                "protocol": "ssh",
                                "connect": "ssh attacker@127.0.0.1 -p 2222",
                                "default_host_port": None,
                                "container_port": "",
                                "override_env": "",
                            },
                        ],
                        "generated_files": {
                            "provider_endpoints": str((provider_output / "endpoints.json").resolve()),
                            "learner_access_json": str(access_manifest.resolve()),
                            "solver_plan_json": str(solver_plan.resolve()),
                        },
                        "solver_ready": True,
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
                        "terminal_sequences": [
                            {
                                "service": "attacker-workstation",
                                "connect": "ssh attacker@127.0.0.1 -p 2222",
                                "commands": ["echo labforge-terminal-ready", "pwd"],
                                "expected_texts": ["labforge-terminal-ready"],
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
            self.assertEqual(report.execution_proof["mode"], "dry-run")
            self.assertEqual(report.execution_proof["live_readiness"]["status"], "planned")
            self.assertGreaterEqual(report.execution_proof["access"]["planned"], 1)
            self.assertGreaterEqual(report.execution_proof["solver"]["planned"], 1)
            self.assertTrue(report.access_bundle_ready)
            self.assertIn("access_bundle=ready", report.access_bundle_findings)
            self.assertTrue((root / "e2e" / "e2e-solver.md").exists())
            self.assertIn("Execution Proof Summary", (root / "e2e" / "e2e-solver.md").read_text(encoding="utf-8"))
            self.assertTrue((root / "e2e" / "e2e-solver.yaml").exists())
            self.assertTrue((root / "e2e" / "e2e-solver.json").exists())
            self.assertTrue((root / "e2e" / "host-preflight.md").exists())
            self.assertTrue((root / "e2e" / "host-preflight.json").exists())

    def test_validate_execution_depth_requires_passed_plugin_and_stage_chain_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solver_plan = root / "solver-plan.json"
            access_manifest = root / "learner-access.json"
            solver_plan.write_text(
                json.dumps(
                    {
                        "steps": [
                            {
                                "step_id": "plugin-support-portal-ssti-preview",
                                "action_type": "vulnerability-behavior",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            access_manifest.write_text(
                json.dumps(
                    {
                        "plugin_checks": [
                            {
                                "step_id": "plugin-support-portal-ssti-preview",
                                "service": "support-portal",
                                "plugin": "ssti-preview",
                            }
                        ],
                        "stage_chain_checks": [
                            {
                                "service": "wiki",
                                "chain_url": "http://127.0.0.1:18080/api/chain",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            access_report = AccessPlaytestReport(
                lab_id="depth",
                title="Depth",
                mode="execute",
                status="warning",
                access_manifest=str(access_manifest),
                items=[
                    AccessPlaytestItem(
                        check_id="plugin-evidence-01",
                        service="support-portal",
                        kind="plugin-evidence",
                        command="GET /api/state",
                        status="warning",
                    ),
                    AccessPlaytestItem(
                        check_id="stage-chain-01",
                        service="wiki",
                        kind="stage-chain",
                        command="GET /api/chain",
                        status="passed",
                    ),
                ],
            )
            solver_report = SolverRunReport(
                lab_id="depth",
                title="Depth",
                mode="execute",
                status="passed",
                solver_plan=str(solver_plan),
                steps=[
                    SolverRunStep(
                        order=1,
                        step_id="plugin-support-portal-ssti-preview",
                        action_type="vulnerability-behavior",
                        status="passed",
                    )
                ],
            )

            findings = validate_execution_depth(
                solver_plan,
                access_manifest,
                access_report,
                solver_report,
                execute=True,
            )

            joined = " ".join(findings)
            self.assertIn("plugin_checks=expected:1:actual:1:passed:0", joined)
            self.assertIn("missing=plugin_checks_passed:1", joined)
            self.assertIn("stage_chain_checks=expected:1:actual:1:passed:1", joined)

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
            self.assertIn("live_readiness=missing", check.messages)

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
            access_bundle = playtest / "lab-access-bundle.json"
            (provider_output / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (provider_output / "endpoints.json").write_text("{}\n", encoding="utf-8")
            solver_plan.write_text(
                json.dumps(
                    {
                        "lab_id": "execute-smoke",
                        "title": "Execute Smoke",
                        "steps": [
                            {
                                "order": 1,
                                "step_id": "access-01",
                                "action_type": "access",
                                "evidence": ["portal_reachable"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            access_bundle.write_text(
                json.dumps(
                    {
                        "lab_id": "execute-smoke",
                        "title": "Execute Smoke",
                        "provider_output_dir": str(provider_output.resolve()),
                        "learner_urls": [],
                        "attacker_ssh": [],
                        "final_submission_urls": [],
                        "published_endpoints": [],
                        "generated_files": {
                            "provider_endpoints": str((provider_output / "endpoints.json").resolve()),
                            "learner_access_json": str(access_manifest.resolve()),
                            "solver_plan_json": str(solver_plan.resolve()),
                        },
                        "solver_ready": True,
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
                        "health_checks": [
                            {
                                "service": "portal",
                                "kind": "http-health",
                                "command": "curl -i http://127.0.0.1:18081/healthz",
                                "expected": "healthy",
                            }
                        ],
                        "stage_chain_checks": [
                            {
                                "service": "portal",
                                "from_stage": "stage-01",
                                "to_stage": "stage-02",
                                "chain_url": "http://127.0.0.1:18081/api/chain",
                                "stage_url": "http://127.0.0.1:18081/api/stages/stage-02",
                                "expected_stage": "stage-02",
                                "expected_from_stage": "stage-01",
                                "expected_evidence": ["portal_reachable"],
                            }
                        ],
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
                    items=[
                        AccessPlaytestItem(
                            check_id="health-01",
                            service="portal",
                            kind="http-health",
                            command="curl -i http://127.0.0.1:18081/healthz",
                            status="passed",
                        ),
                        AccessPlaytestItem(
                            check_id="stage-chain-01",
                            service="portal",
                            kind="stage-chain",
                            command="GET http://127.0.0.1:18081/api/chain; GET http://127.0.0.1:18081/api/stages/stage-02",
                            status="passed",
                        )
                    ],
                )

            def fake_solver(*_args, **kwargs):
                self.assertTrue(kwargs["execute"])
                return SolverRunReport(
                    lab_id="execute-smoke",
                    title="Execute Smoke",
                    mode="execute",
                    status="passed",
                    solver_plan=str(solver_plan),
                    steps=[
                        SolverRunStep(
                            order=1,
                            step_id="access-01",
                            action_type="access",
                            status="passed",
                            evidence=["portal_reachable"],
                        )
                    ],
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
            self.assertTrue(report.access_bundle_ready)
            self.assertEqual(report.execution_proof["mode"], "execute")
            self.assertEqual(report.execution_proof["live_readiness"]["status"], "passed")
            self.assertIn("stage_chain_checks=1; passed_stage_chain_checks=1", report.execution_proof["live_readiness"]["requirements"])
            self.assertIn("solver_steps=1; passed_solver_steps=1", report.execution_proof["live_readiness"]["requirements"])
            self.assertEqual(report.execution_proof["access"]["passed"], 2)
            self.assertEqual(report.execution_proof["stage_chain_checks"]["passed"], 1)
            self.assertEqual(report.execution_proof["solver"]["passed"], 1)
            self.assertEqual(report.execution_proof["failed_or_warning"], [])
            self.assertIn("access_checks=expected:2:actual:2", report.execution_depth_findings)
            self.assertIn("solver_steps=expected:1:actual:1", report.execution_depth_findings)
            self.assertEqual(calls, [("validate", True), ("deploy", True), ("status", True), ("destroy", True)])
            self.assertTrue((out / "e2e-solver.md").exists())
            self.assertIn("Stage-chain evidence", (out / "e2e-solver.md").read_text(encoding="utf-8"))

    def test_e2e_solver_execute_fails_when_reports_do_not_cover_declared_steps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_output = root / "provider-output"
            playtest = root / "playtest"
            out = root / "e2e"
            provider_output.mkdir()
            playtest.mkdir()
            solver_plan = playtest / "solver-plan.json"
            access_manifest = playtest / "learner-access.json"
            access_bundle = playtest / "lab-access-bundle.json"
            (provider_output / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (provider_output / "endpoints.json").write_text("{}\n", encoding="utf-8")
            solver_plan.write_text(
                json.dumps(
                    {
                        "lab_id": "execute-depth",
                        "title": "Execute Depth",
                        "steps": [
                            {"order": 1, "step_id": "access-01", "action_type": "access"},
                            {"order": 2, "step_id": "plugin-portal-ssti-preview", "action_type": "vulnerability-behavior"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            access_bundle.write_text(
                json.dumps(
                    {
                        "lab_id": "execute-depth",
                        "title": "Execute Depth",
                        "provider_output_dir": str(provider_output.resolve()),
                        "learner_urls": ["http://127.0.0.1:18081/"],
                        "attacker_ssh": [],
                        "final_submission_urls": [],
                        "published_endpoints": [
                            {
                                "service": "portal",
                                "protocol": "http",
                                "connect": "http://127.0.0.1:18081/",
                                "default_host_port": None,
                                "container_port": "",
                                "override_env": "",
                            },
                        ],
                        "generated_files": {
                            "provider_endpoints": str((provider_output / "endpoints.json").resolve()),
                            "learner_access_json": str(access_manifest.resolve()),
                            "solver_plan_json": str(solver_plan.resolve()),
                        },
                        "solver_ready": True,
                    }
                ),
                encoding="utf-8",
            )
            access_manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "execute-depth",
                        "title": "Execute Depth",
                        "learner_entrypoints": [
                            {"service": "portal", "protocol": "http", "connect": "http://127.0.0.1:18081/"}
                        ],
                        "attacker_entrypoints": [],
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

            def fake_lifecycle(*_args, **kwargs):
                return ProviderLifecycleResult(
                    provider=kwargs["provider"],
                    action=kwargs["action"],
                    mode="execute",
                    status="completed",
                    output_dir=str(provider_output),
                )

            def fake_access(*_args, **_kwargs):
                return AccessPlaytestReport(
                    lab_id="execute-depth",
                    title="Execute Depth",
                    mode="execute",
                    status="passed",
                    access_manifest=str(access_manifest),
                    items=[],
                )

            def fake_solver(*_args, **_kwargs):
                return SolverRunReport(
                    lab_id="execute-depth",
                    title="Execute Depth",
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

            self.assertEqual(report.status, "failed")
            self.assertIn("missing=access_checks:2", report.execution_depth_findings)
            self.assertIn("missing=solver_steps:2", report.execution_depth_findings)
            self.assertIn("missing=plugin_checks_for_solver_steps:plugin-portal-ssti-preview", report.execution_depth_findings)

    def test_e2e_solver_aligns_plugin_checks_with_solver_vulnerability_steps(self) -> None:
        solver_plan = {
            "steps": [
                {"step_id": "access-01", "action_type": "access"},
                {"step_id": "plugin-portal-ssti-preview", "action_type": "vulnerability-behavior"},
                {"step_id": "plugin-api-jwt-role-confusion", "action_type": "vulnerability-behavior"},
            ]
        }
        access_manifest = {
            "plugin_checks": [
                {"step_id": "plugin-portal-ssti-preview"},
                {"step_id": "plugin-old-unused-check"},
            ]
        }

        findings = validate_plugin_check_alignment(solver_plan, access_manifest)

        self.assertIn("missing=plugin_checks_for_solver_steps:plugin-api-jwt-role-confusion", findings)
        self.assertIn("mismatch=plugin_checks_without_solver_steps:plugin-old-unused-check", findings)

    def test_e2e_solver_accepts_aligned_plugin_checks(self) -> None:
        solver_plan = {
            "steps": [
                {"step_id": "plugin-portal-ssti-preview", "action_type": "vulnerability-behavior"},
                {"step_id": "plugin-api-jwt-role-confusion", "action_type": "vulnerability-behavior"},
            ]
        }
        access_manifest = {
            "plugin_checks": [
                {"step_id": "plugin-portal-ssti-preview"},
                {"step_id": "plugin-api-jwt-role-confusion"},
            ]
        }

        self.assertEqual(validate_plugin_check_alignment(solver_plan, access_manifest), [])

    def test_e2e_solver_warns_when_access_bundle_does_not_match_access_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_output = root / "provider-output"
            provider_output.mkdir()
            (provider_output / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (provider_output / "endpoints.json").write_text("{}\n", encoding="utf-8")
            solver_plan = root / "solver-plan.json"
            access_manifest = root / "learner-access.json"
            (root / "lab-access-bundle.json").write_text(
                json.dumps(
                    {
                        "lab_id": "bundle-mismatch",
                        "title": "Bundle Mismatch",
                        "learner_urls": ["http://127.0.0.1:19999/"],
                        "attacker_ssh": [],
                        "final_submission_urls": [],
                        "generated_files": {
                            "provider_endpoints": str((provider_output / "endpoints.json").resolve()),
                            "learner_access_json": str(access_manifest.resolve()),
                            "solver_plan_json": str(solver_plan.resolve()),
                        },
                        "solver_ready": True,
                    }
                ),
                encoding="utf-8",
            )
            solver_plan.write_text(
                json.dumps({"lab_id": "bundle-mismatch", "title": "Bundle Mismatch", "steps": []}),
                encoding="utf-8",
            )
            access_manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "bundle-mismatch",
                        "title": "Bundle Mismatch",
                        "learner_entrypoints": [
                            {"service": "portal", "protocol": "http", "connect": "http://127.0.0.1:18081/"}
                        ],
                        "attacker_entrypoints": [],
                        "final_submission_endpoints": [],
                        "health_checks": [],
                    }
                ),
                encoding="utf-8",
            )

            def fake_lifecycle(*_args, **kwargs):
                return ProviderLifecycleResult(
                    provider=kwargs["provider"],
                    action=kwargs["action"],
                    mode="execute",
                    status="completed",
                    output_dir=str(provider_output),
                )

            def fake_access(*_args, **_kwargs):
                return AccessPlaytestReport(
                    lab_id="bundle-mismatch",
                    title="Bundle Mismatch",
                    mode="execute",
                    status="passed",
                    access_manifest=str(access_manifest),
                    items=[
                        AccessPlaytestItem(
                            check_id="browser-01",
                            service="portal",
                            kind="browser-http",
                            command="GET http://127.0.0.1:18081/",
                            status="passed",
                        )
                    ],
                )

            def fake_solver(*_args, **_kwargs):
                return SolverRunReport(
                    lab_id="bundle-mismatch",
                    title="Bundle Mismatch",
                    mode="execute",
                    status="passed",
                    solver_plan=str(solver_plan),
                )

            with patch("labforge.e2e_solver.provider_lifecycle", side_effect=fake_lifecycle), patch(
                "labforge.e2e_solver.run_access_playtest",
                side_effect=fake_access,
            ), patch("labforge.e2e_solver.run_solver_plan", side_effect=fake_solver):
                report = run_e2e_solver(
                    provider_output,
                    solver_plan,
                    access_manifest,
                    root / "e2e",
                    execute=True,
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

            self.assertEqual(report.status, "warning")
            self.assertFalse(report.access_bundle_ready)
            self.assertTrue(any(item.startswith("mismatch=learner_urls") for item in report.access_bundle_findings))

    def test_e2e_solver_warns_when_internal_targets_do_not_match_access_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_output = root / "provider-output"
            provider_output.mkdir()
            (provider_output / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (provider_output / "endpoints.json").write_text("{}\n", encoding="utf-8")
            solver_plan = root / "solver-plan.json"
            access_manifest = root / "learner-access.json"
            (root / "lab-access-bundle.json").write_text(
                json.dumps(
                    {
                        "lab_id": "internal-target-mismatch",
                        "title": "Internal Target Mismatch",
                        "learner_urls": [],
                        "attacker_ssh": [],
                        "final_submission_urls": [],
                        "published_endpoints": [],
                        "internal_targets": [
                            {"service": "wiki", "dns": "wiki", "expose": ["6001"]},
                        ],
                        "generated_files": {
                            "provider_endpoints": str((provider_output / "endpoints.json").resolve()),
                            "learner_access_json": str(access_manifest.resolve()),
                            "solver_plan_json": str(solver_plan.resolve()),
                        },
                        "solver_ready": True,
                    }
                ),
                encoding="utf-8",
            )
            solver_plan.write_text(
                json.dumps({"lab_id": "internal-target-mismatch", "title": "Internal Target Mismatch", "steps": []}),
                encoding="utf-8",
            )
            access_manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "internal-target-mismatch",
                        "title": "Internal Target Mismatch",
                        "learner_entrypoints": [],
                        "attacker_entrypoints": [],
                        "final_submission_endpoints": [],
                        "internal_targets": [
                            {"service": "wiki", "dns": "wiki", "expose": ["6000"]},
                        ],
                        "health_checks": [],
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
            self.assertFalse(report.access_bundle_ready)
            self.assertTrue(any(item.startswith("mismatch=internal_targets") for item in report.access_bundle_findings))

    def test_e2e_solver_warns_when_tunnel_commands_do_not_match_access_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_output = root / "provider-output"
            provider_output.mkdir()
            (provider_output / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (provider_output / "endpoints.json").write_text("{}\n", encoding="utf-8")
            solver_plan = root / "solver-plan.json"
            access_manifest = root / "learner-access.json"
            (root / "lab-access-bundle.json").write_text(
                json.dumps(
                    {
                        "lab_id": "tunnel-mismatch",
                        "title": "Tunnel Mismatch",
                        "learner_urls": [],
                        "attacker_ssh": [],
                        "final_submission_urls": [],
                        "published_endpoints": [],
                        "internal_targets": [],
                        "tunnel_commands": [
                            {
                                "service": "wiki",
                                "dns": "wiki",
                                "internal_port": "6000",
                                "local_port": 18181,
                                "command": "ssh -L 18181:wiki:6000 attacker@127.0.0.1 -p 2222",
                                "url": "http://127.0.0.1:18181/",
                            }
                        ],
                        "generated_files": {
                            "provider_endpoints": str((provider_output / "endpoints.json").resolve()),
                            "learner_access_json": str(access_manifest.resolve()),
                            "solver_plan_json": str(solver_plan.resolve()),
                        },
                        "solver_ready": True,
                    }
                ),
                encoding="utf-8",
            )
            solver_plan.write_text(json.dumps({"lab_id": "tunnel-mismatch", "title": "Tunnel Mismatch", "steps": []}), encoding="utf-8")
            access_manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "tunnel-mismatch",
                        "title": "Tunnel Mismatch",
                        "learner_entrypoints": [],
                        "attacker_entrypoints": [],
                        "final_submission_endpoints": [],
                        "internal_targets": [],
                        "tunnel_commands": [
                            {
                                "service": "wiki",
                                "dns": "wiki",
                                "internal_port": "6000",
                                "local_port": 18080,
                                "command": "ssh -L 18080:wiki:6000 attacker@127.0.0.1 -p 2222",
                                "url": "http://127.0.0.1:18080/",
                            }
                        ],
                        "health_checks": [],
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

            self.assertFalse(report.access_bundle_ready)
            self.assertTrue(any(item.startswith("mismatch=tunnel_commands") for item in report.access_bundle_findings))

    def test_e2e_solver_execute_keeps_tunnel_alive_for_solver_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_output = root / "provider-output"
            playtest = root / "playtest"
            out = root / "e2e"
            provider_output.mkdir()
            playtest.mkdir()
            solver_plan = playtest / "solver-plan.json"
            access_manifest = playtest / "learner-access.json"
            access_bundle = playtest / "lab-access-bundle.json"
            tunnel_process = FakeTunnelProcess()
            (provider_output / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (provider_output / "endpoints.json").write_text("{}\n", encoding="utf-8")
            solver_plan.write_text(
                json.dumps(
                    {
                        "lab_id": "persistent-tunnel",
                        "title": "Persistent Tunnel",
                        "steps": [{"order": 1, "step_id": "wiki-01", "action_type": "access"}],
                    }
                ),
                encoding="utf-8",
            )
            tunnel_record = {
                "service": "wiki",
                "dns": "wiki",
                "internal_port": "6000",
                "local_port": 18080,
                "command": "ssh -L 18080:wiki:6000 attacker@127.0.0.1 -p 2222",
                "url": "http://127.0.0.1:18080/",
            }
            access_bundle.write_text(
                json.dumps(
                    {
                        "lab_id": "persistent-tunnel",
                        "title": "Persistent Tunnel",
                        "learner_urls": [],
                        "attacker_ssh": [],
                        "final_submission_urls": [],
                        "published_endpoints": [],
                        "internal_targets": [],
                        "tunnel_commands": [tunnel_record],
                        "generated_files": {
                            "provider_endpoints": str((provider_output / "endpoints.json").resolve()),
                            "learner_access_json": str(access_manifest.resolve()),
                            "solver_plan_json": str(solver_plan.resolve()),
                        },
                        "solver_ready": True,
                    }
                ),
                encoding="utf-8",
            )
            access_manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "persistent-tunnel",
                        "title": "Persistent Tunnel",
                        "learner_entrypoints": [],
                        "attacker_entrypoints": [],
                        "final_submission_endpoints": [],
                        "internal_targets": [],
                        "tunnel_commands": [tunnel_record],
                    }
                ),
                encoding="utf-8",
            )

            def fake_lifecycle(*_args, **kwargs):
                return ProviderLifecycleResult(
                    provider=kwargs["provider"],
                    action=kwargs["action"],
                    mode="execute",
                    status="completed",
                    output_dir=str(provider_output),
                )

            def fake_access(*_args, **kwargs):
                self.assertTrue(kwargs["execute"])
                self.assertFalse(kwargs["execute_tunnels"])
                self.assertFalse(tunnel_process.terminated)
                return AccessPlaytestReport(
                    lab_id="persistent-tunnel",
                    title="Persistent Tunnel",
                    mode="execute",
                    status="passed",
                    access_manifest=str(access_manifest),
                    items=[
                        AccessPlaytestItem(
                            check_id="tunnel-01",
                            service="wiki",
                            kind="ssh-local-forward",
                            command=tunnel_record["command"],
                            status="passed",
                        )
                    ],
                )

            def fake_solver(*_args, **kwargs):
                self.assertTrue(kwargs["execute"])
                self.assertFalse(tunnel_process.terminated)
                return SolverRunReport(
                    lab_id="persistent-tunnel",
                    title="Persistent Tunnel",
                    mode="execute",
                    status="passed",
                    solver_plan=str(solver_plan),
                    steps=[SolverRunStep(order=1, step_id="wiki-01", action_type="access", status="passed")],
                )

            with patch("labforge.e2e_solver.provider_lifecycle", side_effect=fake_lifecycle), patch(
                "labforge.e2e_solver.shutil.which",
                return_value="ssh",
            ), patch("labforge.e2e_solver.subprocess.Popen", return_value=tunnel_process), patch(
                "labforge.e2e_solver.wait_for_tcp_port",
                return_value=True,
            ), patch("labforge.e2e_solver.run_access_playtest", side_effect=fake_access), patch(
                "labforge.e2e_solver.run_solver_plan",
                side_effect=fake_solver,
            ):
                report = run_e2e_solver(
                    provider_output,
                    solver_plan,
                    access_manifest,
                    out,
                    execute=True,
                    execute_tunnels=True,
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
            self.assertEqual(report.persistent_tunnels[0].status, "passed")
            self.assertTrue(tunnel_process.terminated)
            self.assertIn("Persistent Tunnels", (out / "e2e-solver.md").read_text(encoding="utf-8"))

    def test_e2e_solver_execute_fails_when_persistent_tunnel_does_not_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider_output = root / "provider-output"
            playtest = root / "playtest"
            out = root / "e2e"
            provider_output.mkdir()
            playtest.mkdir()
            solver_plan = playtest / "solver-plan.json"
            access_manifest = playtest / "learner-access.json"
            access_bundle = playtest / "lab-access-bundle.json"
            tunnel_process = FakeTunnelProcess()
            (provider_output / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (provider_output / "endpoints.json").write_text("{}\n", encoding="utf-8")
            solver_plan.write_text(
                json.dumps(
                    {
                        "lab_id": "persistent-tunnel-fail",
                        "title": "Persistent Tunnel Fail",
                        "steps": [{"order": 1, "step_id": "wiki-01", "action_type": "access"}],
                    }
                ),
                encoding="utf-8",
            )
            tunnel_record = {
                "service": "wiki",
                "dns": "wiki",
                "internal_port": "6000",
                "local_port": 18080,
                "command": "ssh -L 18080:wiki:6000 attacker@127.0.0.1 -p 2222",
                "url": "http://127.0.0.1:18080/",
            }
            bundle = {
                "lab_id": "persistent-tunnel-fail",
                "title": "Persistent Tunnel Fail",
                "learner_urls": [],
                "attacker_ssh": [],
                "final_submission_urls": [],
                "published_endpoints": [],
                "internal_targets": [],
                "tunnel_commands": [tunnel_record],
                "generated_files": {
                    "provider_endpoints": str((provider_output / "endpoints.json").resolve()),
                    "learner_access_json": str(access_manifest.resolve()),
                    "solver_plan_json": str(solver_plan.resolve()),
                },
                "solver_ready": True,
            }
            access_bundle.write_text(json.dumps(bundle), encoding="utf-8")
            access_manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "persistent-tunnel-fail",
                        "title": "Persistent Tunnel Fail",
                        "learner_entrypoints": [],
                        "attacker_entrypoints": [],
                        "final_submission_endpoints": [],
                        "internal_targets": [],
                        "tunnel_commands": [tunnel_record],
                    }
                ),
                encoding="utf-8",
            )

            def fake_lifecycle(*_args, **kwargs):
                return ProviderLifecycleResult(
                    provider=kwargs["provider"],
                    action=kwargs["action"],
                    mode="execute",
                    status="completed",
                    output_dir=str(provider_output),
                )

            def fake_access(*_args, **_kwargs):
                return AccessPlaytestReport(
                    lab_id="persistent-tunnel-fail",
                    title="Persistent Tunnel Fail",
                    mode="execute",
                    status="passed",
                    access_manifest=str(access_manifest),
                    items=[
                        AccessPlaytestItem(
                            check_id="tunnel-01",
                            service="wiki",
                            kind="ssh-local-forward",
                            command=tunnel_record["command"],
                            status="passed",
                        )
                    ],
                )

            def fake_solver(*_args, **_kwargs):
                return SolverRunReport(
                    lab_id="persistent-tunnel-fail",
                    title="Persistent Tunnel Fail",
                    mode="execute",
                    status="passed",
                    solver_plan=str(solver_plan),
                    steps=[SolverRunStep(order=1, step_id="wiki-01", action_type="access", status="passed")],
                )

            with patch("labforge.e2e_solver.provider_lifecycle", side_effect=fake_lifecycle), patch(
                "labforge.e2e_solver.shutil.which",
                return_value="ssh",
            ), patch("labforge.e2e_solver.subprocess.Popen", return_value=tunnel_process), patch(
                "labforge.e2e_solver.wait_for_tcp_port",
                return_value=False,
            ), patch("labforge.e2e_solver.run_access_playtest", side_effect=fake_access), patch(
                "labforge.e2e_solver.run_solver_plan",
                side_effect=fake_solver,
            ):
                report = run_e2e_solver(
                    provider_output,
                    solver_plan,
                    access_manifest,
                    out,
                    execute=True,
                    execute_tunnels=True,
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

            self.assertEqual(report.status, "failed")
            self.assertEqual(report.persistent_tunnels[0].status, "failed")
            self.assertTrue(tunnel_process.terminated)


if __name__ == "__main__":
    unittest.main()
