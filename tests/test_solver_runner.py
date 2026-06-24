from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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

    def test_solver_runner_executes_supported_plugin_http_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), SolverRunnerSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-execute",
                            "title": "Solver Execute",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-investor-portal-ssti-preview",
                                    "action_type": "vulnerability-behavior",
                                    "service": "investor-portal",
                                    "plugin": "ssti-preview",
                                    "evidence": ["/labforge/scaffold/ssti-preview"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                endpoint_manifest.write_text(
                    json.dumps(
                        {
                            "published_endpoints": [
                                {
                                    "service": "investor-portal",
                                    "protocol": "http",
                                    "url": f"{base_url}/",
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )

                report = run_solver_plan(
                    solver_plan,
                    root / "solver-run",
                    endpoint_manifest=endpoint_manifest,
                    execute=True,
                )

                self.assertEqual(report.status, "passed")
                self.assertEqual(report.service_targets["investor-portal"], base_url)
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("discovery=200", report.steps[0].message)
                self.assertIn("preview=49", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_skips_plugin_without_published_service_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solver_plan = root / "solver-plan.json"
            solver_plan.write_text(
                json.dumps(
                    {
                        "lab_id": "solver-skip",
                        "title": "Solver Skip",
                        "steps": [
                            {
                                "order": 1,
                                "step_id": "plugin-private-ssti-preview",
                                "action_type": "vulnerability-behavior",
                                "service": "private-portal",
                                "plugin": "ssti-preview",
                                "evidence": ["/labforge/scaffold/ssti-preview"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = run_solver_plan(solver_plan, root / "solver-run", execute=True)

            self.assertEqual(report.status, "warning")
            self.assertEqual(report.steps[0].status, "skipped")
            self.assertIn("not published", report.steps[0].message)


class SolverRunnerSmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/operations/reference":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"items": [{"plugin": "ssti-preview"}]}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/labforge/scaffold/ssti-preview":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"preview": "49"}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    unittest.main()
