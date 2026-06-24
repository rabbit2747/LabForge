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
                            {
                                "order": 3,
                                "step_id": "final-01",
                                "action_type": "final-submission",
                                "learner_action": "Submit proof.",
                                "expected_result": "Proof is accepted.",
                                "evidence": [],
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
                        "final_submission_endpoints": [
                            {"service": "controlled-drop", "protocol": "http", "connect": "http://127.0.0.1:18082/"}
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = run_solver_plan(solver_plan, root / "solver-run", access_manifest=access_manifest, execute=False)

            self.assertEqual(report.status, "planned")
            self.assertEqual(report.browser_targets, ["http://127.0.0.1:18081/"])
            self.assertEqual(report.terminal_targets, ["ssh attacker@127.0.0.1 -p 2222"])
            self.assertEqual(report.final_targets, ["http://127.0.0.1:18082/"])
            self.assertEqual([step.status for step in report.steps], ["planned", "planned", "planned"])
            self.assertEqual(report.steps[2].target, "http://127.0.0.1:18082/")
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
                self.assertIn("landing=200", report.steps[0].message)
                self.assertIn("landing_route=/operations/preview", report.steps[0].message)
                self.assertIn("route=/operations/preview", report.steps[0].message)
                self.assertIn("preview=49", report.steps[0].message)
                self.assertIn("stage_state=200", report.steps[0].message)
                self.assertIn("acquired_evidence=1", report.steps[0].message)
                self.assertIn("unlocked_stages=2", report.steps[0].message)
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

    def test_solver_runner_executes_solr_velocity_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), SolrVelocitySmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-solr",
                            "title": "Solver Solr",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-ops-search-solr-velocity-rce",
                                    "action_type": "vulnerability-behavior",
                                    "service": "ops-search",
                                    "plugin": "solr-velocity-rce",
                                    "evidence": ["/operations/search-admin"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                endpoint_manifest.write_text(
                    json.dumps({"published_endpoints": [{"service": "ops-search", "protocol": "http", "url": f"{base_url}/"}]}),
                    encoding="utf-8",
                )

                report = run_solver_plan(solver_plan, root / "solver-run", endpoint_manifest=endpoint_manifest, execute=True)

                self.assertEqual(report.status, "passed")
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("system=200", report.steps[0].message)
                self.assertIn("config=200", report.steps[0].message)
                self.assertIn("select=200", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_fails_when_business_landing_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), MissingLandingSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-missing-landing",
                            "title": "Solver Missing Landing",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-investor-portal-ssti-preview",
                                    "action_type": "vulnerability-behavior",
                                    "service": "investor-portal",
                                    "plugin": "ssti-preview",
                                    "evidence": ["/operations/preview"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                endpoint_manifest.write_text(
                    json.dumps({"published_endpoints": [{"service": "investor-portal", "protocol": "http", "url": f"{base_url}/"}]}),
                    encoding="utf-8",
                )

                report = run_solver_plan(solver_plan, root / "solver-run", endpoint_manifest=endpoint_manifest, execute=True)

                self.assertEqual(report.status, "failed")
                self.assertEqual(report.steps[0].status, "failed")
                self.assertIn("landing=missing", report.steps[0].message)
                self.assertIn("preview=49", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()


class SolverRunnerSmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/operations/reference":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"items": [{"plugin": "ssti-preview"}]}).encode("utf-8"))
            return
        if self.path == "/operations/preview":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Response Preview</h1></body></html>")
            return
        if self.path == "/api/state":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "acquired_evidence": ["template_probe_confirmed"],
                        "stages": [
                            {"stage_id": "stage-01", "status": "unlocked"},
                            {"stage_id": "stage-02", "status": "unlocked"},
                            {"stage_id": "stage-03", "status": "locked"},
                        ],
                    }
                ).encode("utf-8")
            )
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/operations/preview":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"preview": "49"}).encode("utf-8"))
            return
        if self.path == "/labforge/scaffold/ssti-preview":
            self.send_response(500)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class MissingLandingSmokeHandler(BaseHTTPRequestHandler):
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
        if self.path == "/operations/preview":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"preview": "49"}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class SolrVelocitySmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/operations/reference":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"items": [{"plugin": "solr-velocity-rce"}]}).encode("utf-8"))
            return
        if self.path == "/operations/search-admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Search Operations Console</h1></body></html>")
            return
        if self.path == "/solr/ops-core/admin/info/system":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"lucene": {"solr-spec-version": "8.3.1"}}).encode("utf-8"))
            return
        if self.path.startswith("/solr/ops-core/select"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"uid=8983(solr) gid=8983(solr) groups=8983(solr)\n")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/solr/ops-core/config":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"responseHeader": {"status": 0}, "velocity_enabled": True}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    unittest.main()
