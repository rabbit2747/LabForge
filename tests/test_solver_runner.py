from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.error import URLError
from unittest.mock import patch

from labforge.solver_runner import http_json, run_solver_plan, ssh_batch_argv, ssh_command_sequence_argv


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

    def test_solver_runner_executes_command_sequence_step(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solver_plan = root / "solver-plan.json"
            access_manifest = root / "learner-access.json"
            solver_plan.write_text(
                json.dumps(
                    {
                        "lab_id": "solver-command-sequence",
                        "title": "Solver Command Sequence",
                        "steps": [
                            {
                                "order": 1,
                                "step_id": "terminal-attacker-workstation-readiness",
                                "action_type": "command-sequence",
                                "service": "attacker-workstation",
                                "commands": ["echo labforge-terminal-ready", "pwd"],
                                "expected_texts": ["labforge-terminal-ready"],
                                "evidence": ["labforge-terminal-ready"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            access_manifest.write_text(
                json.dumps(
                    {
                        "attacker_entrypoints": [
                            {"service": "attacker-workstation", "protocol": "ssh", "connect": "ssh attacker@127.0.0.1 -p 2222"}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            completed = SimpleNamespace(returncode=0, stdout="labforge-terminal-ready\n/home/attacker\n", stderr="")

            with patch("labforge.solver_runner.shutil.which", return_value="ssh"), patch(
                "labforge.solver_runner.subprocess.run",
                return_value=completed,
            ) as run_mock:
                report = run_solver_plan(solver_plan, root / "solver-run", access_manifest=access_manifest, execute=True)

            self.assertEqual(report.status, "passed")
            self.assertEqual(report.steps[0].status, "passed")
            self.assertEqual(report.steps[0].action_type, "command-sequence")
            self.assertIn("commands=2", report.steps[0].message)
            argv = run_mock.call_args.args[0]
            self.assertEqual(argv[0], "ssh")
            self.assertIn("BatchMode=yes", argv)
            self.assertEqual(argv[-1], "echo labforge-terminal-ready && pwd")

    def test_ssh_command_sequence_argv_adds_remote_script(self) -> None:
        argv = ssh_command_sequence_argv("ssh attacker@127.0.0.1 -p 2222", "echo ready && pwd")

        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertEqual(argv[-1], "echo ready && pwd")

    def test_http_json_retries_transient_connection_errors(self) -> None:
        calls = {"count": 0}

        class FakeResponse:
            status = 200

            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

            def read(self, _size: int) -> bytes:
                return b'{"ok": true}'

        def flaky_urlopen(_request, timeout: int):
            calls["count"] += 1
            if calls["count"] == 1:
                raise URLError("connection refused")
            return FakeResponse()

        with patch("labforge.solver_runner.urlopen", side_effect=flaky_urlopen), patch("labforge.solver_runner.time.sleep"):
            status, data, body = http_json("GET", "http://127.0.0.1:1/", None, 1)

        self.assertEqual(status, 200)
        self.assertEqual(data["ok"], True)
        self.assertEqual(body, '{"ok": true}')
        self.assertEqual(calls["count"], 2)

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
                self.assertIn("runbook=200", report.steps[0].message)
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

    def test_solver_runner_submits_final_proof_to_controlled_drop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            FinalSubmissionSmokeHandler.submissions = []
            server = ThreadingHTTPServer(("127.0.0.1", 0), FinalSubmissionSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                access_manifest = root / "learner-access.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-final-submit",
                            "title": "Solver Final Submit",
                            "final_submission": f"{base_url}/",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "final-01",
                                    "action_type": "final-submission",
                                    "evidence": ["final_object_collected"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                access_manifest.write_text(
                    json.dumps(
                        {
                            "final_submission_endpoints": [
                                {"service": "controlled-drop", "protocol": "http", "connect": f"{base_url}/"}
                            ]
                        }
                    ),
                    encoding="utf-8",
                )

                report = run_solver_plan(solver_plan, root / "solver-run", access_manifest=access_manifest, execute=True)

                self.assertEqual(report.status, "passed")
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("submit=200", report.steps[0].message)
                self.assertIn("accepted=True", report.steps[0].message)
                self.assertIn("recorded=true", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_fails_final_submission_when_submit_api_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), MissingFinalSubmissionHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-final-missing",
                            "title": "Solver Final Missing",
                            "final_submission": f"{base_url}/",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "final-01",
                                    "action_type": "final-submission",
                                    "evidence": [],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )

                report = run_solver_plan(solver_plan, root / "solver-run", execute=True)

                self.assertEqual(report.status, "failed")
                self.assertEqual(report.steps[0].status, "failed")
                self.assertIn("submit=404", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

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

    def test_solver_runner_executes_credential_exposure_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), CredentialExposureSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-credential",
                            "title": "Solver Credential",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-support-portal-credential-exposure",
                                    "action_type": "vulnerability-behavior",
                                    "service": "support-portal",
                                    "plugin": "credential-exposure",
                                    "evidence": ["/operations/config"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                endpoint_manifest.write_text(
                    json.dumps({"published_endpoints": [{"service": "support-portal", "protocol": "http", "url": f"{base_url}/"}]}),
                    encoding="utf-8",
                )

                report = run_solver_plan(solver_plan, root / "solver-run", endpoint_manifest=endpoint_manifest, execute=True)

                self.assertEqual(report.status, "passed")
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("config=200", report.steps[0].message)
                self.assertIn("log=200", report.steps[0].message)
                self.assertIn("secret_value=redacted", report.steps[0].message)
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
        if self.path == "/operations/runbook":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Operations Runbook</h1><p>Response Preview workflow notes</p></body></html>")
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


class CredentialExposureSmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/operations/reference":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"items": [{"plugin": "credential-exposure"}]}).encode("utf-8"))
            return
        if self.path == "/operations/config":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Runtime Configuration</h1></body></html>")
            return
        if self.path == "/api/config":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"secret_value": "redacted", "secret_reference": "lab://secret/ref"}).encode("utf-8"))
            return
        if self.path == "/api/config/startup-log":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"vault-cache export OPERATOR_BIND_CURRENT=LabForge-Operator-Training-Secret!\n")
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class FinalSubmissionSmokeHandler(BaseHTTPRequestHandler):
    submissions: list[dict] = []

    def do_GET(self) -> None:
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"service": "controlled-drop"}).encode("utf-8"))
            return
        if self.path == "/submissions":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"items": self.submissions}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/submit":
            size = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(size).decode("utf-8"))
            self.submissions.append({"payload": payload})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"accepted": True}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class MissingFinalSubmissionHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"service": "not-a-drop"}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        if size:
            self.rfile.read(size)
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": "missing"}).encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    unittest.main()
