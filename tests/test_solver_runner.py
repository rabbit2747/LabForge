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

from labforge.plugin_runtime_smoke import isolate_generated_state, load_generated_app_module
from labforge.solver_runner import http_json, run_solver_plan, ssh_batch_argv, ssh_command_sequence_argv
from labforge.vulnerability_scaffolds import render_vulnerability_scaffold_files


BASE_PLUGIN_APP = """\
from pathlib import Path
import json
from flask import Flask, jsonify

SERVICE = "reporting-console"
PURPOSE = "solver-runner generated plugin host"
STATE_DIR = Path("/state")
LOG_PATH = Path("/var/log/labforge/service-events.jsonl")
app = Flask(__name__)

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
"""


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
                self.assertIn("route_catalog=200", report.steps[0].message)
                self.assertIn("route_count=2", report.steps[0].message)
                self.assertIn("operations_context=200", report.steps[0].message)
                self.assertIn("context_records=1", report.steps[0].message)
                self.assertIn("landing=200", report.steps[0].message)
                self.assertIn("landing_route=/operations/preview", report.steps[0].message)
                self.assertIn("context_route=/api/preview/context", report.steps[0].message)
                self.assertIn("normal_route=/operations/preview", report.steps[0].message)
                self.assertIn("route=/operations/preview", report.steps[0].message)
                self.assertIn("audit_route=/api/preview/audit", report.steps[0].message)
                self.assertIn("preview=49", report.steps[0].message)
                self.assertIn("unexpected_recorded=True", report.steps[0].message)
                self.assertIn("stage_state=200", report.steps[0].message)
                self.assertIn("acquired_evidence=1", report.steps[0].message)
                self.assertIn("unlocked_stages=2", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_uses_tunnel_url_as_internal_service_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            solver_plan = root / "solver-plan.json"
            access_manifest = root / "learner-access.json"
            solver_plan.write_text(
                json.dumps(
                    {
                        "lab_id": "solver-tunnel-target",
                        "title": "Solver Tunnel Target",
                        "steps": [
                            {
                                "order": 1,
                                "step_id": "plugin-internal-wiki-ssti-preview",
                                "action_type": "vulnerability-behavior",
                                "service": "internal-wiki",
                                "plugin": "ssti-preview",
                                "evidence": ["template_probe_confirmed"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            access_manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "solver-tunnel-target",
                        "title": "Solver Tunnel Target",
                        "learner_entrypoints": [],
                        "attacker_entrypoints": [
                            {"service": "attacker-workstation", "protocol": "ssh", "connect": "ssh attacker@127.0.0.1 -p 2222"}
                        ],
                        "tunnel_commands": [
                            {
                                "service": "internal-wiki",
                                "dns": "wiki",
                                "internal_port": "6000",
                                "local_port": 18080,
                                "command": "ssh -L 18080:wiki:6000 attacker@127.0.0.1 -p 2222",
                                "url": "http://127.0.0.1:18080/",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = run_solver_plan(
                solver_plan,
                root / "solver-run",
                access_manifest=access_manifest,
                execute=False,
            )

            self.assertEqual(report.status, "planned")
            self.assertEqual(report.service_targets["internal-wiki"], "http://127.0.0.1:18080")
            self.assertEqual(report.terminal_targets, ["ssh attacker@127.0.0.1 -p 2222"])

    def test_solver_runner_executes_sql_injection_reporting_plugin_against_generated_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = SimpleNamespace(
                service="reporting-console",
                purpose="operations report search",
                model_extra={
                    "vulnerability_plugins": [
                        {
                            "id": "sql-injection-reporting",
                            "reporting_workflow": "analyst compliance report search",
                            "record_model": "compliance reports",
                            "authorization_boundary": "owner scoped report rows",
                            "target_dataset": "LABFORGE_SYNTHETIC_RESTRICTED_REPORT",
                        }
                    ]
                },
            )
            files = render_vulnerability_scaffold_files(artifact, {"app.py": BASE_PLUGIN_APP})
            app_path = root / "app.py"
            app_path.write_text(files["app.py"], encoding="utf-8")
            module, error = load_generated_app_module("reporting-console", app_path)
            self.assertIsNone(error or None)
            self.assertIsNotNone(module)
            isolate_generated_state(module, "reporting-console")

            from werkzeug.serving import make_server

            server = make_server("127.0.0.1", 0, module.app)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-sqli",
                            "title": "Solver SQLi",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-reporting-console-sql-injection-reporting",
                                    "action_type": "vulnerability-behavior",
                                    "service": "reporting-console",
                                    "plugin": "sql-injection-reporting",
                                    "evidence": [],
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
                                    "service": "reporting-console",
                                    "protocol": "http",
                                    "url": base_url,
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
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("restricted_returned=True", report.steps[0].message)
                self.assertIn("audit_recorded=True", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_executes_stored_xss_reviewer_automation_against_generated_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = SimpleNamespace(
                service="release-console",
                purpose="release approval workflow",
                model_extra={
                    "vulnerability_plugins": [
                        {
                            "id": "stored-xss-review",
                            "storage_location": "/state/release-review-items.json",
                            "reviewer_role": "release manager",
                            "review_surface": "release approval inbox",
                            "callback_scope": "lab-internal callback",
                        }
                    ]
                },
            )
            files = render_vulnerability_scaffold_files(artifact, {"app.py": BASE_PLUGIN_APP})
            app_path = root / "app.py"
            app_path.write_text(files["app.py"], encoding="utf-8")
            module, error = load_generated_app_module("release-console", app_path)
            self.assertIsNone(error or None)
            self.assertIsNotNone(module)
            isolate_generated_state(module, "release-console")

            from werkzeug.serving import make_server

            server = make_server("127.0.0.1", 0, module.app)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-stored-xss",
                            "title": "Solver Stored XSS",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-release-console-stored-xss-review",
                                    "action_type": "vulnerability-behavior",
                                    "service": "release-console",
                                    "plugin": "stored-xss-review",
                                    "evidence": [],
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
                                    "service": "release-console",
                                    "protocol": "http",
                                    "url": base_url,
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
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("bot_status=200", report.steps[0].message)
                self.assertIn("bot_run=202", report.steps[0].message)
                self.assertIn("bot_ran=True", report.steps[0].message)
                self.assertIn("callback_recorded=True", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_executes_path_traversal_download_against_generated_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = SimpleNamespace(
                service="document-service",
                purpose="records document library",
                model_extra={
                    "vulnerability_plugins": [
                        {
                            "id": "path-traversal-download",
                            "document_workflow": "records document download",
                            "public_document_root": "documents/public",
                            "restricted_document": "restricted/audit-export.txt",
                            "safe_file_boundary": "synthetic service state document root",
                        }
                    ]
                },
            )
            files = render_vulnerability_scaffold_files(artifact, {"app.py": BASE_PLUGIN_APP})
            app_path = root / "app.py"
            app_path.write_text(files["app.py"], encoding="utf-8")
            module, error = load_generated_app_module("document-service", app_path)
            self.assertIsNone(error or None)
            self.assertIsNotNone(module)
            isolate_generated_state(module, "document-service")

            from werkzeug.serving import make_server

            server = make_server("127.0.0.1", 0, module.app)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-path-traversal",
                            "title": "Solver Path Traversal",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-document-service-path-traversal-download",
                                    "action_type": "vulnerability-behavior",
                                    "service": "document-service",
                                    "plugin": "path-traversal-download",
                                    "evidence": [],
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
                                    "service": "document-service",
                                    "protocol": "http",
                                    "url": base_url,
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
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("archive_match=archive-route-restricted-records", report.steps[0].message)
                self.assertIn("traversal_recorded=True", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_executes_idor_object_access_against_generated_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = SimpleNamespace(
                service="object-console",
                purpose="business object access review",
                model_extra={
                    "vulnerability_plugins": [
                        {
                            "id": "idor-object-access",
                            "object_model": "case-linked business objects",
                            "target_dataset": "LABFORGE_SYNTHETIC_RESTRICTED_OBJECT",
                        }
                    ]
                },
            )
            files = render_vulnerability_scaffold_files(artifact, {"app.py": BASE_PLUGIN_APP})
            app_path = root / "app.py"
            app_path.write_text(files["app.py"], encoding="utf-8")
            module, error = load_generated_app_module("object-console", app_path)
            self.assertIsNone(error or None)
            self.assertIsNotNone(module)
            isolate_generated_state(module, "object-console")

            from werkzeug.serving import make_server

            server = make_server("127.0.0.1", 0, module.app)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-idor-object-access",
                            "title": "Solver IDOR Object Access",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-object-console-idor-object-access",
                                    "action_type": "vulnerability-behavior",
                                    "service": "object-console",
                                    "plugin": "idor-object-access",
                                    "evidence": [],
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
                                    "service": "object-console",
                                    "protocol": "http",
                                    "url": base_url,
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
                self.assertEqual(report.steps[0].status, "passed", report.steps[0].message)
                self.assertIn("review=200", report.steps[0].message)
                self.assertIn("review_case_found=True", report.steps[0].message)
                self.assertIn("target_object_id=obj-9001", report.steps[0].message)
                self.assertIn("policy_gap=True", report.steps[0].message)
                self.assertIn("direct_read_audited=True", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_executes_unsafe_file_upload_review_against_generated_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = SimpleNamespace(
                service="attachment-portal",
                purpose="case attachment handling",
                model_extra={
                    "vulnerability_plugins": [
                        {
                            "id": "unsafe-file-upload",
                            "upload_workflow": "case evidence attachment review",
                            "accepted_extensions": [".txt", ".pdf"],
                            "review_queue": "case-handler-review",
                        }
                    ]
                },
            )
            files = render_vulnerability_scaffold_files(artifact, {"app.py": BASE_PLUGIN_APP})
            app_path = root / "app.py"
            app_path.write_text(files["app.py"], encoding="utf-8")
            module, error = load_generated_app_module("attachment-portal", app_path)
            self.assertIsNone(error or None)
            self.assertIsNotNone(module)
            isolate_generated_state(module, "attachment-portal")

            from werkzeug.serving import make_server

            server = make_server("127.0.0.1", 0, module.app)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-unsafe-upload",
                            "title": "Solver Unsafe Upload",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-attachment-portal-unsafe-file-upload",
                                    "action_type": "vulnerability-behavior",
                                    "service": "attachment-portal",
                                    "plugin": "unsafe-file-upload",
                                    "evidence": [],
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
                                    "service": "attachment-portal",
                                    "protocol": "http",
                                    "url": base_url,
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
                self.assertEqual(report.steps[0].status, "passed", report.steps[0].message)
                self.assertIn("review_workbench=200", report.steps[0].message)
                self.assertIn("review_decision=202", report.steps[0].message)
                self.assertIn("quarantine_recorded=True", report.steps[0].message)
                self.assertIn("quarantine_audited=True", report.steps[0].message)
                self.assertIn("retrieve_audited=True", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_executes_jwt_role_confusion_plugin_against_generated_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = SimpleNamespace(
                service="reporting-console",
                purpose="identity operations session review",
                model_extra={
                    "vulnerability_plugins": [
                        {
                            "id": "jwt-role-confusion",
                            "auth_workflow": "identity operations session review",
                            "normal_role": "analyst",
                            "target_role": "admin",
                            "target_dataset": "LABFORGE_SYNTHETIC_PRIVILEGED_EXPORT",
                        }
                    ]
                },
            )
            files = render_vulnerability_scaffold_files(artifact, {"app.py": BASE_PLUGIN_APP})
            app_path = root / "app.py"
            app_path.write_text(files["app.py"], encoding="utf-8")
            module, error = load_generated_app_module("reporting-console", app_path)
            self.assertIsNone(error or None)
            self.assertIsNotNone(module)
            isolate_generated_state(module, "reporting-console")

            from werkzeug.serving import make_server

            server = make_server("127.0.0.1", 0, module.app)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-jwt",
                            "title": "Solver JWT",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-reporting-console-jwt-role-confusion",
                                    "action_type": "vulnerability-behavior",
                                    "service": "reporting-console",
                                    "plugin": "jwt-role-confusion",
                                    "evidence": [],
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
                                    "service": "reporting-console",
                                    "protocol": "http",
                                    "url": base_url,
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
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("role_confusion=True", report.steps[0].message)
                self.assertIn("audit_recorded=True", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_fails_when_expected_stage_evidence_is_not_emitted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), MissingStageEvidenceSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-missing-stage-evidence",
                            "title": "Solver Missing Stage Evidence",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-investor-portal-ssti-preview",
                                    "action_type": "vulnerability-behavior",
                                    "service": "investor-portal",
                                    "plugin": "ssti-preview",
                                    "evidence": [
                                        "/operations/preview",
                                        "emitted_evidence=template_probe_confirmed",
                                    ],
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
                self.assertIn("expected_evidence=template_probe_confirmed", report.steps[0].message)
                self.assertIn("missing_expected_evidence=template_probe_confirmed", report.steps[0].message)
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
                self.assertIn("cores=200", report.steps[0].message)
                self.assertIn("legacy_cores=1", report.steps[0].message)
                self.assertIn("drift_before=200", report.steps[0].message)
                self.assertIn("system=200", report.steps[0].message)
                self.assertIn("config=200", report.steps[0].message)
                self.assertIn("select=200", report.steps[0].message)
                self.assertIn("drift_after=200", report.steps[0].message)
                self.assertIn("velocity_response_writer=True", report.steps[0].message)
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
                self.assertIn("policy=200", report.steps[0].message)
                self.assertIn("log=200", report.steps[0].message)
                self.assertIn("correlation=200", report.steps[0].message)
                self.assertIn("audit=200", report.steps[0].message)
                self.assertIn("secret_value=redacted", report.steps[0].message)
                self.assertIn("cache_profile_matches_account=True", report.steps[0].message)
                self.assertIn("recovered_credential=present", report.steps[0].message)
                self.assertIn("redacted_config_audited=True", report.steps[0].message)
                self.assertIn("startup_secret_audited=True", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_executes_build_pipeline_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), BuildPipelineSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-build-pipeline",
                            "title": "Solver Build Pipeline",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-release-console-build-pipeline-abuse",
                                    "action_type": "vulnerability-behavior",
                                    "service": "release-console",
                                    "plugin": "build-pipeline-abuse",
                                    "evidence": ["/operations/build"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                endpoint_manifest.write_text(
                    json.dumps({"published_endpoints": [{"service": "release-console", "protocol": "http", "url": f"{base_url}/"}]}),
                    encoding="utf-8",
                )

                report = run_solver_plan(solver_plan, root / "solver-run", endpoint_manifest=endpoint_manifest, execute=True)

                self.assertEqual(report.status, "passed")
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("context=200", report.steps[0].message)
                self.assertIn("metadata=200", report.steps[0].message)
                self.assertIn("policy=200", report.steps[0].message)
                self.assertIn("policy_allowed=True", report.steps[0].message)
                self.assertIn("http_status=201", report.steps[0].message)
                self.assertIn("artifact_fields=4", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_executes_signed_update_publish_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            SignedUpdatePublishSmokeHandler.signed_manifest = {}
            SignedUpdatePublishSmokeHandler.audit_records = []
            SignedUpdatePublishSmokeHandler.sign_audit_records = []
            server = ThreadingHTTPServer(("127.0.0.1", 0), SignedUpdatePublishSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-signed-update",
                            "title": "Solver Signed Update",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-update-server-signed-update-publish",
                                    "action_type": "vulnerability-behavior",
                                    "service": "update-server",
                                    "plugin": "signed-update-publish",
                                    "evidence": ["/operations/update-channel"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                endpoint_manifest.write_text(
                    json.dumps({"published_endpoints": [{"service": "update-server", "protocol": "http", "url": f"{base_url}/"}]}),
                    encoding="utf-8",
                )

                report = run_solver_plan(solver_plan, root / "solver-run", endpoint_manifest=endpoint_manifest, execute=True)

                self.assertEqual(report.status, "passed")
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("policy=200", report.steps[0].message)
                self.assertIn("validation=200", report.steps[0].message)
                self.assertIn("validation_allowed=True", report.steps[0].message)
                self.assertIn("signed=200", report.steps[0].message)
                self.assertIn("published=201", report.steps[0].message)
                self.assertIn("audit=200", report.steps[0].message)
                self.assertIn("audit_records=1", report.steps[0].message)
                self.assertIn("channel=200", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_executes_diagnostic_command_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            DiagnosticCommandSmokeHandler.records = []
            server = ThreadingHTTPServer(("127.0.0.1", 0), DiagnosticCommandSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-diagnostic-command",
                            "title": "Solver Diagnostic Command",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-ops-console-diagnostic-command-injection",
                                    "action_type": "vulnerability-behavior",
                                    "service": "ops-console",
                                    "plugin": "diagnostic-command-injection",
                                    "evidence": ["/operations/diagnostics"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                endpoint_manifest.write_text(
                    json.dumps({"published_endpoints": [{"service": "ops-console", "protocol": "http", "url": f"{base_url}/"}]}),
                    encoding="utf-8",
                )

                report = run_solver_plan(solver_plan, root / "solver-run", endpoint_manifest=endpoint_manifest, execute=True)

                self.assertEqual(report.status, "passed")
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("info=200", report.steps[0].message)
                self.assertIn("policy=200", report.steps[0].message)
                self.assertIn("presets=1", report.steps[0].message)
                self.assertIn("targets=1", report.steps[0].message)
                self.assertIn("accepted=True", report.steps[0].message)
                self.assertIn("blocked=400", report.steps[0].message)
                self.assertIn("blocked_accepted=False", report.steps[0].message)
                self.assertIn("audit=200", report.steps[0].message)
                self.assertIn("accepted_recorded=True", report.steps[0].message)
                self.assertIn("blocked_recorded=True", report.steps[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_solver_runner_executes_ssrf_blocked_and_allowed_fetch_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), SsrfSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "solver-ssrf",
                            "title": "Solver SSRF",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-import-console-ssrf-internal-fetch",
                                    "action_type": "vulnerability-behavior",
                                    "service": "import-console",
                                    "plugin": "ssrf-internal-fetch",
                                    "evidence": ["/operations/fetch"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                endpoint_manifest.write_text(
                    json.dumps({"published_endpoints": [{"service": "import-console", "protocol": "http", "url": f"{base_url}/"}]}),
                    encoding="utf-8",
                )

                report = run_solver_plan(solver_plan, root / "solver-run", endpoint_manifest=endpoint_manifest, execute=True)

                self.assertEqual(report.status, "passed")
                self.assertEqual(report.steps[0].status, "passed")
                self.assertIn("registry=200", report.steps[0].message)
                self.assertIn("jobs=200", report.steps[0].message)
                self.assertIn("job_links_source=True", report.steps[0].message)
                self.assertIn("plan=200", report.steps[0].message)
                self.assertIn("expected_policy=allow", report.steps[0].message)
                self.assertIn("policy=200", report.steps[0].message)
                self.assertIn("approved_source=http://metadata-service:8080/metadata", report.steps[0].message)
                self.assertIn("blocked_fetch_status=400", report.steps[0].message)
                self.assertIn("allowed_fetch_status=200", report.steps[0].message)
                self.assertIn("allowed=True", report.steps[0].message)
                self.assertIn("audit=200", report.steps[0].message)
                self.assertIn("blocked_recorded=True", report.steps[0].message)
                self.assertIn("allowed_recorded=True", report.steps[0].message)
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
        if self.path == "/operations/routes?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "investor-portal",
                        "routes": [
                            {"method": "GET", "path": "/operations/preview", "feature": "response preview"},
                            {"method": "POST", "path": "/operations/preview", "feature": "response preview"},
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/context?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "investor-portal",
                        "records": [
                            {
                                "case_id": "OPS-0001",
                                "workflow": "response preview",
                                "operator_note": "Support writers validate merge fields before sending.",
                            }
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/preview":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Response Preview</h1></body></html>")
            return
        if self.path == "/api/preview/context":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "render_api": "POST /operations/preview",
                        "audit_api": "/api/preview/audit",
                        "context": {"customer": {"name": "Avery Stone"}, "service": {"name": "investor-portal"}},
                        "merge_fields": [{"field": "customer.name"}, {"field": "service.name"}],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/preview/audit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "records": [
                            {"request_id": "preview-1003", "classification": "routine-merge-field", "status": "rendered"},
                            {"request_id": "preview-1004", "classification": "unexpected-expression", "status": "rendered"},
                        ]
                    }
                ).encode("utf-8")
            )
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
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            preview = "49"
            classification = "unexpected-expression"
            if "customer.name" in body:
                preview = "Hello Avery Stone from investor-portal"
                classification = "routine-merge-field"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"preview": preview, "classification": classification}).encode("utf-8"))
            return
        if self.path == "/labforge/scaffold/ssti-preview":
            self.send_response(500)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class MissingStageEvidenceSmokeHandler(SolverRunnerSmokeHandler):
    def do_GET(self) -> None:
        if self.path == "/api/state":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "acquired_evidence": [],
                        "stages": [
                            {"stage_id": "stage-01", "status": "unlocked"},
                            {"stage_id": "stage-02", "status": "locked"},
                        ],
                    }
                ).encode("utf-8")
            )
            return
        super().do_GET()


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


class DiagnosticCommandSmokeHandler(BaseHTTPRequestHandler):
    records: list[dict] = []

    def do_GET(self) -> None:
        if self.path == "/operations/reference":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"items": [{"plugin": "diagnostic-command-injection"}]}).encode("utf-8"))
            return
        if self.path == "/operations/routes?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "ops-console",
                        "routes": [
                            {"method": "GET", "path": "/operations/diagnostics", "feature": "operator diagnostics"},
                            {"method": "POST", "path": "/operations/diagnostics/run", "feature": "operator diagnostics"},
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/context?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "ops-console",
                        "records": [
                            {
                                "case_id": "OPS-0001",
                                "workflow": "operator diagnostics",
                                "operator_note": "Operators run approved presets and review diagnostic audit records.",
                            }
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/diagnostics":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Operations Diagnostics Console</h1></body></html>")
            return
        if self.path == "/api/diagnostics":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "presets": [{"id": "runtime-identity", "command": "id"}],
                        "targets": [{"id": "target-localhost", "name": "localhost", "status": "approved", "zone": "service-runtime"}],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/diagnostics/targets/localhost":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "target": {"id": "target-localhost", "name": "localhost", "status": "approved", "zone": "service-runtime"},
                        "run_hint": {"preset": "runtime-identity", "target": "localhost"},
                        "expected_policy_result": "allow",
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/diagnostics/policy":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "blocked_tokens": ["docker", "kubectl"],
                        "allowed_presets": ["runtime-identity"],
                        "approved_targets": ["localhost"],
                        "run_api": "POST /operations/diagnostics/run",
                        "audit_api": "/api/diagnostics/audit",
                        "target_detail_api": "/api/diagnostics/targets/<target>",
                        "audit_provenance_fields": ["decision", "target_registered", "target_id", "command_source", "output_fingerprint"],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/diagnostics/audit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"records": self.records}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(size).decode("utf-8")) if size else {}
        if self.path == "/operations/diagnostics/run":
            if payload.get("command") == "docker ps":
                decision = {"decision": "deny", "target_registered": True, "target_id": "target-localhost"}
                self.records.append({"preset": payload.get("preset"), "target": payload.get("target"), "accepted": False, "blocked_token_matched": True, "policy_decision": decision})
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"accepted": False, "reason": "blocked by lab boundary", "policy_decision": decision}).encode("utf-8"))
                return
            decision = {"decision": "allow", "target_registered": True, "target_id": "target-localhost"}
            self.records.append({"preset": payload.get("preset"), "target": payload.get("target"), "accepted": True, "returncode": 0, "policy_decision": decision, "output_fingerprint": "diag123"})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"accepted": True, "returncode": 0, "stdout": "uid=1000(operator)\n", "policy_decision": decision, "output_fingerprint": "diag123"}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class BuildPipelineSmokeHandler(BaseHTTPRequestHandler):
    audit_records: list[dict[str, object]] = []

    def do_GET(self) -> None:
        if self.path == "/operations/reference":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"items": [{"plugin": "build-pipeline-abuse"}]}).encode("utf-8"))
            return
        if self.path == "/operations/routes?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "release-console",
                        "routes": [
                            {"method": "GET", "path": "/operations/build", "feature": "release build"},
                            {"method": "POST", "path": "/api/build/jobs", "feature": "release build"},
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/context?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "release-console",
                        "records": [
                            {
                                "case_id": "BR-0001",
                                "workflow": "release build",
                                "operator_note": "Build jobs must match release metadata and pass policy checks.",
                            }
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/build":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Release Build Console</h1></body></html>")
            return
        if self.path == "/api/build/context":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "build_api": "POST /api/build/jobs",
                        "release_metadata_api": "GET /api/build/release-metadata",
                        "policy_api": "POST /api/build/policy",
                        "audit_api": "GET /api/build/audit",
                        "provenance_api": "GET /api/build/jobs/<job_id>/provenance",
                        "repo": "smoke/product-agent",
                        "ref": "refs/heads/release/smoke",
                        "channel": "smoke",
                        "patch_ref_field": "support_patch_ref",
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/build/release-metadata":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "repo": "smoke/product-agent",
                        "ref": "refs/heads/release/smoke",
                        "channel": "smoke",
                        "version": "lab",
                        "required_patch_field": "support_patch_ref",
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/build/jobs/build-0001/provenance":
            self.audit_records.append({"action": "provenance-read", "accepted": True, "job_id": "build-0001"})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "job_id": "build-0001",
                        "provenance": {
                            "repo": "smoke/product-agent",
                            "ref": "refs/heads/release/smoke",
                            "channel": "smoke",
                            "patch_ref": "lab://smoke.patch",
                            "artifact_sha256": "0" * 64,
                        },
                        "artifact": {"sha256": "0" * 64},
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/build/audit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"records": self.audit_records, "count": len(self.audit_records)}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(size).decode("utf-8")) if size else {}
        allowed = bool(payload.get("support_patch_ref"))
        if self.path == "/api/build/policy":
            self.audit_records.append({"action": "policy-check", "accepted": allowed})
            self.send_response(200 if allowed else 400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"allowed": allowed, "checks": [{"name": "patch reference supplied", "passed": allowed}]}).encode("utf-8"))
            return
        if self.path == "/api/build/jobs":
            if not allowed:
                self.audit_records.append({"action": "job-create", "accepted": False})
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "policy rejected"}).encode("utf-8"))
                return
            self.audit_records.append({"action": "job-create", "accepted": True})
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "job_id": "build-0001",
                        "status": "built",
                        "canonical_manifest": {
                            "artifact": {
                                "name": "product-agent-smoke-lab.tar",
                                "sha256": "0" * 64,
                                "url": "http://build/product-agent-smoke-lab.tar",
                                "size_bytes": 24576,
                            }
                        },
                    }
                ).encode("utf-8")
            )
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class SignedUpdatePublishSmokeHandler(BaseHTTPRequestHandler):
    signed_manifest: dict = {}
    audit_records: list[dict] = []
    sign_audit_records: list[dict] = []

    def do_GET(self) -> None:
        if self.path == "/operations/reference":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"items": [{"plugin": "signed-update-publish"}]}).encode("utf-8"))
            return
        if self.path == "/operations/routes?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "update-server",
                        "routes": [
                            {"method": "GET", "path": "/operations/update-channel", "feature": "update channel"},
                            {"method": "GET", "path": "/api/signing/policy", "feature": "update signing"},
                            {"method": "POST", "path": "/api/sign/validate", "feature": "update signing"},
                            {"method": "POST", "path": "/api/sign", "feature": "update signing"},
                            {"method": "POST", "path": "/api/publish", "feature": "update publishing"},
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/context?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "update-server",
                        "records": [
                            {
                                "case_id": "REL-0001",
                                "workflow": "trusted update channel",
                                "operator_note": "Release operators validate canonical manifests before signing and publishing.",
                            }
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/update-channel":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Update Channel Console</h1></body></html>")
            return
        if self.path == "/api/signing/policy":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "allowed_channels": ["smoke", "training"],
                        "required_manifest_fields": ["product", "channel", "version", "build_id", "artifact"],
                        "required_artifact_fields": ["name", "sha256", "url", "size_bytes"],
                        "sign_audit_api": "GET /api/sign/audit",
                        "signed_manifest_inventory_api": "GET /api/signed-manifests",
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/sign/audit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"records": self.sign_audit_records, "count": len(self.sign_audit_records)}).encode("utf-8"))
            return
        if self.path == "/api/signed-manifests":
            manifests = [self.signed_manifest] if self.signed_manifest else []
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"signed_manifests": manifests, "count": len(manifests)}).encode("utf-8"))
            return
        if self.path == "/api/publish/audit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"records": self.audit_records, "count": len(self.audit_records)}).encode("utf-8"))
            return
        if self.path == "/api/channels/smoke":
            if not self.audit_records:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"channel": "smoke", "manifest": self.signed_manifest}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(size).decode("utf-8")) if size else {}
        if self.path == "/api/sign/validate":
            manifest = payload.get("canonical_manifest") or {}
            allowed = bool(manifest.get("artifact", {}).get("sha256") and manifest.get("channel") == "smoke")
            self.sign_audit_records.append({"action": "manifest-validate", "accepted": allowed})
            self.send_response(200 if allowed else 400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"allowed": allowed, "errors": [] if allowed else ["invalid manifest"]}).encode("utf-8"))
            return
        if self.path == "/api/sign":
            manifest = payload.get("canonical_manifest") or {}
            if not manifest:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "canonical_manifest is required"}).encode("utf-8"))
                return
            type(self).signed_manifest = dict(manifest)
            type(self).signed_manifest["signature"] = "signed-smoke"
            type(self).signed_manifest["signing_identity"] = "release-signing"
            self.sign_audit_records.append({"action": "manifest-sign", "accepted": True})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"signed_manifest": type(self).signed_manifest, "source": "request"}).encode("utf-8"))
            return
        if self.path == "/api/publish":
            manifest = payload.get("signed_manifest") or {}
            if not manifest.get("signature"):
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "signature required"}).encode("utf-8"))
                return
            type(self).signed_manifest = manifest
            self.audit_records.append({"channel": payload.get("channel"), "build_id": manifest.get("build_id")})
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"channel": payload.get("channel"), "manifest": manifest}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class SolrVelocitySmokeHandler(BaseHTTPRequestHandler):
    velocity_enabled = False
    audit_records: list[dict[str, object]] = []

    def do_GET(self) -> None:
        if self.path == "/operations/reference":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"items": [{"plugin": "solr-velocity-rce"}]}).encode("utf-8"))
            return
        if self.path == "/operations/routes?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "ops-search",
                        "routes": [
                            {"method": "GET", "path": "/operations/search-admin", "feature": "search maintenance"},
                            {"method": "GET", "path": "/solr/ops-core/admin/info/system", "feature": "search maintenance"},
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/context?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "ops-search",
                        "records": [
                            {
                                "case_id": "OPS-0001",
                                "workflow": "search maintenance",
                                "operator_note": "Operations staff review search core health before release work.",
                            }
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/search-admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Search Operations Console</h1></body></html>")
            return
        if self.path == "/api/search/cores":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "cores": [
                            {
                                "name": "ops-core",
                                "version": "8.3.1",
                                "legacy": True,
                                "velocity_enabled": self.velocity_enabled,
                            }
                        ]
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/search/policy":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "workflow": "legacy operations search maintenance",
                        "core": "ops-core",
                        "version": "8.3.1",
                        "audit_api": "/api/search/audit",
                        "drift_api": "/api/search/config-drift",
                        "legacy_response_writer_policy": "Response-writer changes are audited.",
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/search/config-drift":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "core": "ops-core",
                        "observed_version": "8.3.1",
                        "legacy_track": True,
                        "velocity_response_writer": self.velocity_enabled,
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/solr/ops-core/admin/info/system":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"lucene": {"solr-spec-version": "8.3.1"}}).encode("utf-8"))
            return
        if self.path.startswith("/solr/ops-core/select"):
            self.audit_records.append({"action": "template-query-executed", "accepted": True, "core": "ops-core"})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"uid=8983(solr) gid=8983(solr) groups=8983(solr)\n")
            return
        if self.path == "/api/search/audit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"records": self.audit_records}).encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/solr/ops-core/config":
            type(self).velocity_enabled = True
            self.audit_records.append({"action": "response-writer-config-change", "accepted": True, "core": "ops-core"})
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
        if self.path == "/operations/routes?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "support-portal",
                        "routes": [
                            {"method": "GET", "path": "/operations/config", "feature": "runtime configuration"},
                            {"method": "GET", "path": "/api/config/startup-log", "feature": "runtime configuration"},
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/context?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "support-portal",
                        "records": [
                            {
                                "case_id": "OPS-0001",
                                "workflow": "runtime configuration",
                                "operator_note": "Operators correlate config redaction with startup logs.",
                            }
                        ],
                    }
                ).encode("utf-8")
            )
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
            self.wfile.write(json.dumps({"secret_value": "redacted", "secret_reference": "lab://secret/ref", "bind_profile_api": "/api/config/bind-profile"}).encode("utf-8"))
            return
        if self.path == "/api/config/secret-policy":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "redaction_policy": "runtime config values are redacted",
                        "bind_profile_api": "/api/config/bind-profile",
                        "startup_log_api": "/api/config/startup-log",
                        "correlation_api": "/api/config/correlation",
                        "audit_api": "/api/config/access-audit",
                        "audit_provenance_fields": ["secret_reference_visible", "secret_value_visible", "secret_value_source", "profile_detail_api"],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/config/bind-profile":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "profile": {
                            "account_name": "operator-bind",
                            "downstream_service": "internal-directory",
                            "secret_reference": "lab://secret/ref",
                            "cache_profile": "operator-bind",
                            "cache_export_variable": "OPERATOR_BIND_CURRENT",
                        },
                        "correlation_api": "/api/config/correlation",
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/config/correlation":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "secret_value_in_config": "redacted",
                        "secret_reference": "lab://secret/ref",
                        "bind_profile": {"secret_reference": "lab://secret/ref", "cache_export_variable": "OPERATOR_BIND_CURRENT"},
                        "cache_profile_matches_account": True,
                        "recovered_credential": "LabForge-Operator-Training-Secret!",
                        "evidence_chain": [
                            {"source": "runtime-config", "matches_bind_profile": True},
                            {"source": "bind-profile", "matches_startup_log": True},
                            {"source": "startup-log", "secret_value_visible": True},
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/config/startup-log":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"vault-cache export OPERATOR_BIND_CURRENT=LabForge-Operator-Training-Secret!\n")
            return
        if self.path == "/api/config/access-audit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "records": [
                            {"action": "config-read", "secret_value_visible": False, "provenance": {"secret_value_source": "runtime-config-redaction"}},
                            {"action": "startup-log-read", "secret_value_visible": True, "provenance": {"secret_value_source": "startup-cache-export"}},
                        ]
                    }
                ).encode("utf-8")
            )
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class SsrfSmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/operations/reference":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"items": [{"plugin": "ssrf-internal-fetch"}]}).encode("utf-8"))
            return
        if self.path == "/operations/runbook":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Operations Runbook</h1><p>Upstream import workflow</p></body></html>")
            return
        if self.path == "/operations/routes?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "import-console",
                        "routes": [
                            {"method": "GET", "path": "/operations/fetch", "feature": "upstream import"},
                            {"method": "GET", "path": "/operations/fetch?url=<url>", "feature": "upstream import"},
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/context?format=json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "service": "import-console",
                        "records": [
                            {
                                "case_id": "OPS-0001",
                                "workflow": "upstream import",
                                "operator_note": "Analysts compare blocked metadata targets with approved internal sources.",
                            }
                        ],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/operations/fetch":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Upstream Import Console</h1></body></html>")
            return
        if self.path == "/api/source-registry":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "sources": [
                            {
                                "id": "src-metadata-service",
                                "url": "http://metadata-service:8080/metadata",
                                "owner": "integration-operations",
                                "network_zone": "corp-internal",
                                "status": "approved",
                            }
                        ],
                        "blocked_examples": ["http://169.254.169.254/latest"],
                        "validation_plan_api": "/api/source-registry/<source_id>/validation-plan",
                        "scheduled_jobs_api": "/api/import-jobs",
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/import-jobs":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "jobs": [
                            {
                                "job_id": "import-001",
                                "source_id": "src-metadata-service",
                                "source_url": "http://metadata-service:8080/metadata",
                                "owner": "integration-operations",
                                "schedule": "15m",
                                "last_result": "validated",
                                "business_impact": "metadata enrichment used by import-worker",
                                "validation_plan_api": "/api/source-registry/src-metadata-service/validation-plan",
                            }
                        ]
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/source-registry/src-metadata-service":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "source": {
                            "id": "src-metadata-service",
                            "url": "http://metadata-service:8080/metadata",
                            "owner": "integration-operations",
                            "network_zone": "corp-internal",
                            "status": "approved",
                        },
                        "fetch_api": "/operations/fetch?url=http://metadata-service:8080/metadata",
                        "validation_plan_api": "/api/source-registry/src-metadata-service/validation-plan",
                        "expected_policy_result": "allow",
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/source-registry/src-metadata-service/validation-plan":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "plan": {
                            "source_id": "src-metadata-service",
                            "source_url": "http://metadata-service:8080/metadata",
                            "expected_policy_result": "allow",
                            "manual_validation_url": "/operations/fetch?url=http://metadata-service:8080/metadata",
                            "audit_api": "/api/fetch/audit",
                            "precheck_steps": ["confirm registration", "confirm audit provenance"],
                        }
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/fetch/policy":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "approved_sources": ["http://metadata-service:8080/metadata"],
                        "blocked_examples": ["http://169.254.169.254/latest"],
                        "audit_api": "/api/fetch/audit",
                        "registry_api": "/api/source-registry",
                        "source_detail_api": "/api/source-registry/<source_id>",
                        "response_provenance": ["registry_match", "source_id", "network_zone", "policy_decision", "response_fingerprint"],
                    }
                ).encode("utf-8")
            )
            return
        if self.path == "/api/fetch/audit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "records": [
                            {
                                "url": "http://169.254.169.254/latest",
                                "allowed": False,
                                "status": 400,
                                "provenance": {"policy_decision": "deny", "registry_match": False},
                            },
                            {
                                "url": "http://metadata-service:8080/metadata",
                                "allowed": True,
                                "status": 200,
                                "provenance": {"policy_decision": "allow", "registry_match": True, "source_id": "src-metadata-service"},
                                "response_fingerprint": "abc123",
                            },
                        ]
                    }
                ).encode("utf-8")
            )
            return
        if self.path.startswith("/operations/fetch?url=http://169.254.169.254/latest"):
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "allowed": False,
                        "reason": "blocked local or metadata target",
                        "provenance": {"policy_decision": "deny", "registry_match": False},
                    }
                ).encode("utf-8")
            )
            return
        if self.path.startswith("/operations/fetch?url=http://metadata-service:8080/metadata"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "allowed": True,
                        "status": 200,
                        "upstream": {"service": "metadata-service", "scope": "lab-internal"},
                        "body": '{"service": "metadata-service"}',
                        "provenance": {"policy_decision": "allow", "registry_match": True, "source_id": "src-metadata-service"},
                        "response_fingerprint": "abc123",
                    }
                ).encode("utf-8")
            )
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
