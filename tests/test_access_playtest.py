from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from labforge.access_playtest import command_to_argv, run_access_playtest


class AccessPlaytestTests(unittest.TestCase):
    def test_access_playtest_plans_browser_and_terminal_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "learner-access.json"
            manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "access-smoke",
                        "title": "Access Smoke",
                        "provider": "docker-compose",
                        "profile": "protected",
                        "learner_entrypoints": [
                            {
                                "service": "investor-portal",
                                "role": "learner-entry",
                                "protocol": "http",
                                "connect": "http://127.0.0.1:18081/",
                                "health_url": "http://127.0.0.1:18081/healthz",
                            }
                        ],
                        "attacker_entrypoints": [
                            {
                                "service": "attacker-workstation",
                                "role": "attacker",
                                "protocol": "ssh",
                                "connect": "ssh attacker@127.0.0.1 -p 2222",
                            }
                        ],
                        "final_submission_endpoints": [
                            {
                                "service": "controlled-drop",
                                "role": "final-submission",
                                "protocol": "http",
                                "connect": "http://127.0.0.1:18082/",
                                "health_url": "http://127.0.0.1:18082/healthz",
                            }
                        ],
                        "health_checks": [
                            {
                                "service": "investor-portal",
                                "kind": "http-health",
                                "command": "curl -i http://127.0.0.1:18081/healthz",
                                "expected": "healthy",
                            }
                        ],
                        "terminal_checks": [
                            {
                                "service": "attacker-workstation",
                                "kind": "ssh-connect",
                                "command": "ssh attacker@127.0.0.1 -p 2222",
                                "expected": "shell",
                            }
                        ],
                        "first_action": "Open http://127.0.0.1:18081/",
                    }
                ),
                encoding="utf-8",
            )

            report = run_access_playtest(manifest, root / "access-playtest", execute=False)

            self.assertEqual(report.status, "planned")
            self.assertEqual(report.browser_targets, ["http://127.0.0.1:18081/"])
            self.assertEqual(report.terminal_targets, ["ssh attacker@127.0.0.1 -p 2222"])
            self.assertEqual([item.status for item in report.items], ["planned", "planned", "planned", "planned"])
            self.assertEqual(report.items[0].kind, "browser-http")
            self.assertEqual(report.items[1].kind, "final-http")
            self.assertTrue((root / "access-playtest" / "access-playtest.md").exists())
            self.assertTrue((root / "access-playtest" / "access-playtest.yaml").exists())
            self.assertTrue((root / "access-playtest" / "access-playtest.json").exists())

    def test_access_playtest_executes_browser_http_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), BrowserSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                manifest = root / "learner-access.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "lab_id": "browser-smoke",
                            "title": "Browser Smoke",
                            "learner_entrypoints": [
                                {
                                    "service": "business-portal",
                                    "role": "learner-entry",
                                    "protocol": "http",
                                    "connect": f"{base_url}/",
                                    "expected_texts": ["Operational Summary"],
                                }
                            ],
                            "attacker_entrypoints": [],
                            "health_checks": [],
                            "terminal_checks": [],
                        }
                    ),
                    encoding="utf-8",
                )

                report = run_access_playtest(manifest, root / "access-playtest", execute=True)

                self.assertEqual(report.status, "passed")
                self.assertEqual(len(report.items), 1)
                self.assertEqual(report.items[0].kind, "browser-http")
                self.assertEqual(report.items[0].status, "passed")
                self.assertIn("http_status=200", report.items[0].message)
                self.assertIn("matched_expected_text=1", report.items[0].message)
                self.assertIn("Operational Summary", report.items[0].stdout)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_access_playtest_warns_when_browser_expected_text_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), BrowserSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                manifest = root / "learner-access.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "lab_id": "browser-smoke",
                            "title": "Browser Smoke",
                            "learner_entrypoints": [
                                {
                                    "service": "business-portal",
                                    "role": "learner-entry",
                                    "protocol": "http",
                                    "connect": f"{base_url}/",
                                    "expected_text": "Missing Business Console",
                                }
                            ],
                            "attacker_entrypoints": [],
                            "health_checks": [],
                            "terminal_checks": [],
                        }
                    ),
                    encoding="utf-8",
                )

                report = run_access_playtest(manifest, root / "access-playtest", execute=True)

                self.assertEqual(report.status, "warning")
                self.assertEqual(report.items[0].status, "warning")
                self.assertIn("missing_expected_text=Missing Business Console", report.items[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_access_playtest_can_use_playwright_browser_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "learner-access.json"
            manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "browser-smoke",
                        "title": "Browser Smoke",
                        "learner_entrypoints": [
                            {
                                "service": "business-portal",
                                "role": "learner-entry",
                                "protocol": "http",
                                "connect": "http://127.0.0.1:18081/",
                                "expected_texts": ["Operational Summary"],
                            }
                        ],
                        "attacker_entrypoints": [],
                        "health_checks": [],
                        "terminal_checks": [],
                    }
                ),
                encoding="utf-8",
            )
            completed = SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "ok": True,
                        "url": "http://127.0.0.1:18081/",
                        "title": "Business Portal",
                        "text": "Operational Summary",
                        "missing": [],
                    }
                ),
                stderr="",
            )

            with patch("labforge.access_playtest.shutil.which", return_value="npx"), patch(
                "labforge.access_playtest.subprocess.run",
                return_value=completed,
            ) as run_mock:
                report = run_access_playtest(
                    manifest,
                    root / "access-playtest",
                    execute=True,
                    browser_engine="playwright",
                )

            self.assertEqual(report.status, "passed")
            self.assertEqual(report.items[0].kind, "browser-playwright")
            self.assertEqual(report.items[0].status, "passed")
            self.assertIn("browser_loaded=true", report.items[0].message)
            argv = run_mock.call_args.args[0]
            self.assertIn("--package", argv)
            self.assertIn("playwright", argv)

    def test_ssh_command_is_converted_to_batch_mode_check(self) -> None:
        argv = command_to_argv("ssh attacker@127.0.0.1 -p 2222", "ssh-connect")

        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ConnectTimeout=5", argv)


class BrowserSmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Operational Summary</h1></body></html>")

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    unittest.main()
