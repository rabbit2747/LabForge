from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from labforge.access_playtest import command_to_argv, parse_ssh_local_forward, run_access_playtest, ssh_tunnel_argv


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
                        "terminal_sequences": [
                            {
                                "service": "attacker-workstation",
                                "kind": "ssh-command-sequence",
                                "connect": "ssh attacker@127.0.0.1 -p 2222",
                                "commands": ["echo labforge-terminal-ready", "pwd"],
                                "expected_texts": ["labforge-terminal-ready"],
                            }
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
                        "plugin_checks": [
                            {
                                "service": "investor-portal",
                                "plugin": "ssti-preview",
                                "state_url": "http://127.0.0.1:18081/api/state",
                                "expected_evidence": ["template_probe_confirmed"],
                            }
                        ],
                        "stage_chain_checks": [
                            {
                                "service": "investor-portal",
                                "chain_url": "http://127.0.0.1:18081/api/chain",
                                "expected_stage": "stage-02",
                                "expected_evidence": ["template_probe_confirmed"],
                                "expected_clue": "Use template evidence.",
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
            self.assertEqual([item.status for item in report.items], ["planned", "planned", "planned", "planned", "planned", "planned", "planned", "planned"])
            self.assertEqual(report.items[0].kind, "browser-http")
            self.assertEqual(report.items[1].kind, "final-http")
            self.assertEqual(report.items[-4].kind, "ssh-command-sequence")
            self.assertEqual(report.items[-3].kind, "ssh-local-forward")
            self.assertEqual(report.items[-2].kind, "plugin-evidence")
            self.assertEqual(report.items[-1].kind, "stage-chain")
            self.assertTrue((root / "access-playtest" / "access-playtest.md").exists())
            self.assertTrue((root / "access-playtest" / "access-playtest.yaml").exists())
            self.assertTrue((root / "access-playtest" / "access-playtest.json").exists())

    def test_access_playtest_executes_stage_chain_context_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), ChainContextHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                manifest = root / "learner-access.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "lab_id": "chain-context-smoke",
                            "title": "Chain Context Smoke",
                            "learner_entrypoints": [],
                            "attacker_entrypoints": [],
                            "final_submission_endpoints": [],
                            "stage_chain_checks": [
                                {
                                    "service": "internal-wiki",
                                    "chain_url": f"{base_url}/api/chain",
                                    "expected_stage": "stage-02",
                                    "expected_evidence": ["template_probe_confirmed"],
                                    "expected_clue": "Use template evidence to find wiki context.",
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )

                report = run_access_playtest(manifest, root / "access-playtest", execute=True)

                self.assertEqual(report.status, "passed")
                self.assertEqual(report.items[0].kind, "stage-chain")
                self.assertEqual(report.items[0].status, "passed")
                self.assertIn("stage_chain_context_present", report.items[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

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

    def test_access_playtest_executes_plugin_evidence_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), StateSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                manifest = root / "learner-access.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "lab_id": "plugin-evidence-smoke",
                            "title": "Plugin Evidence Smoke",
                            "learner_entrypoints": [],
                            "attacker_entrypoints": [],
                            "health_checks": [],
                            "terminal_checks": [],
                            "plugin_checks": [
                                {
                                    "service": "support-portal",
                                    "plugin": "ssti-preview",
                                    "state_url": f"{base_url}/api/state",
                                    "expected_evidence": ["template_probe_confirmed"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )

                report = run_access_playtest(manifest, root / "access-playtest", execute=True)

                self.assertEqual(report.status, "passed")
                self.assertEqual(len(report.items), 1)
                self.assertEqual(report.items[0].kind, "plugin-evidence")
                self.assertEqual(report.items[0].status, "passed")
                self.assertIn("expected_evidence_present=1", report.items[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_access_playtest_fails_when_plugin_evidence_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), StateSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                manifest = root / "learner-access.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "lab_id": "plugin-evidence-smoke",
                            "title": "Plugin Evidence Smoke",
                            "learner_entrypoints": [],
                            "attacker_entrypoints": [],
                            "health_checks": [],
                            "terminal_checks": [],
                            "plugin_checks": [
                                {
                                    "service": "support-portal",
                                    "plugin": "ssti-preview",
                                    "state_url": f"{base_url}/api/state",
                                    "expected_evidence": ["missing_event"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )

                report = run_access_playtest(manifest, root / "access-playtest", execute=True)

                self.assertEqual(report.status, "failed")
                self.assertEqual(report.items[0].kind, "plugin-evidence")
                self.assertEqual(report.items[0].status, "failed")
                self.assertIn("missing_expected_evidence=missing_event", report.items[0].message)
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
                                "expected_selectors": ["main", "form"],
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
                        "missingSelectors": [],
                        "selectorCounts": {"main": 1, "form": 1},
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
            self.assertIn("matched_expected_selector=2", report.items[0].message)
            argv = run_mock.call_args.args[0]
            self.assertIn("--package", argv)
            self.assertIn("playwright", argv)
            self.assertIn(json.dumps(["main", "form"]), argv)

    def test_access_playtest_warns_when_playwright_selector_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "learner-access.json"
            manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "browser-selector-smoke",
                        "title": "Browser Selector Smoke",
                        "learner_entrypoints": [
                            {
                                "service": "business-portal",
                                "role": "learner-entry",
                                "protocol": "http",
                                "connect": "http://127.0.0.1:18081/",
                                "expected_texts": ["Operational Summary"],
                                "expected_selectors": ["main", "form"],
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
                        "ok": False,
                        "url": "http://127.0.0.1:18081/",
                        "title": "Business Portal",
                        "text": "Operational Summary",
                        "missing": [],
                        "missingSelectors": ["form"],
                        "selectorCounts": {"main": 1, "form": 0},
                    }
                ),
                stderr="",
            )

            with patch("labforge.access_playtest.shutil.which", return_value="npx"), patch(
                "labforge.access_playtest.subprocess.run",
                return_value=completed,
            ):
                report = run_access_playtest(
                    manifest,
                    root / "access-playtest",
                    execute=True,
                    browser_engine="playwright",
                )

            self.assertEqual(report.status, "warning")
            self.assertEqual(report.items[0].kind, "browser-playwright")
            self.assertEqual(report.items[0].status, "warning")
            self.assertIn("missing_expected_selector=form", report.items[0].message)

    def test_ssh_command_is_converted_to_batch_mode_check(self) -> None:
        argv = command_to_argv("ssh attacker@127.0.0.1 -p 2222", "ssh-connect")

        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ConnectTimeout=5", argv)

    def test_access_playtest_executes_ssh_command_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "learner-access.json"
            manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "terminal-smoke",
                        "title": "Terminal Smoke",
                        "learner_entrypoints": [],
                        "attacker_entrypoints": [],
                        "health_checks": [],
                        "terminal_checks": [],
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
            completed = SimpleNamespace(returncode=0, stdout="labforge-terminal-ready\n/home/attacker\n", stderr="")

            with patch("labforge.access_playtest.shutil.which", return_value="ssh"), patch(
                "labforge.access_playtest.subprocess.run",
                return_value=completed,
            ) as run_mock:
                report = run_access_playtest(manifest, root / "access-playtest", execute=True)

            self.assertEqual(report.status, "passed")
            self.assertEqual(report.items[0].kind, "ssh-command-sequence")
            self.assertEqual(report.items[0].status, "passed")
            self.assertIn("commands=2", report.items[0].message)
            argv = run_mock.call_args.args[0]
            self.assertEqual(argv[0], "ssh")
            self.assertIn("BatchMode=yes", argv)
            self.assertEqual(argv[-1], "echo labforge-terminal-ready && pwd")

    def test_access_playtest_validates_tunnel_command_without_opening_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "learner-access.json"
            manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "tunnel-smoke",
                        "title": "Tunnel Smoke",
                        "learner_entrypoints": [],
                        "attacker_entrypoints": [],
                        "health_checks": [],
                        "terminal_checks": [],
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
                    }
                ),
                encoding="utf-8",
            )

            with patch("labforge.access_playtest.shutil.which", return_value="ssh"):
                report = run_access_playtest(manifest, root / "access-playtest", execute=True)

            self.assertEqual(report.status, "passed")
            self.assertEqual(report.items[0].kind, "ssh-local-forward")
            self.assertEqual(report.items[0].status, "passed")
            self.assertIn("execution_noninvasive=true", report.items[0].message)

    def test_access_playtest_can_execute_tunnel_probe_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "learner-access.json"
            manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "tunnel-live-smoke",
                        "title": "Tunnel Live Smoke",
                        "learner_entrypoints": [],
                        "attacker_entrypoints": [],
                        "health_checks": [],
                        "terminal_checks": [],
                        "tunnel_commands": [
                            {
                                "service": "wiki",
                                "dns": "wiki",
                                "internal_port": "6000",
                                "local_port": 18080,
                                "command": "ssh -L 18080:wiki:6000 attacker@127.0.0.1 -p 2222",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            process = FakeTunnelProcess()

            with patch("labforge.access_playtest.shutil.which", return_value="ssh"), patch(
                "labforge.access_playtest.subprocess.Popen",
                return_value=process,
            ) as popen_mock, patch("labforge.access_playtest.wait_for_tcp_port", return_value=True):
                report = run_access_playtest(
                    manifest,
                    root / "access-playtest",
                    execute=True,
                    execute_tunnels=True,
                )

            self.assertEqual(report.status, "passed")
            self.assertEqual(report.items[0].kind, "ssh-local-forward")
            self.assertIn("tunnel_open=true", report.items[0].message)
            self.assertTrue(process.terminated)
            argv = popen_mock.call_args.args[0]
            self.assertEqual(argv[0], "ssh")
            self.assertIn("-N", argv)
            self.assertIn("ExitOnForwardFailure=yes", argv)

    def test_access_playtest_probes_tunnel_url_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), BrowserSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                local_port = server.server_port
                manifest = root / "learner-access.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "lab_id": "tunnel-url-smoke",
                            "title": "Tunnel URL Smoke",
                            "learner_entrypoints": [],
                            "attacker_entrypoints": [],
                            "health_checks": [],
                            "terminal_checks": [],
                            "tunnel_commands": [
                                {
                                    "service": "wiki",
                                    "dns": "wiki",
                                    "internal_port": "6000",
                                    "local_port": local_port,
                                    "command": f"ssh -L {local_port}:wiki:6000 attacker@127.0.0.1 -p 2222",
                                    "url": f"http://127.0.0.1:{local_port}/",
                                    "expected_texts": ["Operational Summary"],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                process = FakeTunnelProcess()

                with patch("labforge.access_playtest.shutil.which", return_value="ssh"), patch(
                    "labforge.access_playtest.subprocess.Popen",
                    return_value=process,
                ), patch("labforge.access_playtest.wait_for_tcp_port", return_value=True):
                    report = run_access_playtest(
                        manifest,
                        root / "access-playtest",
                        execute=True,
                        execute_tunnels=True,
                    )

                self.assertEqual(report.status, "passed")
                self.assertIn("tunnel_url_status=passed", report.items[0].message)
                self.assertIn("matched_expected_text=1", report.items[0].message)
                self.assertIn("Operational Summary", report.items[0].stdout)
                self.assertTrue(process.terminated)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_access_playtest_fails_tunnel_url_when_expected_text_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = ThreadingHTTPServer(("127.0.0.1", 0), BrowserSmokeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                local_port = server.server_port
                manifest = root / "learner-access.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "lab_id": "tunnel-url-missing-text",
                            "title": "Tunnel URL Missing Text",
                            "learner_entrypoints": [],
                            "attacker_entrypoints": [],
                            "health_checks": [],
                            "terminal_checks": [],
                            "tunnel_commands": [
                                {
                                    "service": "wiki",
                                    "dns": "wiki",
                                    "internal_port": "6000",
                                    "local_port": local_port,
                                    "command": f"ssh -L {local_port}:wiki:6000 attacker@127.0.0.1 -p 2222",
                                    "url": f"http://127.0.0.1:{local_port}/",
                                    "expected_text": "Internal Wiki",
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )

                with patch("labforge.access_playtest.shutil.which", return_value="ssh"), patch(
                    "labforge.access_playtest.subprocess.Popen",
                    return_value=FakeTunnelProcess(),
                ), patch("labforge.access_playtest.wait_for_tcp_port", return_value=True):
                    report = run_access_playtest(
                        manifest,
                        root / "access-playtest",
                        execute=True,
                        execute_tunnels=True,
                    )

                self.assertEqual(report.status, "failed")
                self.assertIn("missing_expected_text=Internal Wiki", report.items[0].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

    def test_access_playtest_fails_tunnel_command_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "learner-access.json"
            manifest.write_text(
                json.dumps(
                    {
                        "lab_id": "tunnel-mismatch",
                        "title": "Tunnel Mismatch",
                        "learner_entrypoints": [],
                        "attacker_entrypoints": [],
                        "health_checks": [],
                        "terminal_checks": [],
                        "tunnel_commands": [
                            {
                                "service": "wiki",
                                "dns": "wiki",
                                "internal_port": "6000",
                                "local_port": 18080,
                                "command": "ssh -L 18081:wiki:6000 attacker@127.0.0.1 -p 2222",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = run_access_playtest(manifest, root / "access-playtest", execute=True)

            self.assertEqual(report.status, "failed")
            self.assertEqual(report.items[0].kind, "ssh-local-forward")
            self.assertIn("local_port mismatch", report.items[0].message)

    def test_parse_ssh_local_forward_supports_joined_l_option(self) -> None:
        parsed = parse_ssh_local_forward("ssh -L18080:wiki:6000 attacker@127.0.0.1 -p 2222")

        self.assertEqual(parsed, {"local_port": "18080", "target_host": "wiki", "target_port": "6000"})

    def test_ssh_tunnel_argv_adds_noninteractive_forward_options(self) -> None:
        argv = ssh_tunnel_argv("ssh -L 18080:wiki:6000 attacker@127.0.0.1 -p 2222")

        self.assertEqual(argv[:2], ["ssh", "-N"])
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ExitOnForwardFailure=yes", argv)
        self.assertIn("18080:wiki:6000", argv)


class BrowserSmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Operational Summary</h1></body></html>")

    def log_message(self, format: str, *args: object) -> None:
        return


class StateSmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"acquired_evidence": ["template_probe_confirmed"], "stages": []}).encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        return


class ChainContextHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(
            json.dumps(
                {
                    "service": "internal-wiki",
                    "stages": [
                        {
                            "stage_id": "stage-02",
                            "required_inputs": ["template_probe_confirmed"],
                            "learner_clue": "Use template evidence to find wiki context.",
                        }
                    ],
                }
            ).encode("utf-8")
        )

    def log_message(self, format: str, *args: object) -> None:
        return


class FakeTunnelProcess:
    def __init__(self) -> None:
        self.terminated = False
        self.killed = False

    def poll(self):
        return None

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self) -> None:
        self.killed = True

    def communicate(self, timeout=None):
        return "", ""


if __name__ == "__main__":
    unittest.main()
