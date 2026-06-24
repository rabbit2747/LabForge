from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

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
            self.assertEqual([item.status for item in report.items], ["planned", "planned"])
            self.assertTrue((root / "access-playtest" / "access-playtest.md").exists())
            self.assertTrue((root / "access-playtest" / "access-playtest.yaml").exists())
            self.assertTrue((root / "access-playtest" / "access-playtest.json").exists())

    def test_ssh_command_is_converted_to_batch_mode_check(self) -> None:
        argv = command_to_argv("ssh attacker@127.0.0.1 -p 2222", "ssh-connect")

        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ConnectTimeout=5", argv)


if __name__ == "__main__":
    unittest.main()
