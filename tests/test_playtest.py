import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from labforge.io import load_yaml
from labforge.playtest import endpoint_group, guidance_for_plugin, run_playtest
from labforge.providers.docker_compose.provider import endpoint_expected_texts


class PlaytestTests(unittest.TestCase):
    def test_playtest_generates_learner_access_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "playtest"
            report = run_playtest(
                Path("examples/scenario-02-ad-domain-compromise"),
                out,
                provider="docker-compose",
                profile="protected",
                materialize=True,
                force=True,
            )

            self.assertIn(report.status, {"passed", "warning"})
            self.assertTrue(report.learner_entrypoints)
            self.assertTrue(report.attacker_entrypoints)
            self.assertFalse(any("attacker" in endpoint.service for endpoint in report.learner_entrypoints))
            self.assertFalse(any("drop" in endpoint.service for endpoint in report.learner_entrypoints))
            self.assertTrue(any(step.step_id == "realism-01" for step in report.steps))
            self.assertTrue(any(step.step_id == "runtime-02" for step in report.steps))
            self.assertTrue(any(step.step_id == "chain-runtime-01" for step in report.steps))
            self.assertTrue((out / "playtest-report.md").exists())
            self.assertTrue((out / "playtest-report.yaml").exists())
            self.assertTrue((out / "learner-access.md").exists())
            self.assertTrue((out / "learner-access.json").exists())
            self.assertTrue((out / "access-playtest" / "access-playtest.md").exists())
            self.assertTrue((out / "access-playtest" / "access-playtest.yaml").exists())
            self.assertTrue((out / "solver-plan.md").exists())
            self.assertTrue((out / "solver-plan.json").exists())
            self.assertTrue((out / "solver-run" / "solver-run.md").exists())
            self.assertTrue((out / "solver-run" / "solver-run.yaml").exists())
            self.assertTrue((out / "playtest-walkthrough.md").exists())

            access = (out / "learner-access.md").read_text(encoding="utf-8")
            self.assertIn("Quick Connect", access)
            self.assertIn("Start Here", access)
            self.assertIn("Attacker Workstation", access)
            self.assertIn("Final Submission", access)
            self.assertIn("Health Checks", access)
            access_manifest = load_yaml(out / "learner-access.json")
            self.assertEqual(access_manifest["lab_id"], report.lab_id)
            self.assertTrue(access_manifest["start_commands"])
            self.assertTrue(access_manifest["status_commands"])
            self.assertTrue(access_manifest["stop_commands"])
            self.assertTrue(access_manifest["learner_entrypoints"])
            self.assertTrue(access_manifest["attacker_entrypoints"])
            self.assertEqual(len(access_manifest["final_submission_endpoints"]), len(report.final_submission_endpoints))
            self.assertTrue(access_manifest["health_checks"])
            self.assertTrue(access_manifest["terminal_checks"])
            self.assertTrue(access_manifest["terminal_sequences"])
            self.assertEqual(access_manifest["terminal_sequences"][0]["commands"], ["echo labforge-terminal-ready", "pwd"])
            self.assertTrue(access_manifest["first_action"])
            solver_plan = load_yaml(out / "solver-plan.json")
            self.assertEqual(solver_plan["lab_id"], report.lab_id)
            self.assertTrue(solver_plan["learner_start"])
            self.assertTrue(solver_plan["attacker_shell"])
            self.assertTrue(solver_plan["steps"])
            terminal_steps = [step for step in solver_plan["steps"] if step["action_type"] == "command-sequence"]
            self.assertTrue(terminal_steps)
            self.assertEqual(terminal_steps[0]["commands"], ["echo labforge-terminal-ready", "pwd"])
            self.assertEqual(terminal_steps[0]["expected_texts"], ["labforge-terminal-ready"])
            solver_run = load_yaml(out / "solver-run" / "solver-run.json")
            self.assertEqual(solver_run["lab_id"], report.lab_id)
            self.assertTrue(solver_run["steps"])
            walkthrough = (out / "playtest-walkthrough.md").read_text(encoding="utf-8")
            self.assertIn("Start the generated provider output", walkthrough)
            self.assertIn("Connect to attacker workstation", walkthrough)

            compose = load_yaml(out / "provider-output" / "docker-compose.yml")
            self.assertIn("labforge_state", compose.get("volumes", {}))
            hr_portal = compose["services"]["hr-portal"]
            self.assertEqual(hr_portal["environment"]["LABFORGE_STATE_DIR"], "/labforge-state")
            self.assertIn("labforge_state:/labforge-state", hr_portal["volumes"])

    def test_plugin_guidance_contains_discovery_cues_and_next_condition(self) -> None:
        guidance = guidance_for_plugin("ssti-preview", "support-portal")

        self.assertIn("preview", guidance["learner_action"])
        self.assertTrue(guidance["discovery_cues"])
        self.assertIn("normal merge fields", guidance["discovery_cues"][0])
        self.assertIn("Proceed when", guidance["next_step_condition"])

    def test_endpoint_group_preserves_browser_expected_texts(self) -> None:
        endpoints = endpoint_group(
            {
                "published_endpoints": [
                    {
                        "service": "document-portal",
                        "role": "learner-entry",
                        "protocol": "http",
                        "connect": "http://127.0.0.1:18080/",
                        "expected_text": "Document Library",
                        "expected_texts": ["Published Documents", "Document Library"],
                    }
                ]
            },
            lambda _item: True,
        )

        self.assertEqual(endpoints[0].expected_texts, ["Document Library", "Published Documents"])

    def test_docker_provider_derives_expected_texts_from_artifact_plugins(self) -> None:
        artifact = SimpleNamespace(
            runtime="business-portal",
            model_extra={
                "vulnerability_plugins": [
                    {"id": "path-traversal-download"},
                    {"id": "diagnostic-command-injection"},
                    {"id": "solr-velocity-rce"},
                ]
            },
        )

        self.assertEqual(
            endpoint_expected_texts(artifact),
            ["Operational Summary", "Document Library", "Operations Diagnostics Console", "Search Operations Console", "Core Status"],
        )


if __name__ == "__main__":
    unittest.main()
