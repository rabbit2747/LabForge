import tempfile
import unittest
from pathlib import Path

from labforge.io import load_yaml
from labforge.playtest import run_playtest


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
            self.assertTrue((out / "playtest-walkthrough.md").exists())

            access = (out / "learner-access.md").read_text(encoding="utf-8")
            self.assertIn("Start Here", access)
            self.assertIn("Attacker Workstation", access)
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
            self.assertTrue(access_manifest["first_action"])
            solver_plan = load_yaml(out / "solver-plan.json")
            self.assertEqual(solver_plan["lab_id"], report.lab_id)
            self.assertTrue(solver_plan["learner_start"])
            self.assertTrue(solver_plan["attacker_shell"])
            self.assertTrue(solver_plan["steps"])
            walkthrough = (out / "playtest-walkthrough.md").read_text(encoding="utf-8")
            self.assertIn("Start the generated provider output", walkthrough)
            self.assertIn("Connect to attacker workstation", walkthrough)

            compose = load_yaml(out / "provider-output" / "docker-compose.yml")
            self.assertIn("labforge_state", compose.get("volumes", {}))
            hr_portal = compose["services"]["hr-portal"]
            self.assertEqual(hr_portal["environment"]["LABFORGE_STATE_DIR"], "/labforge-state")
            self.assertIn("labforge_state:/labforge-state", hr_portal["volumes"])


if __name__ == "__main__":
    unittest.main()
