import tempfile
import unittest
from pathlib import Path

from labforge.provider_lifecycle import provider_lifecycle


class ProviderLifecycleTests(unittest.TestCase):
    def test_non_docker_validate_executes_scaffold_file_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "generated"
            ansible_root = root / "ansible"
            ansible_root.mkdir(parents=True)
            for name in ["README.md", "provider-plan.yaml", "inventory.yaml", "security-profile.md", "site.yml"]:
                (ansible_root / name).write_text("ok\n", encoding="utf-8")

            result = provider_lifecycle(root, provider="ansible", action="validate", execute=True)

            self.assertEqual(result.status, "completed")
            self.assertEqual(result.output_dir, str(ansible_root.resolve()))
            self.assertIn("found site.yml", result.stdout)

    def test_non_docker_deploy_is_planned_but_not_auto_executed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "terraform"
            root.mkdir(parents=True)

            result = provider_lifecycle(root, provider="terraform", action="deploy", execute=False)

            self.assertEqual(result.status, "planned")
            self.assertIn("terraform", result.commands[0][0])
            self.assertIn("apply", result.commands[0])

    def test_non_docker_validate_reports_missing_scaffold_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ludus"
            root.mkdir(parents=True)
            (root / "README.md").write_text("ok\n", encoding="utf-8")

            result = provider_lifecycle(root, provider="ludus", action="validate", execute=True)

            self.assertEqual(result.status, "failed")
            self.assertIn("range-config.yaml", result.message)


if __name__ == "__main__":
    unittest.main()
