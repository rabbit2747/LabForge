import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from labforge.doctor import HostDoctorReport, WslDistro
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

    def test_docker_compose_dry_run_delegates_to_wsl_when_windows_host_lacks_docker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "generated"
            root.mkdir(parents=True)
            (root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            report = HostDoctorReport(
                host_os="windows",
                platform="Windows",
                architecture="AMD64",
                shell_hint="powershell",
                cwd=str(root),
                wsl_available=True,
                wsl_distros=[
                    WslDistro(
                        name="Ubuntu-24.04",
                        state="Running",
                        version="2",
                        docker_cli=True,
                        docker_server=True,
                        docker_server_version="29.1.3",
                    )
                ],
                host_docker_cli=False,
                host_docker_server=False,
                recommended_execution="wsl",
            )

            with patch("labforge.provider_lifecycle.platform.system", return_value="Windows"), patch(
                "labforge.provider_lifecycle.inspect_host",
                return_value=report,
            ):
                result = provider_lifecycle(root, provider="docker-compose", action="validate", execute=False)

            self.assertEqual(result.status, "planned")
            self.assertEqual(result.commands[0][:5], ["wsl.exe", "-d", "Ubuntu-24.04", "--", "bash"])
            self.assertIn("docker compose", result.commands[0][-1])
            self.assertIn("/docker-compose.yml", result.commands[0][-1])


if __name__ == "__main__":
    unittest.main()
