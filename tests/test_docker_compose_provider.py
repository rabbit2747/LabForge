import tempfile
import unittest
from pathlib import Path

from labforge.io import dump_yaml, load_yaml, write_text
from labforge.model import LabSpec
from labforge.providers.docker_compose.provider import render_compose, render_provider_service_plan


class DockerComposeProviderTests(unittest.TestCase):
    def test_trusted_update_services_share_labforge_state_volume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "trusted-update-lab"
            root.mkdir()
            write_text(
                root / "scenario.yaml",
                dump_yaml(
                    {
                        "id": "trusted-update-lab",
                        "title": "Trusted Update Lab",
                        "summary": "Build, sign, publish, and customer update handoff.",
                        "final_objective": "Reach the controlled final object after customer update.",
                    }
                ),
            )
            write_text(
                root / "topology.yaml",
                dump_yaml(
                    {
                        "networks": [{"name": "release_net", "internal": True}, {"name": "customer_net", "internal": True}],
                        "services": [
                            {"name": "build-server", "role": "build service", "networks": ["release_net"], "expose": ["8080"]},
                            {"name": "update-server", "role": "update channel", "networks": ["release_net"], "expose": ["8080"]},
                            {"name": "customer-agent", "role": "customer update consumer", "networks": ["customer_net"], "expose": ["8080"]},
                        ],
                    }
                ),
            )
            write_text(
                root / "stages.yaml",
                dump_yaml(
                    {
                        "stages": [
                            {
                                "id": "stage-01",
                                "title": "Build",
                                "procedure": "Create a build manifest.",
                                "evidence": ["build_manifest_created"],
                                "mitre": {"tactic": "Execution", "techniques": [{"id": "T1195.002", "name": "Compromise Software Supply Chain"}]},
                            },
                            {
                                "id": "stage-02",
                                "title": "Publish",
                                "procedure": "Sign and publish the manifest.",
                                "required_findings": ["build_manifest_created"],
                                "evidence": ["signed_manifest_published"],
                                "mitre": {"tactic": "Persistence", "techniques": [{"id": "T1195.002", "name": "Compromise Software Supply Chain"}]},
                            },
                        ]
                    }
                ),
            )
            write_text(
                root / "artifacts.yaml",
                dump_yaml(
                    {
                        "service_artifacts": [
                            {
                                "service": "build-server",
                                "source_path": "services/build-server",
                                "runtime": "Python web application",
                                "purpose": "Create build manifests.",
                                "healthcheck": "GET /healthz",
                                "reset": "Clear generated build state.",
                                "vulnerability_plugins": [{"id": "build-pipeline-abuse"}],
                            },
                            {
                                "service": "update-server",
                                "source_path": "services/update-server",
                                "runtime": "Python web application",
                                "purpose": "Sign and publish manifests.",
                                "healthcheck": "GET /healthz",
                                "reset": "Clear update channel state.",
                                "vulnerability_plugins": [{"id": "signed-update-publish"}],
                            },
                            {
                                "service": "customer-agent",
                                "source_path": "services/customer-agent",
                                "runtime": "Python web application",
                                "purpose": "Apply trusted update state.",
                                "healthcheck": "GET /healthz",
                                "reset": "Clear customer agent state.",
                                "vulnerability_plugins": [{"id": "customer-update-callback"}],
                            },
                        ]
                    }
                ),
            )

            spec = LabSpec.load(root)
            compose = load_yaml_from_text(render_compose(spec, profile="protected"))
            service_plan = render_provider_service_plan(spec)

        self.assertIn("labforge_state", compose["volumes"])
        for service in ("build-server", "update-server", "customer-agent"):
            entry = compose["services"][service]
            self.assertEqual(entry["environment"]["LABFORGE_STATE_DIR"], "/labforge-state")
            self.assertIn("labforge_state:/labforge-state", entry["volumes"])
            self.assertIn("no-new-privileges:true", entry["security_opt"])
            self.assertIn(service, service_plan)
        self.assertIn("Trusted Update Shared State", service_plan)
        self.assertIn("build manifests, signed manifests, published channel state, and customer update state", service_plan)


def load_yaml_from_text(content: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "compose.yaml"
        write_text(path, content)
        return load_yaml(path)


if __name__ == "__main__":
    unittest.main()
