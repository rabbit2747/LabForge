from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from labforge.plugin_runtime_smoke import isolate_generated_state, load_generated_app_module
from labforge.service_templates import render_enterprise_flask_service


class ServiceTemplateTests(unittest.TestCase):
    def test_enterprise_dashboard_surfaces_operations_reference_when_discovery_exists(self) -> None:
        artifact = SimpleNamespace(
            service="support-portal",
            purpose="customer support case handling",
            runtime="business-portal",
        )

        files = render_enterprise_flask_service(artifact, 8080)
        app = files["app.py"]

        self.assertIn("vulnerability-discovery.json", app)
        self.assertIn("Operations Reference", app)
        self.assertIn("/operations/reference", app)
        self.assertIn("Workflow Hints", app)
        self.assertIn("natural_clues", app)

    def test_enterprise_operations_reference_returns_workflow_guidance(self) -> None:
        artifact = SimpleNamespace(
            service="support-portal",
            purpose="customer support case handling",
            runtime="business-portal",
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = render_enterprise_flask_service(artifact, 8080)
            app_path = root / "app.py"
            seed = root / "seed"
            seed.mkdir(parents=True)
            app_path.write_text(files["app.py"], encoding="utf-8")
            (seed / "vulnerability-discovery.json").write_text(
                json.dumps(
                    {
                        "items": [
                            {
                                "business_feature": "ticket response preview",
                                "normal_routes": ["GET /operations/preview", "POST /operations/preview"],
                                "operator_language": "Preview templates support approved merge fields.",
                                "natural_clues": ["Start with normal merge fields."],
                                "noise": ["routine render errors"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (seed / "clues.json").write_text(json.dumps({"items": [{"title": "Runbook", "detail": "Use normal workflows first."}]}), encoding="utf-8")
            (seed / "workflow.json").write_text(json.dumps({"normal_workflows": [{"name": "triage"}]}), encoding="utf-8")
            module, error = load_generated_app_module("support-portal", app_path)
            self.assertIsNone(error or None)
            isolate_generated_state(module, "support-portal")
            module.SEED_DIR = seed

            response = module.app.test_client().get("/operations/reference")
            data = response.get_json()

            self.assertEqual(response.status_code, 200)
            self.assertEqual(data["service"], "support-portal")
            self.assertEqual(data["items"][0]["business_feature"], "ticket response preview")
            self.assertEqual(data["items"][0]["discovery_cues"], ["Start with normal merge fields."])
            self.assertIn("Confirm the normal route behavior", data["items"][0]["next_observation"])
            self.assertEqual(data["normal_workflows"][0]["name"], "triage")


if __name__ == "__main__":
    unittest.main()
