from __future__ import annotations

import unittest
from types import SimpleNamespace

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


if __name__ == "__main__":
    unittest.main()
