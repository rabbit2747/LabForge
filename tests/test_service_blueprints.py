from __future__ import annotations

import unittest
from types import SimpleNamespace

from labforge.service_blueprints import infer_template_from_artifact


class ServiceBlueprintTemplateTests(unittest.TestCase):
    def test_infer_template_does_not_treat_business_workstation_as_attacker_host(self) -> None:
        artifact = SimpleNamespace(
            service="clinical-workstation",
            runtime="scenario-derived-mvp-runtime",
            purpose="Internal clinical workstation for review and diagnostic workflow.",
        )

        self.assertEqual(infer_template_from_artifact(artifact), "internal-admin-console")

    def test_infer_template_keeps_attacker_workstation_as_ssh_host(self) -> None:
        artifact = SimpleNamespace(
            service="attacker-workstation",
            runtime="scenario-derived-mvp-runtime",
            purpose="Learner attack workstation for lab-contained shell access.",
        )

        self.assertEqual(infer_template_from_artifact(artifact), "attacker-workstation-ssh")


if __name__ == "__main__":
    unittest.main()
