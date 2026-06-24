import unittest
import json
import tempfile
from pathlib import Path

from labforge.intake import (
    NaturalLanguageScenarioRequest,
    infer_industry_from_prompt,
    normalize_industry as normalize_intake_industry,
    scenario_profile_for_request,
)
from labforge.model import LabSpec
from labforge.realism import check_realism
from labforge.realism import get_realism_profile, normalize_industry


class RealismProfileTests(unittest.TestCase):
    def test_banking_aliases_do_not_collapse_to_securities(self) -> None:
        self.assertEqual(normalize_industry("banking"), "banking")
        self.assertEqual(normalize_industry("regional bank"), "banking")
        self.assertEqual(normalize_industry("core-banking"), "banking")
        self.assertEqual(normalize_industry("brokerage"), "securities")

    def test_banking_profile_has_bank_specific_capabilities(self) -> None:
        profile = get_realism_profile("banking")
        capability_ids = {capability.id for capability in profile.capabilities}

        self.assertEqual(profile.industry, "banking")
        self.assertIn("core-account-ledger", capability_ids)
        self.assertIn("loan-operations", capability_ids)
        self.assertIn("payments-batch", capability_ids)
        self.assertIn("fraud-aml-monitoring", capability_ids)
        self.assertIn("core banking", profile.required_zones)
        self.assertIn("loan operations", profile.required_zones)

    def test_banking_prompt_builds_banking_scenario_profile(self) -> None:
        prompt = (
            "Create a realistic regional bank lab with a loan application portal, "
            "core banking, payments, FDS, AML, and a compliance export."
        )
        industry = normalize_intake_industry(infer_industry_from_prompt(prompt))
        profile = scenario_profile_for_request(
            NaturalLanguageScenarioRequest(
                lab_id="banking-test",
                title="Banking Test",
                prompt=prompt,
                industry=industry,
            )
        )

        self.assertEqual(industry, "banking")
        self.assertIn("loan-application-portal", profile["target_infrastructure"][0])
        self.assertTrue(any("core-account-service" in item for item in profile["target_infrastructure"]))
        self.assertTrue(any("fraud-monitoring-service" in item for item in profile["target_infrastructure"]))

    def test_banking_realism_flags_missing_industry_surfaces_data_and_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_lab_files(
                root,
                scenario={
                    "id": "thin-bank",
                    "title": "Thin Bank",
                    "summary": "Regional bank portal lab.",
                    "final_objective": "Collect synthetic evidence.",
                    "target_industry": "banking",
                },
                topology={
                    "networks": [{"name": "public edge"}, {"name": "dmz"}],
                    "services": [{"name": "public-bank-site", "role": "portal", "networks": ["public edge"], "exposed": True}],
                    "deployment": {"recommended_model": "docker-compose", "docker_only_supported": True},
                },
                stages={
                    "stages": [
                        {
                            "id": "stage-01",
                            "title": "Open bank portal.",
                            "procedure": "Review the public banking web portal.",
                            "evidence": ["portal-viewed"],
                            "mitre": {"tactic": "Discovery", "techniques": [{"id": "T1083", "name": "File and Directory Discovery"}]},
                        }
                    ]
                },
                security_controls={"recommended": []},
            )

            report = check_realism(LabSpec.load(root), industry="banking")
            categories = {finding.category for finding in report.findings}
            codes = {finding.code for finding in report.findings}

            self.assertEqual(report.industry, "banking")
            self.assertIn("ui-surface", categories)
            self.assertIn("data-domain", categories)
            self.assertIn("security-control", categories)
            self.assertIn("ui.online-banking.missing", codes)
            self.assertIn("data.ledger.missing", codes)
            self.assertIn("security-control.mfa.missing", codes)

    def test_active_directory_realism_flags_docker_only_provider_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_lab_files(
                root,
                scenario={
                    "id": "ad-docker-only",
                    "title": "AD Docker Only",
                    "summary": "Active Directory lab with Windows workstation and Kerberos.",
                    "final_objective": "Collect synthetic evidence.",
                    "target_industry": "active-directory",
                },
                topology={
                    "networks": [{"name": "public edge"}, {"name": "workstation"}, {"name": "domain services"}, {"name": "data"}, {"name": "security monitoring"}],
                    "services": [
                        {"name": "domain-controller", "role": "windows domain controller", "networks": ["domain services"]},
                        {"name": "windows-workstation", "role": "domain joined workstation", "networks": ["workstation"]},
                    ],
                    "deployment": {"recommended_model": "docker-compose", "docker_only_supported": True},
                },
                stages={
                    "stages": [
                        {
                            "id": "stage-01",
                            "title": "Discover Kerberos services.",
                            "procedure": "Inspect domain controller, workstation, Kerberos, LDAP, GPO, and Windows event log context.",
                            "evidence": ["domain-context"],
                            "mitre": {"tactic": "Discovery", "techniques": [{"id": "T1087", "name": "Account Discovery"}]},
                        }
                    ]
                },
                security_controls={"recommended": ["event logging", "siem"]},
            )

            report = check_realism(LabSpec.load(root), industry="active-directory")
            codes = {finding.code for finding in report.findings}

            self.assertIn("provider.docker-only.realism-gap", codes)


def write_lab_files(root: Path, *, scenario: dict, topology: dict, stages: dict, security_controls: dict | None = None) -> None:
    (root / "scenario.yaml").write_text(json.dumps(scenario, ensure_ascii=False, indent=2), encoding="utf-8")
    (root / "topology.yaml").write_text(json.dumps(topology, ensure_ascii=False, indent=2), encoding="utf-8")
    (root / "stages.yaml").write_text(json.dumps(stages, ensure_ascii=False, indent=2), encoding="utf-8")
    if security_controls is not None:
        (root / "security-controls.yaml").write_text(json.dumps(security_controls, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
