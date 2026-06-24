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
from labforge.realism import check_industry_context, check_realism
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

    def test_industry_context_passes_when_services_and_stages_use_business_language(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_lab_files(
                root,
                scenario={
                    "id": "securities-context",
                    "title": "Securities Context",
                    "summary": "Brokerage lab across investor support, market data, order review, settlement, and compliance export.",
                    "final_objective": "Collect synthetic compliance export evidence.",
                    "target_industry": "securities",
                },
                topology={
                    "networks": [
                        {"name": "public or internet edge"},
                        {"name": "dmz"},
                        {"name": "application"},
                        {"name": "core trading"},
                        {"name": "data"},
                        {"name": "security monitoring"},
                    ],
                    "services": [
                        {"name": "investor-portal", "role": "public brokerage support portal", "networks": ["dmz"], "purpose": "Investor notice and support workflow."},
                        {"name": "market-data-gateway", "role": "quote feed and ticker cache", "networks": ["core trading"], "purpose": "Market data subscription and quote refresh."},
                        {"name": "order-management-system", "role": "trading order review console", "networks": ["application"], "purpose": "Broker order status and execution reports."},
                        {"name": "compliance-export-service", "role": "regulatory reporting and surveillance export", "networks": ["data"], "purpose": "Compliance audit evidence export."},
                    ],
                    "deployment": {"recommended_model": "docker-compose", "docker_only_supported": True},
                },
                stages={
                    "stages": [
                        {
                            "id": "stage-01",
                            "title": "Review investor portal workflow.",
                            "procedure": "Inspect investor notice records and brokerage support requests before testing the preview path.",
                            "evidence": ["investor-portal-context"],
                            "mitre": {"tactic": "Initial Access", "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}]},
                        },
                        {
                            "id": "stage-02",
                            "title": "Correlate quote and order context.",
                            "procedure": "Use market data gateway notes and order management records to locate the ANRC trading channel workflow.",
                            "required_findings": ["investor-portal-context"],
                            "evidence": ["market-data-order-context"],
                            "mitre": {"tactic": "Discovery", "techniques": [{"id": "T1083", "name": "File and Directory Discovery"}]},
                        },
                        {
                            "id": "stage-03",
                            "title": "Locate compliance export.",
                            "procedure": "Follow surveillance and regulatory reporting notes to the compliance export service.",
                            "required_findings": ["market-data-order-context"],
                            "evidence": ["compliance-export-context"],
                            "mitre": {"tactic": "Collection", "techniques": [{"id": "T1005", "name": "Data from Local System"}]},
                        },
                    ]
                },
                security_controls={"recommended": ["waf", "mfa", "siem", "ids", "audit", "segmentation"]},
            )

            coverage = check_industry_context(LabSpec.load(root), industry="securities")

            self.assertEqual(coverage.status, "passed")
            self.assertIn("public-investor-web", coverage.covered_capabilities)
            self.assertIn("market-data", coverage.covered_capabilities)
            self.assertIn("trading-channel", coverage.covered_capabilities)
            self.assertIn("risk-compliance", coverage.covered_capabilities)

    def test_industry_context_flags_generic_services_and_stages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_lab_files(
                root,
                scenario={
                    "id": "generic-bank",
                    "title": "Generic Bank",
                    "summary": "Banking lab.",
                    "final_objective": "Collect synthetic evidence.",
                    "target_industry": "banking",
                },
                topology={
                    "networks": [{"name": "dmz"}, {"name": "data"}],
                    "services": [
                        {"name": "web-one", "role": "generic vulnerable web", "networks": ["dmz"]},
                        {"name": "api-one", "role": "generic internal api", "networks": ["data"]},
                    ],
                    "deployment": {"recommended_model": "docker-compose", "docker_only_supported": True},
                },
                stages={
                    "stages": [
                        {
                            "id": "stage-01",
                            "title": "Find vulnerability.",
                            "procedure": "Open the web app and continue.",
                            "evidence": ["one"],
                            "mitre": {"tactic": "Initial Access", "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}]},
                        },
                        {
                            "id": "stage-02",
                            "title": "Read data.",
                            "procedure": "Use the next service.",
                            "required_findings": ["one"],
                            "evidence": ["two"],
                            "mitre": {"tactic": "Collection", "techniques": [{"id": "T1005", "name": "Data from Local System"}]},
                        },
                    ]
                },
                security_controls={"recommended": []},
            )

            coverage = check_industry_context(LabSpec.load(root), industry="banking")
            codes = {finding.code for finding in coverage.findings}

            self.assertEqual(coverage.status, "warning")
            self.assertIn("industry-context.coverage.too-thin", codes)
            self.assertIn("industry-context.stage-language.missing", codes)
            self.assertIn("industry-context.service-language.missing", codes)


def write_lab_files(root: Path, *, scenario: dict, topology: dict, stages: dict, security_controls: dict | None = None) -> None:
    (root / "scenario.yaml").write_text(json.dumps(scenario, ensure_ascii=False, indent=2), encoding="utf-8")
    (root / "topology.yaml").write_text(json.dumps(topology, ensure_ascii=False, indent=2), encoding="utf-8")
    (root / "stages.yaml").write_text(json.dumps(stages, ensure_ascii=False, indent=2), encoding="utf-8")
    if security_controls is not None:
        (root / "security-controls.yaml").write_text(json.dumps(security_controls, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
