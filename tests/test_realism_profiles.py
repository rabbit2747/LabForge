import unittest

from labforge.intake import (
    NaturalLanguageScenarioRequest,
    infer_industry_from_prompt,
    normalize_industry as normalize_intake_industry,
    scenario_profile_for_request,
)
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


if __name__ == "__main__":
    unittest.main()
