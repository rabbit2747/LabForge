from __future__ import annotations

import unittest

from labforge.intake import IntakeStage, ScenarioIntake, stages_from_intake, vulnerability_plugins_for_service


def plugin_by_id(plugins: list[dict], plugin_id: str) -> dict:
    for plugin in plugins:
        if plugin["id"] == plugin_id:
            return plugin
    raise AssertionError(f"missing plugin: {plugin_id}")


class IntakePluginEvidenceTest(unittest.TestCase):
    def test_stages_from_intake_uses_previous_evidence_as_required_findings(self) -> None:
        intake = ScenarioIntake(
            lab_id="chain-inputs",
            title="Chain Inputs",
            target_industry="enterprise",
            summary="Check chain continuity.",
            final_objective="Finish.",
            learner_entrypoint="Public portal.",
            target_infrastructure=["public-portal", "internal-api"],
            stages=[
                IntakeStage(
                    stage_id="stage-01",
                    learner_goal="Enter.",
                    expected_action="Find first evidence.",
                    evidence=["entry_evidence"],
                    mitre_tactic="Initial Access",
                    mitre_techniques=["T1190"],
                    infrastructure_touched=["public-portal"],
                ),
                IntakeStage(
                    stage_id="stage-02",
                    learner_goal="Continue.",
                    expected_action="Use the previous finding.",
                    evidence=["second_evidence"],
                    mitre_tactic="Discovery",
                    mitre_techniques=["T1046"],
                    infrastructure_touched=["internal-api"],
                ),
            ],
        )

        stages = stages_from_intake(intake)["stages"]

        self.assertEqual(stages[0]["required_findings"], [])
        self.assertEqual(stages[1]["required_findings"], ["entry_evidence"])
        self.assertEqual(stages[1]["infrastructure_touched"], ["internal-api"])

    def test_public_portal_ssti_plugin_inherits_stage_evidence(self) -> None:
        intake = ScenarioIntake(
            lab_id="evidence-map",
            title="Brokerage Support Template Abuse",
            target_industry="securities",
            summary="Learner finds Jinja template rendering in a public support preview.",
            final_objective="Retrieve a controlled compliance export object.",
            learner_entrypoint="Public investor support portal.",
            target_infrastructure=["investor-portal", "trade-ops-console"],
            stages=[
                IntakeStage(
                    stage_id="stage-01",
                    learner_goal="Find server-side template rendering in the investor support preview.",
                    expected_action="Submit a template expression to the preview renderer.",
                    evidence=["stage1_template_probe"],
                    mitre_tactic="Initial Access",
                    mitre_techniques=["T1190"],
                    infrastructure_touched=["investor-portal"],
                ),
                IntakeStage(
                    stage_id="stage-02",
                    learner_goal="Use the internal review workflow to reach privileged context.",
                    expected_action="Store a review payload and wait for a manager review.",
                    evidence=["stage2_review_context"],
                    mitre_tactic="Privilege Escalation",
                    mitre_techniques=["T1059"],
                    infrastructure_touched=["trade-ops-console"],
                ),
            ],
        )

        plugins = vulnerability_plugins_for_service(intake, "investor-portal")

        self.assertEqual(plugin_by_id(plugins, "ssti-preview")["emits_evidence"], ["stage1_template_probe"])

    def test_review_console_xss_plugin_inherits_review_stage_evidence(self) -> None:
        intake = ScenarioIntake(
            lab_id="review-map",
            title="Release Console Stored XSS",
            target_industry="enterprise",
            summary="A release approval bot reviews stored HTML in an internal console.",
            final_objective="Recover a protected build context and continue the release flow.",
            learner_entrypoint="Internal release console.",
            target_infrastructure=["release-console", "build-server"],
            stages=[
                IntakeStage(
                    stage_id="stage-05",
                    learner_goal="Reach the release console and identify the approval workflow.",
                    expected_action="Browse the build request and locate the review surface.",
                    evidence=["stage5_console_reached"],
                    mitre_tactic="Discovery",
                    mitre_techniques=["T1087"],
                    infrastructure_touched=["release-console"],
                ),
                IntakeStage(
                    stage_id="stage-06",
                    learner_goal="Abuse stored XSS in the manager review workflow.",
                    expected_action="Submit a stored payload that a privileged reviewer opens.",
                    evidence=["stage6_manager_context"],
                    mitre_tactic="Credential Access",
                    mitre_techniques=["T1539"],
                    infrastructure_touched=["release-console"],
                ),
            ],
        )

        plugins = vulnerability_plugins_for_service(intake, "release-console")

        self.assertCountEqual(
            plugin_by_id(plugins, "stored-xss-review")["emits_evidence"],
            ["stage6_manager_context", "stage5_console_reached"],
        )

    def test_credential_exposure_plugin_inherits_secret_stage_evidence(self) -> None:
        intake = ScenarioIntake(
            lab_id="credential-map",
            title="Support Startup Log Credential Exposure",
            target_industry="enterprise",
            summary="The learner correlates a vault secret reference with startup logs that expose a cached synthetic credential.",
            final_objective="Use the credential to access the next internal service.",
            learner_entrypoint="Support operations portal.",
            target_infrastructure=["support-portal", "internal-directory"],
            stages=[
                IntakeStage(
                    stage_id="stage-02",
                    learner_goal="Find a secret reference in runtime configuration.",
                    expected_action="Open the configuration diagnostics page and identify the downstream bind profile.",
                    evidence=["stage2_secret_ref_identified"],
                    mitre_tactic="Discovery",
                    mitre_techniques=["T1082"],
                    infrastructure_touched=["support-portal"],
                ),
                IntakeStage(
                    stage_id="stage-03",
                    learner_goal="Recover the synthetic credential from startup diagnostics.",
                    expected_action="Correlate the secret reference with vault-cache restore log lines.",
                    evidence=["stage3_cached_credential_found"],
                    mitre_tactic="Credential Access",
                    mitre_techniques=["T1552 Unsecured Credentials"],
                    infrastructure_touched=["support-portal"],
                ),
            ],
        )

        plugins = vulnerability_plugins_for_service(intake, "support-portal")

        self.assertCountEqual(
            plugin_by_id(plugins, "credential-exposure")["emits_evidence"],
            ["stage2_secret_ref_identified", "stage3_cached_credential_found"],
        )

    def test_solr_velocity_plugin_inherits_legacy_search_stage_evidence(self) -> None:
        intake = ScenarioIntake(
            lab_id="solr-map",
            title="Legacy Search Solr Velocity RCE",
            target_industry="enterprise",
            summary="Learner discovers an internal Apache Solr 8.3.1 search service with Velocity response writer configuration risk.",
            final_objective="Use the legacy search foothold to identify the release console route.",
            learner_entrypoint="Support portal shell.",
            target_infrastructure=["ops-search", "release-console"],
            stages=[
                IntakeStage(
                    stage_id="stage-05",
                    learner_goal="Exploit the legacy search service safely inside the lab.",
                    expected_action="Use Solr Velocity response writer behavior to run a bounded diagnostic command.",
                    evidence=["stage5_search_rce_confirmed"],
                    mitre_tactic="Execution",
                    mitre_techniques=["T1190 Exploit Public-Facing Application"],
                    infrastructure_touched=["ops-search"],
                ),
                IntakeStage(
                    stage_id="stage-06",
                    learner_goal="Use search foothold output to identify the adjacent release service.",
                    expected_action="Run service discovery from the search context and locate release-console.",
                    evidence=["stage6_release_route_found"],
                    mitre_tactic="Discovery",
                    mitre_techniques=["T1046 Network Service Discovery"],
                    infrastructure_touched=["ops-search", "release-console"],
                ),
            ],
        )

        plugins = vulnerability_plugins_for_service(intake, "ops-search")

        self.assertCountEqual(
            plugin_by_id(plugins, "solr-velocity-rce")["emits_evidence"],
            ["stage5_search_rce_confirmed", "stage6_release_route_found"],
        )

    def test_automatic_plugins_without_stage_evidence_are_not_generated(self) -> None:
        intake = ScenarioIntake(
            lab_id="unmapped",
            title="Generic SSRF Mention",
            target_industry="enterprise",
            summary="The scenario mentions SSRF and internal fetch in background notes.",
            final_objective="Retrieve a controlled export.",
            learner_entrypoint="Public portal.",
            target_infrastructure=["public-portal", "export-api"],
            stages=[
                IntakeStage(
                    stage_id="stage-01",
                    learner_goal="Inspect the public portal.",
                    expected_action="Use normal navigation to identify the next system.",
                    evidence=["stage1_portal_seen"],
                    mitre_tactic="Discovery",
                    mitre_techniques=["T1595"],
                    infrastructure_touched=["public-portal"],
                )
            ],
        )

        plugins = vulnerability_plugins_for_service(intake, "export-api")

        self.assertEqual(plugins, [])


if __name__ == "__main__":
    unittest.main()
