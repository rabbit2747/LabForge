import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from labforge.chain import apply_evidence_to_stage_state, build_chain_manifest, service_chain_view, stage_state_seed, write_chain_manifest
from labforge.model import LabSpec
from labforge.service_artifacts import vulnerability_evidence_map


class ChainManifestTests(unittest.TestCase):
    def test_stage_chain_links_evidence_and_services(self) -> None:
        spec = LabSpec.load(Path("examples/scenario-02-ad-domain-compromise"))
        manifest = build_chain_manifest(spec)

        self.assertEqual(manifest.status, "passed")
        self.assertEqual(len(manifest.nodes), 10)
        self.assertEqual(len(manifest.links), 9)
        self.assertEqual(manifest.links[0].from_stage, "stage-01")
        self.assertEqual(manifest.links[0].to_stage, "stage-02")
        self.assertIn("template_probe_confirmed", manifest.links[0].carried_evidence)

        services_by_stage = {node.stage_id: set(node.services) for node in manifest.nodes}
        self.assertIn("hr-portal", services_by_stage["stage-02"])
        self.assertIn("ldap-ad", services_by_stage["stage-04"])
        self.assertIn("backup-server", services_by_stage["stage-07"])
        self.assertIn("controlled-drop", services_by_stage["stage-10"])
        self.assertTrue(manifest.evidence_runtime_sources)
        self.assertTrue(any(source.evidence == "template_probe_confirmed" for source in manifest.evidence_runtime_sources))

    def test_stage_chain_fails_when_required_evidence_is_unproducible(self) -> None:
        spec = SimpleNamespace(
            lab_id="broken-chain",
            title="Broken Chain",
            services=[{"name": "portal"}],
            stage_list=[
                {"id": "stage-01", "title": "Entry", "procedure": "Start.", "evidence": ["entry_seen"]},
                {
                    "id": "stage-02",
                    "title": "Impossible Next Step",
                    "procedure": "Continue.",
                    "required_findings": ["missing_secret"],
                    "evidence": ["done"],
                },
            ],
        )

        manifest = build_chain_manifest(spec)

        self.assertEqual(manifest.status, "failed")
        self.assertIn("stage-02 requires evidence not produced by earlier stages: missing_secret", manifest.failures)
        self.assertTrue(
            any(
                handoff.consumer_stage == "stage-02"
                and handoff.evidence == "missing_secret"
                and handoff.status == "missing-producer"
                for handoff in manifest.evidence_handoffs
            )
        )

    def test_stage_chain_records_non_adjacent_evidence_handoffs(self) -> None:
        spec = SimpleNamespace(
            lab_id="long-handoff",
            title="Long Handoff",
            services=[{"name": "portal"}, {"name": "wiki"}, {"name": "console"}],
            stage_list=[
                {
                    "id": "stage-01",
                    "title": "Portal discovery",
                    "procedure": "Use portal records to collect durable_context for later review.",
                    "evidence": ["durable_context", "portal_only_note"],
                },
                {
                    "id": "stage-02",
                    "title": "Wiki review",
                    "procedure": "Use portal_only_note to identify wiki operating records.",
                    "required_findings": ["portal_only_note"],
                    "evidence": ["wiki_context"],
                },
                {
                    "id": "stage-03",
                    "title": "Console review",
                    "procedure": "Use durable_context and wiki_context to review console approvals.",
                    "required_findings": ["durable_context", "wiki_context"],
                    "evidence": ["console_context"],
                },
            ],
        )

        manifest = build_chain_manifest(spec)

        self.assertEqual(manifest.status, "warning")
        handoff_by_evidence = {handoff.evidence: handoff for handoff in manifest.evidence_handoffs}
        self.assertEqual(handoff_by_evidence["durable_context"].producer_stage, "stage-01")
        self.assertEqual(handoff_by_evidence["durable_context"].consumer_stage, "stage-03")
        self.assertEqual(handoff_by_evidence["durable_context"].distance, 2)
        self.assertEqual(handoff_by_evidence["durable_context"].status, "skipped-stage")
        self.assertTrue(any("durable_context" in item and "intermediate stage" in item for item in manifest.warnings))

    def test_stage_chain_links_only_evidence_consumed_by_the_next_stage(self) -> None:
        spec = SimpleNamespace(
            lab_id="refined-links",
            title="Refined Links",
            services=[{"name": "portal"}, {"name": "wiki"}],
            stage_list=[
                {
                    "id": "stage-01",
                    "title": "Portal discovery",
                    "procedure": "Use portal preview behavior to identify the wiki_route clue.",
                    "evidence": ["wiki_route", "unused_noise"],
                },
                {
                    "id": "stage-02",
                    "title": "Wiki review",
                    "procedure": "Use wiki_route to browse the internal knowledge base.",
                    "required_findings": ["wiki_route"],
                    "evidence": ["wiki_context"],
                },
            ],
        )

        manifest = build_chain_manifest(spec)

        self.assertEqual(manifest.links[0].carried_evidence, ["wiki_route"])
        self.assertNotIn("unused_noise", manifest.links[0].carried_evidence)

    def test_stage_chain_warns_when_learner_clue_uses_generic_fallback(self) -> None:
        spec = SimpleNamespace(
            lab_id="missing-clue",
            title="Missing Clue",
            services=[{"name": "portal"}],
            stage_list=[
                {"id": "stage-01", "title": "Entry", "procedure": "", "evidence": ["entry_seen"]},
                {"id": "stage-02", "title": "Next", "procedure": "Review portal notes.", "evidence": ["done"]},
            ],
        )

        manifest = build_chain_manifest(spec)

        self.assertEqual(manifest.status, "warning")
        self.assertIn("stage-01 learner clue is a generic fallback rather than a scenario-specific clue.", manifest.warnings)

    def test_stage_chain_warns_on_ctf_or_answer_key_clues(self) -> None:
        spec = SimpleNamespace(
            lab_id="ctf-clue",
            title="CTF Clue",
            services=[{"name": "portal"}],
            stage_list=[
                {"id": "stage-01", "title": "Entry", "procedure": "Find the flag in the portal answer key.", "evidence": ["entry_seen"]},
                {"id": "stage-02", "title": "Next", "procedure": "Review portal notes.", "evidence": ["done"]},
            ],
        )

        manifest = build_chain_manifest(spec)

        self.assertEqual(manifest.status, "warning")
        self.assertIn("stage-01 learner clue contains CTF or answer-key wording.", manifest.warnings)

    def test_service_chain_view_returns_local_and_adjacent_context(self) -> None:
        spec = LabSpec.load(Path("examples/scenario-02-ad-domain-compromise"))
        manifest = build_chain_manifest(spec)
        view = service_chain_view(manifest, "hr-portal")

        self.assertEqual(view["service"], "hr-portal")
        self.assertGreaterEqual(view["stage_count"], 1)
        self.assertTrue(any(stage["stage_id"] == "stage-02" for stage in view["stages"]))
        self.assertTrue(view["incoming"] or view["outgoing"])
        self.assertIn("evidence_handoffs", view)

    def test_stage_state_unlocks_when_required_evidence_is_acquired(self) -> None:
        spec = LabSpec.load(Path("examples/scenario-02-ad-domain-compromise"))
        manifest = build_chain_manifest(spec)
        state = stage_state_seed(manifest, "hr-portal")

        stage_02 = next(stage for stage in state["stages"] if stage["stage_id"] == "stage-02")
        self.assertEqual(stage_02["status"], "locked")

        apply_evidence_to_stage_state(state, "preview_request_captured")
        stage_02 = next(stage for stage in state["stages"] if stage["stage_id"] == "stage-02")
        self.assertEqual(stage_02["status"], "locked")

        apply_evidence_to_stage_state(state, "template_probe_confirmed")
        stage_02 = next(stage for stage in state["stages"] if stage["stage_id"] == "stage-02")
        self.assertEqual(stage_02["status"], "unlocked")
        self.assertIn("template_probe_confirmed", state["acquired_evidence"])

    def test_vulnerability_evidence_map_uses_service_stage_outputs(self) -> None:
        spec = LabSpec.load(Path("examples/scenario-02-ad-domain-compromise"))
        manifest = build_chain_manifest(spec)
        artifact = SimpleNamespace(
            service="hr-portal",
            model_extra={"vulnerability_plugins": [{"id": "ssti-preview"}]},
        )
        evidence_map = vulnerability_evidence_map(manifest, artifact)

        self.assertIn("ssti-preview", evidence_map)
        self.assertIn("template_probe_confirmed", evidence_map["ssti-preview"])
        self.assertIn("command_execution_confirmed", evidence_map["ssti-preview"])

    def test_stage_chain_marks_plugin_backed_evidence_sources(self) -> None:
        spec = SimpleNamespace(
            lab_id="plugin-backed-chain",
            title="Plugin Backed Chain",
            services=[{"name": "support-portal"}, {"name": "internal-api"}],
            stage_list=[
                {
                    "id": "stage-01",
                    "title": "Preview workflow",
                    "procedure": "Use the support-portal preview workflow to confirm template rendering behavior.",
                    "evidence": ["template_probe_confirmed"],
                },
                {
                    "id": "stage-02",
                    "title": "Internal API",
                    "procedure": "Use template_probe_confirmed to reach internal-api context.",
                    "required_findings": ["template_probe_confirmed"],
                    "evidence": ["internal_api_context"],
                },
            ],
            artifacts_model=SimpleNamespace(
                service_artifacts=[
                    SimpleNamespace(
                        service="support-portal",
                        evidence_logs=["application.log"],
                        model_extra={
                            "vulnerability_plugins": [
                                {"id": "ssti-preview", "emits_evidence": ["template_probe_confirmed"]}
                            ]
                        },
                    ),
                    SimpleNamespace(service="internal-api", evidence_logs=["internal_api_context.log"], model_extra={}),
                ]
            ),
        )

        manifest = build_chain_manifest(spec)
        source_by_evidence = {source.evidence: source for source in manifest.evidence_runtime_sources}

        self.assertEqual(manifest.status, "passed")
        self.assertEqual(source_by_evidence["template_probe_confirmed"].status, "plugin-backed")
        self.assertEqual(source_by_evidence["template_probe_confirmed"].plugin_emitters, ["support-portal:ssti-preview"])
        self.assertEqual(source_by_evidence["internal_api_context"].status, "runtime-backed")
        self.assertNotIn(
            "stage-01 evidence `template_probe_confirmed` has no declared plugin emitter or explicit runtime evidence path.",
            manifest.warnings,
        )

    def test_write_chain_manifest_outputs_review_files(self) -> None:
        spec = LabSpec.load(Path("examples/scenario-02-ad-domain-compromise"))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_chain_manifest(spec, out)

            self.assertTrue((out / "stage-chain.md").exists())
            self.assertTrue((out / "stage-chain.yaml").exists())
            self.assertTrue((out / "stage-chain.json").exists())
            self.assertIn("Stage Chain", (out / "stage-chain.md").read_text(encoding="utf-8"))
            self.assertIn("Evidence Handoffs", (out / "stage-chain.md").read_text(encoding="utf-8"))
            self.assertIn("Evidence Runtime Sources", (out / "stage-chain.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
