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

    def test_service_chain_view_returns_local_and_adjacent_context(self) -> None:
        spec = LabSpec.load(Path("examples/scenario-02-ad-domain-compromise"))
        manifest = build_chain_manifest(spec)
        view = service_chain_view(manifest, "hr-portal")

        self.assertEqual(view["service"], "hr-portal")
        self.assertGreaterEqual(view["stage_count"], 1)
        self.assertTrue(any(stage["stage_id"] == "stage-02" for stage in view["stages"]))
        self.assertTrue(view["incoming"] or view["outgoing"])

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

    def test_write_chain_manifest_outputs_review_files(self) -> None:
        spec = LabSpec.load(Path("examples/scenario-02-ad-domain-compromise"))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_chain_manifest(spec, out)

            self.assertTrue((out / "stage-chain.md").exists())
            self.assertTrue((out / "stage-chain.yaml").exists())
            self.assertTrue((out / "stage-chain.json").exists())
            self.assertIn("Stage Chain", (out / "stage-chain.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
