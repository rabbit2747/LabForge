import tempfile
import unittest
from pathlib import Path

from labforge.chain import build_chain_manifest, write_chain_manifest
from labforge.model import LabSpec


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
