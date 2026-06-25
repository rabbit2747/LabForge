import json
import tempfile
import unittest
from pathlib import Path

from labforge.intake import create_intake_from_prompt, scaffold_lab_from_intake
from labforge.model import LabSpec
from labforge.service_artifacts import materialize_service_runtimes


class ServiceRuntimeRealismTests(unittest.TestCase):
    def test_materialized_services_include_business_ui_records_clues_and_noise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path("examples/scenario-02-ad-domain-compromise")
            lab = Path(tmp) / "lab"
            import shutil

            shutil.copytree(source, lab, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            spec = LabSpec.load(lab)
            materialize_service_runtimes(spec, force=True)

            service_root = lab / "services" / "hr-portal"
            app = (service_root / "app.py").read_text(encoding="utf-8")

            self.assertIn("render_template_string", app)
            self.assertIn("Operational Summary", app)
            self.assertIn("@app.get('/api/state')", app)
            self.assertIn("@app.post('/api/evidence')", app)
            self.assertTrue((service_root / "seed" / "records.json").exists())
            self.assertTrue((service_root / "seed" / "clues.json").exists())
            self.assertTrue((service_root / "seed" / "chain.json").exists())
            self.assertTrue((service_root / "seed" / "stage-state.json").exists())
            self.assertTrue((service_root / "noise" / "events.jsonl").exists())

            records = (service_root / "seed" / "records.json").read_text(encoding="utf-8")
            clues = (service_root / "seed" / "clues.json").read_text(encoding="utf-8")
            chain = json.loads((service_root / "seed" / "chain.json").read_text(encoding="utf-8"))
            stage_state = json.loads((service_root / "seed" / "stage-state.json").read_text(encoding="utf-8"))
            noise = (service_root / "noise" / "events.jsonl").read_text(encoding="utf-8")

            self.assertIn("synthetic-training-data", records)
            self.assertIn("Operational noise", clues)
            self.assertEqual(chain["service"], "hr-portal")
            self.assertGreaterEqual(chain["stage_count"], 1)
            self.assertEqual(stage_state["service"], "lab-wide")
            self.assertEqual(stage_state["local_service"], "hr-portal")
            self.assertEqual(stage_state["state_scope"], "shared")
            self.assertTrue(stage_state["evidence_catalog"])
            self.assertIn("business-workflow", noise)

    def test_materialized_banking_service_renders_industry_workflow_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            intake_dir = root / "intake"
            lab = root / "lab"
            create_intake_from_prompt(
                intake_dir,
                prompt=(
                    "Create a realistic banking lab where the learner starts from a public loan application portal, "
                    "discovers the customer identity gateway, reviews JWT session behavior, and reaches a controlled compliance export."
                ),
                lab_id="banking-runtime-context",
                title="Banking Runtime Context",
                industry="banking",
                force=True,
            )
            scaffold_lab_from_intake(intake_dir / "scenario-intake.yaml", lab, force=True)
            spec = LabSpec.load(lab)
            materialize_service_runtimes(spec, force=True)

            service_root = lab / "services" / "customer-identity-gateway"
            app = (service_root / "app.py").read_text(encoding="utf-8")
            records = json.loads((service_root / "seed" / "records.json").read_text(encoding="utf-8"))

            self.assertIn("Business Workflow Lanes", app)
            self.assertEqual(records["industry_context"]["display_name"], "Retail / Commercial Banking")
            lane_names = [lane["name"] for lane in records["industry_context"]["workflow_lanes"]]
            self.assertIn("Loan Operations", lane_names)
            self.assertIn("Payments", lane_names)
            self.assertIn("Fraud / AML", lane_names)
            self.assertTrue(any(item["type"] in {"loan-review-case", "aml-case", "payment-batch"} for item in records["items"]))


if __name__ == "__main__":
    unittest.main()
