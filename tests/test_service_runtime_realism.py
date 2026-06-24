import tempfile
import unittest
from pathlib import Path

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
            self.assertTrue((service_root / "seed" / "records.json").exists())
            self.assertTrue((service_root / "seed" / "clues.json").exists())
            self.assertTrue((service_root / "noise" / "events.jsonl").exists())

            records = (service_root / "seed" / "records.json").read_text(encoding="utf-8")
            clues = (service_root / "seed" / "clues.json").read_text(encoding="utf-8")
            noise = (service_root / "noise" / "events.jsonl").read_text(encoding="utf-8")

            self.assertIn("synthetic-training-data", records)
            self.assertIn("Operational noise", clues)
            self.assertIn("business-workflow", noise)


if __name__ == "__main__":
    unittest.main()
