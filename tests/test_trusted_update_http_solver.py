import json
import logging
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from werkzeug.serving import make_server

from labforge.plugin_runtime_smoke import isolate_generated_state, load_generated_app_module
from labforge.solver_runner import run_solver_plan
from labforge.vulnerability_scaffolds import render_vulnerability_scaffold_files


BASE_APP = """\
from pathlib import Path
import json
from flask import Flask, jsonify

SERVICE = "release-workflow"
PURPOSE = "trusted update solver e2e"
STATE_DIR = Path("/state")
LOG_PATH = Path("/var/log/labforge/service-events.jsonl")
app = Flask(__name__)

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
"""


class TrustedUpdateHttpSolverTests(unittest.TestCase):
    def test_solver_executes_trusted_update_chain_against_live_generated_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = SimpleNamespace(
                service="release-workflow",
                model_extra={
                    "vulnerability_plugins": [
                        {"id": "build-pipeline-abuse", "repo": "orion/agent", "channel": "smoke"},
                        {"id": "signed-update-publish", "channel": "smoke"},
                        {"id": "customer-update-callback", "channel": "smoke"},
                    ]
                },
            )
            files = render_vulnerability_scaffold_files(artifact, {"app.py": BASE_APP})
            app_path = root / "app.py"
            app_path.write_text(files["app.py"], encoding="utf-8")
            module, error = load_generated_app_module("release-workflow", app_path)
            self.assertIsNone(error or None)
            isolate_generated_state(module, "release-workflow")
            logging.getLogger("werkzeug").setLevel(logging.ERROR)
            server = make_server("127.0.0.1", 0, module.app, threaded=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                solver_plan = root / "solver-plan.json"
                endpoint_manifest = root / "endpoints.json"
                solver_plan.write_text(
                    json.dumps(
                        {
                            "lab_id": "trusted-update-http-solver",
                            "title": "Trusted Update HTTP Solver",
                            "steps": [
                                {
                                    "order": 1,
                                    "step_id": "plugin-release-workflow-build-pipeline-abuse",
                                    "action_type": "vulnerability-behavior",
                                    "service": "release-workflow",
                                    "plugin": "build-pipeline-abuse",
                                    "evidence": ["/operations/build"],
                                },
                                {
                                    "order": 2,
                                    "step_id": "plugin-release-workflow-signed-update-publish",
                                    "action_type": "vulnerability-behavior",
                                    "service": "release-workflow",
                                    "plugin": "signed-update-publish",
                                    "evidence": ["/operations/update-channel"],
                                },
                                {
                                    "order": 3,
                                    "step_id": "plugin-release-workflow-customer-update-callback",
                                    "action_type": "vulnerability-behavior",
                                    "service": "release-workflow",
                                    "plugin": "customer-update-callback",
                                    "evidence": ["/operations/customer-agent"],
                                },
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                endpoint_manifest.write_text(
                    json.dumps(
                        {
                            "published_endpoints": [
                                {"service": "release-workflow", "protocol": "http", "url": f"{base_url}/"}
                            ]
                        }
                    ),
                    encoding="utf-8",
                )

                report = run_solver_plan(
                    solver_plan,
                    root / "solver-run",
                    endpoint_manifest=endpoint_manifest,
                    execute=True,
                    timeout_seconds=5,
                )

                self.assertEqual(report.status, "passed")
                self.assertEqual([step.status for step in report.steps], ["passed", "passed", "passed"])
                self.assertIn("job_id=build-0001", report.steps[0].message)
                self.assertIn("signed_source=latest-build", report.steps[1].message)
                self.assertIn("build_id=build-0001", report.steps[1].message)
                self.assertIn("build_id=build-0001", report.steps[2].message)
            finally:
                server.shutdown()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
