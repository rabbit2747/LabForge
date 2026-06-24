import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from labforge.io import load_yaml
from labforge.chain import build_chain_manifest
from labforge.playtest import (
    endpoint_group,
    guidance_for_plugin,
    plugin_handoff_context,
    plugin_walkthrough_steps,
    run_playtest,
    stage_implementation_coverage_step,
    trusted_update_handoff_step,
)
from labforge.providers.docker_compose.provider import endpoint_expected_texts


class PlaytestTests(unittest.TestCase):
    def test_playtest_generates_learner_access_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "playtest"
            report = run_playtest(
                Path("examples/scenario-02-ad-domain-compromise"),
                out,
                provider="docker-compose",
                profile="protected",
                materialize=True,
                force=True,
            )

            self.assertIn(report.status, {"passed", "warning"})
            self.assertTrue(report.learner_entrypoints)
            self.assertTrue(report.attacker_entrypoints)
            self.assertFalse(any("attacker" in endpoint.service for endpoint in report.learner_entrypoints))
            self.assertFalse(any("drop" in endpoint.service for endpoint in report.learner_entrypoints))
            self.assertTrue(any(step.step_id == "realism-01" for step in report.steps))
            self.assertTrue(any(step.step_id == "industry-01" for step in report.steps))
            self.assertTrue(any(step.step_id == "implementation-01" for step in report.steps))
            self.assertTrue(any(step.step_id == "runtime-02" for step in report.steps))
            self.assertTrue(any(step.step_id == "chain-runtime-01" for step in report.steps))
            self.assertTrue((out / "playtest-report.md").exists())
            self.assertTrue((out / "playtest-report.yaml").exists())
            self.assertTrue((out / "learner-access.md").exists())
            self.assertTrue((out / "learner-access.json").exists())
            self.assertTrue((out / "access-playtest" / "access-playtest.md").exists())
            self.assertTrue((out / "access-playtest" / "access-playtest.yaml").exists())
            self.assertTrue((out / "solver-plan.md").exists())
            self.assertTrue((out / "solver-plan.json").exists())
            self.assertTrue((out / "solver-run" / "solver-run.md").exists())
            self.assertTrue((out / "solver-run" / "solver-run.yaml").exists())
            self.assertTrue((out / "playtest-walkthrough.md").exists())
            self.assertTrue((out / "lab-access-bundle.md").exists())
            self.assertTrue((out / "lab-access-bundle.json").exists())

            access = (out / "learner-access.md").read_text(encoding="utf-8")
            self.assertIn("Quick Connect", access)
            self.assertIn("Start Here", access)
            self.assertIn("Attacker Workstation", access)
            self.assertIn("Final Submission", access)
            self.assertIn("Health Checks", access)
            access_manifest = load_yaml(out / "learner-access.json")
            self.assertEqual(access_manifest["lab_id"], report.lab_id)
            self.assertTrue(access_manifest["start_commands"])
            self.assertTrue(access_manifest["status_commands"])
            self.assertTrue(access_manifest["stop_commands"])
            self.assertTrue(access_manifest["learner_entrypoints"])
            self.assertTrue(access_manifest["attacker_entrypoints"])
            self.assertEqual(len(access_manifest["final_submission_endpoints"]), len(report.final_submission_endpoints))
            self.assertTrue(access_manifest["health_checks"])
            self.assertTrue(access_manifest["terminal_checks"])
            self.assertTrue(access_manifest["terminal_sequences"])
            self.assertEqual(access_manifest["terminal_sequences"][0]["commands"], ["echo labforge-terminal-ready", "pwd"])
            self.assertTrue(access_manifest["first_action"])
            solver_plan = load_yaml(out / "solver-plan.json")
            self.assertEqual(solver_plan["lab_id"], report.lab_id)
            self.assertTrue(solver_plan["learner_start"])
            self.assertTrue(solver_plan["attacker_shell"])
            self.assertTrue(solver_plan["steps"])
            terminal_steps = [step for step in solver_plan["steps"] if step["action_type"] == "command-sequence"]
            self.assertTrue(terminal_steps)
            self.assertTrue(any(step["action_type"] == "implementation-coverage" for step in solver_plan["steps"]))
            self.assertEqual(terminal_steps[0]["commands"], ["echo labforge-terminal-ready", "pwd"])
            self.assertEqual(terminal_steps[0]["expected_texts"], ["labforge-terminal-ready"])
            solver_run = load_yaml(out / "solver-run" / "solver-run.json")
            self.assertEqual(solver_run["lab_id"], report.lab_id)
            self.assertTrue(solver_run["steps"])
            walkthrough = (out / "playtest-walkthrough.md").read_text(encoding="utf-8")
            self.assertIn("Start the generated provider output", walkthrough)
            self.assertIn("Connect to attacker workstation", walkthrough)
            access_bundle = load_yaml(out / "lab-access-bundle.json")
            self.assertEqual(access_bundle["lab_id"], report.lab_id)
            self.assertTrue(access_bundle["learner_urls"])
            self.assertTrue(access_bundle["attacker_ssh"])
            self.assertTrue(access_bundle["health_commands"])
            self.assertTrue(access_bundle["terminal_sequences"])
            self.assertTrue(access_bundle["solver_ready"])
            self.assertIn("provider_output_dir", access_bundle)
            self.assertIn("solver_plan_json", access_bundle["generated_files"])
            access_bundle_md = (out / "lab-access-bundle.md").read_text(encoding="utf-8")
            self.assertIn("Lab Access Bundle", access_bundle_md)
            self.assertIn("Browser URLs", access_bundle_md)
            self.assertIn("Attacker SSH", access_bundle_md)

            compose = load_yaml(out / "provider-output" / "docker-compose.yml")
            self.assertIn("labforge_state", compose.get("volumes", {}))
            hr_portal = compose["services"]["hr-portal"]
            self.assertEqual(hr_portal["environment"]["LABFORGE_STATE_DIR"], "/labforge-state")
            self.assertIn("labforge_state:/labforge-state", hr_portal["volumes"])

    def test_plugin_guidance_contains_discovery_cues_and_next_condition(self) -> None:
        guidance = guidance_for_plugin("ssti-preview", "support-portal")

        self.assertIn("preview", guidance["learner_action"])
        self.assertTrue(guidance["discovery_cues"])
        self.assertIn("normal merge fields", guidance["discovery_cues"][0])
        self.assertIn("Proceed when", guidance["next_step_condition"])

    def test_trusted_update_handoff_chain_is_detected_across_services(self) -> None:
        spec = SimpleNamespace(
            artifacts_model=SimpleNamespace(
                service_artifacts=[
                    SimpleNamespace(
                        service="build-server",
                        model_extra={"vulnerability_plugins": [{"id": "build-pipeline-abuse"}]},
                    ),
                    SimpleNamespace(
                        service="update-server",
                        model_extra={"vulnerability_plugins": [{"id": "signed-update-publish"}]},
                    ),
                    SimpleNamespace(
                        service="customer-agent",
                        model_extra={"vulnerability_plugins": [{"id": "customer-update-callback"}]},
                    ),
                ]
            )
        )

        step = trusted_update_handoff_step(spec)
        context = plugin_handoff_context(spec)

        self.assertEqual(step.status, "passed")
        self.assertIn("build-pipeline-abuse on build-server", step.evidence)
        self.assertIn("signed-update-publish on update-server", step.evidence)
        self.assertIn("customer-update-callback on customer-agent", step.evidence)
        self.assertIn(
            "signed-update-publish",
            context[("build-server", "build-pipeline-abuse")]["next_step_condition"],
        )
        self.assertTrue(
            any(
                "build-pipeline-abuse" in cue
                for cue in context[("update-server", "signed-update-publish")]["discovery_cues"]
            )
        )

    def test_partial_trusted_update_handoff_chain_warns(self) -> None:
        spec = SimpleNamespace(
            artifacts_model=SimpleNamespace(
                service_artifacts=[
                    SimpleNamespace(
                        service="build-server",
                        model_extra={"vulnerability_plugins": [{"id": "build-pipeline-abuse"}]},
                    )
                ]
            )
        )

        step = trusted_update_handoff_step(spec)

        self.assertEqual(step.status, "warning")
        self.assertTrue(any("missing=" in item for item in step.evidence))

    def test_stage_implementation_fails_when_required_plugin_evidence_is_unmapped(self) -> None:
        spec = SimpleNamespace(
            lab_id="unmapped-evidence",
            title="Unmapped Evidence",
            services=[{"name": "support-portal"}, {"name": "wiki"}],
            stage_list=[
                {
                    "id": "stage-01",
                    "title": "Support preview",
                    "procedure": "Use support-portal preview records to identify the template rendering issue.",
                    "evidence": ["template_probe_confirmed"],
                },
                {
                    "id": "stage-02",
                    "title": "Internal wiki",
                    "procedure": "Use template_probe_confirmed to pivot to wiki and read internal operating notes.",
                    "required_findings": ["template_probe_confirmed"],
                    "evidence": ["wiki_notes_collected"],
                },
            ],
            artifacts_model=SimpleNamespace(
                service_artifacts=[
                    SimpleNamespace(
                        service="support-portal",
                        model_extra={
                            "vulnerability_plugins": [
                                {"id": "ssti-preview", "emits_evidence": ["unrelated_preview_event"]}
                            ]
                        },
                    ),
                    SimpleNamespace(service="wiki", model_extra={}),
                ]
            ),
        )
        manifest = build_chain_manifest(spec)

        step = stage_implementation_coverage_step(spec, manifest)

        self.assertEqual(step.status, "failed")
        self.assertTrue(any("template_probe_confirmed" in item for item in step.evidence))
        self.assertTrue(any("evidence_runtime_sources=" in item for item in step.evidence))

    def test_plugin_walkthrough_steps_include_trusted_update_handoff_cues(self) -> None:
        spec = SimpleNamespace(
            artifacts_model=SimpleNamespace(
                service_artifacts=[
                    SimpleNamespace(
                        service="build-server",
                        model_extra={"vulnerability_plugins": [{"id": "build-pipeline-abuse"}]},
                    ),
                    SimpleNamespace(
                        service="update-server",
                        model_extra={"vulnerability_plugins": [{"id": "signed-update-publish"}]},
                    ),
                ]
            )
        )
        runtime_smoke = SimpleNamespace(
            items=[
                SimpleNamespace(
                    service="build-server",
                    plugin="build-pipeline-abuse",
                    status="passed",
                    endpoint="/api/build/jobs",
                    emitted_evidence=["build_job_created"],
                    unlocked_stages=["stage-08"],
                ),
                SimpleNamespace(
                    service="update-server",
                    plugin="signed-update-publish",
                    status="passed",
                    endpoint="/api/publish",
                    emitted_evidence=["manifest_published"],
                    unlocked_stages=["stage-09"],
                ),
            ]
        )

        steps = plugin_walkthrough_steps(spec, runtime_smoke)
        build_step = next(step for step in steps if step.step_id == "plugin-build-server-build-pipeline-abuse")

        self.assertEqual(build_step.status, "passed")
        self.assertIn("emitted_evidence=build_job_created", build_step.evidence)
        self.assertIn("unlocked_stages=stage-08", build_step.evidence)
        self.assertTrue(any("signed-update-publish" in cue for cue in build_step.discovery_cues))
        self.assertIn("signed-update-publish", build_step.next_step_condition)

    def test_endpoint_group_preserves_browser_expected_texts(self) -> None:
        endpoints = endpoint_group(
            {
                "published_endpoints": [
                    {
                        "service": "document-portal",
                        "role": "learner-entry",
                        "protocol": "http",
                        "connect": "http://127.0.0.1:18080/",
                        "expected_text": "Document Library",
                        "expected_texts": ["Published Documents", "Document Library"],
                    }
                ]
            },
            lambda _item: True,
        )

        self.assertEqual(endpoints[0].expected_texts, ["Document Library", "Published Documents"])

    def test_docker_provider_derives_expected_texts_from_artifact_plugins(self) -> None:
        artifact = SimpleNamespace(
            runtime="business-portal",
            model_extra={
                "vulnerability_plugins": [
                    {"id": "path-traversal-download"},
                    {"id": "diagnostic-command-injection"},
                    {"id": "solr-velocity-rce"},
                ]
            },
        )

        self.assertEqual(
            endpoint_expected_texts(artifact),
            ["Operational Summary", "Document Library", "Operations Diagnostics Console", "Search Operations Console", "Core Status"],
        )


if __name__ == "__main__":
    unittest.main()
