import json
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
    plugin_checks_from_solver_plan,
    plugin_walkthrough_steps,
    build_human_readiness_report,
    run_playtest,
    service_realism_step,
    service_base_urls_from_endpoint_manifest,
    SolverPlan,
    SolverPlanStep,
    stage_handoffs_from_chain_manifest,
    stage_implementation_coverage_step,
    trusted_update_handoff_step,
)
from labforge.providers.docker_compose.provider import endpoint_expected_selectors, endpoint_expected_texts


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
            self.assertTrue((out / "human-readiness.md").exists())
            self.assertTrue((out / "human-readiness.yaml").exists())
            self.assertTrue((out / "human-readiness.json").exists())

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
            self.assertEqual(access_manifest["learner_entrypoints"][0]["host"], "127.0.0.1")
            self.assertEqual(access_manifest["learner_entrypoints"][0]["default_host_port"], 8080)
            self.assertEqual(access_manifest["learner_entrypoints"][0]["container_port"], "8080")
            self.assertEqual(access_manifest["learner_entrypoints"][0]["override_env"], "LABFORGE_PORT_EDGE_PROXY_8080")
            self.assertEqual(access_manifest["attacker_entrypoints"][0]["default_host_port"], 2222)
            self.assertEqual(len(access_manifest["final_submission_endpoints"]), len(report.final_submission_endpoints))
            self.assertTrue(access_manifest["health_checks"])
            self.assertTrue(access_manifest["terminal_checks"])
            self.assertTrue(access_manifest["terminal_sequences"])
            self.assertEqual(access_manifest["terminal_sequences"][0]["commands"], ["echo labforge-terminal-ready", "pwd"])
            self.assertTrue(access_manifest["first_action"])
            self.assertTrue(access_manifest["internal_targets"])
            self.assertTrue(any(target["dns"] == "fileserver" for target in access_manifest["internal_targets"]))
            self.assertTrue(any(target["access_scope"] == "internal-only" for target in access_manifest["internal_targets"]))
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
            self.assertTrue(access_bundle["published_endpoints"])
            self.assertTrue(any(endpoint["override_env"] == "LABFORGE_PORT_EDGE_PROXY_8080" for endpoint in access_bundle["published_endpoints"]))
            self.assertTrue(access_bundle["health_commands"])
            self.assertTrue(access_bundle["terminal_sequences"])
            self.assertTrue(access_bundle["internal_targets"])
            self.assertTrue(any(target["dns"] == "controlled-drop" for target in access_bundle["internal_targets"]))
            self.assertTrue(access_bundle["solver_ready"])
            self.assertIn("plugin_checks", access_bundle)
            self.assertIn("stage_handoffs", access_bundle)
            self.assertTrue(access_bundle["stage_handoffs"])
            self.assertTrue(any(handoff.get("carried_evidence") for handoff in access_bundle["stage_handoffs"]))
            self.assertIn("provider_output_dir", access_bundle)
            self.assertIn("solver_plan_json", access_bundle["generated_files"])
            self.assertIn("human_readiness_report", access_bundle["generated_files"])
            human_readiness = load_yaml(out / "human-readiness.json")
            self.assertIn(human_readiness["status"], {"passed", "warning"})
            self.assertTrue(human_readiness["checks"])
            access_bundle_md = (out / "lab-access-bundle.md").read_text(encoding="utf-8")
            self.assertIn("Lab Access Bundle", access_bundle_md)
            self.assertIn("Browser URLs", access_bundle_md)
            self.assertIn("Attacker SSH", access_bundle_md)
            self.assertIn("Published Endpoint Matrix", access_bundle_md)
            self.assertIn("Internal Targets", access_bundle_md)
            self.assertIn("Stage Handoffs", access_bundle_md)
            self.assertIn("Plugin Evidence Checks", access_bundle_md)
            playtest_md = (out / "playtest-report.md").read_text(encoding="utf-8")
            self.assertIn("Host Port", playtest_md)
            self.assertIn("LABFORGE_PORT_EDGE_PROXY_8080", playtest_md)

            compose = load_yaml(out / "provider-output" / "docker-compose.yml")
            self.assertIn("labforge_state", compose.get("volumes", {}))
            hr_portal = compose["services"]["hr-portal"]
            self.assertEqual(hr_portal["environment"]["LABFORGE_STATE_DIR"], "/labforge-state")
            self.assertIn("labforge_state:/labforge-state", hr_portal["volumes"])

    def test_human_readiness_report_flags_thin_guidance(self) -> None:
        solver_plan = SolverPlan(
            lab_id="thin-guidance",
            title="Thin Guidance",
            provider="docker-compose",
            profile="protected",
            status="planned",
            steps=[
                SolverPlanStep(
                    order=1,
                    step_id="plugin-support-portal-ssti-preview",
                    title="support-portal: ssti-preview",
                    service="support-portal",
                    plugin="ssti-preview",
                    action_type="vulnerability-behavior",
                    learner_action="do it",
                    expected_result="flag",
                    evidence=[],
                    discovery_cues=[],
                    next_step_condition="",
                )
            ],
        )
        report = SimpleNamespace(
            lab_id="thin-guidance",
            title="Thin Guidance",
            learner_entrypoints=[],
            attacker_entrypoints=[],
            final_submission_endpoints=[],
        )
        access = SimpleNamespace(
            first_action="",
            start_commands=[],
            plugin_checks=[],
        )

        readiness = build_human_readiness_report(report, access, solver_plan)

        self.assertEqual(readiness.status, "failed")
        messages = " ".join(message for check in readiness.checks for message in check.messages)
        self.assertIn("too thin", messages)
        self.assertIn("missing plugin evidence check", messages)

    def test_plugin_guidance_contains_discovery_cues_and_next_condition(self) -> None:
        guidance = guidance_for_plugin("ssti-preview", "support-portal")

        self.assertIn("preview", guidance["learner_action"])
        self.assertTrue(guidance["discovery_cues"])
        self.assertIn("normal merge fields", guidance["discovery_cues"][0])
        self.assertIn("Proceed when", guidance["next_step_condition"])

    def test_plugin_checks_from_solver_plan_extracts_expected_evidence(self) -> None:
        plan = SolverPlan(
            lab_id="plugin-checks",
            title="Plugin Checks",
            provider="docker-compose",
            profile="protected",
            status="planned",
            steps=[
                SolverPlanStep(
                    order=1,
                    step_id="plugin-support-portal-ssti-preview",
                    title="support-portal: ssti-preview",
                    service="support-portal",
                    plugin="ssti-preview",
                    action_type="vulnerability-behavior",
                    learner_action="Use preview workflow.",
                    expected_result="Evidence is emitted.",
                    evidence=["/operations/preview", "emitted_evidence=template_probe_confirmed,command_execution_confirmed"],
                    discovery_cues=["Start from normal preview fields."],
                    next_step_condition="Proceed when evidence is present.",
                )
            ],
        )

        checks = plugin_checks_from_solver_plan(plan, service_base_urls={"support-portal": "http://127.0.0.1:18080"})

        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["service"], "support-portal")
        self.assertEqual(checks[0]["plugin"], "ssti-preview")
        self.assertEqual(checks[0]["expected_evidence"], ["template_probe_confirmed", "command_execution_confirmed"])
        self.assertEqual(checks[0]["state_url"], "http://127.0.0.1:18080/api/state")
        self.assertIn("curl -sS http://127.0.0.1:18080/api/state", checks[0]["state_verification"])
        self.assertIn("/api/state", checks[0]["state_verification"])

    def test_service_base_urls_from_endpoint_manifest_prefers_published_http_urls(self) -> None:
        urls = service_base_urls_from_endpoint_manifest(
            {
                "published_endpoints": [
                    {"service": "portal", "protocol": "http", "url": "http://127.0.0.1:18080/"},
                    {"service": "attacker", "protocol": "ssh", "connect": "ssh attacker@127.0.0.1 -p 2222"},
                ],
                "internal_services": [
                    {"service": "worker", "protocol": "http", "connect": "http://worker:8080"},
                ],
            }
        )

        self.assertEqual(urls["portal"], "http://127.0.0.1:18080")
        self.assertEqual(urls["worker"], "http://worker:8080")
        self.assertNotIn("attacker", urls)

    def test_stage_handoffs_from_chain_manifest_preserves_carried_evidence_and_clues(self) -> None:
        manifest = SimpleNamespace(
            nodes=[
                SimpleNamespace(stage_id="stage-01", title="Entry", learner_clue="Start with the public portal."),
                SimpleNamespace(stage_id="stage-02", title="Internal wiki", learner_clue="Use template evidence to find wiki context.", services=["internal-wiki"]),
            ],
            links=[
                SimpleNamespace(
                    from_stage="stage-01",
                    to_stage="stage-02",
                    carried_evidence=["template_probe_confirmed"],
                    status="explicit",
                )
            ],
        )

        handoffs = stage_handoffs_from_chain_manifest(manifest)

        self.assertEqual(len(handoffs), 1)
        self.assertEqual(handoffs[0]["from_stage"], "stage-01")
        self.assertEqual(handoffs[0]["to_stage"], "stage-02")
        self.assertEqual(handoffs[0]["carried_evidence"], ["template_probe_confirmed"])
        self.assertEqual(handoffs[0]["learner_clue"], "Use template evidence to find wiki context.")
        self.assertEqual(handoffs[0]["to_services"], ["internal-wiki"])

    def test_stage_handoffs_from_chain_manifest_prefers_evidence_handoffs(self) -> None:
        manifest = SimpleNamespace(
            nodes=[
                SimpleNamespace(stage_id="stage-01", title="Entry", learner_clue="Collect durable evidence.", services=["portal"]),
                SimpleNamespace(stage_id="stage-02", title="Intermediate", learner_clue="Review normal operations.", services=["wiki"]),
                SimpleNamespace(stage_id="stage-03", title="Console", learner_clue="Use durable evidence in the console.", services=["release-console"]),
            ],
            links=[
                SimpleNamespace(
                    from_stage="stage-01",
                    to_stage="stage-02",
                    carried_evidence=["intermediate_note"],
                    status="inferred",
                )
            ],
            evidence_handoffs=[
                SimpleNamespace(
                    evidence="durable_context",
                    producer_stage="stage-01",
                    consumer_stage="stage-03",
                    status="skipped-stage",
                ),
                SimpleNamespace(
                    evidence="wiki_context",
                    producer_stage="stage-02",
                    consumer_stage="stage-03",
                    status="direct",
                ),
            ],
        )

        handoffs = stage_handoffs_from_chain_manifest(manifest)

        self.assertTrue(any(item["from_stage"] == "stage-01" and item["to_stage"] == "stage-03" for item in handoffs))
        long_handoff = next(item for item in handoffs if item["from_stage"] == "stage-01" and item["to_stage"] == "stage-03")
        self.assertEqual(long_handoff["carried_evidence"], ["durable_context"])
        self.assertEqual(long_handoff["status"], "skipped-stage")
        self.assertEqual(long_handoff["to_services"], ["release-console"])

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

    def test_service_realism_step_fails_empty_or_ctf_seed_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service_root = root / "services" / "support-portal"
            (service_root / "seed").mkdir(parents=True)
            (service_root / "noise").mkdir(parents=True)
            (service_root / "seed" / "records.json").write_text('{"items":[]}\n', encoding="utf-8")
            (service_root / "seed" / "clues.json").write_text(
                '{"items":[{"title":"answer key","detail":"copy paste the flag"}]}\n',
                encoding="utf-8",
            )
            (service_root / "noise" / "events.jsonl").write_text(
                '{"event":"todo-placeholder"}\n',
                encoding="utf-8",
            )
            spec = SimpleNamespace(
                artifacts_model=SimpleNamespace(
                    service_artifacts=[
                        SimpleNamespace(
                            service="support-portal",
                            source_path="services/support-portal",
                            purpose="Customer support request portal",
                            seed_inputs=["support-cases"],
                            noise_inputs=["support-access-noise"],
                        )
                    ]
                )
            )

            step = service_realism_step(spec, root)

            self.assertEqual(step.status, "failed")
            self.assertTrue(any("at least 2 business records" in item for item in step.evidence))
            self.assertTrue(any("CTF/placeholder" in item for item in step.evidence))

    def test_service_realism_step_fails_thin_non_business_record_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service_root = root / "services" / "support-portal"
            (service_root / "seed").mkdir(parents=True)
            (service_root / "noise").mkdir(parents=True)
            (service_root / "seed" / "records.json").write_text(
                '{"items":[{"name":"one"},{"name":"two"}]}\n',
                encoding="utf-8",
            )
            (service_root / "seed" / "clues.json").write_text(
                '{"items":[{"title":"Runbook","detail":"Use support workflow records before testing edge cases."},{"title":"Queue","detail":"Review support case routing and routine customer notes."}]}\n',
                encoding="utf-8",
            )
            (service_root / "noise" / "events.jsonl").write_text(
                '{"service":"support-portal","message":"started"}\n{"service":"support-portal","message":"polled"}\n',
                encoding="utf-8",
            )
            spec = SimpleNamespace(
                artifacts_model=SimpleNamespace(
                    service_artifacts=[
                        SimpleNamespace(
                            service="support-portal",
                            source_path="services/support-portal",
                            purpose="Customer support request portal",
                            seed_inputs=["support-cases"],
                            noise_inputs=["support-access-noise"],
                        )
                    ]
                )
            )

            step = service_realism_step(spec, root)

            self.assertEqual(step.status, "failed")
            self.assertTrue(any("records are too thin" in item for item in step.evidence))
            self.assertTrue(any("lack an event/action/workflow field" in item for item in step.evidence))

    def test_service_realism_step_accepts_business_shaped_records_and_noise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service_root = root / "services" / "support-portal"
            (service_root / "seed").mkdir(parents=True)
            (service_root / "noise").mkdir(parents=True)
            (service_root / "seed" / "records.json").write_text(
                json.dumps(
                    {
                        "items": [
                            {
                                "classification": "synthetic-training-data",
                                "source_service": "support-portal",
                                "id": "CASE-1001",
                                "type": "support-case",
                                "status": "triage",
                                "owner": "l1-support",
                                "updated_at": "2026-05-18T08:22:15Z",
                            },
                            {
                                "classification": "synthetic-training-data",
                                "source_service": "support-portal",
                                "id": "CASE-1002",
                                "type": "billing-case",
                                "status": "waiting-customer",
                                "owner": "billing-support",
                                "updated_at": "2026-05-18T09:22:15Z",
                            },
                            {
                                "classification": "synthetic-training-data",
                                "source_service": "support-portal",
                                "id": "CASE-1003",
                                "type": "support-case",
                                "status": "closed",
                                "owner": "l2-support",
                                "updated_at": "2026-05-18T10:22:15Z",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (service_root / "seed" / "clues.json").write_text(
                json.dumps(
                    {
                        "items": [
                            {"title": "Queue review", "detail": "Review support case records and route metadata before testing preview behavior."},
                            {"title": "Audit posture", "detail": "Correlate customer workflow notes with routine support access events."},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (service_root / "noise" / "events.jsonl").write_text(
                '\n'.join(
                    [
                        '{"service":"support-portal","event":"case.updated","severity":"info","source":"business-workflow"}',
                        '{"service":"support-portal","event":"queue.polled","severity":"info","source":"operations-job"}',
                        '{"service":"support-portal","event":"audit.reviewed","severity":"warning","source":"monitoring"}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            spec = SimpleNamespace(
                artifacts_model=SimpleNamespace(
                    service_artifacts=[
                        SimpleNamespace(
                            service="support-portal",
                            source_path="services/support-portal",
                            purpose="Customer support request portal",
                            seed_inputs=["support-cases"],
                            noise_inputs=["support-access-noise"],
                        )
                    ]
                )
            )

            step = service_realism_step(spec, root)

            self.assertEqual(step.status, "passed")

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
                        "default_host_port": 18080,
                        "container_port": "8080",
                        "override_env": "LABFORGE_PORT_DOCUMENT_PORTAL_8080",
                        "expected_text": "Document Library",
                        "expected_texts": ["Published Documents", "Document Library"],
                        "expected_selector": "main",
                        "expected_selectors": ["form", "main"],
                    }
                ]
            },
            lambda _item: True,
        )

        self.assertEqual(endpoints[0].expected_texts, ["Document Library", "Published Documents"])
        self.assertEqual(endpoints[0].expected_selectors, ["main", "form"])
        self.assertEqual(endpoints[0].host, "127.0.0.1")
        self.assertEqual(endpoints[0].default_host_port, 18080)
        self.assertEqual(endpoints[0].container_port, "8080")
        self.assertEqual(endpoints[0].override_env, "LABFORGE_PORT_DOCUMENT_PORTAL_8080")

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
        self.assertEqual(
            endpoint_expected_selectors(artifact),
            ["main", "nav", "a[href*='download'], table", "form", "input[name='command']", "input[name='core']"],
        )


if __name__ == "__main__":
    unittest.main()
