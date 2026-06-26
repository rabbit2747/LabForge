from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace

from labforge.qa import (
    QaCheck,
    critical_playtest_gap_messages,
    learner_access_plugin_evidence_messages,
    learner_access_stage_handoff_messages,
    human_readiness_gap_messages,
    human_readiness_check_count,
    learner_access_live_requirement_messages,
    plugin_evidence_check_count,
    release_gate_live_metadata,
    stage_handoff_clue_messages,
    stage_handoff_count,
    stage_handoff_runtime_check_messages,
    stage_handoff_solver_coverage_messages,
)
from labforge.io import write_text, dump_yaml


class QaReleaseGateTests(unittest.TestCase):
    def test_release_gate_live_metadata_marks_scaffold_for_dry_run_e2e(self) -> None:
        metadata = release_gate_live_metadata(
            [
                QaCheck(
                    name="e2e-solver-evidence",
                    status="passed",
                    messages=[
                        "mode=dry-run",
                        "execute=false",
                        "browser_engine=none",
                        "execute_tunnels=false",
                        "live_readiness=not-run",
                        "executed_access_passed=0",
                        "executed_solver_passed=0",
                    ],
                )
            ],
            release_ready=True,
        )

        self.assertEqual(metadata["verification_level"], "scaffold")
        self.assertFalse(metadata["live_verified"])
        self.assertEqual(metadata["live_execution"]["status"], "planned")

    def test_release_gate_live_metadata_marks_live_for_executed_e2e(self) -> None:
        metadata = release_gate_live_metadata(
            [
                QaCheck(
                    name="e2e-solver-evidence",
                    status="passed",
                    messages=[
                        "mode=execute",
                        "execute=true",
                        "browser_engine=playwright",
                        "execute_tunnels=true",
                        "live_readiness=passed",
                        "executed_access_passed=2",
                        "executed_solver_passed=5",
                        "live_requirement=browser:required=1:passed=1:status=passed",
                        "live_requirement=solver:required=5:passed=5:status=passed",
                    ],
                )
            ],
            release_ready=True,
        )

        self.assertEqual(metadata["verification_level"], "live")
        self.assertTrue(metadata["live_verified"])
        self.assertEqual(metadata["live_execution"]["status"], "passed")
        self.assertEqual(
            metadata["live_execution"]["requirements"],
            [
                {"name": "browser", "required": 1, "passed": 1, "status": "passed"},
                {"name": "solver", "required": 5, "passed": 5, "status": "passed"},
            ],
        )

    def test_learner_access_live_requirement_messages_summarize_access_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(
                root / "lab-access-bundle.json",
                dump_yaml(
                    {
                        "live_readiness_requirements": [
                            {"name": "browser", "required": 1, "status": "declared"},
                            {"name": "plugin-evidence", "required": 0, "status": "missing"},
                        ]
                    }
                ),
            )

            self.assertEqual(
                learner_access_live_requirement_messages(root),
                [
                    "declared_live_requirement=browser:required=1:status=declared",
                    "declared_live_requirement=plugin-evidence:required=0:status=missing",
                ],
            )

    def test_critical_playtest_gap_messages_fail_stage_implementation_gaps(self) -> None:
        report = SimpleNamespace(
            steps=[
                SimpleNamespace(
                    step_id="implementation-01",
                    status="warning",
                    evidence=[
                        "stage-03: mapped service internal-api has no vulnerability plugin or explicit runtime evidence path"
                    ],
                ),
                SimpleNamespace(step_id="industry-01", status="warning", evidence=["advisory realism note"]),
            ]
        )

        messages = critical_playtest_gap_messages(report)

        self.assertIn("critical=implementation-01:stage implementation coverage:warning", messages)
        self.assertTrue(any("stage-03" in message for message in messages))
        self.assertFalse(any("industry-01" in message for message in messages))

    def test_critical_playtest_gap_messages_allow_passed_implementation_coverage(self) -> None:
        report = SimpleNamespace(
            steps=[
                SimpleNamespace(
                    step_id="implementation-01",
                    status="passed",
                    evidence=["stage-01: plugin evidence stage-01_completed"],
                )
            ]
        )

        self.assertEqual(critical_playtest_gap_messages(report), [])

    def test_learner_access_plugin_evidence_messages_pass_when_access_checks_match_solver_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_playtest_evidence_files(
                root,
                plugin_checks=[
                    {
                        "service": "support-portal",
                        "plugin": "ssti-preview",
                        "state_url": "http://127.0.0.1:18080/api/state",
                        "state_verification": "curl -sS http://127.0.0.1:18080/api/state",
                        "expected_evidence": ["template_probe_confirmed"],
                    }
                ],
                access_items=[
                    {
                        "check_id": "plugin-evidence-01",
                        "service": "support-portal",
                        "kind": "plugin-evidence",
                        "status": "planned",
                    }
                ],
            )

            self.assertEqual(learner_access_plugin_evidence_messages(root), [])
            self.assertEqual(plugin_evidence_check_count(root), 1)

    def test_learner_access_plugin_evidence_messages_fail_when_plugin_checks_are_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_playtest_evidence_files(root, plugin_checks=[], access_items=[])

            messages = learner_access_plugin_evidence_messages(root)

            self.assertTrue(any("no plugin_checks" in message for message in messages))

    def test_learner_access_stage_handoff_messages_pass_when_bundle_contains_carried_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_stage_handoff_files(
                root,
                stage_handoffs=[
                    {
                        "from_stage": "stage-01",
                        "to_stage": "stage-02",
                        "carried_evidence": ["template_probe_confirmed"],
                        "learner_clue": "Use the template evidence collected from stage-01 to review the internal wiki operating notes.",
                    }
                ],
            )

            self.assertEqual(learner_access_stage_handoff_messages(root), [])
            self.assertEqual(stage_handoff_count(root), 1)

    def test_learner_access_stage_handoff_messages_fail_when_bundle_has_no_handoffs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_stage_handoff_files(root, stage_handoffs=[])

            messages = learner_access_stage_handoff_messages(root)

            self.assertTrue(any("no stage_handoffs" in message for message in messages))

    def test_stage_handoff_solver_coverage_messages_pass_when_plugin_checks_verify_evidence(self) -> None:
        solver_plan = {
            "steps": [
                {"step_id": "chain-01", "action_type": "stage-chain"},
                {"step_id": "plugin-support-portal-ssti-preview", "action_type": "vulnerability-behavior"},
            ]
        }
        access_bundle = {
            "stage_handoffs": [
                {
                    "from_stage": "stage-01",
                    "to_stage": "stage-02",
                    "carried_evidence": ["template_probe_confirmed"],
                    "learner_clue": "Use template_probe_confirmed from the support workflow to review internal notes.",
                }
            ],
            "plugin_checks": [
                {
                    "service": "support-portal",
                    "plugin": "ssti-preview",
                    "expected_evidence": ["template_probe_confirmed"],
                }
            ],
        }

        self.assertEqual(stage_handoff_solver_coverage_messages(solver_plan, access_bundle), [])

    def test_stage_handoff_runtime_check_messages_require_stage_detail_probe(self) -> None:
        access_bundle = {
            "stage_handoffs": [
                {
                    "from_stage": "stage-01",
                    "to_stage": "stage-02",
                    "to_services": ["internal-wiki"],
                    "carried_evidence": ["template_probe_confirmed"],
                    "learner_clue": "Use template_probe_confirmed from the support workflow to review internal notes.",
                }
            ],
            "stage_chain_checks": [
                {
                    "service": "internal-wiki",
                    "from_stage": "stage-01",
                    "to_stage": "stage-02",
                    "chain_url": "http://127.0.0.1:18080/api/chain",
                    "expected_stage": "stage-02",
                    "expected_from_stage": "stage-01",
                    "expected_evidence": ["template_probe_confirmed"],
                }
            ],
        }

        messages = stage_handoff_runtime_check_messages(access_bundle)

        self.assertEqual(
            messages,
            ["critical=stage-handoff:stage-01->stage-02:runtime check missing stage_url"],
        )

        access_bundle["stage_chain_checks"][0]["stage_url"] = "http://127.0.0.1:18080/api/stages/stage-02"

        self.assertEqual(stage_handoff_runtime_check_messages(access_bundle), [])

    def test_stage_handoff_runtime_check_messages_accept_source_service_fallback(self) -> None:
        access_bundle = {
            "stage_handoffs": [
                {
                    "from_stage": "stage-02",
                    "to_stage": "stage-03",
                    "from_services": ["investor-portal"],
                    "to_services": ["api-gateway"],
                    "carried_evidence": ["object_id_discovered"],
                    "learner_clue": "Use object_id_discovered from investor portal review when validating API traffic.",
                }
            ],
            "stage_chain_checks": [
                {
                    "service": "investor-portal",
                    "check_scope": "source-service",
                    "from_stage": "stage-02",
                    "to_stage": "stage-03",
                    "chain_url": "http://127.0.0.1:18081/api/chain",
                    "stage_url": "http://127.0.0.1:18081/api/stages/stage-03",
                    "expected_stage": "stage-03",
                    "expected_from_stage": "stage-02",
                    "expected_evidence": ["object_id_discovered"],
                }
            ],
        }

        self.assertEqual(stage_handoff_runtime_check_messages(access_bundle), [])

    def test_stage_handoff_runtime_check_messages_accept_chain_observer_fallback(self) -> None:
        access_bundle = {
            "stage_handoffs": [
                {
                    "from_stage": "stage-03",
                    "to_stage": "stage-04",
                    "from_services": ["internal-api"],
                    "to_services": ["trade-ops-console"],
                    "carried_evidence": ["review_context_collected"],
                    "learner_clue": "Use review_context_collected when moving into trade operations.",
                }
            ],
            "stage_chain_checks": [
                {
                    "service": "controlled-drop",
                    "check_scope": "chain-observer",
                    "from_stage": "stage-03",
                    "to_stage": "stage-04",
                    "chain_url": "http://127.0.0.1:18084/api/chain",
                    "stage_url": "http://127.0.0.1:18084/api/stages/stage-04",
                    "expected_stage": "stage-04",
                    "expected_from_stage": "stage-03",
                    "expected_evidence": ["review_context_collected"],
                }
            ],
        }

        self.assertEqual(stage_handoff_runtime_check_messages(access_bundle), [])

    def test_stage_handoff_solver_coverage_messages_fail_when_handoff_evidence_is_not_verified(self) -> None:
        solver_plan = {
            "steps": [
                {
                    "step_id": "chain-01",
                    "action_type": "stage-chain",
                    "evidence": ["stage chain exists"],
                    "learner_action": "Review normal business notes.",
                }
            ]
        }
        access_bundle = {
            "stage_handoffs": [
                {
                    "from_stage": "stage-01",
                    "to_stage": "stage-02",
                    "carried_evidence": ["template_probe_confirmed"],
                    "learner_clue": "Use template_probe_confirmed from the support workflow to review internal notes.",
                }
            ],
            "plugin_checks": [],
        }

        messages = stage_handoff_solver_coverage_messages(solver_plan, access_bundle)

        self.assertEqual(
            messages,
            ["critical=stage-handoff:solver plan does not verify carried evidence: template_probe_confirmed"],
        )

    def test_stage_handoff_clue_messages_fail_on_thin_or_answer_key_clues(self) -> None:
        self.assertEqual(
            stage_handoff_clue_messages(
                {
                    "from_stage": "stage-01",
                    "to_stage": "stage-02",
                    "carried_evidence": ["template_probe_confirmed"],
                    "learner_clue": "next",
                }
            ),
            ["critical=stage-handoff:stage-01->stage-02:learner_clue is too thin"],
        )
        self.assertEqual(
            stage_handoff_clue_messages(
                {
                    "from_stage": "stage-01",
                    "to_stage": "stage-02",
                    "carried_evidence": ["template_probe_confirmed"],
                    "learner_clue": "Copy paste this answer key to get the flag.",
                }
            ),
            ["critical=stage-handoff:stage-01->stage-02:learner_clue contains answer-key wording"],
        )

    def test_stage_handoff_clue_messages_require_evidence_or_stage_context_anchor(self) -> None:
        self.assertEqual(
            stage_handoff_clue_messages(
                {
                    "from_stage": "stage-01",
                    "from_title": "Support Preview",
                    "to_stage": "stage-02",
                    "to_title": "Internal Wiki Review",
                    "carried_evidence": ["template_probe_confirmed"],
                    "learner_clue": "Use the template behavior observed in support preview to review internal wiki notes.",
                }
            ),
            [],
        )
        self.assertEqual(
            stage_handoff_clue_messages(
                {
                    "from_stage": "stage-01",
                    "from_title": "Support Preview",
                    "to_stage": "stage-02",
                    "to_title": "Internal Wiki Review",
                    "carried_evidence": ["template_probe_confirmed"],
                    "learner_clue": "Review normal operating material and decide what to do next.",
                }
            ),
            ["critical=stage-handoff:stage-01->stage-02:learner_clue does not reference carried evidence or stage context"],
        )

    def test_stage_handoff_clue_messages_accept_service_context_anchor(self) -> None:
        self.assertEqual(
            stage_handoff_clue_messages(
                {
                    "from_stage": "stage-04",
                    "from_title": "Separate useful engineering clues from noise.",
                    "to_stage": "stage-05",
                    "to_title": "Discover bounded production services.",
                    "from_services": ["engineering-wiki", "historian"],
                    "to_services": ["mes-api", "historian", "ot-jump-host"],
                    "carried_evidence": ["stage-04_completed"],
                    "learner_clue": "Use historian maintenance notes and MES route records to identify the jump-host surface used by production operations.",
                }
            ),
            [],
        )

    def test_stage_handoff_clue_messages_reject_lab_framing_language(self) -> None:
        self.assertEqual(
            stage_handoff_clue_messages(
                {
                    "from_stage": "stage-04",
                    "to_stage": "stage-05",
                    "to_services": ["mes-api", "historian"],
                    "carried_evidence": ["stage-04_completed"],
                    "learner_clue": "Enumerate MES and historian surfaces that are intentionally simulated for the lab.",
                }
            ),
            ["critical=stage-handoff:stage-04->stage-05:learner_clue contains answer-key wording"],
        )

    def test_human_readiness_gap_messages_pass_when_report_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(
                root / "human-readiness.json",
                dump_yaml(
                    {
                        "status": "passed",
                        "checks": [
                            {
                                "check_id": "human-01",
                                "step_id": "plugin-support-portal-ssti-preview",
                                "status": "passed",
                                "messages": ["ready"],
                            }
                        ],
                    }
                ),
            )

            self.assertEqual(human_readiness_gap_messages(root), [])
            self.assertEqual(human_readiness_check_count(root), 1)

    def test_human_readiness_gap_messages_fail_when_report_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(
                root / "human-readiness.json",
                dump_yaml(
                    {
                        "status": "warning",
                        "checks": [
                            {
                                "check_id": "human-access-01",
                                "step_id": "access",
                                "status": "warning",
                                "messages": ["No final submission endpoint is available."],
                            }
                        ],
                    }
                ),
            )

            messages = human_readiness_gap_messages(root)

            self.assertTrue(any("status=warning" in message for message in messages))

    def test_human_readiness_gap_messages_fail_when_report_has_failed_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(
                root / "human-readiness.json",
                dump_yaml(
                    {
                        "status": "failed",
                        "checks": [
                            {
                                "check_id": "human-02",
                                "step_id": "plugin-release-signed-update-publish",
                                "status": "failed",
                                "messages": ["vulnerability step has no discovery_cues."],
                            }
                        ],
                    }
                ),
            )

            messages = human_readiness_gap_messages(root)

            self.assertTrue(any("status=failed" in message for message in messages))
            self.assertTrue(any("no discovery_cues" in message for message in messages))


def write_playtest_evidence_files(root: Path, *, plugin_checks: list[dict], access_items: list[dict]) -> None:
    write_text(
        root / "solver-plan.json",
        dump_yaml(
            {
                "steps": [
                    {
                        "step_id": "plugin-support-portal-ssti-preview",
                        "service": "support-portal",
                        "plugin": "ssti-preview",
                        "action_type": "vulnerability-behavior",
                    }
                ]
            }
        ),
    )
    write_text(root / "learner-access.json", dump_yaml({"plugin_checks": plugin_checks}))
    access_dir = root / "access-playtest"
    access_dir.mkdir(parents=True, exist_ok=True)
    write_text(access_dir / "access-playtest.yaml", dump_yaml({"items": access_items}))


def write_stage_handoff_files(root: Path, *, stage_handoffs: list[dict]) -> None:
    expected_evidence = sorted(
        {
            str(evidence)
            for handoff in stage_handoffs
            for evidence in handoff.get("carried_evidence", []) or []
            if str(evidence).strip()
        }
    )
    write_text(
        root / "solver-plan.json",
        dump_yaml(
            {
                "steps": [
                    {"step_id": "chain-01", "action_type": "stage-chain"},
                    {"step_id": "implementation-01", "action_type": "implementation-coverage"},
                ]
            }
        ),
    )
    plugin_checks = [
        {
            "service": "support-portal",
            "plugin": "stage-evidence-check",
            "expected_evidence": expected_evidence,
        }
    ] if expected_evidence else []
    stage_chain_checks = []
    for handoff in stage_handoffs:
        to_stage = str(handoff.get("to_stage", ""))
        from_stage = str(handoff.get("from_stage", ""))
        service = str((handoff.get("to_services") or ["internal-wiki"])[0])
        stage_chain_checks.append(
            {
                "service": service,
                "from_stage": from_stage,
                "to_stage": to_stage,
                "chain_url": "http://127.0.0.1:18080/api/chain",
                "stage_url": f"http://127.0.0.1:18080/api/stages/{to_stage}",
                "expected_stage": to_stage,
                "expected_from_stage": from_stage,
                "expected_evidence": handoff.get("carried_evidence", []),
            }
        )
    write_text(root / "lab-access-bundle.json", dump_yaml({"stage_handoffs": stage_handoffs, "plugin_checks": plugin_checks, "stage_chain_checks": stage_chain_checks}))


if __name__ == "__main__":
    unittest.main()
