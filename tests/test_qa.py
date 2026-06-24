from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace

from labforge.qa import (
    critical_playtest_gap_messages,
    learner_access_plugin_evidence_messages,
    learner_access_stage_handoff_messages,
    plugin_evidence_check_count,
    stage_handoff_clue_messages,
    stage_handoff_count,
)
from labforge.io import write_text, dump_yaml


class QaReleaseGateTests(unittest.TestCase):
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
    write_text(root / "lab-access-bundle.json", dump_yaml({"stage_handoffs": stage_handoffs}))


if __name__ == "__main__":
    unittest.main()
