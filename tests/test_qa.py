from __future__ import annotations

import unittest
from types import SimpleNamespace

from labforge.qa import critical_playtest_gap_messages


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


if __name__ == "__main__":
    unittest.main()
