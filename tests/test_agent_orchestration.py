from __future__ import annotations

import unittest
from types import SimpleNamespace

from labforge.agent_orchestration import (
    DEFAULT_AGENT_ROLES,
    orchestration_manifest,
    render_agent_system_prompt,
    render_agent_task_prompt,
)


class AgentOrchestrationTest(unittest.TestCase):
    def test_manifest_declares_specialist_boundaries_and_handoffs(self) -> None:
        spec = SimpleNamespace(lab_id="agent-test", title="Agent Test Lab")
        manifest = orchestration_manifest(spec)

        self.assertIn("handoff_rules", manifest)
        self.assertTrue(any("service-builder owns service code" in rule for rule in manifest["handoff_rules"]))
        self.assertTrue(any("qa-playtester validates learner-path" in rule for rule in manifest["handoff_rules"]))
        boundaries = {item["agent_id"]: item for item in manifest["specialist_boundaries"]}
        self.assertIn("security-controls", boundaries)
        self.assertIn("qa-playtester", boundaries)
        self.assertIn("protected/unprotected delta", boundaries["security-controls"]["outputs"])

    def test_specialist_prompts_include_role_specific_done_criteria(self) -> None:
        spec = SimpleNamespace(lab_id="agent-test", title="Agent Test Lab")
        roles = {role.agent_id: role for role in DEFAULT_AGENT_ROLES}

        security_prompt = render_agent_task_prompt(spec, roles["security-controls"], 4)
        self.assertIn("control placement table", security_prompt)
        self.assertIn("protected/unprotected behavior differences", security_prompt)

        qa_system = render_agent_system_prompt(spec, roles["qa-playtester"])
        self.assertIn("Learner-mode testing starts only from declared learner entrypoints", qa_system)
        self.assertIn("Instructor-mode verification separately checks answer keys", qa_system)


if __name__ == "__main__":
    unittest.main()
