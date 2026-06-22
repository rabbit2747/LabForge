# Live Agent Adapters

LabForge agent adapters consume `AgentExecutionPackageSpec` files and either
prepare handoff files or call a live LLM runtime. Live calls are opt-in.
`agents run` defaults to dry-run mode.

## Adapter Matrix

| Adapter | Live execution | Purpose |
|---|---:|---|
| `manual` | no | Create copy/paste Markdown instructions for a human-operated LLM session. |
| `openai` | yes | Call the OpenAI Responses API and write a LabForge agent result YAML. |
| `claude-cli` | yes | Call a local Claude CLI process and write a LabForge agent result YAML. |
| `mcp` | no | Create a JSON handoff file for an external MCP-capable orchestrator. |

## Safe Default

This command creates packages and adapter-specific handoff files only:

```powershell
python -m labforge agents run output/my-lab-agents --adapter openai --dry-run --agent scenario-designer --context-root examples/my-lab
```

Dry-run mode writes files under `.ai/run/` but does not call an LLM.

## OpenAI Adapter

Requirements:

- `OPENAI_API_KEY`
- optional `LABFORGE_OPENAI_MODEL`, default `gpt-4.1-mini`
- optional `LABFORGE_LLM_TIMEOUT`, default `120` seconds

Execute one agent:

```powershell
$env:OPENAI_API_KEY = "<key>"
python -m labforge agents run output/my-lab-agents --adapter openai --execute --agent scenario-designer --context-root examples/my-lab
```

The adapter writes:

- `.ai/run/<task>.package.openai.json` in dry-run mode
- `.ai/run/<task>.package.openai.transcript.json` in execute mode
- `.ai/outputs/<task>.result.yaml`

If the model returns plain prose instead of a YAML object, LabForge preserves
the prose as a `needs-review` result rather than discarding it.

## Claude CLI Adapter

Requirements:

- `claude` on `PATH`, or `LABFORGE_CLAUDE_BIN`
- optional `LABFORGE_CLAUDE_ARGS`
- optional `LABFORGE_LLM_TIMEOUT`, default `300` seconds

Example:

```powershell
$env:LABFORGE_CLAUDE_ARGS = "--print"
python -m labforge agents run output/my-lab-agents --adapter claude-cli --execute --agent mitre-mapper --context-root examples/my-lab
```

LabForge sends the package prompt through standard input and captures stdout,
stderr, return code, and command metadata in a transcript file.

## MCP Handoff Adapter

The `mcp` adapter does not call an MCP server directly yet. It writes a stable
handoff JSON file that an external MCP runner can consume:

```powershell
python -m labforge agents run output/my-lab-agents --adapter mcp --dry-run --agent infrastructure-architect --context-root examples/my-lab
```

The handoff contains the system prompt, task prompt, task manifest, context
root, output path, and expected result schema.

## Result Contract

Live adapters ask models to return only YAML with this shape:

```yaml
task_id: 01-scenario-designer
status: draft
summary: Short reviewable summary.
findings: []
artifacts: []
open_questions: []
```

Supervisors should still run:

```powershell
python -m labforge agents review output/my-lab-agents --write
```

Live adapter output is never treated as automatically approved.
