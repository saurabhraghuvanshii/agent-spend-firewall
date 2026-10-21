# SUBAGENTS.md

Specialised subagents for this repo. Definitions live in `.claude/agents/*.md` (Claude Code loads them automatically).
Each runs in its own context window, so the main session stays focused.

| Subagent | Use it when | Can edit? |
|---|---|---|
| `architect` | Starting a task that spans packages, or unsure where code belongs | No (plans only) |
| `mcp-proxy-dev` | Work in `packages/proxy`: MCP server/client, tool discovery, schema rewrite, forwarding, retries | Yes |
| `policy-engine-dev` | Work in `packages/core`: policy DSL, rule evaluation, decisions, audit hash-chain | Yes |
| `frontend-dev` | Work in `packages/dashboard` and `packages/api` | Yes |
| `test-writer` | Adding unit/integration tests, especially failure paths | Yes (tests only) |
| `security-reviewer` | **Mandatory** after any change to money tools, policy, approvals, or audit log | No (review only) |
| `eval-designer` | Writing adversarial scenarios in `evals/` and the results table | Yes (evals only) |

## Typical flow for a task

```
/next-task
  └─ architect          → short plan: files, interfaces, risks
  └─ <domain>-dev       → implement
  └─ test-writer        → fill test gaps (happy path + every failure path)
  └─ security-reviewer  → review money paths; fix findings
/finish-task            → verify criteria, update .plan, print suggested commit message (no commit)
```

## Rules all subagents follow

- Obey `AGENTS.md` hard rules: **no git commit/push**, no secrets, test mode only, paise integers, fail closed.
- Stay inside your area; if a change is needed elsewhere, report it back instead of making it.
- End with a short report: what changed (files), what's tested, open questions.
