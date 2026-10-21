# AGENTS.md — Agent Spend Firewall

Guidance for any AI coding agent (Claude Code, Codex, Cursor, …) working in this repo.
Claude Code loads this file through `CLAUDE.md`.

---

## 🚫 Hard rules (read first)

1. **Never run `git commit` or `git push`** (or `gh pr create`, `git tag`). The human owner commits and pushes.
   When a task is done, print a *suggested* commit message and stop. This is also enforced by
   `.claude/settings.json` (deny rules) and `.claude/hooks/block-git-write.mjs`.
2. **Never read, print, or log secrets.** Do not open `.env` / `.env.local`. Use `.env.example` for key names.
3. **Razorpay TEST mode only.** Keys must start with `rzp_test_`. Refuse to run anything with `rzp_live_`.
4. **Money amounts are integers in paise** (₹1 = 100 paise). Never use floats for money. Name variables `amountPaise`
   when ambiguity is possible.
5. **Fail closed.** If the policy engine errors, times out, or can't decide → the money action is **denied**, never allowed.
6. Work from the plan: pick tasks from `.plan/tasks/`, follow their acceptance criteria, update their status.

---

## What this project is

**Agent Spend Firewall** is a drop-in **MCP proxy** that sits between any AI agent and Razorpay (MCP server / APIs).
It makes every money-moving agent action **explainable, bounded, gated, and auditable**.

```
AI Agent ──MCP──▶ [ Firewall: intercept → require reason → policy → allow/deny/approve/transform → audit ] ──▶ Razorpay (test)
                                         │                                 │
                                         └──▶ Telegram approval            └──▶ Dashboard (timeline / replay)
```

Core ideas:
- **Pass-through for reads**, policy-gated for money tools (refunds, payouts, payment links, …).
- **Forced justification**: money tools' input schemas are rewritten to require a `reason: string` field.
- **Policy as code** in TypeScript (`policies/*.ts`), decisions: `allow | deny | require_approval | transform`.
- **Hash-chained, append-only audit log** (tamper-evident).
- **Failure handling**: idempotency keys, verify-before-retry on timeouts, kill switch, shadow mode.
- **Evals**: adversarial scenario suite (prompt injection, unit confusion, loops, over-refunds) with a results table.

## Tech stack

| Area | Choice |
|---|---|
| Language / runtime | TypeScript (strict), Node 20+, ESM |
| Monorepo | pnpm workspaces |
| MCP | `@modelcontextprotocol/sdk` (proxy is MCP server to agent + MCP client to Razorpay) |
| Razorpay | Razorpay MCP server (test mode) + `razorpay` npm SDK for status lookups |
| Validation | `zod` |
| Storage | SQLite via `better-sqlite3` + Drizzle ORM |
| HTTP API | Hono |
| Approvals | Telegram via `grammy` |
| Dashboard | Vite + React + Tailwind |
| Demo agent | Claude Agent SDK (TypeScript) |
| Tests / evals | Vitest |

## Repository layout (target)

```
agent-spend-firewall/
├── AGENTS.md / CLAUDE.md / SUBAGENTS.md
├── .claude/              # Claude Code config: settings, subagents, slash commands, hooks
├── .plan/                # roadmap, decisions, tasks (source of truth for what to do next)
├── packages/
│   ├── core/             # PURE: policy DSL + engine, decision types, audit hash-chain. No I/O except via injected ports.
│   ├── proxy/            # MCP proxy server: tool discovery, classification, schema rewrite, forwarding, failure handling
│   ├── approvals/        # pending-approval store + Telegram bot
│   ├── api/              # Hono server: audit, approvals, kill switch endpoints for dashboard
│   └── dashboard/        # React UI
├── policies/default.ts   # example policy
├── examples/support-agent/  # demo agent (Claude Agent SDK) used in the video
├── evals/                # adversarial scenarios, runner, results
└── docs/                 # architecture, razorpay-tools.json, failure cases
```

## Commands

```bash
pnpm install
pnpm -r build          # build all packages
pnpm -r typecheck      # tsc --noEmit everywhere
pnpm -r test           # vitest
pnpm lint              # eslint + prettier check
pnpm --filter @asf/proxy dev      # run the proxy (stdio)
pnpm --filter @asf/dashboard dev  # dashboard
pnpm evals             # run adversarial eval suite
```

(Commands become valid after task T001 scaffolds the monorepo.)

## Coding conventions

- Package names: `@asf/core`, `@asf/proxy`, `@asf/approvals`, `@asf/api`, `@asf/dashboard`.
- `packages/core` stays **pure and dependency-light** — inject Razorpay lookups, clock, and storage as interfaces (ports).
- Validate all external input (tool args, Razorpay responses, Telegram callbacks) with zod at the boundary.
- Return typed results instead of throwing across package boundaries: `type Result<T> = { ok: true; value: T } | { ok: false; error: FirewallError }`.
- Denials returned to the agent are **structured** (`{ decision: "deny", ruleId, message }`) so the agent can explain rather than retry.
- Every money action writes exactly one audit entry *before* forwarding and updates it with the outcome.
- Tests live next to code (`*.test.ts`). Every policy rule and every failure path needs a test.
- No `any`. No floating-point money. No silent catch blocks.

## Definition of done (every task)

- Acceptance criteria in the task file are met.
- `pnpm -r typecheck` and `pnpm -r test` pass.
- Money-path changes were reviewed by the `security-reviewer` subagent.
- Task file status → `review`, `.plan/tasks/INDEX.md` updated, a suggested commit message printed.
- **No commit, no push.**
