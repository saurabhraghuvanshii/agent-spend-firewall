# Agent Spend Firewall

**Agent Spend Firewall** is a drop-in MCP proxy that sits between any AI agent and Razorpay. Read-only tools pass
straight through; every money-moving tool (refunds, payouts, payment links, ...) must carry a stated reason, is
checked against policy-as-code, and is allowed, denied, transformed, or routed for human approval — with each
decision written to a hash-chained, tamper-evident audit log. The result: agent spending that is **explainable,
bounded, gated, and auditable**. Razorpay **test mode only** (`rzp_test_` keys).

## Demo (2 min)

[![Agent Spend Firewall: 2-minute MVP demo](agent-spend-firewall-mvp/poster.png)](agent-spend-firewall-mvp/agent-spend-firewall-mvp.mp4)

▶ [Watch the MVP demo](agent-spend-firewall-mvp/agent-spend-firewall-mvp.mp4) · [captions (.srt)](agent-spend-firewall-mvp/agent-spend-firewall-mvp.srt)

A scripted agent sends seven refund calls through the real firewall (default policy, SQLite hash-chained audit log,
approval flow): a call with no reason, a legitimate ₹499 refund, a duplicate retry, a prompt-injected ₹50,000 refund,
an over-refund, a ₹4,500 refund approved over Telegram, and a call while the kill switch is on. It ends by tampering
with one audit row so `audit:verify` reports the break. Razorpay and Telegram are local test fakes in this recording.

## Development

Requires Node 20 (see `.nvmrc`) and pnpm (version pinned in `package.json`).

```bash
pnpm install
pnpm typecheck   # tsc --noEmit in every package
pnpm test        # vitest in every package
pnpm lint        # eslint + prettier --check
pnpm build       # emit dist/ for every package
pnpm evals       # adversarial eval suite
```

Copy `.env.example` to `.env` and fill in **test-mode** credentials.

> Native modules (e.g. `better-sqlite3`) are compiled for the active Node version. After switching Node versions,
> run `pnpm rebuild`.
