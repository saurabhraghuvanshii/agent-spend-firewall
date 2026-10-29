# Agent Spend Firewall

**Agent Spend Firewall** is a drop-in MCP proxy that sits between any AI agent and Razorpay. Read-only tools pass
straight through; every money-moving tool (refunds, payouts, payment links, ...) must carry a stated reason, is
checked against policy-as-code, and is allowed, denied, transformed, or routed for human approval — with each
decision written to a hash-chained, tamper-evident audit log. The result: agent spending that is **explainable,
bounded, gated, and auditable**. Razorpay **test mode only** (`rzp_test_` keys).

## Demo (2 min)

[![Agent Spend Firewall: 2-minute MVP demo](agent-spend-firewall-mvp/poster.png)](agent-spend-firewall-mvp/agent-spend-firewall-mvp.mp4)

▶ [Watch the MVP demo](agent-spend-firewall-mvp/agent-spend-firewall-mvp.mp4) · [captions (.srt)](agent-spend-firewall-mvp/agent-spend-firewall-mvp.srt)

A scripted agent sends eight refund calls through the real firewall (default policy, SQLite hash-chained audit log,
approval service, `@asf/api`) while the live dashboard updates over SSE: a call with no reason, a legitimate ₹499
refund, a duplicate retry, a prompt-injected ₹50,000 refund, an over-refund, and a ₹4,500 refund held for a human and
approved with one tap in the approver chat (a real signed callback into the firewall). Shadow mode is then switched
on from the dashboard so a would-deny refund goes through flagged "would deny", and the kill switch (behind a confirm
dialog) freezes the next refund. It ends by editing one audit row in the SQLite file: the dashboard's chain badge
turns red at that record, and `audit:verify` reports the same break. Razorpay is a local fake upstream, and the
Telegram chat is a simulated test bot page driving the real Telegram approver code over a fake transport; no network
calls are made.

### Screenshots

| Dashboard (dark, default)                                                         | Dashboard (light)                                                                   |
| --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| ![Dashboard, dark theme](agent-spend-firewall-mvp/screenshots/dashboard-dark.png) | ![Dashboard, light theme](agent-spend-firewall-mvp/screenshots/dashboard-light.png) |

![A ₹4,500 refund waiting for approval on the dashboard and in the simulated Telegram approver chat](agent-spend-firewall-mvp/screenshots/telegram-approval.png)

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

## Running the dashboard

The dashboard (`packages/dashboard`) is a Vite + React app that talks to the HTTP API served **inside the proxy**
process (`packages/api`). The API only exists while the proxy runs with `ASF_API_PORT` set.

1. **Create an admin token** (≥ 32 chars). Keep it away from the AI agent — the agent must never hold it:

   ```bash
   openssl rand -hex 32 > ~/.asf-admin-token && chmod 600 ~/.asf-admin-token
   ```

2. **Start the proxy with the API on.** These go in the proxy's launch environment (e.g. the `env` block of the
   agent's MCP server config); `ASF_ADMIN_TOKEN_FILE` and `ASF_API_APPROVALS` are ignored in `.env`:

   ```bash
   ASF_API_PORT=8787 ASF_ADMIN_TOKEN_FILE=$HOME/.asf-admin-token pnpm --filter @asf/proxy start
   ```

   The API binds to `127.0.0.1` only. Dashboard approve/reject is **off** by default (403 → "Approve via Telegram");
   enable it with `ASF_API_APPROVALS=1` only if the agent has no shell/file tools or the proxy runs as a separate OS
   user (see D-036).

3. **Start the dashboard:**

   ```bash
   pnpm --filter @asf/dashboard dev    # http://localhost:5173
   ```

   It calls `http://127.0.0.1:8787` by default. For another port, set `VITE_ASF_API_URL` in the shell or in
   `packages/dashboard/.env.local` (the root `.env` is not read by Vite).

4. **Open http://localhost:5173 and paste the admin token.** It is kept in this tab's `sessionStorage` only; use
   "Forget token" to clear it.

What you get: a live audit timeline (₹ amounts, decision badges, matched rule, agent reasons labelled _untrusted_),
pending approvals, session replay, the chain-integrity badge, and enforce/shadow mode + kill switch controls.

Production build: `pnpm --filter @asf/dashboard build` (output in `packages/dashboard/dist`). Serve it with
`Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY` headers.
