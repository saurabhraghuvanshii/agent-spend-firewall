# Pointing an MCP client at the firewall proxy

The proxy is an MCP server on **stdio**. Your agent talks to it exactly as it would talk to the Razorpay MCP server;
the proxy starts the real Razorpay MCP server itself (a hardened Docker container) and forwards to it.

```
agent (Claude Code / Desktop / Inspector) ──stdio──▶ @asf/proxy ──stdio──▶ docker: razorpay/mcp (test mode)
```

## Prerequisites

1. Node 20.19+, pnpm, and `pnpm install` in the repo.
2. Docker running, and the pinned Razorpay MCP image pulled (the proxy runs it with `--pull=never`):

   ```bash
   docker pull razorpay/mcp@sha256:435109006d6247103899938cf7b1747ba8be1c1a8a28d452cf9fa8eff506e5c6
   ```

3. Razorpay **TEST** keys. Put them in the repo's `.env` (see `.env.example` for the names) or export them in the
   shell that launches the proxy:
   - `RAZORPAY_KEY_ID` — must start with `rzp_test_`. A `rzp_live_` value anywhere in the environment makes the proxy
     refuse to start (exit code 2).
   - `RAZORPAY_KEY_SECRET`

   - `RAZORPAY_KEY_SECRET` must be 16+ letters/digits (Razorpay secrets are 24); anything else is refused (exit 2).

   The proxy reads `.env` itself at startup (shell values win). Keys are handed to the container through its
   environment by name (`-e RAZORPAY_KEY_ID`), never on the proxy's or docker's command line, and are redacted from
   every log line and error result. An upstream result that contains a key in any encoding is replaced entirely by
   an `upstream_error` result. **Never put key values in an MCP client config file.**

   > **Who can see the keys:** anyone with access to the Docker daemon can read the container's environment with
   > `docker inspect asf-upstream-<hex>`, and the pinned image's entrypoint passes the keys to the Razorpay server as
   > `--key/--secret` arguments inside the container, so they also appear in the host's process list (`ps`) while it
   > runs. Docker access is root-equivalent anyway; only run the proxy on a machine where everyone with docker / root
   > access may see your **test** keys, and never use live keys (refused).

Optional settings:

| Variable                    | Default               | Notes                                                                                                                                                                                                                                                                                                                                                                                        |
| --------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ASF_UPSTREAM_TIMEOUT_MS`   | `30000`               | Per-call upstream timeout for READ tools, 1000–600000. A timed-out read returns `upstream_timeout` and is not retried.                                                                                                                                                                                                                                                                       |
| `ASF_MONEY_CALL_TIMEOUT_MS` | `10000`               | **Shell environment only.** Upstream timeout for MONEY tool calls, 1000–120000 ⇒ else exit 2. A timed-out money call is verified with Razorpay before anything else (see "Timeouts" below).                                                                                                                                                                                                  |
| `ASF_VERIFY_WAIT_MS`        | `15000`               | **Shell environment only.** How long (1000–120000 ms) a timed-out refund waits for Razorpay's late answer before deciding; out of range ⇒ exit 2.                                                                                                                                                                                                                                            |
| `ASF_POLICY`                | `policies/default.ts` | **Shell environment only** (a value only in `.env` is ignored with a note). Policy file (`.ts`/`.js`/`.mjs`) **inside the repo** (symlinks resolved). Must compile and use `default: "deny"`, else the proxy exits 2.                                                                                                                                                                        |
| `ASF_AUDIT_DB`              | `data/audit.db`       | **Shell environment only** (a value only in `.env` is ignored with a note). Audit log SQLite file; must be **inside `<repo>/data/`** (relative paths resolve against the repo root; the parent directory's real path is checked, and the file must not be a symlink) ⇒ else exit 2. `<repo>/data/` is created if missing; other subdirectories must already exist. Can't be opened ⇒ exit 2. |
| `ASF_LOCK_WAIT_MS`          | `5000`                | Max wait (1–60000 ms) for the money-path locks; a call that waits longer is denied `firewall.busy`.                                                                                                                                                                                                                                                                                          |
| `ASF_DUPLICATE_WINDOW_MS`   | `600000`              | **Shell environment only** (a value only in `.env` is ignored with a note). How long (60000–86400000 ms) an executed or possibly executed money action blocks an identical one (`firewall.duplicate`); in-flight actions and pending approvals block for 24 h regardless. Out of range ⇒ exit 2.                                                                                             |
| `ASF_RAZORPAY_MCP_IMAGE`    | pinned digest         | Image override. Read from the **shell** environment only (ignored in `.env`).                                                                                                                                                                                                                                                                                                                |
| `DOCKER_HOST`, …            | —                     | Docker client settings, shell environment only.                                                                                                                                                                                                                                                                                                                                              |

Why shell-only: the policy decides which money moves and the audit DB is the evidence trail, so they can't be
redirected by editing `.env` (which is easy to change unnoticed and often copied between machines).

At startup the proxy logs to stderr which policy and audit log are in force, so you can check them:

```
[asf-proxy] policy policies/default.ts sha256 <hex> loaded (<n> rules)
[asf-proxy] audit log /…/data/audit.db: <n> records, head hash <hex>
```

The policy `sha256` covers the **entry file only** (e.g. `policies/default.ts`), not modules it imports, and is
computed just before the file is imported. Changes in imported helper modules do not change the logged hash.

It prints a `WARNING:` line when the audit DB did not exist and was created empty (payment history starts from
zero, so duplicate / velocity limits start from zero too — stop the proxy if you expected an existing log), and when
the audit hash chain does not verify (run `pnpm --filter @asf/proxy audit:verify`).

**Broken audit chain ⇒ money actions disabled.** If the audit hash chain fails verification at startup, the proxy
still starts and serves read tools, but it logs `WARNING: MONEY ACTIONS ARE DISABLED …` and **every money tool call is
denied** with `audit_unavailable` ("audit log failed verification at startup; money actions disabled until it is
repaired"); each such deny is still written to the audit log on a best-effort basis. Repair or replace the audit
log, then restart the proxy. Attempts that have no outcome (reported by `audit:verify` as a warning) do **not**
disable money actions. An audit DB that can't be opened or read still makes the proxy exit with code 2.

## The command

```bash
pnpm -s --dir /absolute/path/to/agent-spend-firewall --filter @asf/proxy start
```

- `-s` (silent) is **required**: stdout is the MCP channel, and without it pnpm prints a banner there that breaks
  the protocol. The proxy itself logs only to stderr (lines prefixed `[asf-proxy]`).
- `--dir` lets the client launch it from any working directory.
- Shutdown: closing stdin, SIGINT, SIGTERM or SIGHUP closes the upstream connection and force-removes the container
  (`asf-upstream-<hex>`). The container runs as `nobody` (`--user 65534:65534`) with `--memory 512m`,
  `--pids-limit 256`, a read-only filesystem and no capabilities.
- Leftover containers (e.g. after `kill -9` of the proxy): list them with
  `docker ps -a --filter name=asf-upstream- --format '{{.Names}} {{.Status}}'` and remove them with
  `docker rm -f <name>`. Nothing should be listed while no proxy is running.
- One agent message is capped at 1 MiB on stdio; a larger one closes the channel and the proxy exits.

## Claude Code

```bash
claude mcp add razorpay-firewall -- pnpm -s --dir /absolute/path/to/agent-spend-firewall --filter @asf/proxy start
```

Or a project-scoped `.mcp.json` at the root of the project where you run the agent:

```json
{
  "mcpServers": {
    "razorpay-firewall": {
      "command": "pnpm",
      "args": [
        "-s",
        "--dir",
        "/absolute/path/to/agent-spend-firewall",
        "--filter",
        "@asf/proxy",
        "start"
      ]
    }
  }
}
```

Then `/mcp` in Claude Code should show `razorpay-firewall` connected with the Razorpay tools.

## Claude Desktop

Edit `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "razorpay-firewall": {
      "command": "pnpm",
      "args": [
        "-s",
        "--dir",
        "/absolute/path/to/agent-spend-firewall",
        "--filter",
        "@asf/proxy",
        "start"
      ]
    }
  }
}
```

Desktop apps often start with a minimal `PATH`; if `pnpm` or `docker` isn't found, use the absolute path to `pnpm`
(`which pnpm`) as `command`, and add `"env": { "PATH": "<dirs containing node, pnpm and docker>" }`. Keys still come
from the repo's `.env`.

## MCP Inspector

```bash
npx @modelcontextprotocol/inspector pnpm -s --dir /absolute/path/to/agent-spend-firewall --filter @asf/proxy start
```

List tools, then try a read tool such as `fetch_all_payments` with `{ "count": 1 }`.

## What to expect

- **Tools**: the same tools the Razorpay MCP server offers (41 for the pinned image), same names. Money tools
  (anything that isn't a known read) require a `reason` (10–500 characters), integer paise amounts and `currency: "INR"`.
- **Money calls** go through the policy (`ASF_POLICY`) and are written to the audit log before anything is sent:
  - allowed ⇒ forwarded (without `reason`) and the outcome is audited;
  - denied ⇒ `isError: true` with `{"decision":"deny","ruleId":…,"message":…}`, never sent;
  - needs approval ⇒ `{"decision":"pending_approval","approvalId":"apr_…","message":"awaiting human approval; NOT executed"}`
    (`isError: false`). Until T011 approvals are held in memory only and **never executed**.
  - Calls acting on a payment (`payment_id`) or an order (`order_id`, e.g. `initiate_payment`, `update_order`) are only
    allowed for INR payments / orders (`firewall.currency_not_inr`); the proxy looks them up via `fetch_payment` /
    `fetch_order` first and denies if the lookup fails (`firewall.payment_lookup_failed` /
    `firewall.order_lookup_failed`).
  - Transformed args are re-checked by the firewall for currency (INR), amount validity (positive integer paise)
    and unchanged top-level `*_id` keys: if a transform changes / adds / removes any top-level `*_id` argument
    (`firewall.transform_retarget`), sets a non-INR currency or an invalid amount, the call is denied. Any other
    field a transform changes is trusted as a policy-author change (policy files are trusted code, D-013).
  - **Timeouts / unclear outcomes (T010)**: a money call that timed out or failed after it was sent is checked with
    Razorpay first (refunds by an `asf_attempt` notes marker the firewall adds; `asf_*` notes keys and more than 14
    notes are refused). Executed ⇒ `{"outcome":"success","verifiedAfterTimeout":true,"attemptId":…}`; provably not
    executed after a late failure answer ⇒ retried exactly once; otherwise ⇒ `isError: true`
    `{"outcome":"unknown","attemptId":…,"flaggedForHuman":true}` — the action keeps blocking identical ones until a
    human resolves it (stderr line; `audit:verify` lists them). Right after start, money calls are denied
    `firewall.reconciling` for a moment while unsettled actions from an earlier run are verified.
  - If the audit log can't be written, money calls are denied (`audit_unavailable`); if an outcome can't be recorded
    after a call was sent, all later money calls are denied until the proxy restarts. If the audit chain failed
    verification at startup, all money calls are denied from the start (see above).
- **Every tool result** the agent sees (reads and money tools alike) has card data, tokens and customer / beneficiary
  PII (email, contact, VPA, names, bank accounts, addresses) replaced with `[REDACTED]`; non-JSON text is
  pattern-scrubbed and non-text content is removed. Razorpay reference ids are kept only for a fixed allowlist of
  keys (`customer_id`, `token_id`, `card_id`, `payment_id`, `order_id`, …) whose value carries the matching Razorpay
  prefix (`cust_`, `token_`, `card_`, `pay_`, `order_`, …); other `*_id` keys and anything inside `notes` stay
  redacted. The audit log and the proxy's own policy lookups see the unredacted upstream data.
- **Unknown tool names** (including case variants like `Create_Refund`) are refused without contacting Razorpay:
  `isError: true` with `{"decision":"deny","ruleId":"firewall.unknown_tool","message":…}`.
- **Not audited:** rejections that happen before a call reaches the firewall pipeline — unknown tool name,
  arguments that aren't a JSON object (`firewall.invalid_args`), or no usable upstream tool list
  (`upstream_unavailable`). Nothing is sent upstream in these cases, and neither the tool nor the arguments are
  trustworthy enough to record. Every money call that does reach the pipeline (including every deny) is audited.
- **Upstream problems** never crash the proxy. Calls return `isError: true` with
  `{"error":"upstream_unavailable"|"upstream_timeout"|"upstream_error"|"cancelled","message":…,"forwarded":…}`.
  `forwarded: true` means the request may have reached Razorpay — check the resource's status before retrying.
  `cancelled` means the agent cancelled the request (after sending: `forwarded: true`, outcome unknown).
- **Calls are only forwarded against the live list of the current upstream connection.** After a reconnect, or a
  `tools/list_changed` from upstream, a call waits for a successful re-list; if that fails it gets
  `upstream_unavailable` (for a name in the snapshot) or `firewall.unknown_tool`, and is never sent.
- If Razorpay answers a call after the proxy gave up on it (timeout / cancel), the log shows only
  `late upstream response: id …, tool …, result|error, generation …` — never the response body.
- **Upstream down at startup**: the proxy still starts. `tools/list` serves the committed snapshot
  `docs/razorpay-tools.json`, calls fail with `upstream_unavailable` until the container is reachable (the proxy
  retries on each call with bounded backoff), and the client gets `notifications/tools/list_changed` if the live
  list differs from the snapshot.
