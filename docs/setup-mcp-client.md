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

| Variable                  | Default       | Notes                                                                                                   |
| ------------------------- | ------------- | ------------------------------------------------------------------------------------------------------- |
| `ASF_UPSTREAM_TIMEOUT_MS` | `30000`       | Per-call upstream timeout, 1000–600000. A timed-out call returns `upstream_timeout` and is not retried. |
| `ASF_RAZORPAY_MCP_IMAGE`  | pinned digest | Image override. Read from the **shell** environment only (ignored in `.env`).                           |
| `DOCKER_HOST`, …          | —             | Docker client settings, shell environment only.                                                         |

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

- **Tools**: the same tools the Razorpay MCP server offers (41 for the pinned image), same names and schemas.
  (Later milestones add a required `reason` field to money tools.)
- **Unknown tool names** (including case variants like `Create_Refund`) are refused without contacting Razorpay:
  `isError: true` with `{"decision":"deny","ruleId":"firewall.unknown_tool","message":…}`.
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
