import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { FetchLike } from "./api/client";
import { App } from "./App";
import { attempt, HASH, jsonResponse, TOKEN } from "./test/fixtures";
import { TOKEN_STORAGE_KEY } from "./token";

const API = "http://127.0.0.1:8787";

const outcome = (seq: number, attemptId: string, o: string) => ({
  kind: "outcome",
  seq,
  id: `out-${String(seq)}`,
  ts: "2026-10-29T10:00:01.000Z",
  hash: HASH,
  attemptId,
  outcome: o,
  latencyMs: 12,
});

const session = [
  attempt({ seq: 1, id: "att-1", amountPaise: 50_000 }),
  outcome(2, "att-1", "success"),
  attempt({
    seq: 3,
    id: "att-2",
    decision: "deny",
    matchedRules: ["max-refund"],
    amountPaise: 9_000_000,
  }),
  outcome(4, "att-2", "denied"),
];

/** Routes fetches like the API; `/events` streams one `ready` + one `audit` event, then stays open. */
function router(over: Record<string, () => Response> = {}): FetchLike {
  return vi.fn<FetchLike>((url, init) => {
    const path = url.slice(API.length);
    const hit = over[path];
    if (hit !== undefined) return Promise.resolve(hit());
    switch (path.split("?")[0]) {
      case "/audit":
        return Promise.resolve(
          jsonResponse(200, { records: session.slice(0, 2), nextCursor: null }),
        );
      case "/audit/verify":
        return Promise.resolve(
          jsonResponse(200, { ok: true, count: 4, headHash: HASH, danglingAttempts: 0 }),
        );
      case "/approvals":
        return Promise.resolve(jsonResponse(200, { approvals: [] }));
      case "/mode":
        return Promise.resolve(jsonResponse(200, { mode: { killSwitch: false, shadow: false } }));
      case "/sessions/sess-1":
        return Promise.resolve(
          jsonResponse(200, { sessionId: "sess-1", records: session, truncated: false }),
        );
      case "/events": {
        const body = new ReadableStream<Uint8Array>({
          start(c) {
            const enc = new TextEncoder();
            c.enqueue(enc.encode('event: ready\ndata: {"type":"ready"}\n\n'));
            c.enqueue(
              enc.encode(
                `event: audit\ndata: ${JSON.stringify({ type: "audit", records: session.slice(2) })}\n\n`,
              ),
            );
            init.signal?.addEventListener("abort", () => {
              c.error(new DOMException("aborted", "AbortError"));
            });
          },
        });
        return Promise.resolve(new Response(body, { status: 200 }));
      }
      default:
        return Promise.resolve(
          jsonResponse(404, { error: { code: "api.not_found", message: "no such route" } }),
        );
    }
  });
}

describe("App", () => {
  it("keeps the token in sessionStorage only and never puts it in a URL", async () => {
    const fetchImpl = router();
    render(<App apiUrl={API} fetchImpl={fetchImpl} />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Admin token"), TOKEN);
    await user.click(screen.getByRole("button", { name: "Connect" }));
    await screen.findByText("Live timeline");
    expect(window.sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBe(TOKEN);
    expect(window.localStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
    expect(JSON.stringify(window.localStorage)).not.toContain(TOKEN);
    await waitFor(() => {
      expect(vi.mocked(fetchImpl).mock.calls.length).toBeGreaterThan(4);
    });
    for (const [url] of vi.mocked(fetchImpl).mock.calls) expect(url).not.toContain(TOKEN);
  });

  it("rejects a short token without storing it", async () => {
    render(<App apiUrl={API} fetchImpl={router()} />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Admin token"), "short");
    await user.click(screen.getByRole("button", { name: "Connect" }));
    expect(screen.getByRole("alert").textContent).toMatch(/32 to 512/);
    expect(window.sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it("shows the initial page plus live events, denials red, and the verify badge", async () => {
    window.sessionStorage.setItem(TOKEN_STORAGE_KEY, TOKEN);
    render(<App apiUrl={API} fetchImpl={router()} />);
    await waitFor(() => {
      expect(screen.getAllByTestId("timeline-row")).toHaveLength(2);
    });
    const [newest, oldest] = screen.getAllByTestId("timeline-row");
    expect(newest?.dataset.decision).toBe("deny");
    expect(newest?.textContent).toContain("₹90,000.00");
    expect(oldest?.textContent).toContain("₹500.00");
    expect(oldest?.textContent).toContain("success");
    await waitFor(() => {
      expect(screen.getByTestId("chain-badge").dataset.state).toBe("ok");
    });
    expect(screen.getByTestId("stream-status").textContent).toBe("live");
  });

  it("a malformed audit response is an error state, not a crash", async () => {
    window.sessionStorage.setItem(TOKEN_STORAGE_KEY, TOKEN);
    const bad = { records: [{ ...attempt(), amountPaise: 1.25 }], nextCursor: null };
    render(
      <App
        apiUrl={API}
        fetchImpl={router({
          "/audit?limit=200": () => jsonResponse(200, bad),
          "/audit/verify": () => jsonResponse(200, { ok: "maybe" }),
        })}
      />,
    );
    await waitFor(() => {
      expect(
        screen
          .getAllByRole("alert")
          .some((a) => a.textContent.includes("Could not load the audit log")),
      ).toBe(true);
    });
    await waitFor(() => {
      expect(screen.getByTestId("chain-badge").dataset.state).toBe("error");
    });
    expect(screen.queryByText("₹0.01")).toBeNull();
  });

  it("session replay steps through a session's calls", async () => {
    window.sessionStorage.setItem(TOKEN_STORAGE_KEY, TOKEN);
    render(<App apiUrl={API} fetchImpl={router()} />);
    const user = userEvent.setup();
    await screen.findByRole("option", { name: "sess-1" });
    await user.selectOptions(screen.getByLabelText("Session"), "sess-1");
    expect((await screen.findByTestId("replay-position")).textContent).toBe("Step 1 of 2");
    expect(screen.getByRole("button", { name: "← Prev" })).toHaveProperty("disabled", true);
    await user.click(screen.getByRole("button", { name: "Next →" }));
    expect(screen.getByTestId("replay-position").textContent).toBe("Step 2 of 2");
    expect(screen.getByRole("button", { name: "Next →" })).toHaveProperty("disabled", true);
    expect(screen.getByText(/Executed in this session: ₹500.00/)).toBeTruthy();
  });

  it("401 on the stream asks for a new token", async () => {
    window.sessionStorage.setItem(TOKEN_STORAGE_KEY, TOKEN);
    render(
      <App
        apiUrl={API}
        fetchImpl={router({
          "/events": () => jsonResponse(401, { error: { code: "api.unauthorized", message: "x" } }),
        })}
      />,
    );
    await screen.findByRole("button", { name: "Enter a new token" });
    await userEvent.setup().click(screen.getByRole("button", { name: "Enter a new token" }));
    expect(window.sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
    expect(screen.getByLabelText("Admin token")).toBeTruthy();
  });
});
