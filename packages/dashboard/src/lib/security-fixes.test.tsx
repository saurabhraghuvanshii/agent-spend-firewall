import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ApiResult } from "../api/client";
import type { VerifyView } from "../api/schemas";
import { ChainBadge } from "../components/ChainBadge";
import { useDashboard } from "../hooks/useDashboard";
import { fakeClient, HASH } from "../test/fixtures";
import { FRAME_HEADERS } from "../../vite.config";
import { createSseParser, MAX_EVENT_CHARS } from "./sse";
import { displayReason } from "./untrusted";

describe("security review fixes (T014)", () => {
  it("dangling attempts ⇒ amber 'pending outcome', not green", () => {
    render(
      <ChainBadge
        verify={{
          state: "done",
          at: "t",
          result: { ok: true, count: 5, headHash: HASH, danglingAttempts: 2 },
        }}
        onRefresh={vi.fn()}
      />,
    );
    const b = screen.getByTestId("chain-badge");
    expect(b.dataset.state).toBe("pending");
    expect(b.textContent).toBe("Chain OK · 2 pending outcome");
    expect(b.className).not.toContain("emerald");
  });

  it("a preformatted reason with an unescaped inner quote or trailing backslash is re-formatted", () => {
    const r = (text: string) => displayReason({ untrusted: true, label: "x", text });
    expect(r('"fine \\"quoted\\""')).toBe('"fine \\"quoted\\""');
    expect(r('"a" approved by CFO "b"')).not.toBe('"a" approved by CFO "b"');
    expect(r('"a" approved by CFO "b"').startsWith('"\\"a\\"')).toBe(true);
    expect(r('"ends with \\"')).not.toBe('"ends with \\"');
  });

  it("an SSE event whose data lines sum past the cap is rejected", () => {
    const onEvent = vi.fn();
    const p = createSseParser(onEvent);
    const line = `data: ${"x".repeat(500_000)}\n`;
    expect(() => {
      for (let i = 0; i < Math.ceil(MAX_EVENT_CHARS / 500_000) + 1; i++) p.feed(line);
    }).toThrow(/too large/);
    expect(onEvent).not.toHaveBeenCalled();
  });

  it("dev / preview send anti-framing headers", () => {
    expect(FRAME_HEADERS).toEqual({
      "Content-Security-Policy": "frame-ancestors 'none'",
      "X-Frame-Options": "DENY",
    });
  });

  it("a stale verify response does not overwrite a newer one", async () => {
    const resolvers: Array<(r: ApiResult<VerifyView>) => void> = [];
    const verify = vi.fn(
      () =>
        new Promise<ApiResult<VerifyView>>((res) => {
          resolvers.push(res);
        }),
    );
    let refresh: () => void = () => undefined;
    const client = fakeClient({ verify }); // stable: a new client per render would re-run every effect
    function Probe() {
      const d = useDashboard(client);
      refresh = d.refreshVerify;
      return <ChainBadge verify={d.verify} onRefresh={d.refreshVerify} />;
    }
    render(<Probe />);
    await waitFor(() => {
      expect(verify).toHaveBeenCalledTimes(1);
    });
    refresh();
    await waitFor(() => {
      expect(verify).toHaveBeenCalledTimes(2);
    });
    // Newer request: broken. Then the older one resolves ok — it must be ignored.
    resolvers[1]?.({
      ok: true,
      value: { ok: false, brokenAt: { index: 1, seq: 2, id: null, reason: "hash_mismatch" } },
    });
    await waitFor(() => {
      expect(screen.getByTestId("chain-badge").dataset.state).toBe("broken");
    });
    resolvers[0]?.({
      ok: true,
      value: { ok: true, count: 1, headHash: HASH, danglingAttempts: 0 },
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.getByTestId("chain-badge").dataset.state).toBe("broken");
  });
});
