import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { fakeClient, HASH } from "../test/fixtures";
import { ChainBadge } from "./ChainBadge";
import { ModeControls } from "./ModeControls";

describe("ChainBadge", () => {
  it("ok", () => {
    render(
      <ChainBadge
        verify={{
          state: "done",
          at: "10:00",
          result: { ok: true, count: 12, headHash: HASH, danglingAttempts: 0 },
        }}
        onRefresh={vi.fn()}
      />,
    );
    const b = screen.getByTestId("chain-badge");
    expect(b.dataset.state).toBe("ok");
    expect(b.textContent).toBe("Chain OK · 12 records");
  });

  it("broken", () => {
    render(
      <ChainBadge
        verify={{
          state: "done",
          at: "10:00",
          result: {
            ok: false,
            brokenAt: { index: 4, seq: 5, id: "att-5", reason: "hash_mismatch" },
          },
        }}
        onRefresh={vi.fn()}
      />,
    );
    const b = screen.getByTestId("chain-badge");
    expect(b.dataset.state).toBe("broken");
    expect(b.textContent).toContain("BROKEN at seq 5");
    expect(b.dataset.tone).toBe("danger");
  });

  it("an error is never shown as ok", () => {
    render(<ChainBadge verify={{ state: "error", message: "HTTP 500" }} onRefresh={vi.fn()} />);
    const b = screen.getByTestId("chain-badge");
    expect(b.dataset.state).toBe("error");
    expect(b.textContent).toBe("Chain: unverified");
    expect(b.textContent).not.toMatch(/OK/);
    expect(b.dataset.tone).toBe("warn");
  });

  it("click re-verifies", async () => {
    const onRefresh = vi.fn();
    render(<ChainBadge verify={{ state: "loading" }} onRefresh={onRefresh} />);
    await userEvent.setup().click(screen.getByTestId("chain-badge"));
    expect(onRefresh).toHaveBeenCalled();
  });
});

describe("ModeControls", () => {
  it("kill switch needs a confirm, and the state changes only after the API confirms", async () => {
    const setKillSwitch = vi.fn(() =>
      Promise.resolve({ ok: true as const, value: { killSwitch: true, shadow: false } }),
    );
    const onChanged = vi.fn();
    render(
      <ModeControls
        client={fakeClient({ setKillSwitch })}
        mode={{ state: "ok", mode: { killSwitch: false, shadow: false } }}
        onChanged={onChanged}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByTestId("kill-switch"));
    expect(setKillSwitch).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByTestId("kill-switch"));
    await user.click(screen.getByRole("button", { name: "Block all money actions" }));
    expect(setKillSwitch).toHaveBeenCalledWith(true);
    expect(onChanged).toHaveBeenCalledWith({ killSwitch: true, shadow: false });
  });

  it("a failed change is shown and not applied", async () => {
    const setMode = vi.fn(() =>
      Promise.resolve({
        ok: false as const,
        error: {
          kind: "http" as const,
          status: 500,
          code: "mode.write_failed",
          message: "the mode change was NOT recorded",
        },
      }),
    );
    const onChanged = vi.fn();
    render(
      <ModeControls
        client={fakeClient({ setMode })}
        mode={{ state: "ok", mode: { killSwitch: false, shadow: false } }}
        onChanged={onChanged}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByTestId("mode-toggle"));
    await user.click(screen.getByRole("button", { name: "Switch" }));
    expect(setMode).toHaveBeenCalledWith("shadow");
    expect(onChanged).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toContain("NOT applied");
    expect(screen.getByTestId("mode-toggle").getAttribute("aria-checked")).toBe("false");
    expect(screen.getByTestId("mode-toggle").textContent).toContain("off · enforcing");
  });

  it("an unreadable mode is unknown, not 'off'", () => {
    render(
      <ModeControls
        client={fakeClient()}
        mode={{ state: "error", message: "HTTP 503" }}
        onChanged={vi.fn()}
      />,
    );
    expect(screen.getByTestId("kill-switch").textContent).toContain("unknown");
    expect(screen.getByTestId("kill-switch")).toHaveProperty("disabled", true);
  });
});
