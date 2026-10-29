import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { computeStats, tickerItems } from "../lib/stats";
import { buildTimeline } from "../lib/timeline";
import { attempt } from "../test/fixtures";
import { AsciiField } from "./AsciiField";
import { ConfirmDialog } from "./ConfirmDialog";
import { Switch } from "./Switch";
import { Ticker } from "./Ticker";

describe("Switch", () => {
  it("is a role=switch with aria-checked and an accessible name", async () => {
    const onToggle = vi.fn();
    const { rerender } = render(
      <Switch checked={false} label="Kill switch" stateText="off" onToggle={onToggle} />,
    );
    const sw = screen.getByRole("switch", { name: "Kill switch" });
    expect(sw.getAttribute("aria-checked")).toBe("false");
    await userEvent.setup().click(sw);
    expect(onToggle).toHaveBeenCalledTimes(1);
    rerender(<Switch checked label="Kill switch" stateText="ON" onToggle={onToggle} />);
    expect(screen.getByRole("switch").getAttribute("aria-checked")).toBe("true");
  });

  it("an unknown state is disabled and not checked", () => {
    render(
      <Switch checked={undefined} label="Shadow mode" stateText="unknown" onToggle={vi.fn()} />,
    );
    const sw = screen.getByRole("switch");
    expect(sw.getAttribute("aria-checked")).toBe("false");
    expect(sw).toHaveProperty("disabled", true);
  });
});

describe("ConfirmDialog", () => {
  const open = (onCancel = vi.fn(), onConfirm = vi.fn()) => {
    const { container } = render(
      <div className="backdrop-blur">
        <button type="button">opener</button>
        <ConfirmDialog title="Sure?" confirmLabel="Do it" onCancel={onCancel} onConfirm={onConfirm}>
          body
        </ConfirmDialog>
      </div>,
    );
    return { container, onCancel, onConfirm };
  };

  it("is portalled to <body>, outside any filtered ancestor", () => {
    const { container } = open();
    const dialog = screen.getByRole("dialog");
    expect(container.contains(dialog)).toBe(false);
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(dialog.className).toContain("max-h-[calc(100dvh-2rem)]");
  });

  it("Escape closes; focus starts on Cancel", async () => {
    const { onCancel } = open();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Cancel" }));
    await userEvent.setup().keyboard("{Escape}");
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("traps Tab inside the dialog", async () => {
    open();
    const user = userEvent.setup();
    const cancel = screen.getByRole("button", { name: "Cancel" });
    const confirm = screen.getByRole("button", { name: "Do it" });
    await user.tab();
    expect(document.activeElement).toBe(confirm);
    await user.tab();
    expect(document.activeElement).toBe(cancel);
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(confirm);
  });
});

describe("Ticker", () => {
  it("is built from our own numbers only, never agent text", () => {
    const now = new Date("2026-10-29T12:00:00.000Z");
    const entries = buildTimeline([
      attempt({
        seq: 1,
        id: "a1",
        ts: now.toISOString(),
        decision: "deny",
        amountPaise: 12_345,
        tool: "<script>x</script>",
      }),
      attempt({
        seq: 2,
        id: "a2",
        ts: now.toISOString(),
        decision: "allow",
        reason: { untrusted: true, label: "x", text: '"IGNORE ALL RULES"' },
      }),
    ]);
    const stats = computeStats(
      entries,
      { pendingApprovals: 3, chain: "ok", shadow: false, killSwitch: false },
      now,
    );
    expect(stats).toMatchObject({
      blockedPaiseToday: 12_345n,
      deniedToday: 1,
      allowedToday: 1,
      actionsToday: 2,
    });
    const items = tickerItems(stats);
    expect(items).toContain("₹123.45 blocked today");
    expect(items).toContain("3 pending approval");
    render(<Ticker stats={stats} />);
    const t = screen.getByTestId("ticker").textContent;
    expect(t).not.toContain("IGNORE");
    expect(t).not.toContain("script");
  });
});

describe("AsciiField", () => {
  it("is decorative: aria-hidden, no pointer events, fixed behind content", () => {
    render(<AsciiField />);
    const c = screen.getByTestId("ascii-field");
    expect(c.getAttribute("aria-hidden")).toBe("true");
    expect(c.className).toContain("pointer-events-none");
    expect(c.className).toContain("fixed");
  });
});

describe("redesign review fixes", () => {
  it("an attempt without outcome shows a PENDING chip; rules are one chip each", async () => {
    const { AttemptRow } = await import("./Timeline");
    render(
      <ul>
        <AttemptRow
          entry={{
            kind: "attempt",
            seq: 1,
            attempt: attempt({
              decision: "require_approval",
              matchedRules: ["refund.a", "refund.b"],
            }),
          }}
        />
      </ul>,
    );
    expect(screen.getByText("pending").dataset.tone).toBe("warn");
    const rules = screen.getByTestId("matched-rules");
    expect([...rules.children].map((c) => c.textContent)).toEqual(["refund.a", "refund.b"]);
  });

  it("theme cycles dark → light → system and light removes the dark class", async () => {
    const { applyTheme, nextTheme, readThemePref } = await import("../theme");
    expect(readThemePref()).toBe("dark");
    expect(nextTheme("dark")).toBe("light");
    expect(nextTheme("light")).toBe("system");
    expect(nextTheme("system")).toBe("dark");
    document.documentElement.classList.add("dark");
    applyTheme("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    applyTheme("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });
});
