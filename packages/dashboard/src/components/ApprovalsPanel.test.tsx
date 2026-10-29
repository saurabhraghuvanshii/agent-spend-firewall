import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { ApiResult } from "../api/client";
import type { DecisionResponse } from "../api/schemas";
import { fakeClient, pending } from "../test/fixtures";
import { ApprovalsPanel } from "./ApprovalsPanel";

const httpErr = (status: number, code: string, message = "m"): ApiResult<DecisionResponse> => ({
  ok: false,
  error: { kind: "http", status, code, message },
});

async function approveWith(
  result: ApiResult<DecisionResponse>,
  action: "Approve" | "Reject" = "Approve",
) {
  const decide = vi.fn(() => Promise.resolve(result));
  const onReload = vi.fn();
  render(
    <ApprovalsPanel
      client={fakeClient({ decide })}
      approvals={{ state: "ok", approvals: [pending()] }}
      onReload={onReload}
    />,
  );
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: action }));
  if (action === "Approve") {
    expect(screen.getByRole("dialog").textContent).toContain("₹6,000.00");
    await user.click(screen.getAllByRole("button", { name: "Approve" }).at(-1) as HTMLElement);
  }
  return { decide, onReload };
}

describe("ApprovalsPanel", () => {
  it("shows the amount in ₹ and the reason as untrusted", () => {
    render(
      <ApprovalsPanel
        client={fakeClient()}
        approvals={{ state: "ok", approvals: [pending()] }}
        onReload={vi.fn()}
      />,
    );
    expect(screen.getByTestId("approval").textContent).toContain("₹6,000.00");
    expect(screen.getAllByText("untrusted").length).toBeGreaterThan(0);
  });

  it("403 approvals_disabled ⇒ 'Approve via Telegram', buttons disabled, approval still listed", async () => {
    const { decide, onReload } = await approveWith(httpErr(403, "api.approvals_disabled"));
    expect(decide).toHaveBeenCalledWith(pending().approvalId, "approve");
    expect(screen.getAllByText(/Approve via Telegram/).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Approve" })).toHaveProperty("disabled", true);
    expect(screen.getByTestId("approval")).toBeTruthy();
    expect(onReload).not.toHaveBeenCalled();
  });

  it("409 kill-switch ⇒ explains the approval stays pending", async () => {
    await approveWith(httpErr(409, "kill-switch"));
    expect(screen.getByRole("alert").textContent).toMatch(/kill switch is ON.*left pending/);
    expect(screen.getByTestId("approval")).toBeTruthy();
  });

  it("409 already decided and 5xx show the API's error, never success", async () => {
    await approveWith(
      httpErr(409, "approval.already_decided", "This approval was already decided."),
    );
    expect(screen.getByRole("alert").textContent).toContain("already decided");
    expect(screen.queryByRole("status")).toBeNull();
  });

  it.each([
    [httpErr(500, "api.internal_error", "internal error"), /internal error \(HTTP 500/],
    [httpErr(503, "approval.unavailable", "nothing was executed"), /HTTP 503/],
    [
      { ok: false, error: { kind: "network", message: "Failed to fetch" } } as const,
      /Cannot reach/,
    ],
    [
      { ok: false, error: { kind: "malformed", message: "status: bad" } } as const,
      /unexpected response/,
    ],
  ])("reject failure %# is shown as an error", async (result, re) => {
    const { onReload } = await approveWith(result, "Reject");
    expect(screen.getByRole("alert").textContent).toMatch(re);
    expect(onReload).not.toHaveBeenCalled();
  });

  it("success shows the API message and re-fetches instead of removing optimistically", async () => {
    let resolve: (r: ApiResult<DecisionResponse>) => void = () => undefined;
    const decide = vi.fn(
      () =>
        new Promise<ApiResult<DecisionResponse>>((r) => {
          resolve = r;
        }),
    );
    const onReload = vi.fn();
    render(
      <ApprovalsPanel
        client={fakeClient({ decide })}
        approvals={{ state: "ok", approvals: [pending()] }}
        onReload={onReload}
      />,
    );
    await userEvent.setup().click(screen.getByRole("button", { name: "Reject" }));
    expect(screen.getByRole("button", { name: "Rejecting…" })).toBeTruthy();
    expect(onReload).not.toHaveBeenCalled();
    act(() => {
      resolve({
        ok: true,
        value: {
          approvalId: pending().approvalId,
          status: "rejected",
          approver: "dashboard:admin",
          message: "Rejected. Nothing was executed.",
        },
      });
    });
    await waitFor(() => {
      expect(screen.getByRole("status").textContent).toContain("Rejected. Nothing was executed.");
    });
    expect(onReload).toHaveBeenCalledTimes(1);
  });

  it("shows a load error", () => {
    render(
      <ApprovalsPanel
        client={fakeClient()}
        approvals={{ state: "error", message: "HTTP 500" }}
        onReload={vi.fn()}
      />,
    );
    expect(screen.getByRole("alert").textContent).toContain("Could not load approvals");
  });
});
