import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { attempt } from "../test/fixtures";
import { AttemptRow } from "./Timeline";

const entry = {
  kind: "attempt" as const,
  seq: 1,
  attempt: attempt({ decision: "deny", matchedRules: ["refund.approval", "refund.max‮"] }),
};

describe("AttemptRow layout", () => {
  it("full variant uses fixed md: columns", () => {
    render(
      <ul>
        <AttemptRow entry={entry} />
      </ul>,
    );
    const row = screen.getByTestId("timeline-row");
    expect(row.dataset.variant).toBe("full");
    expect(row.innerHTML).toContain(
      "md:grid-cols-[4.5rem_minmax(0,1fr)_7rem_8rem_minmax(0,1.4fr)_6rem]",
    );
  });

  it("compact variant (replay sidebar) never applies the viewport 6-column grid", () => {
    render(
      <ul>
        <AttemptRow entry={entry} compact />
      </ul>,
    );
    const row = screen.getByTestId("timeline-row");
    expect(row.dataset.variant).toBe("compact");
    expect(row.innerHTML).not.toMatch(/md:/);
    expect(screen.getByTestId("matched-rules").className).not.toContain("truncate");
  });

  it("matched rules carry a tooltip, formatted as identifiers", () => {
    render(
      <ul>
        <AttemptRow entry={entry} />
      </ul>,
    );
    const title = screen.getByTestId("matched-rules").getAttribute("title") ?? "";
    expect(title).toContain("refund.approval, ");
    expect(title).not.toContain("‮");
    expect(title).toContain("\\u{202E}");
  });
});
