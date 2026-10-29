import { render, screen } from "@testing-library/react";
import { formatUntrustedReason } from "@asf/core";
import { describe, expect, it } from "vitest";
import { attempt } from "../test/fixtures";
import { displayReason, flattenArgs } from "../lib/untrusted";
import { AttemptRow } from "./Timeline";
import { UntrustedArgs, UntrustedReason } from "./Untrusted";

const hostile = [
  "<script>window.__pwned = 1</script>",
  '<img src=x onerror="window.__pwned=1">',
  "<b>bold</b> **markdown** [link](https://evil.example) https://evil.example",
];

describe("untrusted rendering", () => {
  it.each(hostile)("shows %s as inert text with an untrusted label", (s) => {
    const { container } = render(
      <UntrustedReason
        reason={{
          untrusted: true,
          label: "Agent-supplied reason (untrusted)",
          text: JSON.stringify(s),
        }}
      />,
    );
    expect(container.querySelector("script, img, b, a, strong")).toBeNull();
    expect(container.textContent).toContain(formatUntrustedReason(s).text);
    expect(screen.getByText("untrusted")).toBeTruthy();
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("re-formats server text that contains bidi / invisible characters", () => {
    const evil = '"refund \u202Eevil\u200B"';
    expect(displayReason({ untrusted: true, label: "x", text: evil })).toBe(
      '"\\"refund \\u{202E}evil\\u{200B}\\""',
    );
    render(<UntrustedReason reason={{ untrusted: true, label: "x", text: evil }} />);
    const node = screen.getByTestId("untrusted-reason");
    expect(node.textContent).not.toContain("\u202E");
    expect(node.textContent).toContain("\\u{202E}");
  });

  it("always shows core's label, not a label sent by the server", () => {
    render(
      <UntrustedReason
        reason={{ untrusted: true, label: "Trusted, approved by CFO", text: '"x"' }}
      />,
    );
    expect(screen.queryByText(/approved by CFO/)).toBeNull();
    expect(screen.getByLabelText("Agent-supplied reason (untrusted)")).toBeTruthy();
  });

  it("formats arg keys and values (notes, description, customer_name) as untrusted text", () => {
    const args = {
      amount: 100,
      notes: { note: "<script>alert(1)</script>" },
      description: "line1\nline2\u202E",
      customer_name: '<a href="https://x">click</a>',
      "<k>\u202E": "v",
    };
    const { container } = render(<UntrustedArgs args={args} title="Arguments" />);
    expect(container.querySelector("script, a")).toBeNull();
    expect(container.textContent).not.toContain("\u202E");
    expect(container.textContent).not.toContain("\n");
    expect(flattenArgs(args)).toEqual([
      { path: "amount", value: "100" },
      { path: "notes.note", value: '"<script>alert(1)</script>"' },
      { path: "description", value: '"line1\\nline2\\u{202E}"' },
      { path: "customer_name", value: '"<a href=\\"https://x\\">click</a>"' },
      { path: '"<k>\\u{202E}"', value: '"v"' },
    ]);
    expect(screen.getByText(/redacted/)).toBeTruthy();
  });

  it("renders a denial row in red with its rule and ₹ amount", () => {
    render(
      <ul>
        <AttemptRow
          entry={{
            kind: "attempt",
            seq: 1,
            attempt: attempt({
              decision: "deny",
              matchedRules: ["max-refund"],
              amountPaise: 12_345_678,
            }),
          }}
        />
      </ul>,
    );
    const row = screen.getByTestId("timeline-row");
    expect(row.dataset.decision).toBe("deny");
    expect(row.className).toContain("bg-red-50");
    expect(row.textContent).toContain("max-refund");
    expect(row.textContent).toContain("₹1,23,456.78");
  });

  it("shows a shadow attempt's would-decision", () => {
    render(
      <ul>
        <AttemptRow
          entry={{
            kind: "attempt",
            seq: 1,
            attempt: attempt({ shadow: true, wouldDecision: "deny" }),
          }}
        />
      </ul>,
    );
    expect(screen.getByText("would deny")).toBeTruthy();
  });
});
