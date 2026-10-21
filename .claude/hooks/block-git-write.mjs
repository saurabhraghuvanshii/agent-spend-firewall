#!/usr/bin/env node
// PreToolUse hook: blocks git commit / push (and friends) even if they slip past permission rules,
// e.g. inside `cd x && git commit`, `bash -c "..."`, or `npx ... && git push`.
// Exit code 2 = block the tool call and show stderr to Claude.

let input = "";
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  let command = "";
  try {
    command = JSON.parse(input)?.tool_input?.command ?? "";
  } catch {
    process.exit(0);
  }

  const blocked = [
    /\bgit\b(\s+-[^\s]+(\s+[^\s-][^\s]*)?)*\s+(commit|push|tag)\b/,
    /\bgh\s+pr\s+(create|merge)\b/,
    /\bgh\s+release\b/,
  ];

  if (blocked.some((re) => re.test(command))) {
    console.error(
      "BLOCKED by project policy: AI agents must not commit, push, tag, or open PRs in this repo.\n" +
        "Stop here and print a suggested commit message for the human instead (see AGENTS.md)."
    );
    process.exit(2);
  }
  process.exit(0);
});
