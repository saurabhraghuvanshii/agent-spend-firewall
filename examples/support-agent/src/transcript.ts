/**
 * Concise, safe transcript of an Agent SDK run: agent text, tool calls and tool results (T015).
 *
 * SDK messages are parsed loosely with zod (unknown shapes are skipped, never trusted). Tool results are printed
 * only after the proxy's result redaction (`redactSensitiveResult`: card / VPA / PII scrubbed — needed for
 * `--target=direct`, where nothing else redacts them), key redaction (`redactSecrets`), terminal escaping and a
 * length cap.
 */
import { escapeForTerminal, redactSecrets, redactSensitiveResult, type TestKeys } from "@asf/proxy";
import { z } from "zod";

export const MAX_SHOWN_CHARS = 600;

const textBlock = z.looseObject({ type: z.literal("text"), text: z.string() });
const toolUseBlock = z.looseObject({
  type: z.literal("tool_use"),
  id: z.string(),
  name: z.string(),
  input: z.unknown(),
});
const toolResultBlock = z.looseObject({
  type: z.literal("tool_result"),
  tool_use_id: z.string(),
  is_error: z.boolean().optional(),
  content: z.union([z.string(), z.array(z.unknown())]).optional(),
});
const assistantMsg = z.looseObject({
  type: z.literal("assistant"),
  message: z.looseObject({ content: z.array(z.unknown()) }),
});
const userMsg = z.looseObject({
  type: z.literal("user"),
  message: z.looseObject({ content: z.union([z.string(), z.array(z.unknown())]) }),
});
const resultMsg = z.looseObject({
  type: z.literal("result"),
  subtype: z.string(),
  num_turns: z.number().optional(),
});
const systemInit = z.looseObject({
  type: z.literal("system"),
  subtype: z.literal("init"),
  mcp_servers: z.array(z.looseObject({ name: z.string(), status: z.string() })).optional(),
});

export function cap(s: string, max = MAX_SHOWN_CHARS): string {
  return s.length > max ? `${s.slice(0, max)}… (${String(s.length - max)} more chars)` : s;
}

export interface TranscriptPrinter {
  /** Feed one SDK message; returns the lines to print (already escaped). */
  lines(message: unknown): string[];
}

const MCP_PREFIX = /^mcp__[A-Za-z0-9_-]+__/;

export function createTranscript(keys: TestKeys): TranscriptPrinter {
  const toolNames = new Map<string, string>();
  const safe = (s: string): string => escapeForTerminal(cap(redactSecrets(s, keys)));

  const resultText = (tool: string, content: string | unknown[] | undefined, isError: boolean) => {
    const texts: string[] = [];
    if (typeof content === "string") texts.push(content);
    else if (Array.isArray(content)) {
      for (const c of content) {
        const t = textBlock.safeParse(c);
        texts.push(t.success ? t.data.text : "[non-text content]");
      }
    }
    const redacted = redactSensitiveResult(tool.replace(MCP_PREFIX, ""), {
      isError,
      content: texts.map((text) => ({ type: "text" as const, text })),
    });
    return redacted.content
      .map((c) => (c.type === "text" ? c.text : "[non-text content]"))
      .join(" | ");
  };

  return {
    lines(message: unknown): string[] {
      const out: string[] = [];
      const init = systemInit.safeParse(message);
      if (init.success) {
        for (const s of init.data.mcp_servers ?? []) {
          out.push(`  [mcp] ${safe(s.name)}: ${safe(s.status)}`);
        }
        return out;
      }
      const a = assistantMsg.safeParse(message);
      if (a.success) {
        for (const block of a.data.message.content) {
          const t = textBlock.safeParse(block);
          if (t.success && t.data.text.trim() !== "") {
            out.push(`  agent: ${safe(t.data.text.trim())}`);
            continue;
          }
          const u = toolUseBlock.safeParse(block);
          if (u.success) {
            toolNames.set(u.data.id, u.data.name);
            out.push(`  → ${safe(u.data.name)} ${safe(JSON.stringify(u.data.input) ?? "")}`);
          }
        }
        return out;
      }
      const u = userMsg.safeParse(message);
      if (u.success && Array.isArray(u.data.message.content)) {
        for (const block of u.data.message.content) {
          const r = toolResultBlock.safeParse(block);
          if (!r.success) continue;
          const tool = toolNames.get(r.data.tool_use_id) ?? "unknown";
          const isError = r.data.is_error === true;
          out.push(
            `  ← ${safe(tool)}${isError ? " [isError]" : ""}: ${safe(resultText(tool, r.data.content, isError))}`,
          );
        }
        return out;
      }
      const res = resultMsg.safeParse(message);
      if (res.success) {
        const turns =
          res.data.num_turns === undefined ? "" : `, ${String(res.data.num_turns)} turns`;
        out.push(`  [done: ${safe(res.data.subtype)}${turns}]`);
      }
      return out;
    },
  };
}
