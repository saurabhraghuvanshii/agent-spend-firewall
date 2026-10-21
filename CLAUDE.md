# CLAUDE.md

@AGENTS.md
@SUBAGENTS.md
@.plan/README.md

## Claude Code specifics

- **Do not commit or push.** `git commit`, `git push`, `git tag`, and `gh pr create` are blocked by
  `.claude/settings.json` and `.claude/hooks/block-git-write.mjs`. Don't try to work around the block.
  When finished, print a suggested commit message for the human.
- Start a work session with `/next-task`; close it with `/finish-task`. See progress with `/plan-status`.
- Delegate to subagents in `.claude/agents/` as described in `SUBAGENTS.md`. Use the `security-reviewer`
  for any change touching money tools, policy evaluation, approvals, or the audit log.
- Before editing, read the task file in `.plan/tasks/` and the relevant `packages/*` code.
- Record any significant design choice in `.plan/DECISIONS.md`.
