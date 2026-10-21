---
description: Verify the current task, run reviews, update the plan, and print a suggested commit message (never commits)
---

1. Find the task with status `in-progress` in `.plan/tasks/INDEX.md`.
2. Check every acceptance criterion in its file; mark each `[x]` or explain what's missing.
3. Run `pnpm -r typecheck`, `pnpm -r test`, and `pnpm lint` if available. Report results honestly.
4. If the change touches money tools, policy, approvals, retries, or the audit log, run the `security-reviewer` subagent
   and fix critical/high findings (or list them as open).
5. Update the task file: status `review` (or `blocked` with reason), add a short "Notes" section with what changed.
   Update `INDEX.md` to match. Add any design decision to `.plan/DECISIONS.md`.
6. Show `git status` and `git diff --stat`.
7. Print a suggested Conventional Commit message (e.g. `feat(proxy): ...`). **Do NOT run git commit or git push** —
   the human will review and commit.
