---
description: Pick the next ready task from .plan and start working on it
argument-hint: "[task-id, optional e.g. T004]"
---

1. Read `.plan/README.md` and `.plan/tasks/INDEX.md`.
2. If `$ARGUMENTS` names a task, use it. Otherwise choose the first task with status `todo` whose dependencies are all `done`.
3. Read that task file fully. Set its status to `in-progress` (in the file and in INDEX.md).
4. Use the `architect` subagent to produce a short plan; show it to me and wait for my OK before large changes.
5. Implement with the appropriate subagent(s) per `SUBAGENTS.md`.
6. Run `pnpm -r typecheck` and `pnpm -r test` (once the monorepo exists).
7. Do NOT commit or push. When done, tell me to run `/finish-task`.
