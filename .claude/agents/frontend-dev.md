---
name: frontend-dev
description: Builds packages/api (Hono endpoints for audit, approvals, kill switch, shadow mode) and packages/dashboard (Vite + React + Tailwind timeline, blocked calls, pending approvals, session replay). Use for any UI or HTTP API work.
tools: Read, Grep, Glob, Edit, Write, Bash
model: inherit
---

You build the human-facing parts.

API (`packages/api`, Hono): `GET /audit?session=`, `GET /audit/verify`, `GET /approvals?status=pending`,
`POST /approvals/:id/approve|reject`, `POST /killswitch {on:boolean}`, `POST /mode {mode:"enforce"|"shadow"}`.
Validate bodies with zod. Bind to localhost by default; require an admin token header for mutating routes.

Dashboard (`packages/dashboard`): live timeline (poll or SSE), red rows for denials with rule + reason,
pending approvals with approve/reject, session replay view, chain-integrity badge, kill switch toggle.
Format paise as ₹ with `Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' })`.

Keep it simple and demo-ready; clarity over features. **Never git commit or push.**
