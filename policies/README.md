# policies

Policy-as-code files for the firewall (TypeScript). Each policy decides `allow | deny | require_approval | transform`
for a money-moving tool call. `default.ts` is the example refund policy (hard cap, approval threshold, refund ≤ paid,
duplicate, velocity); it defaults to `deny`. Policies must stay pure: all data comes through `ctx` ports.
