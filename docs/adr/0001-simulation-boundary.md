# ADR 0001: Simulation runs on a range; real targets only with proof of authority

Status: **Proposed** (becomes Accepted when you merge it). Date: 2026-11-25. Spec: `docs/SIMULATION.md`.

## Context
We want agents that test the software the way a white-box reviewer, a gray-box user and a red team would, and simulators that show how each block works.
An agent that can send attack traffic is also a tool for attacking other people. S1 to S4 already drew a line: we do not send attack traffic from our servers; active
tests run in the customer's CI; passive checks go only to a domain whose ownership was proved in that run.

## Decision
1. **The default target is a range**: an emulated copy of the software's own blocks, generated from the map, with no network egress. Nothing real is attacked.
2. **Real targets are limited to two routes**: the customer's own CI runner (authenticated with GitHub OIDC), or a domain whose ownership was proved in the same run. Both need an approved rules-of-engagement (ROE) record naming who approved it. Our servers send no simulation traffic to a third party.
3. **Real targets get `observe` and `probe` only.** The `exploit-range` class works on the range only. The `intrusive` class is **not available**: no agent has it in its ceiling and no ROE may grant it. Adding it later needs a new ADR and a per-action human approval gate.
4. **Scope is enforced by code, not by prompt.** One pure function, `allow()`, default-deny, sits in front of every tool call. Agents cannot read or write the ROE, run state or approvals.
5. **Every run is bounded**: a window of at most 24 hours, mandatory hard-capped budgets (steps, tokens, time, cost), and a kill switch checked first.
6. **Every step is recorded** in a hash-chained, redacted audit log whose head is stored outside the log.

## Consequences
- Safe by construction, and a defensible answer to "can this be used to attack someone": only through proof of ownership and only by probing.
- Red-team realism is limited to what the range models. A finding on the range says "the emulator of this block is exploitable the way the scanner said"; it is not proof about production.
- The range needs ingestion to run in an isolated sandbox first (backlog B1).
- More up-front work (ROE, guard, audit) before any agent is useful.

## Alternatives rejected
- **Scope in the system prompt.** One injected sentence defeats it.
- **Allow any target the user types, with a terms-of-service checkbox.** Makes us an attack-as-a-service tool.
- **Run active scans from our servers against verified domains.** Ownership proof stops strangers but not a compromised account or a changed-hands domain; probing is a safer ceiling than attacking.
- **Skip the range and test only in CI.** No explanation use case, no safe place for the red team, and every run depends on customer infrastructure.

## Revisit when
A customer needs intrusive testing of a real system (separate decision, separate approval design); or the range proves too unlike production to be useful.
