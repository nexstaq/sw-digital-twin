# Usability pass (P5)

**What this is, and is not.** This is a task walkthrough run by the builder against the real app in a real browser (Playwright, 1440x900), with timings measured. It is **not user research**. The acceptance line "an exec can state system health in < 5 seconds" needs real people; the protocol for that is at the bottom. Treat everything below as the pre-flight check before putting it in front of anyone.

## Personas and tasks

| Persona | Default lens | Task | What they do | Observed |
|---|---|---|---|---|
| **Exec / PM** | Overview | "Is it safe to ship? What's wrong, in plain words?" | Reads the banner, clicks it | Verdict (`NO-GO`) and one-line reason ("Payments failing") were on screen **~0.5s after navigation** (dev server, `/demo`). No interaction needed. Tiles use friendly names and a plain-English line (AI-written when a model is set, rule-based otherwise). |
| **SRE / on-call** | Ops | "What's broken, why, and what else goes down with it?" | Clicks the banner, picks a blocker; or `⌘K` "show failing things"; hovers/asks "what breaks if payments is down" | Banner popover lists the *deepest* failing parts with the failing step as the reason; **Show on map** zooms there and opens the drawer. Impact answer lit the 2 affected parts in red and dimmed the rest. Drawer links to the exact GitHub run/job. |
| **New engineer** | Tour, then Flow | "How does this system fit together?" | Tour lens, then Flow; `⌘K` to jump to a part by name; "Ask AI about this" in the drawer | Tour plays end to end (P3). Flow keeps jobs/environments/services bright. Jump-by-name works. The AI question box needs a model key; without one it says exactly which env var to set. |

## Findings from the pass (all fixed)

1. **The GO/NO-GO popover rendered under the canvas** so its buttons could not be clicked (header had no stacking layer). Fixed: header is its own layer.
2. **Typing right after `⌘K` lost the first keystrokes** (focus was set on a 30 ms timer). A fast user would hit this every time. Fixed: the input focuses on mount.
3. **Duplicate React keys on the deploy timeline** when one commit is deployed twice. Fixed.
4. Ops lens dimmed *every* tile when nothing needed attention. Fixed: it only dims healthy tiles when something else does need attention.

## Known rough edges (not fixed)

- Tile subtitles are small (≈11px, two lines, truncated). Fine at a glance, tight for long sentences. Needs a real read-through.
- "What changed in the last deploy?" answers with the last deploy's age/result and the deploy-related parts. It does **not** yet map the commit's changed files onto nodes (that needs the GitHub compare API plus ownership mapping, planned for P6 with replay).
- The **Risk** lens only emphasises the exposure surface (endpoints, external services, data stores). There are no vulnerability or secret-scanning signals yet, so it says nothing about *actual* risk.
- AI features (free-form `⌘K`, "Ask AI about this", persona descriptions) were exercised with mock models and with no key. Output quality on a live model is **unverified**.
- No screen-reader pass yet beyond roles/labels on the new dialogs (palette is `role=dialog aria-modal`, verdict popover is `role=dialog` and closes on Esc).

## Protocol for the real test (3 people per persona, ~15 min each)

Show `/demo` or a live repo with one seeded failure. No coaching.

1. **Exec**: "In your own words, is this healthy? What's the problem?" Start the clock at first paint; stop when they answer. Target: correct answer in < 5 s for ≥ 2 of 3.
2. **SRE**: "Something is red. Find out what failed and what else it affects." Target: names the failing step and the affected parts in < 60 s without being told about `⌘K` or the popover. Note whether they discover the banner click.
3. **New engineer**: "Explain to me what this system does and how it ships." Target: can name the main blocks and the delivery path in < 3 min using any lens.

Record: time to first correct statement, where they hesitated, words they used for things (compare with our labels), anything they clicked that did nothing.
