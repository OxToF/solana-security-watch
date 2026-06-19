---
name: solana-security-watch
description: >-
  Continuous security monitoring for Solana / Anchor programs. Not a one-shot
  audit — a daily "watch" loop that pulls fresh ecosystem disclosures (exploits,
  CVEs, RUSTSEC, auditor advisories) and re-confronts your program's code against
  each new technique. Ships an executable /security-watch command that scans a
  target Anchor repo for known vulnerability classes and emits a dated report.
license: MIT
author: OxToF
---

# Solana Security Watch

A skill for Claude Code that turns security from a **point-in-time audit** into a
**continuous watch**. Audits go stale the day after they ship — new exploit
techniques surface weekly across the EVM and Solana worlds, and most of them
transpose to bug *classes* (rounding, donation, account substitution, oracle,
governance capture) that may already exist in code that "passed audit" months ago.

This skill encodes a repeatable daily loop:

> **Collect** fresh disclosures → **Confront** them against the target program's
> code → **Report** a dated entry with severity, `file:line`, and a proposed fix
> (propose only — never auto-patch production code).

## When to use this skill

- You maintain a Solana / Anchor program and want a recurring security review.
- You want to react to a fresh exploit ("does the Raydium LP-mint forgery affect
  us?") by mechanically checking your own surfaces.
- You want a scheduled agent (cron / Claude Code `/loop`) to run the watch daily.
- You're reviewing an Anchor codebase and want a fast first-pass risk scan.

This skill complements one-shot audit skills (e.g. Trail of Bits-style review):
use those for depth on a frozen snapshot, use this to stay current over time.

## How it's organised (progressive disclosure)

Load only the file you need for the task at hand:

| File | Load it when… |
|---|---|
| [`skill/daily-watch.md`](skill/daily-watch.md) | Running the watch loop — the collect/confront/report procedure and source list. |
| [`skill/vuln-classes.md`](skill/vuln-classes.md) | Confronting code against bug classes — the Anchor/SPL checklist with detection patterns. |
| [`skill/case-studies.md`](skill/case-studies.md) | You want worked examples of real findings (anonymised) to calibrate severity and format. |
| [`commands/security-watch.md`](commands/security-watch.md) | You want the mechanical scan: deps + grep + advisory search → report. |

## The executable command

Install `commands/security-watch.md` as a Claude Code slash command and run
`/security-watch [path-to-anchor-repo]`. It will:

1. **Scan dependencies** — parse `Cargo.lock`, cross-check `anchor-lang` /
   `anchor-spl` and transitive crates against RUSTSEC, flag missing
   `overflow-checks`, flag known-malicious crate names.
2. **Grep risky patterns** — `UncheckedAccount` / manual `try_deserialize`
   without an owner check, `init_if_needed`, unbounded `as u64` casts, divisions
   without a `> 0` guard, missing `Signer` on sensitive permissionless ix.
3. **Pull recent advisories** — WebSearch the last 48h of Solana/Anchor/DeFi
   disclosures.
4. **Emit a dated report** — `RAS` (nothing relevant) or per-finding: technique,
   surface, `file:line`, estimated severity, proposed fix. Never auto-applies.

## Core principle

**Propose, don't apply.** On production code, this skill flags and proposes — it
does not push fixes. Human validation gates every change. After any struct or
account-context change, the IDL must be rebuilt before fixes are trusted on-chain.
