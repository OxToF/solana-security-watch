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

**CPI is a separate, deeper surface.** For classes #15 (arbitrary CPI) and the
CPI-adjacent parts of #16 (stale account after CPI), reach for
[`solana-cpi-safety-skill`](https://github.com/RECTOR-LABS/solana-cpi-safety-skill)
instead — a sibling skill purpose-built for return-data spoofing, arbitrary
CPI, stale-account-after-CPI, and PDA signing, with its own runnable PoC suite.
This skill stays broad (18 classes, continuous watch); that one goes deep on
one high-severity surface. Install both; they don't overlap in scope.

## How it's organised (progressive disclosure)

Load only the file you need for the task at hand:

| File | Load it when… |
|---|---|
| [`daily-watch.md`](daily-watch.md) | Running the watch loop — the collect/confront/report procedure, verification discipline (§0: confidence tiers, toolchain), and source list. |
| [`vuln-classes.md`](vuln-classes.md) | Confronting code against bug classes — the Anchor/SPL checklist with detection patterns. |
| [`case-studies.md`](case-studies.md) | You want worked examples of real findings (anonymised) to calibrate severity and format. |
| [`poc-harness.md`](poc-harness.md) | You want runnable proof (not just a grep pattern) that a class is real and that the fix works — [`poc/`](../../poc/) ships EXPLOIT/DEFENSE/POSITIVE CONTROL test suites. |
| [`../../commands/security-watch.md`](../../commands/security-watch.md) | You want the mechanical scan: deps + grep + advisory search → report. |
| [`../../agents/security-auditor.md`](../../agents/security-auditor.md) | You want a dedicated read-only subagent to run the full audit workflow autonomously. |

## The executable command and agent

Install `commands/security-watch.md` as a Claude Code slash command and run
`/security-watch [path-to-anchor-repo]`, or invoke the `security-auditor`
subagent for the same workflow run autonomously. Either will:

1. **Scan dependencies** — parse `Cargo.lock`, cross-check `anchor-lang` /
   `anchor-spl` and transitive crates against RUSTSEC, flag missing
   `overflow-checks`, flag known-malicious crate names.
2. **Grep risky patterns** — `UncheckedAccount` / manual `try_deserialize`
   without an owner check, `init_if_needed`, unbounded `as u64` casts, divisions
   without a `> 0` guard, missing `Signer` on sensitive permissionless ix.
3. **Pull recent advisories** — WebSearch the last 48h of Solana/Anchor/DeFi
   disclosures.
4. **Emit a dated report** — `RAS` (nothing relevant) or per-finding: technique,
   surface, `file:line`, estimated severity, confidence tier, proposed fix.
   Never auto-applies.

## Core principles

- **Propose, don't apply.** On production code, this skill flags and proposes —
  it does not push fixes. Human validation gates every change. After any struct
  or account-context change, the IDL must be rebuilt before fixes are trusted
  on-chain.
- **A hit is a lead, not a finding — and a clean read isn't either.** A grep
  hit must be confirmed by reading the source before it's a finding.
  Symmetrically, a passing fuzz run or a reassuring RPC read must be
  confirmed — who holds the program's upgrade authority, cross-verified
  against a second RPC — before it's a "no finding." Every conclusion carries
  a confidence tier tied to its method (`PROVEN` formal verification / `TESTED`
  fuzzing / `VERIFIED-LIVE` / `VERIFIED-SOURCE` / `INFERRED` / `UNKNOWN`); see
  [`daily-watch.md` §0](daily-watch.md#0-verification-discipline--a-scientific-process-for-security-claims).
  No complacent findings — a friendly-sounding conclusion earns its wording or
  it doesn't ship.
- **Claims can be backed by a runnable artifact, not just prose.** Where a
  [`poc/`](../../poc/) harness exists for a class, a `TESTED`-tier claim should
  point at it — see [`poc-harness.md`](poc-harness.md).
