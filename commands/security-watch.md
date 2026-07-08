---
description: Run a continuous security watch pass over a Solana/Anchor repo — scan deps, grep risky patterns, pull fresh advisories, emit a dated report.
argument-hint: "[path-to-anchor-repo]  (defaults to .)"
allowed-tools: Bash(grep:*), Bash(cargo audit:*), Bash(find:*), Bash(cat:*), Read, Glob, Grep, WebSearch
---

# /security-watch

Run one watch pass over the Anchor program at `$ARGUMENTS` (default: current
directory). Produce a dated report; **propose** fixes, never auto-apply.

**Verification discipline applies to every step below** — see
[`daily-watch.md` §0](../skills/solana-security-watch/daily-watch.md#0-verification-discipline--a-scientific-process-for-security-claims).
No conclusion, positive or negative, ships without a confidence tier
(`PROVEN` / `TESTED` / `VERIFIED-LIVE` / `VERIFIED-SOURCE` / `INFERRED` /
`UNKNOWN`). A grep exiting clean, or an RPC call returning the expected value,
is a lead — it becomes a finding (including a "no finding") only once the
method, evidence, and refutation attempt behind it are written out.

Follow the steps in order. Use [`vuln-classes.md`](../skills/solana-security-watch/vuln-classes.md)
for the detection patterns and [`daily-watch.md`](../skills/solana-security-watch/daily-watch.md)
for the severity rubric and confidence tiers.

## Step 1 — Dependency scan

Set `REPO` to `$ARGUMENTS` (or `.`). Then:

1. If `cargo audit` is available, run it in `REPO` and capture advisories.
   Otherwise, read `REPO/Cargo.lock` and list direct deps + versions.
2. Confirm `overflow-checks = true` under `[profile.release]` in `REPO/Cargo.toml`.
   Flag as a finding if absent (re-enables a whole class of arithmetic advisories).
3. Cross-check the Anchor crates (`anchor-lang`, `anchor-spl`) and any unusual
   transitive crate names against RUSTSEC and known supply-chain campaigns
   (see vuln-classes #14). Flag known-malicious or known-vulnerable versions.

```bash
REPO="${ARGUMENTS:-.}"
cargo audit --file "$REPO/Cargo.lock" 2>/dev/null || true
grep -nE "overflow-checks|anchor-lang|anchor-spl" "$REPO/Cargo.toml"
```

## Step 2 — Risky-pattern grep

Run these over `REPO`'s program sources and triage every hit against the matching
vuln class. A hit is a *lead*, not a finding — read the surrounding code to confirm.

```bash
# #1 / #3 — accounts trusted without owner/PDA validation
grep -rnE "UncheckedAccount|AccountInfo<" "$REPO" --include=*.rs
grep -rnE "try_deserialize|try_from_slice|from_le_bytes" "$REPO" --include=*.rs

# #2 — re-init surface
grep -rn "init_if_needed" "$REPO" --include=*.rs

# #7 — truncating casts
grep -rnE "as u64|as u32" "$REPO" --include=*.rs

# #6 — divisions (check each denominator for a > 0 guard)
grep -rnE "checked_div|/ " "$REPO" --include=*.rs

# #8 — signer surface on privileged ix
grep -rnE "Signer<|pub authority|pub admin" "$REPO" --include=*.rs
```

For each `UncheckedAccount` / manual deserialisation: confirm an
`owner == program_id` check **and** a canonical-PDA re-derivation precede the read.
For each division: identify who gets the remainder (rounding must favour the
protocol). **Diff sibling instructions** — a context that omits a check its peers
have is the most common finding.

## Step 2.5 — Control-surface check + formal verification attempt

Before writing any guard/check as "safe," resolve two things and record both
in the report:

1. **Control surface** — `solana program show <program_id>` to read the
   upgrade authority (bare keypair / Squads multisig / `none`/immutable).
   Cross-verify against a 2nd RPC endpoint. A check enforced by code that a
   single keypair can silently replace is `VERIFIED-LIVE` at best, never
   phrased as closed.
2. **Formal verification, where tractable (`PROVEN` tier)** — for pure
   math/invariant claims (rounding, donation math, division guards, overflow
   bounds — classes #4–#7), attempt a [Kani](https://github.com/model-checking/kani)
   proof harness (`cargo kani --harness <name>`) before writing the claim as
   closed. If Kani isn't installed/feasible in the time budget, fall back to
   Trident/`cargo-fuzz` fuzzing (`TESTED`, record run count) and say
   explicitly that `PROVEN` wasn't attempted. Account-substitution / CPI /
   PDA / governance classes (#1, #3, #10, #15, #16, #18) are not `PROVEN`-
   tractable today — cap at `TESTED`/`VERIFIED-SOURCE`.
3. **Runnable evidence, where a PoC exists** — for class #1 (account
   substitution), a working exploit/defense harness ships at
   [`../poc/account-substitution/`](../poc/account-substitution/) (see
   [`poc-harness.md`](../skills/solana-security-watch/poc-harness.md)). If the
   target's bug shape matches the harness's pattern, adapt and run it instead
   of resting on a manual read — that's the difference between
   `VERIFIED-SOURCE` and `TESTED`.

Skipping this step is how "the check is present" quietly becomes "there's no
hole" — a false negative that reads like a clean audit.

## Step 3 — Fresh advisories (WebSearch)

Search the last 48h across Solana/Anchor/DeFi disclosures (terms in
`skills/solana-security-watch/daily-watch.md`). For each new technique, ask: does any surface in this repo
match? Confirm or rule out by reading the relevant code.

## Step 4 — Emit the report

Append a dated entry to `REPO/SECURITY_WATCH.md` (create it if missing):

```markdown
### YYYY-MM-DD — Watch pass (<model>)

#### Sources swept
- <links / advisories checked>

#### Findings
- **<SEVERITY> — <one-line title>**
  - Class: <#n from vuln-classes>
  - Surface: `path/file.rs:line`
  - Confidence: <PROVEN/TESTED/VERIFIED-LIVE/VERIFIED-SOURCE/INFERRED/UNKNOWN>
    — <method + evidence, e.g. "Kani harness `proof_x`, bounds u64" or
    "Trident 50k runs, seed 42, 0 counterexamples" or "getAccountInfo @ slot N,
    cross-checked on 2nd RPC">
  - Technique: <how it would be exploited>
  - Proposed fix (DO NOT auto-apply): <minimal change + whether it touches an
    account context → IDL rebuild required>

# RAS is only valid if every applicable item reached PROVEN/TESTED/VERIFIED-LIVE.
# Otherwise: "No finding above <confidence> — <what's unverified>. Sources swept listed above."
```

Severity and confidence tiers per `daily-watch.md` (§0 for tiers). **Never push
a fix to production code.** If a proposed fix changes a struct or
`#[derive(Accounts)]` context, state explicitly that the IDL must be rebuilt and
re-copied to the client before the fix is trusted on-chain.
