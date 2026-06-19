---
description: Run a continuous security watch pass over a Solana/Anchor repo — scan deps, grep risky patterns, pull fresh advisories, emit a dated report.
argument-hint: "[path-to-anchor-repo]  (defaults to .)"
allowed-tools: Bash(grep:*), Bash(cargo audit:*), Bash(find:*), Bash(cat:*), Read, Glob, Grep, WebSearch
---

# /security-watch

Run one watch pass over the Anchor program at `$ARGUMENTS` (default: current
directory). Produce a dated report; **propose** fixes, never auto-apply.

Follow the four steps in order. Use [`skill/vuln-classes.md`](../skill/vuln-classes.md)
for the detection patterns and [`skill/daily-watch.md`](../skill/daily-watch.md)
for the severity rubric.

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

## Step 3 — Fresh advisories (WebSearch)

Search the last 48h across Solana/Anchor/DeFi disclosures (terms in
`skill/daily-watch.md`). For each new technique, ask: does any surface in this repo
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
  - Technique: <how it would be exploited>
  - Proposed fix (DO NOT auto-apply): <minimal change + whether it touches an
    account context → IDL rebuild required>

(or: **RAS** — nothing relevant. Sources swept listed above.)
```

Severity per the rubric in `daily-watch.md`. **Never push a fix to production
code.** If a proposed fix changes a struct or `#[derive(Accounts)]` context, state
explicitly that the IDL must be rebuilt and re-copied to the client before the fix
is trusted on-chain.
