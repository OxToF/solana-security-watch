# Solana Security Watch — a Claude Code skill

> Continuous security monitoring for Solana / Anchor programs. Not a one-shot
> audit — a daily **watch** loop that pulls fresh ecosystem disclosures and
> re-confronts your program's code against each new exploit technique.

Audits are point-in-time; exploit techniques surface weekly. This skill turns
security into a repeatable loop:

> **Collect** fresh disclosures (exploits, CVEs, RUSTSEC, auditor advisories) →
> **Confront** them against your program's code → **Report** a dated finding with
> severity, `file:line`, and a *proposed* fix. Propose only — never auto-patch
> production code.

It ships an executable `/security-watch` command that scans a target Anchor repo
for known vulnerability classes (account substitution, `init_if_needed` re-init,
rounding arbitrage, donation attacks, unbounded casts, governance capture, oracle
manipulation, supply-chain risk) and emits a dated report.

## What's inside

```
solana-security-watch/
├── SKILL.md                    # entry hub (progressive disclosure)
├── skill/
│   ├── daily-watch.md          # the collect → confront → report procedure + severity rubric
│   ├── vuln-classes.md         # 18 Solana/Anchor bug classes with grep patterns + safe patterns
│   └── case-studies.md         # anonymised real findings (HIGH/MEDIUM/LOW/INFO) for calibration
├── commands/
│   └── security-watch.md       # executable slash command: deps + grep + advisories → report
└── README.md
```

## Install

**As a Claude Code skill** — drop this folder into your skills directory (e.g.
`~/.claude/skills/solana-security-watch/`), or add it to the
[Solana AI Kit](https://github.com/solanabr/solana-ai-kit) skill registry.

**As a slash command** — copy `commands/security-watch.md` to
`~/.claude/commands/security-watch.md` (user-level) or
`.claude/commands/security-watch.md` (project-level).

## Use

```
/security-watch .                 # one watch pass over the current repo
/loop 1d /security-watch .        # self-paced daily watch
```

Or point a scheduled agent / cron job at the command with the repo path as
argument, appending each run to the repo's `SECURITY_WATCH.md` journal.

## Demo — a real watch pass

Below is an **unedited** report from running `/security-watch` against a public
third-party Anchor repo: [`coral-xyz/sealevel-attacks`](https://github.com/coral-xyz/sealevel-attacks)
— the canonical teaching corpus of Solana exploits. It was chosen deliberately:
its vulnerabilities are **public and intentional** (each ships an `insecure` +
`secure` pair), so the demo proves the detection works without accusing any
production protocol. Reproduce with:

```
git clone --depth 1 https://github.com/coral-xyz/sealevel-attacks
/security-watch sealevel-attacks
```

---

### 2026-06-19 — Watch pass (Claude Opus 4.8)

**Target:** `coral-xyz/sealevel-attacks` (intentionally-vulnerable teaching repo —
findings below are by-design, used to validate detection coverage).

#### Sources swept
- RUSTSEC advisory DB (`anchor-lang`, `solana-program`) — for the pinned versions.
- Anchor release security notes (`init_if_needed` gating, account-close
  discriminator) — relevant to the stale pins below.

#### Step 1 — Dependency scan

| Check | Result |
|---|---|
| `anchor-lang` | **0.20.1 / 0.25.0** — predates numerous security hardenings (e.g. `init_if_needed` was gated behind a feature flag in 0.24 *precisely* because of reinitialization attacks; account-close discriminator handling improved through later releases). **Finding: Low** — upgrade to a current 0.3x line. |
| `solana-program` | 1.10.31 — ancient. **Info** — bump in lockstep with Anchor. |
| `overflow-checks` | **Absent** from `[profile.release]`. **Finding: Low** — set `overflow-checks = true` to turn silent wrapping into a panic (neutralises a whole class of arithmetic advisories). |

#### Step 2 — Risky-pattern grep → triaged findings

The grep flags *leads*; each was confirmed by reading the source. Mapping to the
skill's [`vuln-classes.md`](skill/vuln-classes.md):

| # | Program (`insecure` variant) | Class | Surface | Severity |
|---|---|---|---|---|
| 1 | `0-signer-authorization` | **#8** missing `Signer` | `authority: AccountInfo` with no signature check → anyone impersonates | High |
| 2 | `2-owner-checks` | **#1** missing owner check | `SplTokenAccount::unpack` on an `AccountInfo` without verifying the account's *program owner* is the Token program → spoofed data | High |
| 3 | `1-account-data-matching` | **#1** account substitution | reads token data without binding the account to the expected authority | High |
| 4 | `3-type-cosplay` | **#3** manual deser, no discriminator | `User::try_from_slice` with no type tag → account-type confusion | High |
| 5 | `4-initialization` | **#2 / #3** reinit | `try_from_slice` + unconditional init on a possibly-existing account | High |
| 6 | `5-arbitrary-cpi` | **#15** arbitrary CPI | `token_program: AccountInfo` passed to `invoke` unconstrained → malicious program substitution | High |
| 7 | `9-closing-accounts` | **#16** close/revival | manual lamport-zeroing close, account revivable in-tx | High |
| 8 | `6-duplicate-mutable-accounts` | **#17** duplicate mutable | two same-type `mut` accounts, no inequality constraint | Medium |
| 9 | `7-bump-seed-canonicalization` | **#18** bump canonicalization | PDA re-derived from a user-supplied bump | Medium |
| 10 | `10-sysvar-address-checking` | **#1** address constraint | sysvar passed as `AccountInfo` with no `address =` pin | Medium |

#### Signal quality (no false positives)

A naive grep for `AccountInfo` also matched the **`secure`** variants — but reading
the body cleared them, exactly as the procedure prescribes ("a hit is a lead, not a
finding"). Example: `0-signer-authorization/secure` keeps `authority: AccountInfo`
yet adds `if !ctx.accounts.authority.is_signer { return Err(..) }` in the handler →
**not** flagged. 13 `insecure` variants flagged; 22 `secure`/`recommended` variants
correctly passed.

#### Skill self-improvement

This pass surfaced four canonical Solana classes **missing** from the checklist at
the time — arbitrary CPI, account closing/revival, duplicate mutable accounts, and
bump-seed canonicalization. They were added as classes **#15–#18** in
[`vuln-classes.md`](skill/vuln-classes.md). That is the watch loop working as
intended: each pass can harden the skill itself, not only the target.

---

## Design principles

- **Continuous, not point-in-time** — complements one-shot audit skills; keeps you
  current as new techniques drop.
- **Bug *classes*, not signatures** — an EVM exploit this week becomes a Solana
  checklist item, because the class (rounding, donation, oracle, capture) transposes.
- **Diff the siblings** — most real findings are a context that drifted from a
  correct peer instruction, not a novel bug.
- **Propose, don't apply** — on production code, flag and propose; a human gates
  every change. After any account-context change, the IDL must be rebuilt first.

## License

MIT — see headers. Author: OxToF.
