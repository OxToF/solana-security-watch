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

It ships an executable `/security-watch` command (and a `security-auditor`
subagent for autonomous runs) that scans a target Anchor repo for known
vulnerability classes (account substitution, `init_if_needed` re-init,
rounding arbitrage, donation attacks, unbounded casts, governance capture, oracle
manipulation, supply-chain risk) and emits a dated report — backed, where a
class has one, by a **runnable proof-of-concept** instead of just a grep
pattern and a paragraph.

**Related:** for cross-program-invocation vulnerabilities specifically (arbitrary
CPI, return-data spoofing, stale account after CPI, PDA signing), see the
sibling skill [`solana-cpi-safety-skill`](https://github.com/RECTOR-LABS/solana-cpi-safety-skill)
— deep, CPI-only coverage with its own PoC suite. This skill stays broad
(18 classes, continuous watch); install both, they don't overlap.

## What's inside

```
solana-security-watch/
├── skills/solana-security-watch/
│   ├── SKILL.md                 # entry hub (progressive disclosure)
│   ├── daily-watch.md           # the collect → confront → report procedure + severity rubric
│   ├── vuln-classes.md          # 18 Solana/Anchor bug classes with grep patterns + safe patterns
│   ├── case-studies.md          # anonymised real findings (HIGH/MEDIUM/LOW/INFO) for calibration
│   └── poc-harness.md           # how the poc/ suites work + how to extend them
├── commands/
│   └── security-watch.md        # executable slash command: deps + grep + advisories → report
├── agents/
│   └── security-auditor.md      # read-only subagent running the same workflow autonomously
├── poc/                        # runnable EXPLOIT/DEFENSE/POSITIVE-CONTROL LiteSVM suites
│   ├── account-substitution/   #   class #1  — missing owner check
│   ├── init-reinit/            #   class #2  — init_if_needed reinit takeover
│   ├── rounding-arbitrage/     #   class #4  — rounding-direction arbitrage
│   ├── unbounded-cast/         #   class #7  — unbounded integer cast / truncation
│   ├── duplicate-mutable/      #   class #17 — duplicate mutable accounts
│   └── run-all.sh              #   run every suite (no validator, no rebuild)
├── bin/
│   ├── cli.mjs                 # install + collect + scan subcommands
│   ├── collect.mjs             # advisory collector (RustSec/OSV → dated report)
│   └── scan.mjs                # per-repo scanner (clone → advisories + leads → report)
├── site/index.html            # hostable landing page (paste-repo → scan funnel)
├── .github/workflows/
│   ├── pocs.yml                # CI: run every PoC suite on push
│   └── watch.yml               # scheduled: daily advisory collect → report artifact
├── examples/                   # a committed sample collect report
└── README.md
```

## Install

One-line install (recommended) — full bundle (skill + `/security-watch` command
+ `security-auditor` agent), global (`~/.claude`):

```bash
npx solana-security-watch
# project-local instead: npx solana-security-watch --project
```

From a clone (runs the same installer locally):

```bash
git clone https://github.com/OxToF/solana-security-watch.git
cd solana-security-watch
node bin/cli.mjs                      # global (~/.claude)
node bin/cli.mjs --project             # project-local: ./.claude
node bin/cli.mjs --target <dir>        # custom base: installs <dir>/skills, <dir>/commands, <dir>/agents
```

Or add the skill to the [Solana AI Kit](https://github.com/solanabr/solana-ai-kit)
skill registry.

## Scan one repo — the `scan` command

Point it at a public GitHub Anchor repo and it produces a dated report: dependency
advisories matched against the repo's **exact pinned versions** (RustSec/OSV,
version-filtered), build-hygiene checks (`overflow-checks`, `anchor-lang`), and
grep-level code leads mapped to the vuln-class checklist. Deterministic, near-zero
cost — no LLM. Writes `scan-out/<owner>-<repo>-<date>.{md,html}`.

```bash
node bin/cli.mjs scan https://github.com/<owner>/<repo>
```

A scan is a hygiene + known-class first line, **not** an audit — the report says so,
and code items are labelled leads to confirm, not confirmed findings. A sample
report is in [`examples/`](examples/sample-scan-report.html), and
[`site/index.html`](site/index.html) is a hostable landing page that wraps the scan
in a paste-your-repo funnel.

## Continuous watch — the `collect` command

The "watch" half is a zero-dependency collector that pulls current RustSec/OSV
advisories for the Solana + Anchor dependency surface (`anchor-lang`, `spl-token`,
`borsh`, `curve25519-dalek`, `ring`, …), **diffs against the last run**, and writes
a dated report — so a scheduled run surfaces only what is *new*:

```bash
npx solana-security-watch collect            # writes watch-reports/reports/<date>.{md,json}
node bin/cli.mjs collect --out watch-reports  # from a clone
```

Point `watch.yml` (or any cron / scheduled agent) at it for a daily heartbeat. A
sample report lives in [`examples/`](examples/); it flags, among others, the
`arrayref` malicious-release advisory (RUSTSEC-2026-0260) and the two 2026 Anchor
account-substitution advisories (RUSTSEC-2026-0144/0146) that map straight onto
class #1. State is kept in `watch-reports/state.json`; only the first sighting of
an advisory (across all of its RUSTSEC/CVE/GHSA aliases) is reported as new.

## Use

```
/security-watch .                 # one watch pass over the current repo
/loop 1d /security-watch .        # self-paced daily watch
```

Or invoke the `security-auditor` subagent directly for the same workflow run
autonomously, or point a scheduled agent / cron job at the command with the
repo path as argument, appending each run to the repo's `SECURITY_WATCH.md`
journal.

## Proof, not just prose

Five vulnerability classes ship a **runnable** proof — a compiled Anchor program
with a vulnerable/fixed instruction pair and a LiteSVM suite that fires an actual
transaction, not a read of the source:

| PoC | Class | What the EXPLOIT proves |
|---|---|---|
| [`account-substitution`](poc/account-substitution/) | #1 | a forged, non-program-owned account bypasses `unstake` |
| [`init-reinit`](poc/init-reinit/) | #2 | a second `init_if_needed` call hijacks `config.authority` |
| [`rounding-arbitrage`](poc/rounding-arbitrage/) | #4 | a redeem quote rounds **up** (34) vs the owed 33 |
| [`unbounded-cast`](poc/unbounded-cast/) | #7 | `2^64+500` truncates past a `u64` cap check, crediting ~1.8e19 |
| [`duplicate-mutable`](poc/duplicate-mutable/) | #17 | a self-transfer mints 100 out of nothing (100 → 200) |

Each suite follows the **EXPLOIT / DEFENSE / POSITIVE CONTROL** pattern: the bug
fires, the fix rejects it *on the right error* (not an unrelated failure), and the
fix is shown to still accept genuine inputs (not a blanket reject). Run one, or all:

```bash
bash poc/run-all.sh                    # all 5 suites — 15 passing, no validator, no rebuild
cd poc/unbounded-cast && yarn && yarn test   # or just one
```

Every PoC ships its compiled `target/deploy/*.so`, so the suites run with only
Node + yarn. See [`poc-harness.md`](skills/solana-security-watch/poc-harness.md)
for the pattern and how to add the next class.

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
skill's [`vuln-classes.md`](skills/solana-security-watch/vuln-classes.md):

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
[`vuln-classes.md`](skills/solana-security-watch/vuln-classes.md). That is the watch loop working as
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
