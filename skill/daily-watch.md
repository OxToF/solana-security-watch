# Daily Watch — the collect / confront / report loop

> Playbook for an agent (best run on the most capable model available — detection
> quality scales with model strength) executed on a schedule.

## Honest framing

There is no "official feed of vulnerabilities an LLM detects." The watch works by
**searching** for recent disclosures, then **re-auditing** the target program in
light of those new techniques. It is a force-multiplier on a human security
process, not a replacement for an audit or a bug bounty.

## Procedure

### 1. Collect (WebSearch)

Pull items from the last 24–48h across:

- **DeFi exploits / post-mortems, any chain** — bug classes transpose across
  chains (oracle manipulation, logic reentrancy, rounding, donation/inflation,
  governance capture). An EVM exploit this week is a Solana checklist item next week.
- **Solana-specific advisories** — Anchor, SPL Token / Token-2022, account
  validation, CPI, PDA derivation, `realloc`, `init_if_needed`, sysvars,
  compute budget, durable nonces.
- **Dependency advisories** — Anchor releases, [RUSTSEC](https://rustsec.org/),
  `cargo audit`, supply-chain reports (malicious crates).
- **Auditor / research output** — OtterSec, Neodyme, Zellic, Sec3, Trail of Bits,
  Helius, Dedaub, Check Point Research, plus aggregators (Rekt, blockchain
  security weeklies).

Suggested search terms:

```
"Solana exploit"  "Anchor vulnerability"  "SPL token drain"
"PDA confusion"   "account substitution"  "init_if_needed reinit"
"rounding bug AMM"  "donation attack first deposit"
"ve-token governance attack"  "gauge bribe exploit"
"durable nonce"  "RUSTSEC anchor"  "Solana oracle manipulation"
```

### 2. Confront the code

For every technique found, check whether the **target program** is exposed. Work
the surfaces in priority order (see [`vuln-classes.md`](vuln-classes.md) for the
detection patterns):

1. **Account validation** — every `UncheckedAccount` / manual `try_deserialize`
   must verify `owner == program_id` **and** the expected PDA before trusting any
   field. This is the single highest-yield surface.
2. **Math / invariants** — bonding curves, AMM `k`, accumulators: rounding
   direction, overflow, division-by-zero, internal-vs-on-chain reserve tracking.
3. **Governance** — gauge/vote/bribe: double-vote, double-claim, snapshot
   immutability, weight caps, epoch/seed confusion.
4. **Collateral / vesting** — lock bypass, claim re-entry, debt without collateral,
   unchecked deserialisation of vesting accounts.
5. **Fee accounting** — advance-before-mutate ordering, debt bookkeeping.
6. **Pause coverage** — entries gated, exits always open.
7. **Dependencies** — known-vulnerable versions, missing `overflow-checks`,
   malicious crate names.

### 3. Report

Append a dated entry to a journal (`SECURITY_WATCH.md` in the target repo):

- **`RAS`** (nothing relevant) — list the sources swept so the absence is auditable.
- **Finding** — technique, affected surface, `file:line`, estimated severity
  (Critical / High / Medium / Low / Info), and a **proposed** fix.

**Do not push fixes to production code automatically.** Propose; let a human
validate. After any change to a struct or `#[derive(Accounts)]` context, the IDL
must be rebuilt and re-copied to the client before the fix is trusted on-chain.

## Severity rubric (quick)

| Severity | Test |
|---|---|
| Critical | Unauthenticated fund drain or mint, no preconditions. |
| High | Fund loss with a plausible precondition (privileged role, specific state). |
| Medium | Invariant break with bounded impact, or self-inflicted user loss in normal use. |
| Low | Bounded DoS, griefing, no direct fund loss. |
| Info | Defence-in-depth; not exploitable in any realistic scenario. |

## Running it on a schedule

- **Claude Code `/loop`** — `/loop 1d /security-watch .` for a self-paced daily run.
- **Cron / scheduled agent** — point a scheduled task at the `/security-watch`
  command with the repo path as argument.
- Keep each run's report appended to the same journal so the absence of findings
  is itself a record, and so fixes can be confirmed in later runs.
