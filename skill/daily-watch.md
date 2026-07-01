# Daily Watch — the collect / confront / report loop

> Playbook for an agent (best run on the most capable model available — detection
> quality scales with model strength) executed on a schedule.

## Honest framing

There is no "official feed of vulnerabilities an LLM detects." The watch works by
**searching** for recent disclosures, then **re-auditing** the target program in
light of those new techniques. It is a force-multiplier on a human security
process, not a replacement for an audit or a bug bounty.

---

## 0. Verification discipline — a scientific process for security claims

The failure mode this section exists to kill: writing a reassuring conclusion
because it reads well, not because it was actually checked. A "no hole found"
that turns out to mean "I read one `getAccountInfo` once" is worse than no
report — it's a false negative wearing the credibility of a security pass.

**The standard: every claim is a falsifiable hypothesis, tested by a stated
method, backed by reproducible evidence, and reported at the tier its method
actually earned — never higher.** This is also an honest boundary, not a
tone: "mathematically proven" is a real, narrow category (formal verification
of pure logic under stated bounds), not a rhetorical upgrade. Claims about
who holds an upgrade authority today, whether a validator is honest, or the
absence of a future exploit **cannot** be proven mathematically — they can
only be tested empirically and labeled as such. Dressing an empirical check
up as a proof is exactly the complacency this process exists to ban.

### Every claim: hypothesis → method → evidence → refutation attempt → residual uncertainty

1. **Hypothesis** — a specific, falsifiable statement. Not "rounding is safe"
   but "for all `deposit` amounts in `[1, u64::MAX]`, `withdraw(deposit(x))`
   never returns more than `x` to the caller."
2. **Method** — the exact tool + configuration used to test it (Toolchain
   below). Precise enough that a third party can rerun it and get the same
   result — that's what turns it into evidence instead of an opinion.
3. **Evidence** — the actual artifact: Kani proof-harness output, Trident/fuzz
   run count and seed, RPC response + slot number, `file:line`. No artifact,
   no claim.
4. **Refutation attempt** — what you actively tried to break the hypothesis
   with, and it survived. A hypothesis nobody tried to falsify isn't verified
   — it's unchallenged. (E.g.: fuzzed `withdraw`/`deposit` interleavings
   targeting rounding drift; tried passing a forged account at every
   `UncheckedAccount` site to see if the owner/PDA check actually rejects it.)
5. **Residual uncertainty** — what the method's scope does *not* cover.
   Kani proofs are bounded to the pure function they harness, not the whole
   on-chain account/CPI surface; fuzzing is probabilistic; RPC reads are
   point-in-time. State the boundary explicitly instead of letting the
   reader assume totality.

### Confidence tiers — tied to method, not to how confident the prose sounds

| Tier | Method | Claim license |
|---|---|---|
| **PROVEN** | Formal verification of a pure-logic function — [Kani](https://github.com/model-checking/kani) (SMT/CBMC-backed bounded model checking via `#[kani::proof]`), or a Certora Prover spec if Solana support is confirmed available at the time — proves a property holds for *all* inputs within stated bounds. | The only tier allowed words like "cannot," "impossible," "guaranteed." Must state the bounds (integer ranges, harness assumptions) and that it covers the *extracted logic*, not the full on-chain instruction (accounts/CPI are out of scope for this tier). |
| **TESTED** | Property-based / invariant fuzzing — [Trident](https://ackee.xyz/trident/docs/latest/) (Anchor-native fuzzer) for full instructions, or `cargo-fuzz`/`proptest` for extracted pure functions — N runs, given seed/corpus, zero counterexamples. | "No counterexample found in `<N>` runs" — never "safe." Probabilistic, not proof; report the run count and config so it's reproducible. |
| **VERIFIED-LIVE** | On-chain read (`getAccountInfo` / `getProgramAccounts` / `solana program show`), cross-verified against a 2nd RPC endpoint, control-surface resolved (program **upgrade authority** — bare keypair vs. Squads multisig vs. immutable; PDA `authority` field). | Point-in-time fact only — "as of slot `<N>`." Must be re-checked every pass; an upgradeable program's authority can change between passes with zero on-chain announcement. |
| **VERIFIED-SOURCE** | Manually traced logic in source, no tool. | Weakest "checked" tier — not mechanically reproducible by a third party. State what was traced and what wasn't. |
| **INFERRED** | Lineage/naming/pattern similarity (e.g. "forks protocol X"), not diffed against its claimed origin. | A lead, never a conclusion. Cannot appear in a "verified good" row. |
| **UNKNOWN** | Could not be determined (closed-source, no RPC access, out of budget). | Must be listed explicitly — never smoothed into "looks fine." |

`RAS` is only valid when every applicable checklist item reached `PROVEN`,
`TESTED`, or `VERIFIED-LIVE`. Otherwise report what's actually known: "no
finding above INFERRED confidence — X and Y remain unverified."

### Non-negotiables

- **A single point-in-time read never proves safety.** If a pass concludes
  "authority X holds the upgrade key" from one RPC call, that only proves it
  *at that slot, on that RPC, right now*. Before writing anything stronger,
  resolve: (1) is the program even upgradeable (`solana program show` →
  `Authority`) — bare keypair, Squads multisig, or `none` (immutable)?
  (2) has it ever changed — check the program-data account's history when
  feasible; (3) cross-verify the read against a second independent RPC
  endpoint (a single provider's stale/cached response is a false negative
  waiting to happen).
- **Lineage claims need a diff, not a name match.** "Forks protocol X"
  because account/instruction names match is `INFERRED` until the actual
  guarded logic is diffed against the claimed upstream — matching names is
  exactly what a fork that changed the one check that matters would still have.
- **Every claim above `INFERRED` documents its refutation attempt**, not just
  the positive fact. "Owner check present" is an assertion; "fuzzed the
  instruction 20k runs passing a forged/uninitialised account at every
  `UncheckedAccount` site, all rejected" is evidence. If you can't write the
  refutation attempt, you haven't done it — downgrade the tier instead of the
  wording.
- **Don't write a finding to make the report look better.** No padding
  Info/Low items to seem thorough, no soft-pedaling a Medium into an Info to
  keep a pitch friendly, no "everything looks solid" closer unless every
  relevant item cleared `PROVEN`/`TESTED`/`VERIFIED-LIVE`. If the honest state
  is "closed-source, one `UNKNOWN`, nothing above `VERIFIED-LIVE`" — that IS
  the report.
- **Tractability note.** Account substitution, CPI trust, and PDA derivation
  bugs (classes #1, #3, #15, #16, #18) depend on the whole runtime account
  model — today's Solana formal-verification tooling does not cover that
  surface end-to-end, so cap those at `TESTED`/`VERIFIED-SOURCE` and say so.
  Pure math/invariant claims (classes #4, #5, #6, #7 — rounding, donation
  math, division guards, overflow bounds) are the tractable `PROVEN` targets
  once the logic is extracted into a harnessable pure function.

---

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

- **`RAS`** (nothing relevant) — only when every applicable checklist item
  reached `PROVEN`, `TESTED`, or `VERIFIED-LIVE` (§0). Otherwise say what's
  actually unverified instead of defaulting to `RAS`; list the sources swept
  so the absence is auditable.
- **Finding** — technique, affected surface, `file:line`, estimated severity
  (Critical / High / Medium / Low / Info), **confidence tier + method +
  evidence** (§0), and a **proposed** fix.

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

## Toolchain

```bash
# Static / dependency (leads only — every hit still needs source confirmation)
cargo audit                                  # RUSTSEC advisories
grep -nE "overflow-checks|anchor-lang|anchor-spl" Cargo.toml

# --- PROVEN tier: formal verification of extracted pure-logic functions ---
# Kani (SMT/CBMC-backed bounded model checking) — write a #[kani::proof]
# harness around the pure math (bonding curve, rounding, invariant), run:
cargo kani --harness proof_withdraw_never_exceeds_deposit
# Scope: the harnessed pure function only — not the on-chain account/CPI
# surface. Certora Prover: check current Solana-support maturity before
# relying on it for a PROVEN claim — don't assume tooling that may not exist
# or may not cover this program's constructs.

# --- TESTED tier: property-based / invariant fuzzing (probabilistic, not proof) ---
trident fuzz run-hfuzz                       # Anchor-native fuzzer (Ackee) —
                                              # record run count / corpus / seed
cargo fuzz run <target>                      # for an extracted pure function
proptest                                     # property-based unit tests

# --- VERIFIED-LIVE tier: on-chain ---
solana program show <program_id>             # upgrade authority: keypair vs.
                                              # multisig (Squads) vs. none
solana account <pubkey> --output json        # getAccountInfo equivalent
# Cross-verify every read against a 2nd RPC endpoint before it backs a claim.
```

**Tractability note:** not every vuln class in `vuln-classes.md` is reachable
at `PROVEN` with today's Solana tooling. Rounding, donation-math, division
guards, and overflow bounds (#4–#7) are tractable once extracted into a
harnessable pure function. Account substitution, CPI trust, PDA derivation,
and governance capture (#1, #3, #10, #15, #16, #18) depend on the whole
runtime account model — cap those at `TESTED`/`VERIFIED-SOURCE` and say so;
do not stretch the word "proven" to cover them.

## Running it on a schedule

- **Claude Code `/loop`** — `/loop 1d /security-watch .` for a self-paced daily run.
- **Cron / scheduled agent** — point a scheduled task at the `/security-watch`
  command with the repo path as argument.
- Keep each run's report appended to the same journal so the absence of findings
  is itself a record, and so fixes can be confirmed in later runs.
