# Case studies — worked findings from a real watch

Anonymised findings produced by running this exact loop on a production Solana
DeFi protocol. They calibrate what a good report looks like and how the vuln
classes show up in practice. Code identifiers are generic.

All four below are tagged `VERIFIED-SOURCE` — the source was read and the
exploit path traced by hand, no formal/fuzz tooling was run. That's an honest,
weaker tier than `PROVEN`/`TESTED` (see
[`daily-watch.md` §0](daily-watch.md#0-verification-discipline--a-scientific-process-for-security-claims))
— a real re-run of this pass on classes #4–#7 (rounding/math) would attempt a
Kani harness or a Trident fuzz run before closing the finding, not stop at a
manual read.

---

## HIGH — Vesting lock bypass via unchecked deserialisation

**Class** — #1 account substitution + #3 manual deserialisation without owner check.

**Confidence** — `VERIFIED-SOURCE` (manual trace of the instruction; no fuzz/formal tooling run).

**Surface** — An `unstake` instruction read the founder's vesting account as an
`UncheckedAccount`, then `VestingState::try_deserialize`'d it **without** checking
the canonical PDA or the program owner.

**Exploit** — The privileged user passes a forged account with `claimed = 0` →
`locked = 0` → the vesting lock is entirely bypassed → early unstake → sale of
unbacked tokens → drain of the floor reserve at real buyers' expense.

**Fix** — Pin to the canonical PDA `[b"founder_vesting"]` and assert
`owner == program_id` **before** trusting `claimed`. No `#[derive(Accounts)]`
change → no IDL rebuild required.

**Lesson** — The highest-severity bug was not in the math; it was one missing owner
check on a manually-deserialised account. This is why surface #1 is always first.

---

## MEDIUM — Debt without collateral (divergence from a correct sibling)

**Class** — #8 missing check, surfaced by sibling comparison.

**Confidence** — `VERIFIED-SOURCE` (diffed against sibling instructions `borrow`/`founder_borrow`; no tooling run).

**Surface** — A `contributor_borrow` instruction allowed borrowing up to a % of a
claimed allocation **without** declaring the collateral token account or checking
its real balance — unlike its siblings `borrow` and `founder_borrow`, which both
verify `new_borrowed ≤ collateral_balance`.

**Exploit** — Claim the allocation tokens, sell/transfer them all, then borrow
anyway → debt with zero on-chain collateral → an unrecoverable claim against the
reserve.

**Fix** — Add the collateral token account to the context and mirror the sibling's
check: `require!(new_borrowed <= balance, BorrowLimitExceeded)`.

**Lesson** — Most real findings are **divergences from a correct sibling**, not
novel bugs. When several instructions do the same kind of thing, diff their
contexts — the odd one out is the finding.

---

## LOW — Bounded DoS via a pre-occupied PDA

**Class** — #1 account substitution, DoS variant.

**Confidence** — `VERIFIED-SOURCE` (traced the byte-offset read and the missing owner check by hand).

**Surface** — A `rollover` instruction read bytes 48–56 of a gauge-state account
without checking `owner == program_id`. A PDA can be pre-created by a third party
before the real instruction initialises it.

**Exploit** — Pre-fund the canonical gauge PDA with a forged account whose bytes
48–56 form a non-zero `u64` → the rollover believes votes existed → forces a 2-epoch
grace period (~14 days) even though nobody voted. Cost to attacker: rent for a
≥56-byte account (~0.0008 SOL). No fund loss; bounded griefing.

**Fix** — Gate the read on ownership:
`let has_votes = acc.owner == program_id && data.len() >= 56 && u64::from_le_bytes(..) > 0;`

**Lesson** — Even Low-severity, no-fund-loss issues are worth a dated entry: they're
cheap to fix and the journal proves the surface was considered.

---

## INFO — Silent truncating cast (defence-in-depth)

**Class** — #7 unbounded cast.

**Confidence** — `VERIFIED-SOURCE` for the cast itself; the "not exploitable" claim rests on a supply-curve argument that was reasoned, not proven — a real Kani harness bounding the `u128→u64` cast against the maximum achievable supply would upgrade this to `PROVEN`.

**Surface** — A voting-power formula computed in `u128` then did `as u64`. For an
extreme whale the `u128` could exceed `u64::MAX` and silently truncate, under-counting
voting power.

**Assessment** — Not exploitable: the token supply curve can't physically emit
enough tokens to reach the threshold in any realistic scenario. Logged as **Info**.

**Fix** — `.min(u64::MAX as u128) as u64` saturates cleanly. Defence-in-depth, zero
impact on normal use.

**Lesson** — Info findings document that the cast was analysed and bounded — useful
context for a future auditor, and honest about severity rather than inflating it.

---

## Pattern across all four

1. **Owner checks first.** Two of four were a missing `owner == program_id`.
2. **Diff the siblings.** The Medium was a context that drifted from its peers.
3. **Log the Lows and Infos too.** The journal's value is the *record*, including
   "considered, bounded, not exploitable."
4. **Propose, never auto-apply.** Every fix above was proposed for human review;
   the ones touching an account context required an IDL rebuild before trust.
