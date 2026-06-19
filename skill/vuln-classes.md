# Solana / Anchor vulnerability classes — detection checklist

The bug classes worth re-verifying on every watch run. Each has: what it is, how
to spot it (grep/read pattern), and the safe pattern.

---

## 1. Account substitution / missing constraints

**What** — An instruction trusts an account that the runtime never constrained, so
an attacker passes a forged or look-alike account.

**Spot it** — Any `UncheckedAccount` or `AccountInfo` that is later read via manual
`try_deserialize` / byte slicing. Any `Account<T>` lacking a `seeds`, `address`,
`has_one`, or `owner` constraint where identity matters.

```
grep -rn "UncheckedAccount\|AccountInfo" programs/**/src
grep -rn "try_deserialize\|try_from_slice" programs/**/src
```

**Safe pattern** — Before trusting any field:

```rust
require_keys_eq!(*acc.owner, crate::ID, ErrorCode::WrongOwner);
let expected = Pubkey::find_program_address(&[b"seed", key.as_ref()], &crate::ID).0;
require_keys_eq!(acc.key(), expected, ErrorCode::WrongPda);
```

Prefer Anchor's typed accounts with `seeds`/`bump` over manual deserialisation. If
you must read raw bytes, check `owner` **and** re-derive the canonical PDA first.

---

## 2. `init_if_needed` re-initialisation

**What** — A handler that runs init-time logic (resetting balances/flags) on an
account that already exists, letting an attacker wipe accumulated state.

**Spot it**

```
grep -rn "init_if_needed" programs/**/src
```

**Safe pattern** — Handlers behind `init_if_needed` must be **accumulate-only**
(`checked_add` onto existing state), never reset to a constant. For typed PDAs,
prefer plain `init` (fails on replay) when one-time creation is the intent. For
ATAs the address is deterministic and owner = Token Program, so re-init is
physically impossible — those are safe.

---

## 3. Manual deserialisation without owner check

**What** — Reading specific byte offsets of an account to extract a `u64`/flag
without confirming the program owns it. A forged account fabricates the value.

**Spot it** — `from_le_bytes` / slice indexing on an `AccountInfo.data` where no
`owner == program_id` precedes it.

**Safe pattern**

```rust
let owned = acc.owner == ctx.program_id;
let value = owned && data.len() >= END
    && u64::from_le_bytes(data[START..END].try_into().unwrap()) > 0;
```

A non-owned or uninitialised account (owner = System Program) must collapse to the
safe default, not the attacker-chosen value.

---

## 4. Rounding-direction arbitrage

**What** — Division rounding in the user's favour, accumulated over many calls, to
drain reserves (cf. the Balancer V2 `mulDown` $128M class).

**Spot it** — Every `/` or `checked_div` on a user-facing payout. Ask: who does the
remainder go to?

**Safe pattern** — Always round **in the protocol's favour**: round *down* what you
pay out, round *up* what you collect. Document the direction at each division site.

---

## 5. Donation / first-deposit inflation (AMM/LP)

**What** — An attacker donates tokens directly to a pool vault to inflate share
price and steal from the first real LP.

**Spot it** — Pool/vault logic that reads `token_account.amount` (the on-chain
balance) to compute reserves or share price.

**Safe pattern** — Track reserves **internally** in program state (`reserve_a` /
`reserve_b`), never from the live vault balance. Lock a `MINIMUM_LIQUIDITY` to a
dead address on first deposit. Revert deposits that round to zero LP.

---

## 6. Division by zero / empty-set math

**What** — Pro-rata or reward math that divides by a total which can be zero
(no votes, no stake, no supply) → panic or undefined payout.

**Spot it** — Any division where the denominator is a summed total.

**Safe pattern**

```rust
require!(total_votes > 0, ErrorCode::NothingToDistribute);
```

Guard every aggregate denominator before dividing.

---

## 7. Unbounded integer cast / overflow

**What** — `as u64` silently truncating a `u128`, or arithmetic wrapping. Cetus
($200M) was a defective overflow check.

**Spot it**

```
grep -rn "as u64\|as u32" programs/**/src      # truncating casts
grep -rn "overflow-checks" Cargo.toml          # must be true in [profile.release]
```

**Safe pattern** — `checked_*` everywhere on value math; saturate or `require!`
bounds before any narrowing cast: `value.min(u64::MAX as u128) as u64`. Set
`overflow-checks = true` in release.

---

## 8. Missing `Signer` on sensitive permissionless instructions

**What** — A state-changing instruction that should require the owner's signature
takes a plain account instead.

**Spot it** — Compare each privileged ix's context: who is `Signer<'info>` vs.
`AccountInfo`? Cross-check sibling instructions — a missing signer is usually a
divergence from a correct sibling.

**Safe pattern** — Mark the authorising party `Signer`, and assert
`account.owner == signer.key()` for token accounts.

---

## 9. Epoch / seed confusion

**What** — Using the wrong `to_le_bytes` width, or an epoch derivation that lets two
logical periods collide on one PDA.

**Spot it** — PDA seeds built from `epoch.to_le_bytes()` — confirm consistent width
(`epoch_le8`) everywhere the same PDA is derived.

**Safe pattern** — One canonical seed layout, re-derived identically at every call
site. Snapshot voting power immutably per epoch.

---

## 10. Governance / gauge capture & double-action

**What** — Double-vote, double-claim, post-vote power inflation, single-address
gauge domination.

**Spot it** — Vote/claim handlers: is there an `init` receipt PDA blocking replay?
Is voting power snapshotted immutably? Is there a per-address weight cap?

**Safe pattern** — `init` (not `init_if_needed`) on `UserVoteReceipt` /
`UserBribeClaim`; immutable `total_power_snapshot` per epoch; a weight cap in bps.

---

## 11. Oracle manipulation

**What** — Reading a manipulable spot price (a low-liquidity pool, a wash-traded
token) to value collateral or mint. Drift ($286M) combined this with social
engineering.

**Spot it** — Any external price read. Is it spot or TWAP? Manipulable in one tx?

**Safe pattern** — Prefer deterministic/invariant pricing where possible; otherwise
TWAP with sanity bounds and staleness checks. Avoid pricing off pools you don't control.

---

## 12. Admin authority & key management (opsec)

**What** — A single hot wallet holding `authority`. Pre-signed durable nonces let a
compromised signer act months later (Drift).

**Spot it** — Where does `authority` live? `transfer_authority` present and
guarded? Any durable nonces in admin flows?

**Safe pattern** — Move `authority` to an M-of-N multisig (e.g. Squads) with a
timelock before mainnet. `transfer_authority` must require the current holder's
signature and reject `Pubkey::default()`.

---

## 13. Token-2022 extensions

**What** — Transfer hooks, transfer fees, and other Token-2022 extensions change
the amount actually moved, breaking naive `amount`-based accounting.

**Spot it** — Does the program accept arbitrary mints? Does it assume the SPL Token
program, or allow Token-2022? Does it account for transfer-fee deltas?

**Safe pattern** — Whitelist accepted mints, or explicitly handle extension
semantics (read post-transfer balances rather than trusting the requested amount).

---

## 14. Supply-chain / dependency risk

**What** — A vulnerable or malicious crate in the dependency tree (cf. the
`chrono_anchor` et al. `.env`-exfiltration campaign; the `bytes` `BytesMut::reserve`
overflow RUSTSEC-2026-0007).

**Spot it**

```
cargo audit                                    # if installed
grep -c "name = " Cargo.lock                   # surface area
```

Cross-check direct deps against [RUSTSEC](https://rustsec.org/) and recent
supply-chain reports.

**Safe pattern** — Minimise direct dependencies; pin versions; `overflow-checks =
true` neutralises a whole class of arithmetic advisories; review new transitive
crates before bumping.
