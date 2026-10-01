# Porting Solidity to Anchor: the traps

A Solidity contract translated line by line into Anchor usually compiles. Many of
the bugs live in what the translation keeps. EVM habits that are safe there
become holes on Solana, because the runtime makes different guarantees. This
file lists those habits, what goes wrong, and the Anchor pattern that closes each
one.

Most entries come from porting a ve(3,3) DEX (Velodrome / Aerodrome lineage)
from the EVM to Solana: **Soladrome** ([`OxToF/soladrome`](https://github.com/OxToF/soladrome)).
Where an entry was hit there, it cites the public commit or file that fixed it.
Entries without a citation are general Solana facts that the port relied on.

Each entry: **EVM habit** → **What happens on Solana** → **Anchor fix** →
**Test it** → **Evidence**. Numbers like `#17` point to
[`vuln-classes.md`](vuln-classes.md).

Read it in this order when planning a port: §1 (who can move value), §2
(accounts), §3 (state layout), then the rest.

---

## 1. Ownership, balances and who can move value

### 1.1 "Transfers go through my contract" — they do not

**EVM habit.** An ERC-20 you deploy runs your code on every transfer:
`_beforeTokenTransfer` / `_update` checkpoint votes, settle rewards, block a
transfer while a position is locked.

**On Solana.** An SPL token transfer calls the **Token program**, never yours.
There is no hook on classic SPL Token, and you cannot add one after the mint
exists. "The user cannot unstake, so the tokens cannot move" is false: unstaking
is your instruction, a transfer is not. Any right you compute from a **wallet
token balance** (votes, fees, rewards, borrow capacity) can be moved to a fresh
wallet and claimed again there.

**Anchor fix**, best first:
1. **Do not make it a token.** Keep the position as a number in a PDA the program
   owns (`UserPosition.amount`). Nothing to transfer, nothing to contain.
2. If it must be a token: take **custody** (the program holds it in a PDA-owned
   vault for the lock's duration), or create the mint with a freeze authority you
   keep (it cannot be added after creation).
3. If wallet balances must still count: pay on `min(program-recorded deposit,
   wallet balance)`. It requires both, and the same tokens cannot satisfy both in
   two wallets at once.

**Test it.** Stake in wallet A, transfer to a fresh wallet B, call every
reward/vote/borrow/claim instruction from B. Each must pay zero or refuse.

**Evidence.** Soladrome hit this three times before removing the token:
- LP rewards were paid on the wallet's LP balance. `0180ca3` moved them to the
  program-recorded deposit (`reward_basis = min(lp_amount, wallet_lp)`,
  `programs/soladrome/src/instructions/amm.rs`).
- Fees, votes and borrow capacity were read from balances. `3022686` closed
  three balance-as-entitlement holes, each proved by mutation; the `fee_basis`
  doc comment in `programs/soladrome/src/math.rs` records a stamped-at-zero
  position measured claiming fourteen times the fee vault.
- `bc13d62` made the staked asset a non-transferable position, which removed the
  whole class instead of containing it.

### 1.2 "A new holder starts from zero" — only if every path stamps the baseline

**EVM habit.** MasterChef-style accounting: `rewardDebt = amount * accPerShare`
set on deposit.

**On Solana.** Positions are PDAs opened with `init_if_needed` from **several**
instructions (stake, vote, borrow, lock…). Any path that creates the account
without stamping the debt baseline leaves it at 0: the first claim reads
"staked since genesis" and pays the whole accumulator.

**Anchor fix.** One function opens a position and always stamps the baseline;
every `init_if_needed` path calls it. List the paths by grepping **every**
instruction file, not just `lib.rs`.

**Test it.** For each instruction that can create the position: open it that
way on a fresh wallet, then claim. Expect zero.

**Evidence.** `3022686` (one of the three holes) and `ee8bd59` ("one function
books an LP deposit").

### 1.3 `approve(spender, amount)` per spender — one delegate per token account

**EVM habit.** A user grants allowances to several contracts independently.

**On Solana.** An SPL token account has **one** delegate and one delegated
amount. A second `approve` replaces the first. Two features that each ask for
an allowance on the same token account silently cancel each other.

**Anchor fix.** Prefer a program-owned vault the user deposits into, over a
standing allowance. If several features need one, give them a single shared
budget, and design every consumer for "the allowance can be lower than what I
need": spend up to it, keep the rest accrued, never revert forever.

**Test it.** Grant feature A, then feature B, then run A. Run a consumer with
an allowance below its pending amount: it must make partial progress, not fail
on every call.

**Evidence.** `e991ec6`: a voting round exercised the whole pending amount with
no cap, so once pending exceeded the allowance it failed on every run; it now
spends what the budget pays and keeps the rest accrued.

### 1.4 `msg.sender` and `onlyOwner`

**EVM habit.** `msg.sender` is the caller; `owner` is a storage slot.

**On Solana.** Any account can be passed; only `Signer<'info>` proves a
signature. An admin check written as `has_one = authority` needs the
`authority` account to be a `Signer` too. There is no `tx.origin`.

**Anchor fix.** `#[account(address = state.authority)] pub authority: Signer<'info>`.
Grep for `has_one` gives false negatives when the check is written with
`address =`; review both (#8).

---

## 2. Accounts are inputs

### 2.1 "Storage is mine" — every account is caller-supplied

**EVM habit.** `mapping(address => Position)` is your storage; nobody can hand
you a fake one.

**On Solana.** The caller supplies every account. `Account<'info, T>` checks the
owner program and the discriminator; `UncheckedAccount`, `AccountInfo` and
manual deserialisation check nothing (#1, #3). Seeds pin a PDA to its key;
without them a valid account of the right type but the **wrong instance**
(someone else's position, another pool) is accepted.

**Anchor fix.** Seeds + bump on every PDA. `UncheckedAccount` only with an
explicit owner check, discriminator check and seed re-derivation, and a
`/// CHECK:` that says which.

### 2.2 Passing the same account twice

**EVM habit.** Two storage references to different mappings cannot alias by
accident.

**On Solana.** Nothing stops a caller from passing one account in two slots.
Anchor does **not** refuse it, and at the end of the instruction it writes
every mutable program-owned copy back **in field order**. A stale copy written
last silently reverts the real update (#17).

**Anchor fix.** For every pair of same-type, program-owned mutable accounts:
`require!(a.key() != b.key())`. Optional accounts that a route does not use
must be **absent**, not merely unread.

**Test it.** Pass the same account in both slots. Then mutate *both* guards
(distinctness and absence) together: removing only one can leave the test
passing because the other still holds.

**Evidence.** `832a775`: a cranker could pass the sale pool again as an unused
optional hop; its stale copy, written last, reverted the reserve update. The
comment above the fix in `programs/soladrome/src/instructions/auto_lp.rs` gives
the mechanism. Token accounts passed twice do not trigger this: they are owned
by the token program and Anchor never writes them back.

### 2.3 The token account you send to may not exist

**EVM habit.** `transfer(to, amount)` works for any address.

**On Solana.** A recipient needs a token account for that mint, usually the
associated token account (ATA), and it may not exist yet. An instruction that
declares it without `init_if_needed` fails with `AccountNotInitialized` (3012).
Wrapped SOL is an ordinary ATA that clients often close after unwrapping.

**Anchor fix.** Either `init_if_needed` (the payer funds the rent) or have the
client create the ATA idempotently before the call, for **both** sides,
wrapped SOL included.

### 2.4 One token standard — or two token programs per pair

**EVM habit.** Every ERC-20 answers the same interface.

**On Solana.** SPL Token and Token-2022 are different programs. A pair can mix
them (a Token-2022 stock token quoted in classic USDC), so one `token_program`
account cannot serve both sides.

**Anchor fix.** `Interface<'info, TokenInterface>` + `InterfaceAccount<'info, Mint>`,
**one token program per mint**, each bound with `mint::token_program`. Use
`transfer_checked`.

**Evidence.** `08d1512` (Token-2022 support): pools, bribes and the partner
stream take one token program per side.

### 2.5 Token-2022 extensions break vault accounting

**EVM habit.** Fee-on-transfer tokens are an edge case you document.

**On Solana.** Token-2022 extensions change what a vault receives or whether it
can move at all (#13). They must be read **at admission**, before any account
is created with `init` on seeds derived from the mint, because a mint found
unusable afterwards leaves seeds that can never be reopened.

| Extension | What it does to a vault | Decision in Soladrome |
|---|---|---|
| `TransferFeeConfig` | vault receives less than the amount booked, cumulatively | refused |
| `TransferHook` with a program set | needs extra accounts; every transfer fails | refused |
| `TransferHook` unset | can be armed later by its authority | allowed, risk disclosed |
| `DefaultAccountState::Frozen` | vault born frozen | refused |
| `PermanentDelegate` | issuer can move tokens out of any account | allowed; never place protocol liquidity there |
| `PausableConfig` | issuer can freeze all transfers | allowed, disclosed |
| `ScaledUiAmountConfig` | display multiplier; base units unchanged | allowed; off-chain pricing must apply it |

**Evidence.** `programs/soladrome/src/token_ext.rs` (`require_supported_mint`),
one function for the whole admission policy.

---

## 3. State layout

### 3.1 Appending a storage variable — accounts do not grow

**EVM habit.** Add a variable at the end of storage in an upgrade.

**On Solana.** An account's size is fixed at creation. Changing `LEN` only
affects **new** accounts. An existing singleton is now too short to deserialise,
and **every** instruction that loads it fails (3003 `AccountDidNotDeserialize`).
Anchor's TypeScript coder is lenient (it reads zeros past the end), so the UI
keeps displaying normal values while every transaction fails.

**Anchor fix.**
- Reserve spare bytes in every long-lived account from the start, and carve new
  fields from them.
- Pin the size with a compile-time assert (`const _: () = assert!(...)`).
- To grow a live account: a dedicated, authority-gated migration that reads it as
  raw bytes (an `Account<T>` of the new type would fail to deserialise),
  re-derives its seeds, tops up rent and reallocs.
- Before shipping a new field, compare the **on-chain** size of existing accounts
  with the new layout.

**Evidence.** `88c1ab2` (`migrate_protocol_state`, realloc of the singleton
after an appended field).

### 3.2 Unbounded arrays and iteration

**EVM habit.** Arrays of holders, loops bounded by gas.

**On Solana.** An account is capped at 10 MiB and grows by at most 10 KiB per
instruction; a transaction has a compute budget (1.4 M CU) and a size limit
(1 232 bytes), which caps how many accounts it can reference. You cannot iterate
over "all positions": they are separate accounts, which the program cannot even
list.

**Anchor fix.** One PDA per (user, key). Global aggregates are maintained
incrementally (accumulators), never recomputed by iteration. Long routes use
address lookup tables.

### 3.3 Upgradeable by default

**EVM habit.** A contract is immutable unless you deploy a proxy.

**On Solana.** A program is **upgradeable by default**, and its upgrade
authority is the deploying keypair: one key that can replace the code and
everything the program controls. Moving the authority to a multisig (Squads)
with a time lock, or making the program immutable, is a separate, deliberate
step.

**Check it.** `/agent/program` on Solana Watchdog reads the authority and, for
Squads v4, proves the multisig by re-deriving its vault.

### 3.4 The binary records line numbers

**EVM habit.** Moving code around does not change the deployed bytecode's
behaviour, and verification matches source to bytecode.

**On Solana.** Anchor's `require!` / `error!` capture `line!()`. Adding a line
above the program code, even a test module declaration, changes the `.so`
**at the same size**, which looks like a non-deterministic build. The SBF build
is deterministic: a differing hash always has a cause, and it bisects.

**Anchor fix.** Declare test modules at the **end** of `lib.rs`. To check that
a deployed binary is a given commit, compare hashes of a dump with a build, not
sizes.

---

## 4. Arithmetic

### 4.1 Overflow is not checked by default

**EVM habit.** Solidity ≥ 0.8 reverts on overflow.

**On Solana.** Rust release builds **wrap** unless the profile says otherwise.

**Anchor fix.** `overflow-checks = true` under `[profile.release]` in the
workspace `Cargo.toml`, plus `checked_*` / `saturating_*` where the intent
differs. Cast with `try_from`, never `as`, when narrowing (#7). Soladrome's
workspace sets it.

### 4.2 Rounding direction

Same rule as on the EVM, with more ways to repeat a call cheaply: round **in the
protocol's favour** on every user-facing conversion (#4), and check empty-pool
and first-deposit cases (#5, #6).

---

## 5. Invariants and atomicity

### 5.1 One guard, every call site

**EVM habit.** A modifier on the swap function protects the invariant.

**On Solana.** Several instructions can move the same reserves: the AMM swap, a
flash-arbitrage path that does not call the swap, an automation route. A guard
written into one of them protects that one.

**Anchor fix.** One `require_*` function that every reserve-moving instruction
calls at its end, and a comment at the guard that lists its call sites. When a
path is profitable only on average (an arbitrage that crosses the price), check
the **final** state, not the average execution price.

**Evidence.** `programs/soladrome/src/instructions/amm.rs`
(`require_floor_respected`), called from the AMM swap, `auto_lp.rs` and
`curve.rs` (`flash_arbitrage`), introduced in `e257457`.

### 5.2 Reentrancy and callbacks

**On Solana.** A program cannot be re-entered through a CPI chain (A → B → A is
refused); only direct self-recursion is allowed. The EVM reentrancy guard
mostly disappears. What replaces it is **arbitrary CPI** (#15): an
instruction that invokes a program the caller chose. Pin every invoked program
(`Program<'info, T>` or `address =`).

### 5.3 Permissionless keepers

**EVM habit.** A keeper calls `harvest()`; the contract reads its own storage.

**On Solana.** A permissionless crank passes **all** the accounts. Every account
it supplies must be validated as if hostile, including optional ones the current
route does not use (§2.2), and the crank must make bounded progress when funds
or allowances are short (§1.3), never fail on every run.

---

## 6. Transactions and clients

### 6.1 Blockhashes expire

A transaction carries a recent blockhash and dies about 150 slots later (around
a minute nominally; we measured about 25 s on devnet under load). Fetch it
**after** the user has signed, at send time, not when the transaction is built.

### 6.2 Durable nonces

Pre-signed transactions use a durable nonce. Two runtime rules matter:
- `nonceAdvance` must be the **first** instruction. Anything before it, even a
  `ComputeBudget`, and the transaction is never processed.
- A nonce transaction that **fails** still consumes the nonce. Simulate before
  broadcasting, or the pre-signed transaction is burnt.

### 6.3 Regenerate the IDL with the program

An IDL older than the program puts accounts in the wrong order: the client sends
valid-looking transactions that fail on seeds (`ConstraintSeeds`). Rebuild and
ship the IDL in the same change as any account-struct edit. Adding an
**argument** is not symmetrical with adding an account: deploy the program
before the client that sends it.

---

## Port review checklist

- [ ] No right is computed from a transferable token balance alone (§1.1).
- [ ] Every path that opens a position stamps its baselines (§1.2).
- [ ] No two features compete for one token-account delegate (§1.3).
- [ ] Every PDA has seeds; every `UncheckedAccount` checks owner, discriminator, seeds (§2.1).
- [ ] Every pair of same-type mutable program accounts is proved distinct; unused optional accounts are absent (§2.2).
- [ ] Recipient token accounts exist or are created, both sides, wrapped SOL included (§2.3).
- [ ] One token program per mint; `transfer_checked` (§2.4).
- [ ] Token-2022 extensions read at admission (§2.5).
- [ ] Long-lived accounts have spare bytes and a size assert; growth goes through a migration (§3.1).
- [ ] No iteration over users; aggregates are incremental (§3.2).
- [ ] Upgrade authority is a multisig with a time lock, or none (§3.3).
- [ ] `overflow-checks = true`; narrowing casts use `try_from` (§4.1).
- [ ] Each invariant guard is called by every instruction that can break it (§5.1).
- [ ] Every CPI target is pinned (§5.2).
- [ ] Cranks validate every account and make bounded progress (§5.3).
- [ ] Clients fetch the blockhash at send time; IDL rebuilt with the program (§6).

A checklist is a starting point, not an audit.
