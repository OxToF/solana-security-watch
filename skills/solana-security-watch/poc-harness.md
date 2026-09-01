# PoC harness — runnable proof, not just prose

A grep pattern and a paragraph are a *claim*. A transaction that succeeds when
it shouldn't, and fails once the fix lands, is *evidence*. This skill ships
runnable proof-of-concept suites under [`poc/`](../../poc/) for the classes where
that distinction matters most — five so far (#1, #2, #4, #7, #17) — so a
`TESTED`-tier claim (§0 in [`daily-watch.md`](daily-watch.md)) can point at an
actual artifact instead of an instruction to "go run a fuzzer sometime."

## Pattern: EXPLOIT / DEFENSE / POSITIVE CONTROL

Every PoC package ships one Anchor program with a vulnerable instruction next
to its fixed sibling, and a test suite with (at least) three cases:

| Case | Proves |
|---|---|
| **EXPLOIT** | The vulnerable instruction accepts attacker-controlled input it should have rejected. |
| **DEFENSE** | The fixed instruction rejects the *identical* attacker input — same bytes, same shape, only the account-validation strategy differs. |
| **POSITIVE CONTROL** | The fixed instruction is not a blanket-reject: a genuine, correctly-shaped account is still accepted, and a genuine account that legitimately fails business logic (not the security check) is rejected for the *right* reason. |

Skipping POSITIVE CONTROL is how a security fix quietly turns into a
denial-of-service — a "fix" that rejects everything passes DEFENSE for the
wrong reason. So assert the *effect*, not just pass/fail. The suites read program
state back after the transaction and assert the exact number: `unbounded-cast`
checks the ledger holds `2^64+500` after the exploit; `duplicate-mutable` checks
the balance is exactly `200` (value minted from nothing); `init-reinit` reads
`config.authority` and confirms it flipped to the attacker. The POSITIVE CONTROL
then proves the fix still accepts a genuine input and rejects a genuine
over-limit one on *business logic*, not on the security check.

## Toolchain

[LiteSVM](https://github.com/LiteSVM/litesvm) (`litesvm` on npm) — an in-process
SVM, no `solana-test-validator` needed. Tests run in milliseconds. Current
LiteSVM (≥1.0) is built on [`@solana/kit`](https://www.npmjs.com/package/@solana/kit)
("web3.js v2") — functional/`pipe`-based transaction construction, not the
class-based `@solana/web3.js` v1 API. `svm.setAccount()` is the key primitive
for these PoCs: it plants an arbitrary account (any owner, any bytes) without
needing a second "attacker program" to fabricate one.

```bash
cd poc/<name>
yarn                 # installs litesvm + deps
yarn test            # runs immediately — the compiled .so + IDL are committed,
                      # no `anchor build` required
# or, from poc/: bash run-all.sh   # every suite in one shot
```

The test runner is `mocha` launched as `NODE_OPTIONS="--import tsx" mocha` (see
each PoC's `package.json` + `.mocharc.cjs`). `tsx` transpiles the TypeScript specs
and shims `__dirname` in both CJS and ESM scopes — this sidesteps the mocha/ts-node
ESM-vs-CJS loader ambiguity that otherwise breaks `litesvm` + `@solana/kit` specs
on Node 22. A `.yarnrc` sets `ignore-engines true` so install doesn't trip on a
transitive `engines: node >= 24` pin.

To rebuild after editing a program: `anchor build` inside the PoC directory
regenerates `target/deploy/*.so` and `target/idl/*.json` (both are committed on
purpose — see the PoC's `.gitignore` — so the suite runs standalone). Discriminators
are derived in-test from the instruction name (`sha256("global:<name>")[..8]`), so
a rebuilt program needs no test edits unless you rename an instruction.

## Available PoCs

| PoC | Class (vuln-classes.md) | What it proves |
|---|---|---|
| [`poc/account-substitution/`](../../poc/account-substitution/) | #1 account substitution / missing owner check | A forged, `System`-owned account with hand-crafted bytes bypasses an `UncheckedAccount` read; the identical bytes are rejected the instant the account is typed `Account<T>`. |
| [`poc/init-reinit/`](../../poc/init-reinit/) | #2 `init_if_needed` re-initialisation | A second call to an `init_if_needed` initializer re-runs the body on the existing config PDA and overwrites `authority` with the attacker's key; plain `init` fails the replay. |
| [`poc/rounding-arbitrage/`](../../poc/rounding-arbitrage/) | #4 rounding-direction arbitrage | Redeeming 1 share of a 100/3 pool quotes 34 (ceil, favours redeemer) vs the 33 owed (floor); on an exact split both agree, proving it's a direction bug, not a constant. |
| [`poc/unbounded-cast/`](../../poc/unbounded-cast/) | #7 unbounded integer cast / truncation | `amount = 2^64 + 500` truncates to `500 <= cap` in an `as u64` bound check and passes, then credits the full `u128` — a Cetus-class width defect. |
| [`poc/duplicate-mutable/`](../../poc/duplicate-mutable/) | #17 duplicate mutable accounts | Passing one account as both `source` and `destination` of an internal transfer mints funds from nothing (100 → 200); a `source.key() != destination.key()` guard rejects it. |

## Extending

For classes #15–#18 (arbitrary CPI, account revival, duplicate mutable
accounts, bump-seed canonicalization) reach first for
[`solana-cpi-safety-skill`](https://github.com/RECTOR-LABS/solana-cpi-safety-skill)
— a sibling skill purpose-built for the CPI surface, with its own PoC suite
covering arbitrary CPI, return-data spoofing, stale-account-after-CPI, and PDA
signing. Don't duplicate that coverage here; link to it (see
[`SKILL.md`](SKILL.md)).

New PoCs in *this* skill's own scope (#5 donation/first-deposit inflation, #6
empty-set division, #9 epoch/seed confusion, #10 governance capture, #16
account close/revival are the next natural candidates — common and demonstrable
without CPI) should follow the same shape: scaffold `poc/<name>/` from an existing
PoC, a vulnerable + fixed instruction pair sharing one account struct, a LiteSVM
test with the three-case pattern above, and a `.gitignore` that ships the compiled
`target/deploy/*.so` + `target/idl/` (but not the program keypair) so the suite
runs standalone. Then add it to `poc/run-all.sh`'s sweep (it auto-discovers any
`poc/*/` with a `package.json`) and the table above.
