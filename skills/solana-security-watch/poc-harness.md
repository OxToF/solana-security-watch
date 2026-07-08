# PoC harness — runnable proof, not just prose

A grep pattern and a paragraph are a *claim*. A transaction that succeeds when
it shouldn't, and fails once the fix lands, is *evidence*. This skill ships
runnable proof-of-concept suites under [`poc/`](../../poc/) for the classes where
that distinction matters most — starting with the highest-yield class, #1
account substitution — so a `TESTED`-tier claim (§0 in
[`daily-watch.md`](daily-watch.md)) can point at an actual artifact instead of
an instruction to "go run a fuzzer sometime."

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
wrong reason. Always assert the failure mode, not just pass/fail: see
[`poc/account-substitution/tests/account-substitution.ts`](../../poc/account-substitution/tests/account-substitution.ts),
which reads the emitted program log and confirms it's specifically
`AccountOwnedByWrongProgram` (Anchor error 3007) — not an unrelated crash.

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
```

To rebuild after editing a program: `anchor build` inside the PoC directory
regenerates `target/deploy/*.so` and `target/idl/*.json` (both are committed on
purpose — see the PoC's `.gitignore` — so the suite runs standalone).

## Available PoCs

| PoC | Class (vuln-classes.md) | What it proves |
|---|---|---|
| [`poc/account-substitution/`](../../poc/account-substitution/) | #1 account substitution / missing owner check | A forged, `System`-owned account with hand-crafted bytes bypasses an `UncheckedAccount` read; the identical bytes are rejected the instant the account is typed `Account<T>`. |

## Extending

For classes #15–#18 (arbitrary CPI, account revival, duplicate mutable
accounts, bump-seed canonicalization) reach first for
[`solana-cpi-safety-skill`](https://github.com/RECTOR-LABS/solana-cpi-safety-skill)
— a sibling skill purpose-built for the CPI surface, with its own PoC suite
covering arbitrary CPI, return-data spoofing, stale-account-after-CPI, and PDA
signing. Don't duplicate that coverage here; link to it (see
[`SKILL.md`](SKILL.md)).

New PoCs in *this* skill's own scope (#2, #5, #9, #10, #16, #17 are the next
natural candidates — donation attacks and governance capture are common and
don't need CPI to demonstrate) should follow the same shape: `anchor init` in
`poc/<name>/`, vulnerable + fixed instruction pair sharing one account struct,
LiteSVM test with the three-case pattern above, and a `.gitignore` that ships
the compiled `target/deploy/*.so` + `target/idl/` (but not the program keypair)
so the suite runs standalone.
