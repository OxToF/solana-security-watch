# Security watch pass — Orca Whirlpools

**Target:** [`orca-so/whirlpools`](https://github.com/orca-so/whirlpools) ·
`programs/whirlpool` (~52k LOC Rust/Anchor) · repo tip `3b47341` (2026-08-26)
**Deployed program (mainnet):** `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc`
**Date:** 2026-09-01 · **Analyst:** OxToF (solana-security-watch)

> **Headline: no live vulnerability found.** This is a hardening / dependency-hygiene
> pass over a mature, repeatedly-audited target. Every dependency advisory that the
> collector flagged was triaged to *not-applicable* or *already mitigated*; the two
> code observations are defense-in-depth with no exploit path. Everything below uses
> only public source and public advisory data. There is nothing here that warrants
> embargoed disclosure; the two hardening notes are offered as upstream PRs.

## Method

1. **Collect** — `solana-security-watch collect` over the Solana/Anchor dependency
   surface (RustSec/OSV). Three advisories landed on crates Whirlpools actually uses.
2. **Confront** — each advisory checked against the *pinned* version in
   `Cargo.lock`, and the flagged code paths read directly.
3. **Report** — findings below, severity per the skill's rubric, each with the
   fact that establishes it.

## Dependency advisories — triaged

| Advisory | Crate (used at) | Pinned | Verdict |
|---|---|---|---|
| [RUSTSEC-2026-0260](https://rustsec.org/advisories/RUSTSEC-2026-0260.html) / MAL-2026-14336 — malicious `arrayref` release | `arrayref` (`pinocchio/utils/account_load.rs`, `state/tick_array.rs`, …) | `=0.3.9` | **Not affected.** Malicious code shipped in **0.3.10**; the exact `=0.3.9` pin blocks the auto-upgrade. The pin *is* the mitigation. |
| [RUSTSEC-2026-0144](https://rustsec.org/advisories/RUSTSEC-2026-0144.html) (CVE-2026-45137) — `Program<System>` not validated | `anchor-lang` (30 `Program<'info, System>` sites) | `0.32.1` | **Not affected.** Introduced in `1.0.0`, fixed in `1.0.2`. 0.32.1 predates the affected line. |
| [RUSTSEC-2026-0146](https://rustsec.org/advisories/RUSTSEC-2026-0146.html) — `InterfaceAccount` type substitution | `anchor-lang` (used in ~10 instruction contexts) | `0.32.1` | **Not affected.** Introduced in `1.0.0-rc.1`, fixed in `1.0.0-rc.2`. 0.32.1 predates it. |

**Recommendation (Info):** keep the `=0.3.9` `arrayref` pin and record a checksum for
it; when Whirlpools eventually moves to Anchor `1.x`, land on **≥ 1.0.2** so both
Anchor advisories are covered in one jump.

## Code observations — hardening only, no live impact

### [LOW] `overflow-checks = false` in `[profile.release]`

`Cargo.toml:14` disables overflow checks in release. Per class #7, this turns an
arithmetic overflow into a silent wrap instead of a panic. **Impact here is limited:**
the value math is pervasively `checked_*` / `u128`-widened, and the liquidity path
was reviewed for narrowing casts (see below). Still, enabling `overflow-checks = true`
is cheap defense-in-depth that neutralises a whole advisory class at once.

### [INFO] Raw-cast tick-array loader lacks a compile-time size assertion

`pinocchio/state/whirlpool/tick_array/loader.rs` casts an account byte buffer to
`MemoryMappedDynamicTickArray` via a raw pointer, where the struct is sized for the
*maximum* tick array (~10,004 bytes) though the account starts smaller and grows via
`realloc`. This is **memory-safe today**: Solana guarantees `MAX_PERMITTED_DATA_INCREASE`
= 10,240 bytes of writable padding, and 10,004 < 10,240 — a known, deliberate
technique, not an oversight. The gap is that the invariant is enforced by *nothing at
compile time*: a future `NUM_REWARDS` bump, an added tick field, or a tick-array-size
change would silently erode the 236-byte margin. **Recommendation:** add a
`const _: () = assert!(core::mem::size_of::<MemoryMappedDynamicTickArray>() <= MAX_PERMITTED_DATA_INCREASE);`
guard so the invariant fails the build rather than in production.

## What was reviewed and found sound

The deployed liquidity path runs through hand-rolled **Pinocchio** handlers (the
custom `entrypoint.rs` is the default build), replacing Anchor's automatic checks.
All six handlers (increase/decrease liquidity, their v2 variants, reposition,
increase-by-token-amounts) were read: each re-verifies, by hand, every relation
Anchor would enforce — `position.whirlpool == whirlpool`, the position-NFT authority
(mint + `amount == 1` + delegate/owner + signer), `token_vault_{a,b}` against the
whirlpool, mints (v2), and tick-array ↔ whirlpool linkage — plus owner + discriminator
on every account load. No account-substitution, missing-signer/owner, relational, or
transfer-fee-direction gap was found. This is consistent with the program's repeated
2026 audits.

---

*Generated with the [`solana-security-watch`](https://github.com/OxToF/solana-security-watch)
skill: `collect` for the advisory feed, the vuln-class checklist for the code pass.*
