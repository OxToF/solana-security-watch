//! PoC for vuln-classes.md #4 — Rounding-direction arbitrage.
//!
//! A share-based vault redeems assets: `assets_out = shares * total_assets /
//! total_shares`. The insecure path rounds the payout **up** (in the redeemer's
//! favour); the secure path rounds **down** (in the protocol's favour). Rounding a
//! payout up hands out one base unit more than the pool owes on every inexact
//! division — repeated, this drains reserves (the Balancer V2 `mulDown` class).
//!
//! Each call records the quoted payout in a `Meter` PDA so the test can read the
//! exact number. `redeem_insecure` reproduces the bug; `redeem_secure` applies the
//! "round down what you pay out" safe pattern from vuln-classes.md #4. The redeem
//! math is deterministic and self-contained (no token CPI); the quoted amount is
//! what a real vault would transfer out.

use anchor_lang::prelude::*;

declare_id!("4hBF3mmenLCt8ps62uuhrKDGFwufBy616G96fNqj6Dcq");

/// Fixed pool used by the PoC: 100 assets backing 3 shares. Redeeming 1 share owes
/// exactly 33.33... assets — the inexact case that exposes the rounding direction.
pub const TOTAL_ASSETS: u128 = 100;
pub const TOTAL_SHARES: u128 = 3;

#[program]
pub mod rounding_arbitrage {
    use super::*;

    pub fn init_meter(ctx: Context<InitMeter>) -> Result<()> {
        ctx.accounts.meter.last_payout = 0;
        Ok(())
    }

    /// VULNERABLE: rounds the payout UP (ceil). Redeeming 1 share of a 100/3 pool
    /// quotes 34 instead of the 33 owed — one unit skimmed from reserves per call.
    pub fn redeem_insecure(ctx: Context<Redeem>, shares: u64) -> Result<()> {
        let numer = (shares as u128).checked_mul(TOTAL_ASSETS).unwrap();
        // ceil division = round up = favour the redeemer (the bug)
        let payout = numer.div_ceil(TOTAL_SHARES);
        ctx.accounts.meter.last_payout = payout as u64;
        Ok(())
    }

    /// FIXED: rounds the payout DOWN (floor). Redeeming 1 share quotes 33 — the
    /// remainder stays with the pool, never with the redeemer.
    pub fn redeem_secure(ctx: Context<Redeem>, shares: u64) -> Result<()> {
        let numer = (shares as u128).checked_mul(TOTAL_ASSETS).unwrap();
        // floor division = round down = favour the protocol (the fix)
        let payout = numer / TOTAL_SHARES;
        ctx.accounts.meter.last_payout = payout as u64;
        Ok(())
    }
}

#[account]
pub struct Meter {
    pub last_payout: u64, // 8
}

impl Meter {
    pub const LEN: usize = 8 + 8;
}

#[derive(Accounts)]
pub struct InitMeter<'info> {
    #[account(init, payer = payer, space = Meter::LEN, seeds = [b"meter"], bump)]
    pub meter: Account<'info, Meter>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Redeem<'info> {
    #[account(mut, seeds = [b"meter"], bump)]
    pub meter: Account<'info, Meter>,
}
