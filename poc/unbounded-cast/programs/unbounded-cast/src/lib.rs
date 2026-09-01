//! PoC for vuln-classes.md #7 — Unbounded integer cast / truncation.
//!
//! A protocol enforces a per-call credit cap. The amount is a full-width `u128`
//! (assembled here from a high and low limb, as it would be from 64.64 fixed-point
//! math or a `u128` accumulator). The insecure handler narrows that value to
//! `u64` **inside the cap comparison** — silently dropping the high 64 bits — while
//! crediting the full `u128`. Any amount congruent to a small number mod 2^64
//! passes a small cap yet credits an astronomically larger balance.
//!
//! This is the Cetus ($200M, 2024) class: a defective width check on value math.
//! The truncation happens on an `as u64` cast, so it is deterministic regardless
//! of `overflow-checks` — casts never panic (unlike wrapping arithmetic).
//!
//! `credit_insecure` reproduces the bug. `credit_secure` fixes it by comparing at
//! full `u128` width — exactly the "saturate/require bounds before any narrowing
//! cast" safe pattern in vuln-classes.md #7.

use anchor_lang::prelude::*;

declare_id!("A3ofMnuA4GAvRmZTi3q3kucyGnBUPJKku7VrfGrAn7Z");

/// Per-call credit cap the protocol intends to enforce (1,000,000 base units).
pub const CREDIT_CAP: u64 = 1_000_000;

#[program]
pub mod unbounded_cast {
    use super::*;

    pub fn init_ledger(ctx: Context<InitLedger>) -> Result<()> {
        ctx.accounts.ledger.credited = 0;
        Ok(())
    }

    /// VULNERABLE: the cap check narrows `amount` to `u64` before comparing, so the
    /// high 64 bits never reach the comparison. `amount = 2^64 + 500` truncates to
    /// `500 <= CREDIT_CAP` and passes, but the full `amount` is credited.
    pub fn credit_insecure(ctx: Context<Credit>, amount_hi: u64, amount_lo: u64) -> Result<()> {
        let amount: u128 = ((amount_hi as u128) << 64) | (amount_lo as u128);

        // BUG: `amount as u64` drops the high limb before the bound is checked.
        require!(amount as u64 <= CREDIT_CAP, LedgerError::ExceedsCap);

        let ledger = &mut ctx.accounts.ledger;
        ledger.credited = ledger
            .credited
            .checked_add(amount)
            .ok_or(LedgerError::MathOverflow)?;
        Ok(())
    }

    /// FIXED: the bound is checked at full `u128` width, so no high bits are lost.
    /// An over-cap amount is rejected before any state changes.
    pub fn credit_secure(ctx: Context<Credit>, amount_hi: u64, amount_lo: u64) -> Result<()> {
        let amount: u128 = ((amount_hi as u128) << 64) | (amount_lo as u128);

        // FIX: compare at the same width as the value being bounded.
        require!(amount <= CREDIT_CAP as u128, LedgerError::ExceedsCap);

        let ledger = &mut ctx.accounts.ledger;
        ledger.credited = ledger
            .credited
            .checked_add(amount)
            .ok_or(LedgerError::MathOverflow)?;
        Ok(())
    }
}

#[account]
pub struct Ledger {
    pub credited: u128, // 16
}

impl Ledger {
    pub const LEN: usize = 8 + 16;
}

#[derive(Accounts)]
pub struct InitLedger<'info> {
    #[account(init, payer = payer, space = Ledger::LEN)]
    pub ledger: Account<'info, Ledger>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Credit<'info> {
    #[account(mut)]
    pub ledger: Account<'info, Ledger>,
}

#[error_code]
pub enum LedgerError {
    #[msg("amount exceeds the per-call credit cap")]
    ExceedsCap,
    #[msg("credited total overflowed")]
    MathOverflow,
}
