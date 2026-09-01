//! PoC for vuln-classes.md #17 — Duplicate mutable accounts.
//!
//! An internal `transfer` debits `source.amount` and credits `destination.amount`.
//! Nothing asserts the two are distinct accounts. If the attacker passes ONE
//! account as both `source` and `destination`, Anchor deserialises it into two
//! independent structs; at instruction exit both are serialised back in field
//! order, so the credited copy (written last) wins. A self-transfer of the full
//! balance therefore mints the amount from nothing (100 -> 200).
//!
//! `transfer_insecure` reproduces the bug. `transfer_secure` adds the
//! `source.key() != destination.key()` guard from vuln-classes.md #17's safe
//! pattern and uses checked arithmetic. Field order is `source` then
//! `destination`, so the inflation is deterministic.

use anchor_lang::prelude::*;

declare_id!("7AptpiMiL6WTBgNjDaRZgZMnbqGGiNjfjzvvvHdtxQo1");

#[program]
pub mod duplicate_mutable {
    use super::*;

    pub fn init_balance(ctx: Context<InitBalance>, amount: u64) -> Result<()> {
        ctx.accounts.balance.amount = amount;
        Ok(())
    }

    /// VULNERABLE: no distinctness check. Passing the same account for source and
    /// destination inflates it — the credited struct is serialised last and wins.
    pub fn transfer_insecure(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        let source = &mut ctx.accounts.source;
        source.amount = source.amount.saturating_sub(amount);
        let destination = &mut ctx.accounts.destination;
        destination.amount = destination.amount.saturating_add(amount);
        Ok(())
    }

    /// FIXED: reject aliased accounts before touching balances, then move funds with
    /// checked arithmetic. A self-transfer is refused; distinct accounts still work.
    pub fn transfer_secure(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        require_keys_neq!(
            ctx.accounts.source.key(),
            ctx.accounts.destination.key(),
            TransferError::DuplicateAccount
        );
        let source = &mut ctx.accounts.source;
        source.amount = source
            .amount
            .checked_sub(amount)
            .ok_or(TransferError::InsufficientFunds)?;
        let destination = &mut ctx.accounts.destination;
        destination.amount = destination
            .amount
            .checked_add(amount)
            .ok_or(TransferError::MathOverflow)?;
        Ok(())
    }
}

#[account]
pub struct Balance {
    pub amount: u64, // 8
}

impl Balance {
    pub const LEN: usize = 8 + 8;
}

#[derive(Accounts)]
pub struct InitBalance<'info> {
    #[account(init, payer = payer, space = Balance::LEN)]
    pub balance: Account<'info, Balance>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub source: Account<'info, Balance>,
    #[account(mut)]
    pub destination: Account<'info, Balance>,
}

#[error_code]
pub enum TransferError {
    #[msg("source and destination must be distinct accounts")]
    DuplicateAccount,
    #[msg("insufficient funds in source")]
    InsufficientFunds,
    #[msg("destination balance overflowed")]
    MathOverflow,
}
