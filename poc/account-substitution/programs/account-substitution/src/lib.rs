//! PoC for vuln-classes.md #1 — Account substitution / missing owner check.
//!
//! Mirrors the skill's own "vesting lock bypass" case study (skill/case-studies.md):
//! an `unstake` instruction that reads a vesting account as `UncheckedAccount` and
//! manually deserializes it, without confirming `owner == program_id`. A forged
//! account with attacker-chosen bytes at the same offsets passes the check.
//!
//! `unstake_insecure` reproduces the bug. `unstake_secure` fixes it by switching to
//! Anchor's typed `Account<'info, VestingState>`, which enforces the discriminator
//! and owner check before the handler body ever runs — exactly the "safe pattern"
//! documented in vuln-classes.md #1.

use anchor_lang::prelude::*;

declare_id!("EnhLFLMZAYgVFr2gSeNWuWUCimsMkeaxakNXbPHfdimX");

#[program]
pub mod account_substitution {
    use super::*;

    pub fn init_vesting(ctx: Context<InitVesting>, locked: u64) -> Result<()> {
        let vesting = &mut ctx.accounts.vesting;
        vesting.owner = ctx.accounts.owner.key();
        vesting.locked = locked;
        vesting.claimed = 0;
        Ok(())
    }

    /// VULNERABLE: `vesting` is `UncheckedAccount` — no owner check, no PDA
    /// re-derivation. Bytes are read at fixed offsets after the 8-byte Anchor
    /// discriminator: owner(32) | locked(8) | claimed(8).
    pub fn unstake_insecure(ctx: Context<UnstakeInsecure>) -> Result<()> {
        let data = ctx.accounts.vesting.try_borrow_data()?;
        require!(data.len() >= 56, VestingError::MalformedAccount);
        let locked = u64::from_le_bytes(data[40..48].try_into().unwrap());
        let claimed = u64::from_le_bytes(data[48..56].try_into().unwrap());
        require!(claimed >= locked, VestingError::StillLocked);
        Ok(())
    }

    /// FIXED: `vesting` is `Account<'info, VestingState>`. Anchor deserializes via
    /// the typed discriminator and rejects any account not owned by this program
    /// before the handler body runs — a forged account never reaches the require!.
    pub fn unstake_secure(ctx: Context<UnstakeSecure>) -> Result<()> {
        let vesting = &ctx.accounts.vesting;
        require!(vesting.claimed >= vesting.locked, VestingError::StillLocked);
        Ok(())
    }
}

#[account]
pub struct VestingState {
    pub owner: Pubkey, // 32
    pub locked: u64,   // 8
    pub claimed: u64,  // 8
}

impl VestingState {
    pub const LEN: usize = 8 + 32 + 8 + 8;
}

#[derive(Accounts)]
pub struct InitVesting<'info> {
    #[account(init, payer = owner, space = VestingState::LEN)]
    pub vesting: Account<'info, VestingState>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UnstakeInsecure<'info> {
    /// CHECK: intentionally unchecked — this is the bug under test.
    pub vesting: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct UnstakeSecure<'info> {
    pub vesting: Account<'info, VestingState>,
}

#[error_code]
pub enum VestingError {
    #[msg("account too small to hold VestingState")]
    MalformedAccount,
    #[msg("vesting is still locked")]
    StillLocked,
}
