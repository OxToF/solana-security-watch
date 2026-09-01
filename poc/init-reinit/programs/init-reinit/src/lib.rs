//! PoC for vuln-classes.md #2 — `init_if_needed` re-initialisation.
//!
//! A config PDA records its `authority`. The insecure initializer uses
//! `init_if_needed` and unconditionally writes `authority = signer`. Because
//! `init_if_needed` runs the handler body even when the account ALREADY exists, a
//! second caller (the attacker) re-runs it and overwrites `authority` with their
//! own key — a full ownership takeover of an already-initialised account.
//!
//! `initialize_insecure` reproduces the bug. `initialize_secure` fixes it with a
//! plain `init` (the transaction fails on replay because the account already
//! exists) — exactly the "prefer plain init when one-time creation is the intent"
//! safe pattern in vuln-classes.md #2. Both target the same PDA (seeds = [b"config"]),
//! so the two variants act on one address.

use anchor_lang::prelude::*;

declare_id!("6Gcu3VQHJFHq4jeM7iRcYsvXBRDzjv4vaxiqUnFfaFn8");

#[program]
pub mod init_reinit {
    use super::*;

    /// VULNERABLE: `init_if_needed` + unconditional `authority` write. Re-callable
    /// by anyone; each call overwrites the authority with the current signer.
    pub fn initialize_insecure(ctx: Context<InitializeInsecure>) -> Result<()> {
        ctx.accounts.config.authority = ctx.accounts.authority.key();
        Ok(())
    }

    /// FIXED: plain `init` — the account can be created exactly once. A replay by
    /// the attacker fails at the constraint layer before the body runs.
    pub fn initialize_secure(ctx: Context<InitializeSecure>) -> Result<()> {
        ctx.accounts.config.authority = ctx.accounts.authority.key();
        Ok(())
    }
}

#[account]
pub struct Config {
    pub authority: Pubkey, // 32
}

impl Config {
    pub const LEN: usize = 8 + 32;
}

#[derive(Accounts)]
pub struct InitializeInsecure<'info> {
    #[account(
        init_if_needed,
        payer = authority,
        space = Config::LEN,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeSecure<'info> {
    #[account(
        init,
        payer = authority,
        space = Config::LEN,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
