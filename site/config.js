// Landing configuration. Edit, then push (Vercel auto-redeploys from `site/`).
//
//   SSW_API_BASE : deployed backend base URL. null = payment works, delivery manual.
//   SSW_CONTACT  : email that receives leads / signatures / watch requests.
//   SSW_WALLET   : USDC (Solana) recipient address.
//   SSW_RPC      : Solana RPC endpoint (replace the public one before real traffic).
//   SSW_AMOUNT_USDC : price in USDC. Set to 1 for your first test payment.
window.SSW_API_BASE    = null;
window.SSW_CONTACT     = "solanawatchdog@proton.me";
window.SSW_WALLET      = "7yMnWMrxzZ3YCtWXRsZEhAFwexHoJzBJy8RgN7Lhvy1P";
window.SSW_RPC         = "https://api.mainnet-beta.solana.com";
window.SSW_AMOUNT_USDC = 69;

// Reserved for the upcoming EVM scanner (not wired yet):
// window.SSW_WALLET_EVM = "0x0e659996C75dcB352E95e130D79831e3e2fa82a8";
