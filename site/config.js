// Landing configuration. Edit, then push (Vercel auto-redeploys once Root Directory
// is set to `site`, or run `npx vercel --prod` from this folder).
//
//   SSW_API_BASE : your deployed backend base URL (no trailing slash). While null,
//                  payment still works but the report is delivered manually (the
//                  payer is told to email you the transaction signature).
//   SSW_CONTACT  : the email that receives leads / signatures / watch requests.
//   SSW_WALLET   : your USDC (Solana) recipient address.
//   SSW_RPC      : a Solana RPC endpoint. The public one is rate-limited; replace
//                  it with your own (Helius/QuickNode) before real traffic.
//   SSW_AMOUNT_USDC : price in USDC. Set to 1 for your first test payment.
window.SSW_API_BASE    = null;
window.SSW_CONTACT     = "solanawatchdog@proton.me";
window.SSW_WALLET      = "7yMnWMrxzZ3YCtWXRsZEhAFwexHoJzBJy8RgN7Lhvy1P";
window.SSW_RPC         = "https://api.mainnet-beta.solana.com";
window.SSW_AMOUNT_USDC = 80;
