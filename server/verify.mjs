// On-chain verification of a USDC payment. Given a transaction signature, confirm
// via RPC that it succeeded and moved at least `amountUsdc` of USDC into the
// merchant wallet. Uses jsonParsed token-balance deltas (robust: no instruction
// decoding). Zero deps — plain fetch to a Solana RPC.

export const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

// Verify against the pre/post token balances in a getTransaction result. Exported
// separately so it can be unit-tested with a synthetic RPC payload (no network).
export function verifyFromTx(tx, { amountUsdc, merchant, mint = USDC_MINT }) {
  if (!tx) return { ok: false, reason: "transaction not found or not yet confirmed" };
  if (tx.meta && tx.meta.err) return { ok: false, reason: "transaction failed on-chain" };
  const post = (tx.meta && tx.meta.postTokenBalances) || [];
  const pre = (tx.meta && tx.meta.preTokenBalances) || [];
  const need = BigInt(Math.round(Number(amountUsdc) * 1e6));

  // Sum the merchant's USDC increase across any matching accounts.
  let delta = 0n;
  const idxs = new Set();
  for (const b of post) if (b.mint === mint && b.owner === merchant) idxs.add(b.accountIndex);
  for (const b of pre) if (b.mint === mint && b.owner === merchant) idxs.add(b.accountIndex);
  for (const i of idxs) {
    const p = post.find((b) => b.accountIndex === i);
    const q = pre.find((b) => b.accountIndex === i);
    const postAmt = p ? BigInt(p.uiTokenAmount.amount) : 0n;
    const preAmt = q ? BigInt(q.uiTokenAmount.amount) : 0n;
    delta += postAmt - preAmt;
  }
  if (delta < need) {
    return { ok: false, reason: `USDC received (${delta}) is less than required (${need})` };
  }
  return { ok: true, received: delta.toString() };
}

async function getTransaction(signature, rpcUrl, fetchImpl) {
  const res = await fetchImpl(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "getTransaction",
      params: [signature, { encoding: "jsonParsed", commitment: "confirmed", maxSupportedTransactionVersion: 0 }],
    }),
  });
  if (!res.ok) throw new Error(`RPC ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`RPC error: ${body.error.message}`);
  return body.result;
}

export async function verifyUsdcPayment({ signature, amountUsdc, merchant, rpcUrl, mint = USDC_MINT, fetchImpl = globalThis.fetch }) {
  if (!/^[1-9A-HJ-NP-Za-km-z]{64,120}$/.test(signature || "")) {
    return { ok: false, reason: "invalid signature format" };
  }
  let tx;
  try { tx = await getTransaction(signature, rpcUrl, fetchImpl); }
  catch (e) { return { ok: false, reason: `RPC lookup failed: ${e.message}` }; }
  return verifyFromTx(tx, { amountUsdc, merchant, mint });
}
