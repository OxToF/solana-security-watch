// On-chain verification of a USDC (or SOL) payment. Given a transaction signature,
// confirm via RPC that it succeeded and moved at least `amountUsdc` of USDC into the
// merchant wallet. Uses jsonParsed token-balance deltas (robust: no instruction
// decoding). Zero deps — plain fetch to a Solana RPC.

export const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
export const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const MEMO_PROGRAM_IDS = new Set([MEMO_PROGRAM_ID, "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"]); // v2, v1

// Every memo string the transaction carries, top-level or via CPI. jsonParsed
// renders an SPL Memo instruction as { program: "spl-memo", programId, parsed: "<text>" }.
export function memosOf(tx) {
  const ixs = [...((tx.transaction && tx.transaction.message && tx.transaction.message.instructions) || [])];
  for (const inner of (tx.meta && tx.meta.innerInstructions) || []) ixs.push(...(inner.instructions || []));
  return ixs.filter((ix) => MEMO_PROGRAM_IDS.has(ix.programId) && typeof ix.parsed === "string").map((ix) => ix.parsed);
}

// Verify against the pre/post token balances in a getTransaction result. Exported
// separately so it can be unit-tested with a synthetic RPC payload (no network).
//
// `memo`, when set, binds the payment to one job: the transfer's signature is
// public the moment it lands, so without it anyone watching the merchant wallet
// could claim someone else's payment for their own job before the payer does.
export function verifyFromTx(tx, { amountUsdc, merchant, mint = USDC_MINT, memo = null }) {
  if (!tx) return { ok: false, reason: "transaction not found or not yet confirmed" };
  if (tx.meta && tx.meta.err) return { ok: false, reason: "transaction failed on-chain" };
  if (memo !== null && !memosOf(tx).includes(memo)) {
    return { ok: false, reason: `transaction does not carry the required memo "${memo}"` };
  }
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

// Same check for a payment in SOL: the merchant's lamport balance must rise by at
// least `lamports`. jsonParsed lists the account keys as { pubkey }, and pre/post
// balances are indexed the same way.
export const LAMPORTS_PER_SOL = 1_000_000_000n;
export const solToLamports = (sol) => BigInt(Math.round(Number(sol) * 1e9));
export function verifySolFromTx(tx, { lamports, merchant, memo = null }) {
  if (!tx) return { ok: false, reason: "transaction not found or not yet confirmed" };
  if (tx.meta && tx.meta.err) return { ok: false, reason: "transaction failed on-chain" };
  if (memo !== null && !memosOf(tx).includes(memo)) {
    return { ok: false, reason: `transaction does not carry the required memo "${memo}"` };
  }
  const keys = ((tx.transaction && tx.transaction.message && tx.transaction.message.accountKeys) || []).map((k) => (typeof k === "string" ? k : k.pubkey));
  const i = keys.indexOf(merchant);
  const pre = (tx.meta && tx.meta.preBalances) || [];
  const post = (tx.meta && tx.meta.postBalances) || [];
  const delta = i < 0 || pre[i] === undefined || post[i] === undefined ? 0n : BigInt(post[i]) - BigInt(pre[i]);
  const need = BigInt(lamports);
  if (delta < need) return { ok: false, reason: `SOL received (${delta} lamports) is less than required (${need})` };
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function verifyUsdcPayment({ amountUsdc, merchant, mint = USDC_MINT, memo = null, ...lookup }) {
  return verifyWith(lookup, (tx) => verifyFromTx(tx, { amountUsdc, merchant, mint, memo }));
}

export async function verifySolPayment({ lamports, merchant, memo = null, ...lookup }) {
  return verifyWith(lookup, (tx) => verifySolFromTx(tx, { lamports, merchant, memo }));
}

async function verifyWith({ signature, rpcUrl, fetchImpl = globalThis.fetch, retries = 10, delayMs = 3000 }, check) {
  if (!/^[1-9A-HJ-NP-Za-km-z]{64,120}$/.test(signature || "")) {
    return { ok: false, reason: "invalid signature format" };
  }
  // The client submits the tx and calls us immediately, so the tx is usually not
  // yet confirmed on the first lookup. Poll for it before giving up.
  let tx = null, lastErr = null;
  for (let i = 0; i < retries; i++) {
    try {
      tx = await getTransaction(signature, rpcUrl, fetchImpl);
    } catch (e) {
      lastErr = e; // transient RPC error — keep polling
    }
    if (tx) break;
    if (i < retries - 1) await sleep(delayMs);
  }
  if (!tx && lastErr) return { ok: false, reason: `RPC lookup failed: ${lastErr.message}` };
  return check(tx);
}
