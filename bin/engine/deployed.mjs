// The source says which program it is (declare_id!). The chain says who can replace
// it and whether the deployed binary matches public source. A report on the code
// alone misses the risk a user actually takes: a single key that can swap the code.

import { inspectProgram } from "./program.mjs";

const CLUSTERS = [
  { name: "mainnet", url: () => process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com" },
  { name: "devnet", url: () => process.env.SOLANA_DEVNET_RPC_URL || "https://api.devnet.solana.com" },
];

function rpcFor(url, fetchImpl) {
  return async (method, params) => {
    for (let i = 0; ; i++) {
      const r = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
      if (r.status === 429 && i < 3) { await new Promise((s) => setTimeout(s, 800 * (i + 1))); continue; }
      const j = await r.json();
      if (j.error) throw new Error(`${method}: ${j.error.message || JSON.stringify(j.error)}`);
      return j.result;
    }
  };
}

// For each declared program id: where it is deployed (mainnet first) and what the
// chain says about it. Never throws: an RPC failure is reported, not hidden.
export async function inspectDeployed(ids, { fetchImpl = globalThis.fetch, log = () => {} } = {}) {
  const out = [];
  for (const id of ids.slice(0, 5)) {
    let found = null, errors = [];
    for (const c of CLUSTERS) {
      try {
        const r = await inspectProgram(id, { rpc: rpcFor(c.url(), fetchImpl), fetchImpl });
        if (r.exists && r.executable) { found = { cluster: c.name, ...r }; break; }
      } catch (e) { errors.push(`${c.name}: ${String(e.message).slice(0, 120)}`); }
    }
    out.push(found || { programId: id, cluster: null, exists: false, errors });
    log(`[scan] ${id}: ${found ? `deployed on ${found.cluster}, authority ${found.authority ? found.authority.kind : "none"}` : "not deployed on mainnet or devnet"}`);
  }
  return out;
}
