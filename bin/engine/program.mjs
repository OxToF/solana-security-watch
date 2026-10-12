// Who can change a deployed Solana program, and what can be checked about it.
// Read-only RPC lookups plus OtterSec's public verified-build API. No key needed.
//
// The upgrade authority is the question an agent has before signing: a key on the
// ed25519 curve is one private key that can swap the code at any time; an address
// off the curve is a PDA, i.e. a program decides (a multisig vault, a DAO). For
// Squads v4 the multisig is found in the last upgrade transaction and the vault is
// re-derived from it, so the claim is proved, not guessed.
import { createHash } from "node:crypto";

export const LOADER_UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111";
export const LOADER_V4 = "LoaderV411111111111111111111111111111111111";
const LOADERS_IMMUTABLE = new Set(["BPFLoader2111111111111111111111111111111111", "BPFLoader1111111111111111111111111111111111"]);
export const SQUADS_V4 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
export const SQUADS_V3 = "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu";
export const SPL_GOVERNANCE = "GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw";
const VERIFY_API = process.env.OSEC_VERIFY_URL || "https://verify.osec.io/status";
const RECENT_UPGRADE_DAYS = 7;

// --- base58 --------------------------------------------------------------------
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function b58decode(s) {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error("not base58");
    n = n * 58n + BigInt(i);
  }
  const out = [];
  while (n > 0n) { out.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const c of s) { if (c !== "1") break; out.unshift(0); }
  return Uint8Array.from(out);
}
export function b58encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; s = "1" + s; }
  return s;
}
export function isPubkey(s) {
  if (typeof s !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s)) return false;
  try { return b58decode(s).length === 32; } catch { return false; }
}

// --- ed25519: is this 32-byte string a point on the curve? -----------------------
const P = 2n ** 255n - 19n;
const D = (-121665n * modInv(121666n)) % P + P;
function mod(a) { const r = a % P; return r < 0n ? r + P : r; }
function pow(b, e) { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = mod(r * b); b = mod(b * b); e >>= 1n; } return r; }
function modInv(a) { return pow(a, P - 2n); }
export function isOnCurve(bytes) {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? bytes[i] & 0x7f : bytes[i]);
  if (y >= P) return false;
  const y2 = mod(y * y), u = mod(y2 - 1n), v = mod(D * y2 + 1n);
  const x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n));
  const vx2 = mod(v * x * x);
  return vx2 === u || vx2 === mod(-u);
}

// --- PDAs ------------------------------------------------------------------------
const sha256 = (...parts) => createHash("sha256").update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
export function createProgramAddress(seeds, programId) {
  const h = sha256(...seeds, b58decode(programId), Buffer.from("ProgramDerivedAddress"));
  if (isOnCurve(h)) return null;
  return b58encode(h);
}
export function findProgramAddress(seeds, programId) {
  for (let bump = 255; bump >= 0; bump--) {
    const a = createProgramAddress([...seeds, Uint8Array.of(bump)], programId);
    if (a) return a;
  }
  throw new Error("no viable bump");
}
export function createWithSeed(base, seed, owner) {
  return b58encode(sha256(b58decode(base), Buffer.from(seed), b58decode(owner)));
}
export function anchorIdlAddress(programId) {
  return createWithSeed(findProgramAddress([], programId), "anchor:idl", programId);
}

// --- security.txt (neodyme-labs/solana-security-txt) ------------------------------
const SEC_BEGIN = "=======BEGIN SECURITY.TXT V1=======\0";
const SEC_END = "=======END SECURITY.TXT V1=======\0";
export function parseSecurityTxt(buf) {
  const b = Buffer.from(buf);
  const start = b.indexOf(SEC_BEGIN, 0, "latin1");
  if (start < 0) return null;
  const end = b.indexOf(SEC_END, start, "latin1");
  if (end < 0) return null;
  const parts = b.subarray(start + SEC_BEGIN.length, end).toString("utf8").split("\0");
  const out = {};
  for (let i = 0; i + 1 < parts.length; i += 2) if (parts[i]) out[parts[i]] = parts[i + 1].slice(0, 500);
  return out;
}

// --- Squads v4 multisig account ---------------------------------------------------
const MULTISIG_DISC = sha256("account:Multisig").subarray(0, 8);
export function parseSquadsMultisig(data) {
  const b = Buffer.from(data);
  if (b.length < 100 || !b.subarray(0, 8).equals(MULTISIG_DISC)) return null;
  const threshold = b.readUInt16LE(72), timeLock = b.readUInt32LE(74);
  let o = 94;
  o += b[o] === 1 ? 33 : 1; // rent_collector: Option<Pubkey>
  o += 1; // bump
  const n = b.readUInt32LE(o); o += 4;
  if (n > 100 || o + n * 33 > b.length) return null;
  return { threshold, members: n, timeLockSeconds: timeLock };
}
export function squadsVault(multisig, index) {
  const idx = Uint8Array.of(index);
  return findProgramAddress([Buffer.from("multisig"), b58decode(multisig), Buffer.from("vault"), idx], SQUADS_V4);
}

const duration = (sec) => (sec % 3600 === 0 ? `${sec / 3600} h` : sec % 60 === 0 ? `${sec / 60} min` : `${sec} s`);

// --- the inspection ---------------------------------------------------------------
// rpc(method, params) -> result. fetchImpl for the verify API.
export async function inspectProgram(programId, { rpc, fetchImpl = globalThis.fetch, now = Date.now() }) {
  const acct = await rpc("getAccountInfo", [programId, { encoding: "base64", dataSlice: { offset: 0, length: 64 } }]);
  const v = acct && acct.value;
  if (!v) return { programId, exists: false, flags: [{ severity: "high", id: "not-found", text: "No account at this address on Solana mainnet." }] };
  if (!v.executable) return { programId, exists: true, executable: false, flags: [{ severity: "high", id: "not-a-program", text: `This account is not an executable program (owner ${v.owner}).` }] };

  const out = { programId, exists: true, executable: true, loader: v.owner, upgradeable: false, authority: null, lastDeploy: null, verifiedBuild: null, securityTxt: null, anchorIdl: null, flags: [] };
  let elf = null;
  let authority = null;

  if (v.owner === LOADER_UPGRADEABLE) {
    const head = Buffer.from(v.data[0], "base64");
    if (head.readUInt32LE(0) !== 2) throw new Error("unexpected upgradeable-loader program account");
    const programData = b58encode(head.subarray(4, 36));
    const pd = await rpc("getAccountInfo", [programData, { encoding: "base64" }]);
    if (!pd || !pd.value) throw new Error("program data account not found");
    const d = Buffer.from(pd.value.data[0], "base64");
    out.programData = programData;
    out.lastDeploy = { slot: Number(d.readBigUInt64LE(4)) };
    if (d[12] === 1) authority = b58encode(d.subarray(13, 45));
    elf = d.subarray(45);
    out.upgradeable = !!authority;
  } else if (v.owner === LOADER_V4) {
    const full = await rpc("getAccountInfo", [programId, { encoding: "base64" }]);
    const d = Buffer.from(full.value.data[0], "base64");
    out.lastDeploy = { slot: Number(d.readBigUInt64LE(0)) };
    const status = Number(d.readBigUInt64LE(40)); // 0 retracted, 1 deployed, 2 finalized
    if (status !== 2) authority = b58encode(d.subarray(8, 40));
    elf = d.subarray(48);
    out.upgradeable = !!authority;
  } else if (!LOADERS_IMMUTABLE.has(v.owner)) {
    out.flags.push({ severity: "info", id: "unknown-loader", text: `Owned by ${v.owner}, a loader this check does not know.` });
  }

  if (out.lastDeploy) {
    try {
      const t = await rpc("getBlockTime", [out.lastDeploy.slot]);
      if (t) out.lastDeploy.at = new Date(t * 1000).toISOString();
    } catch {}
  }

  if (!authority) {
    out.authority = { kind: "none", text: "No upgrade authority: the code can no longer change." };
  } else if (isOnCurve(b58decode(authority))) {
    out.authority = { address: authority, kind: "single-key", text: "One private key can replace this program's code at any time, with no delay." };
    out.flags.push({ severity: "high", id: "single-key-authority", text: `Upgrade authority ${authority} is a single key: whoever holds it can swap the code, and drain what the program controls, in one transaction.` });
  } else {
    out.authority = { address: authority, kind: "program-controlled", text: "The upgrade authority is a program-derived address: an upgrade needs that program's approval (typically a multisig or a DAO)." };
    const ctrl = await identifyController(authority, out.programData || programId, rpc);
    if (ctrl) Object.assign(out.authority, ctrl);
    else out.flags.push({ severity: "info", id: "controller-unidentified", text: "The authority is program-controlled, but which program (and its approval rules) could not be identified from recent history." });
    if (ctrl && ctrl.kind === "squads-v4" && ctrl.threshold === 1)
      out.flags.push({ severity: "high", id: "multisig-1-of-n", text: `Squads multisig with threshold 1 of ${ctrl.members}: any single member can upgrade.` });
    if (ctrl && ctrl.kind === "squads-v4" && ctrl.timeLockSeconds === 0 && ctrl.threshold > 1)
      out.flags.push({ severity: "info", id: "no-timelock", text: "No time lock on the multisig: an approved upgrade executes immediately." });
  }

  if (out.upgradeable && out.lastDeploy && out.lastDeploy.at && now - Date.parse(out.lastDeploy.at) < RECENT_UPGRADE_DAYS * 864e5)
    out.flags.push({ severity: "medium", id: "recent-upgrade", text: `Code changed on ${out.lastDeploy.at.slice(0, 10)}, less than ${RECENT_UPGRADE_DAYS} days ago.` });

  // Verified build (OtterSec).
  try {
    const r = await fetchImpl(`${VERIFY_API}/${programId}`);
    if (r.ok) {
      const j = await r.json();
      out.verifiedBuild = { verified: !!j.is_verified, repo: j.repo_url || null, commit: j.commit && j.commit !== "None" ? j.commit : null, lastVerifiedAt: j.last_verified_at || null, onChainHash: j.on_chain_hash || null };
      if (!j.is_verified) out.flags.push(j.repo_url
        ? { severity: "medium", id: "build-mismatch", text: `A verification was submitted for ${j.repo_url}, but it does not match the deployed binary (${out.upgradeable ? "upgraded since, or " : ""}not reproducible).` }
        : { severity: "medium", id: "no-verified-build", text: "No verified build: nothing ties the deployed binary to public source code." });
    }
  } catch {}

  if (elf) {
    out.securityTxt = parseSecurityTxt(elf);
    if (!out.securityTxt) out.flags.push({ severity: "low", id: "no-security-txt", text: "No embedded security.txt: no published way to report a vulnerability." });
    out.binaryBytes = elf.length;
  }

  try {
    const idl = await rpc("getAccountInfo", [anchorIdlAddress(programId), { encoding: "base64", dataSlice: { offset: 0, length: 0 } }]);
    out.anchorIdl = !!(idl && idl.value && idl.value.owner === programId);
  } catch {}

  const order = { high: 0, medium: 1, low: 2, info: 3 };
  out.flags.sort((a, b) => order[a.severity] - order[b.severity]);
  return out;
}

// Find the program behind a PDA authority from the latest transactions of the
// authority itself (it takes part in every upgrade), then of the program data.
// Squads v4 is proved by re-deriving the vault from the multisig account.
async function identifyController(authority, programData, rpc) {
  const sigs = [];
  for (const addr of [authority, programData]) {
    try { sigs.push(...((await rpc("getSignaturesForAddress", [addr, { limit: 15 }])) || []).filter((s) => !s.err)); } catch {}
  }
  const seen = new Set();
  for (const s of sigs) {
    if (seen.has(s.signature)) continue;
    seen.add(s.signature);
    let tx;
    try { tx = await rpc("getTransaction", [s.signature, { encoding: "json", maxSupportedTransactionVersion: 0 }]); } catch { continue; }
    if (!tx) continue;
    const keys = [...tx.transaction.message.accountKeys, ...((tx.meta && tx.meta.loadedAddresses && [...tx.meta.loadedAddresses.writable, ...tx.meta.loadedAddresses.readonly]) || [])];
    const invoked = new Set(tx.transaction.message.instructions.map((ix) => keys[ix.programIdIndex]));
    if (invoked.has(SQUADS_V4)) {
      let accts;
      try { accts = await rpc("getMultipleAccounts", [keys.slice(0, 100), { encoding: "base64" }]); } catch { continue; }
      for (let i = 0; i < accts.value.length; i++) {
        const a = accts.value[i];
        if (!a || a.owner !== SQUADS_V4) continue;
        const ms = parseSquadsMultisig(Buffer.from(a.data[0], "base64"));
        if (!ms) continue;
        for (let idx = 0; idx < 16; idx++) {
          if (squadsVault(keys[i], idx) === authority)
            return { kind: "squads-v4", multisig: keys[i], vaultIndex: idx, ...ms, text: `Squads v4 multisig: ${ms.threshold} of ${ms.members} members must approve an upgrade${ms.timeLockSeconds ? `, then a ${duration(ms.timeLockSeconds)} time lock` : ""}.`, proof: `vault PDA re-derived from multisig ${keys[i]} (index ${idx}), seen in ${s.signature}` };
        }
      }
    }
    if (invoked.has(SPL_GOVERNANCE)) return { kind: "spl-governance", text: "The authority acts through SPL Governance (a DAO vote).", proof: `seen in ${s.signature}` };
    if (invoked.has(SQUADS_V3)) return { kind: "squads-v3", text: "The authority acts through Squads v3 (multisig, legacy); its approval rules are not read.", proof: `seen in ${s.signature}` };
  }
  return null;
}
