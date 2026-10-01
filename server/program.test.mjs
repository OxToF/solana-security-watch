// node --test server/program.test.mjs
// Program inspection against a fake RPC: the authority classes, the Squads proof,
// security.txt, and the primitives they rest on.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  inspectProgram, isOnCurve, b58decode, b58encode, isPubkey, findProgramAddress, squadsVault, parseSecurityTxt,
  LOADER_UPGRADEABLE, SQUADS_V4,
} from "./program.mjs";

const PROGRAM = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
const PROGRAM_DATA = "CtXfPzz36dH5Ws4UYKZvrQ1Xqzn42ecDW6y8NKuiN8nD";
const WALLET = "7yMnWMrxzZ3YCtWXRsZEhAFwexHoJzBJy8RgN7Lhvy1P"; // a keypair: on the curve
const MULTISIG = "BQsDWkL417U4tVE2sDnPks469pKdm6YzFgKH77doiEjF";
const NOW = Date.parse("2026-10-01T12:00:00Z");
const b64 = (b) => [Buffer.from(b).toString("base64"), "base64"];

function programAccount() {
  const d = Buffer.alloc(36); d.writeUInt32LE(2, 0); Buffer.from(b58decode(PROGRAM_DATA)).copy(d, 4);
  return { executable: true, owner: LOADER_UPGRADEABLE, data: b64(d) };
}
function programData(authority, elf = Buffer.from("ELF....")) {
  const d = Buffer.alloc(45); d.writeUInt32LE(3, 0); d.writeBigUInt64LE(440170207n, 4);
  if (authority) { d[12] = 1; Buffer.from(b58decode(authority)).copy(d, 13); }
  return { executable: false, owner: LOADER_UPGRADEABLE, data: b64(Buffer.concat([d, elf])) };
}
function multisigData(threshold, members, timeLock) {
  const disc = createHash("sha256").update("account:Multisig").digest().subarray(0, 8);
  const d = Buffer.alloc(8 + 32 + 32 + 2 + 4 + 8 + 8 + 1 + 1 + 4 + members * 33);
  disc.copy(d, 0); d.writeUInt16LE(threshold, 72); d.writeUInt32LE(timeLock, 74);
  d[94] = 0; d[95] = 255; d.writeUInt32LE(members, 96);
  return d;
}
function fakeRpc({ authority, elf, multisig, deployedAt = "2026-08-19T01:28:54Z", txProgram = SQUADS_V4 }) {
  const calls = [];
  const rpc = async (method, params) => {
    calls.push(method);
    if (method === "getAccountInfo") {
      if (params[0] === PROGRAM) return { value: programAccount() };
      if (params[0] === PROGRAM_DATA) return { value: programData(authority, elf) };
      return { value: null };
    }
    if (method === "getBlockTime") return Date.parse(deployedAt) / 1000;
    if (method === "getSignaturesForAddress") return params[0] === authority ? [{ signature: "SIG1", err: null }] : [];
    if (method === "getTransaction") return {
      transaction: { message: { accountKeys: [WALLET, MULTISIG, authority, txProgram], instructions: [{ programIdIndex: 3 }] } },
      meta: { loadedAddresses: { writable: [], readonly: [] } },
    };
    if (method === "getMultipleAccounts") return { value: params[0].map((k) => (k === MULTISIG && multisig ? { owner: SQUADS_V4, data: b64(multisig) } : null)) };
    throw new Error(`unexpected ${method}`);
  };
  return { rpc, calls };
}
const verifyApi = (body) => async () => ({ ok: true, json: async () => body });
const NOT_VERIFIED = { is_verified: false, repo_url: "" };

test("primitives: base58 round trip, curve membership, a known ATA", () => {
  assert.equal(b58encode(b58decode(WALLET)), WALLET);
  assert.equal(isPubkey(WALLET), true);
  assert.equal(isPubkey("0OIl"), false);
  assert.equal(isOnCurve(b58decode(WALLET)), true);
  // 7yMn's USDC associated token account, as it exists on mainnet.
  const ata = findProgramAddress([b58decode(WALLET), b58decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"), b58decode("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")], "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
  assert.equal(isOnCurve(b58decode(ata)), false);
  // Orca's upgrade authority is vault 0 of its Squads multisig (checked on mainnet).
  assert.equal(squadsVault(MULTISIG, 0), "GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV");
});

test("a single-key authority is a high flag", async () => {
  const { rpc } = fakeRpc({ authority: WALLET });
  const r = await inspectProgram(PROGRAM, { rpc, fetchImpl: verifyApi(NOT_VERIFIED), now: NOW });
  assert.equal(r.authority.kind, "single-key");
  assert.equal(r.flags[0].id, "single-key-authority");
  assert.equal(r.flags[0].severity, "high");
  assert.ok(r.flags.some((f) => f.id === "no-verified-build"));
  assert.ok(r.flags.some((f) => f.id === "no-security-txt"));
});

test("a Squads v4 authority is proved by re-deriving the vault, threshold and time lock read", async () => {
  const vault = squadsVault(MULTISIG, 0);
  const { rpc } = fakeRpc({ authority: vault, multisig: multisigData(5, 13, 86400) });
  const r = await inspectProgram(PROGRAM, { rpc, fetchImpl: verifyApi({ is_verified: true, repo_url: "https://github.com/x/y" }), now: NOW });
  assert.equal(r.authority.kind, "squads-v4");
  assert.equal(r.authority.threshold, 5);
  assert.equal(r.authority.members, 13);
  assert.match(r.authority.text, /5 of 13 .* 24 h time lock/);
  assert.equal(r.authority.multisig, MULTISIG);
  assert.deepEqual(r.flags.map((f) => f.id), ["no-security-txt"]);
});

test("a multisig that is not the authority's is not taken as proof", async () => {
  // Same transaction shape, but the authority is vault 0 of ANOTHER multisig.
  const other = squadsVault("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf", 0);
  const { rpc } = fakeRpc({ authority: other, multisig: multisigData(5, 13, 0) });
  const r = await inspectProgram(PROGRAM, { rpc, fetchImpl: verifyApi(NOT_VERIFIED), now: NOW });
  assert.equal(r.authority.kind, "program-controlled");
  assert.ok(r.flags.some((f) => f.id === "controller-unidentified"));
});

test("1-of-N multisig is high, a recent upgrade is flagged", async () => {
  const { rpc } = fakeRpc({ authority: squadsVault(MULTISIG, 0), multisig: multisigData(1, 3, 0), deployedAt: "2026-09-29T00:00:00Z" });
  const r = await inspectProgram(PROGRAM, { rpc, fetchImpl: verifyApi({ is_verified: true }), now: NOW });
  assert.deepEqual(r.flags.map((f) => f.id), ["multisig-1-of-n", "recent-upgrade", "no-security-txt"]);
});

test("no authority: immutable, and security.txt is read from the binary", async () => {
  const sec = Buffer.from("=======BEGIN SECURITY.TXT V1=======\0name\0Whirlpool\0contacts\0email:sec@x.io\0=======END SECURITY.TXT V1=======\0");
  const { rpc, calls } = fakeRpc({ authority: null, elf: Buffer.concat([Buffer.from("ELF.."), sec, Buffer.from("..")]) });
  const r = await inspectProgram(PROGRAM, { rpc, fetchImpl: verifyApi({ is_verified: true }), now: NOW });
  assert.equal(r.upgradeable, false);
  assert.equal(r.authority.kind, "none");
  assert.deepEqual(r.securityTxt, { name: "Whirlpool", contacts: "email:sec@x.io" });
  assert.deepEqual(r.flags, []);
  assert.ok(!calls.includes("getSignaturesForAddress"));
  assert.equal(parseSecurityTxt(Buffer.from("no marker")), null);
});

test("not a program, or nothing there", async () => {
  const none = await inspectProgram(WALLET, { rpc: async () => ({ value: null }), fetchImpl: verifyApi(NOT_VERIFIED) });
  assert.equal(none.flags[0].id, "not-found");
  const notExec = await inspectProgram(WALLET, { rpc: async () => ({ value: { executable: false, owner: "11111111111111111111111111111111", data: b64([]) } }), fetchImpl: verifyApi(NOT_VERIFIED) });
  assert.equal(notExec.flags[0].id, "not-a-program");
});
