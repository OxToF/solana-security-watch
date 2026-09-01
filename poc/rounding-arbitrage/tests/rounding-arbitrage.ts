import { LiteSVM, FailedTransactionMetadata } from "litesvm";
import {
  address,
  type Address,
  AccountRole,
  appendTransactionMessageInstructions,
  createTransactionMessage,
  generateKeyPairSigner,
  getProgramDerivedAddress,
  lamports,
  pipe,
  setTransactionMessageFeePayerSigner,
  signTransactionMessageWithSigners,
  type Instruction,
  type TransactionSigner,
} from "@solana/kit";
import { createHash } from "node:crypto";
import { expect } from "chai";
import * as path from "path";

// vuln-classes.md #4 — Rounding-direction arbitrage.
// Pool = 100 assets / 3 shares. Redeeming 1 share owes 33.33... assets.
//   EXPLOIT           — redeem_insecure quotes 34 (ceil): one unit more than owed.
//   DEFENSE           — redeem_secure quotes 33 (floor): remainder stays in pool,
//                        and 33 < 34.
//   POSITIVE CONTROL  — on an exact division (3 shares -> 100) both quote 100, so
//                        the fix is a rounding-direction change, not a blanket -1.

const PROGRAM_ID: Address = address("4hBF3mmenLCt8ps62uuhrKDGFwufBy616G96fNqj6Dcq");
const SYSTEM_PROGRAM: Address = address("11111111111111111111111111111111");
const SO_PATH = path.join(process.cwd(), "target", "deploy", "rounding_arbitrage.so");

function disc(name: string): Uint8Array {
  return Uint8Array.from(createHash("sha256").update(`global:${name}`).digest()).slice(0, 8);
}
function u64le(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n, true);
  return out;
}
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
function readPayout(data: Uint8Array): bigint {
  return new DataView(data.buffer, data.byteOffset + 8, 8).getBigUint64(0, true);
}
function isFailure(res: unknown): boolean {
  return res instanceof FailedTransactionMetadata;
}

async function meterPda(): Promise<Address> {
  const [pda] = await getProgramDerivedAddress({ programAddress: PROGRAM_ID, seeds: ["meter"] });
  return pda;
}
async function send(svm: LiteSVM, payer: TransactionSigner, instructions: Instruction[]) {
  const tx = await pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(payer, m),
    (m) => svm.setTransactionMessageLifetimeUsingLatestBlockhash(m),
    (m) => appendTransactionMessageInstructions(instructions, m),
    (m) => signTransactionMessageWithSigners(m)
  );
  return svm.sendTransaction(tx);
}
async function setup(): Promise<{ svm: LiteSVM; payer: TransactionSigner; meter: Address }> {
  const svm = new LiteSVM();
  svm.addProgramFromFile(PROGRAM_ID, SO_PATH);
  const payer = await generateKeyPairSigner();
  svm.airdrop(payer.address, lamports(10_000_000_000n));
  const meter = await meterPda();
  const initIx: Instruction = {
    programAddress: PROGRAM_ID,
    accounts: [
      { address: meter, role: AccountRole.WRITABLE },
      { address: payer.address, role: AccountRole.WRITABLE_SIGNER, signer: payer },
      { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
    ],
    data: disc("init_meter"),
  };
  expect(isFailure(await send(svm, payer, [initIx])), "init_meter should succeed").to.be.false;
  return { svm, payer, meter };
}
function redeemIx(meter: Address, name: "redeem_insecure" | "redeem_secure", shares: bigint): Instruction {
  return {
    programAddress: PROGRAM_ID,
    accounts: [{ address: meter, role: AccountRole.WRITABLE }],
    data: concatBytes(disc(name), u64le(shares)),
  };
}
async function quote(svm: LiteSVM, payer: TransactionSigner, meter: Address,
  name: "redeem_insecure" | "redeem_secure", shares: bigint): Promise<bigint> {
  expect(isFailure(await send(svm, payer, [redeemIx(meter, name, shares)])), `${name} should succeed`).to.be.false;
  return readPayout(svm.getAccount(meter)!.data);
}

describe("rounding-arbitrage (vuln-classes.md #4)", () => {
  it("EXPLOIT — redeem_insecure rounds a 33.33 payout UP to 34", async () => {
    const { svm, payer, meter } = await setup();
    const payout = await quote(svm, payer, meter, "redeem_insecure", 1n);
    expect(payout, "ceil rounding overpays by one unit").to.equal(34n);
  });

  it("DEFENSE — redeem_secure rounds the same payout DOWN to 33", async () => {
    const { svm, payer, meter } = await setup();
    const secure = await quote(svm, payer, meter, "redeem_secure", 1n);
    const insecure = await quote(svm, payer, meter, "redeem_insecure", 1n);
    expect(secure, "floor rounding pays only what is owed").to.equal(33n);
    expect(secure < insecure, "secure must pay strictly less than insecure on an inexact split").to.be.true;
  });

  it("POSITIVE CONTROL — on an exact split both quote 100", async () => {
    const { svm, payer, meter } = await setup();
    // 3 shares -> exactly 100 assets: no remainder, so direction cannot matter.
    expect(await quote(svm, payer, meter, "redeem_insecure", 3n)).to.equal(100n);
    expect(await quote(svm, payer, meter, "redeem_secure", 3n)).to.equal(100n);
  });
});
