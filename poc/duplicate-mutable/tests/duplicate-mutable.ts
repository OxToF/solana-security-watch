import { LiteSVM, FailedTransactionMetadata } from "litesvm";
import {
  address,
  type Address,
  AccountRole,
  appendTransactionMessageInstructions,
  createTransactionMessage,
  generateKeyPairSigner,
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

// vuln-classes.md #17 — Duplicate mutable accounts.
//   EXPLOIT           — transfer_insecure with source == destination inflates the
//                        balance (100 -> 200): the credited copy is serialised last.
//   DEFENSE           — transfer_secure rejects the aliased self-transfer; balance
//                        stays 100.
//   POSITIVE CONTROL  — transfer_secure moves funds correctly between two DISTINCT
//                        accounts (100/0 -> 60/40).

const PROGRAM_ID: Address = address("7AptpiMiL6WTBgNjDaRZgZMnbqGGiNjfjzvvvHdtxQo1");
const SYSTEM_PROGRAM: Address = address("11111111111111111111111111111111");
const SO_PATH = path.join(process.cwd(), "target", "deploy", "duplicate_mutable.so");

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
function readAmount(data: Uint8Array): bigint {
  return new DataView(data.buffer, data.byteOffset + 8, 8).getBigUint64(0, true);
}
function isFailure(res: unknown): boolean {
  return res instanceof FailedTransactionMetadata;
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
async function setup(): Promise<{ svm: LiteSVM; payer: TransactionSigner }> {
  const svm = new LiteSVM();
  svm.addProgramFromFile(PROGRAM_ID, SO_PATH);
  const payer = await generateKeyPairSigner();
  svm.airdrop(payer.address, lamports(10_000_000_000n));
  return { svm, payer };
}
async function initBalance(svm: LiteSVM, payer: TransactionSigner, amount: bigint): Promise<Address> {
  const acct = await generateKeyPairSigner();
  const ix: Instruction = {
    programAddress: PROGRAM_ID,
    accounts: [
      { address: acct.address, role: AccountRole.WRITABLE_SIGNER, signer: acct },
      { address: payer.address, role: AccountRole.WRITABLE_SIGNER, signer: payer },
      { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
    ],
    data: concatBytes(disc("init_balance"), u64le(amount)),
  };
  expect(isFailure(await send(svm, payer, [ix])), "init_balance should succeed").to.be.false;
  return acct.address;
}
function transferIx(name: "transfer_insecure" | "transfer_secure", source: Address, destination: Address, amount: bigint): Instruction {
  return {
    programAddress: PROGRAM_ID,
    accounts: [
      { address: source, role: AccountRole.WRITABLE },
      { address: destination, role: AccountRole.WRITABLE },
    ],
    data: concatBytes(disc(name), u64le(amount)),
  };
}

describe("duplicate-mutable (vuln-classes.md #17)", () => {
  it("EXPLOIT — transfer_insecure self-transfer mints 100 out of nothing", async () => {
    const { svm, payer } = await setup();
    const a = await initBalance(svm, payer, 100n);

    // source == destination == A, amount = full balance.
    expect(isFailure(await send(svm, payer, [transferIx("transfer_insecure", a, a, 100n)])),
      "self-transfer should (wrongly) succeed").to.be.false;
    expect(
      readAmount(svm.getAccount(a)!.data),
      "balance must have doubled — value created from nothing"
    ).to.equal(200n);
  });

  it("DEFENSE — transfer_secure rejects the aliased self-transfer", async () => {
    const { svm, payer } = await setup();
    const a = await initBalance(svm, payer, 100n);

    expect(isFailure(await send(svm, payer, [transferIx("transfer_secure", a, a, 100n)])),
      "aliased self-transfer must be rejected").to.be.true;
    expect(readAmount(svm.getAccount(a)!.data), "balance unchanged").to.equal(100n);
  });

  it("POSITIVE CONTROL — transfer_secure moves funds between distinct accounts", async () => {
    const { svm, payer } = await setup();
    const a = await initBalance(svm, payer, 100n);
    const b = await initBalance(svm, payer, 0n);

    expect(isFailure(await send(svm, payer, [transferIx("transfer_secure", a, b, 40n)])),
      "a genuine transfer between distinct accounts must succeed").to.be.false;
    expect(readAmount(svm.getAccount(a)!.data)).to.equal(60n);
    expect(readAmount(svm.getAccount(b)!.data)).to.equal(40n);
  });
});
