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

// vuln-classes.md #7 — Unbounded integer cast / truncation.
// A per-call credit cap (CREDIT_CAP = 1_000_000) is enforced on a u128 amount.
// The insecure handler narrows the amount to u64 INSIDE the cap comparison, so a
// value of 2^64 + 500 truncates to `500 <= cap` and passes — yet the full u128 is
// credited. Three tests, EXPLOIT / DEFENSE / POSITIVE CONTROL:
//
//   EXPLOIT           — credit_insecure accepts amount = 2^64 + 500, crediting a
//                        balance ~1.8e19 despite the 1e6 cap.
//   DEFENSE           — credit_secure rejects the identical amount (full-width
//                        u128 bound check) before any state change.
//   POSITIVE CONTROL  — credit_secure is not a blanket-reject: a genuine 500 (under
//                        cap) is accepted, and a genuine 2_000_000 (over cap) is
//                        rejected on the real cap, not on a width artifact.

const PROGRAM_ID: Address = address(
  "A3ofMnuA4GAvRmZTi3q3kucyGnBUPJKku7VrfGrAn7Z"
);
const SYSTEM_PROGRAM: Address = address("11111111111111111111111111111111");
const SO_PATH = path.join(
  process.cwd(),
  "target",
  "deploy",
  "unbounded_cast.so"
);
const CREDIT_CAP = 1_000_000n;

/** Anchor instruction discriminator: first 8 bytes of sha256("global:<name>"). */
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
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Reads the little-endian u128 `credited` field (Ledger data, offset 8..24). */
function readCredited(data: Uint8Array): bigint {
  const view = new DataView(data.buffer, data.byteOffset + 8, 16);
  const lo = view.getBigUint64(0, true);
  const hi = view.getBigUint64(8, true);
  return (hi << 64n) | lo;
}

function isFailure(res: unknown): boolean {
  return res instanceof FailedTransactionMetadata;
}

async function setup(): Promise<{ svm: LiteSVM; payer: TransactionSigner }> {
  const svm = new LiteSVM();
  svm.addProgramFromFile(PROGRAM_ID, SO_PATH);
  const payer = await generateKeyPairSigner();
  svm.airdrop(payer.address, lamports(10_000_000_000n));
  return { svm, payer };
}

async function send(
  svm: LiteSVM,
  payer: TransactionSigner,
  instructions: Instruction[]
) {
  const tx = await pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(payer, m),
    (m) => svm.setTransactionMessageLifetimeUsingLatestBlockhash(m),
    (m) => appendTransactionMessageInstructions(instructions, m),
    (m) => signTransactionMessageWithSigners(m)
  );
  return svm.sendTransaction(tx);
}

async function initLedger(
  svm: LiteSVM,
  payer: TransactionSigner
): Promise<TransactionSigner> {
  const ledger = await generateKeyPairSigner();
  const ix: Instruction = {
    programAddress: PROGRAM_ID,
    accounts: [
      { address: ledger.address, role: AccountRole.WRITABLE_SIGNER, signer: ledger },
      { address: payer.address, role: AccountRole.WRITABLE_SIGNER, signer: payer },
      { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
    ],
    data: disc("init_ledger"),
  };
  const res = await send(svm, payer, [ix]);
  expect(isFailure(res), "init_ledger should succeed").to.be.false;
  return ledger;
}

function creditIx(
  ledger: Address,
  name: "credit_insecure" | "credit_secure",
  amountHi: bigint,
  amountLo: bigint
): Instruction {
  return {
    programAddress: PROGRAM_ID,
    accounts: [{ address: ledger, role: AccountRole.WRITABLE }],
    data: concatBytes(disc(name), u64le(amountHi), u64le(amountLo)),
  };
}

describe("unbounded-cast (vuln-classes.md #7)", () => {
  it("EXPLOIT — credit_insecure accepts 2^64+500 and blows past the cap", async () => {
    const { svm, payer } = await setup();
    const ledger = await initLedger(svm, payer);

    // amount = 2^64 + 500. `amount as u64` == 500 <= CREDIT_CAP, so the check passes.
    const res = await send(svm, payer, [
      creditIx(ledger.address, "credit_insecure", 1n, 500n),
    ]);
    expect(
      isFailure(res),
      "expected credit_insecure to SUCCEED on a truncated over-cap amount (the bug)"
    ).to.be.false;

    const credited = readCredited(svm.getAccount(ledger.address)!.data);
    const expected = (1n << 64n) + 500n;
    expect(credited).to.equal(expected);
    expect(
      credited > CREDIT_CAP,
      "credited balance must exceed the cap it was supposed to enforce"
    ).to.be.true;
  });

  it("DEFENSE — credit_secure rejects the identical 2^64+500 amount", async () => {
    const { svm, payer } = await setup();
    const ledger = await initLedger(svm, payer);

    const res = await send(svm, payer, [
      creditIx(ledger.address, "credit_secure", 1n, 500n),
    ]);
    expect(
      isFailure(res),
      "expected credit_secure to REJECT an over-cap amount at full u128 width"
    ).to.be.true;

    const credited = readCredited(svm.getAccount(ledger.address)!.data);
    expect(credited, "no state change on a rejected credit").to.equal(0n);
  });

  it("POSITIVE CONTROL — credit_secure accepts genuine under-cap, rejects genuine over-cap", async () => {
    const { svm, payer } = await setup();
    const ledger = await initLedger(svm, payer);

    // Genuine under-cap (500) — must be accepted and credited exactly.
    const okRes = await send(svm, payer, [
      creditIx(ledger.address, "credit_secure", 0n, 500n),
    ]);
    expect(isFailure(okRes), "a genuine under-cap credit must be accepted").to.be.false;
    expect(readCredited(svm.getAccount(ledger.address)!.data)).to.equal(500n);

    // Genuine over-cap (2_000_000, high limb zero) — must be rejected on the REAL
    // cap, proving the fix isn't a width artifact that only triggers on high bits.
    const overRes = await send(svm, payer, [
      creditIx(ledger.address, "credit_secure", 0n, 2_000_000n),
    ]);
    expect(isFailure(overRes), "a genuine over-cap credit must be rejected").to.be.true;
    expect(
      readCredited(svm.getAccount(ledger.address)!.data),
      "balance unchanged after the rejected over-cap credit"
    ).to.equal(500n);
  });
});
