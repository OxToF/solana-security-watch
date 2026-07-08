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
import { expect } from "chai";
import * as path from "path";

// vuln-classes.md #1 — Account substitution / missing owner check.
// Reproduces the skill's own case study (skill/case-studies.md, HIGH finding):
// an `unstake` instruction that trusts an UncheckedAccount without verifying
// owner == program_id. Three tests, mirroring the EXPLOIT / DEFENSE / POSITIVE
// CONTROL pattern:
//
//   EXPLOIT           — a forged, System-Program-owned account with attacker-chosen
//                        bytes passes `unstake_insecure` and bypasses the lock.
//   DEFENSE           — the identical forged account is rejected by `unstake_secure`
//                        before the handler body ever runs (Anchor's typed
//                        Account<T> owner check fires first).
//   POSITIVE CONTROL  — `unstake_secure` is not a blanket-reject: a real, genuinely
//                        vested VestingState account is correctly accepted, and a
//                        real, still-locked one is correctly rejected on business
//                        logic (not on the owner check).

const PROGRAM_ID: Address = address(
  "EnhLFLMZAYgVFr2gSeNWuWUCimsMkeaxakNXbPHfdimX"
);
const SYSTEM_PROGRAM: Address = address(
  "11111111111111111111111111111111"
);
const SO_PATH = path.join(
  __dirname,
  "..",
  "target",
  "deploy",
  "account_substitution.so"
);

const DISCRIMINATORS = {
  init_vesting: Uint8Array.from([119, 192, 67, 41, 47, 82, 152, 27]),
  unstake_insecure: Uint8Array.from([38, 65, 44, 7, 145, 116, 145, 121]),
  unstake_secure: Uint8Array.from([110, 206, 173, 109, 50, 235, 228, 107]),
};

function u64le(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n, true);
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
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

function isFailure(res: unknown): boolean {
  return res instanceof FailedTransactionMetadata;
}

/** Plants a forged VestingState-shaped account NOT owned by our program. */
function plantForgedVesting(
  svm: LiteSVM,
  forgedAddress: Address,
  locked: bigint,
  claimed: bigint
) {
  const data = concatBytes(
    new Uint8Array(8), // discriminator — irrelevant, unstake_insecure never checks it
    new Uint8Array(32), // owner field — irrelevant filler, never read by unstake_insecure
    u64le(locked),
    u64le(claimed)
  );
  svm.setAccount({
    address: forgedAddress,
    data,
    executable: false,
    lamports: lamports(1_000_000n),
    programAddress: SYSTEM_PROGRAM, // NOT owned by our program at all
    space: BigInt(data.length),
  });
}

describe("account-substitution (vuln-classes.md #1)", () => {
  it("EXPLOIT — unstake_insecure accepts a forged, System-owned account", async () => {
    const { svm, payer } = await setup();
    const forged = await generateKeyPairSigner();

    // claimed(0) >= locked(0) trivially passes the "fully vested" check, despite
    // no real vesting account ever having been created for this address.
    plantForgedVesting(svm, forged.address, 0n, 0n);

    const ix: Instruction = {
      programAddress: PROGRAM_ID,
      accounts: [{ address: forged.address, role: AccountRole.READONLY }],
      data: DISCRIMINATORS.unstake_insecure,
    };

    const res = await send(svm, payer, [ix]);
    expect(
      isFailure(res),
      "expected unstake_insecure to SUCCEED on forged data (that is the bug)"
    ).to.be.false;
  });

  it("DEFENSE — unstake_secure rejects the identical forged account", async () => {
    const { svm, payer } = await setup();
    const forged = await generateKeyPairSigner();

    plantForgedVesting(svm, forged.address, 0n, 0n);

    const ix: Instruction = {
      programAddress: PROGRAM_ID,
      accounts: [{ address: forged.address, role: AccountRole.READONLY }],
      data: DISCRIMINATORS.unstake_secure,
    };

    const res = await send(svm, payer, [ix]);
    expect(
      isFailure(res),
      "expected unstake_secure to REJECT a forged, non-program-owned account"
    ).to.be.true;
  });

  it("POSITIVE CONTROL — unstake_secure correctly handles genuine accounts", async () => {
    const { svm, payer } = await setup();
    const vesting = await generateKeyPairSigner();

    const initIx: Instruction = {
      programAddress: PROGRAM_ID,
      accounts: [
        { address: vesting.address, role: AccountRole.WRITABLE_SIGNER, signer: vesting },
        { address: payer.address, role: AccountRole.WRITABLE_SIGNER, signer: payer },
        { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
      ],
      data: concatBytes(DISCRIMINATORS.init_vesting, u64le(1_000n)),
    };
    const initRes = await send(svm, payer, [initIx]);
    expect(isFailure(initRes), "init_vesting itself should succeed").to.be.false;

    // Still locked (claimed=0 < locked=1000) — must be rejected on BUSINESS LOGIC,
    // not on an owner check (this account is genuinely owned by our program).
    const stillLockedIx: Instruction = {
      programAddress: PROGRAM_ID,
      accounts: [{ address: vesting.address, role: AccountRole.READONLY }],
      data: DISCRIMINATORS.unstake_secure,
    };
    const lockedRes = await send(svm, payer, [stillLockedIx]);
    expect(
      isFailure(lockedRes),
      "a real but still-locked account must be rejected"
    ).to.be.true;

    // A second, fully-vested real account (locked=0) must be ACCEPTED — proves
    // unstake_secure isn't a blanket-reject, it's a genuine owner+logic check.
    const vested = await generateKeyPairSigner();
    const initVestedIx: Instruction = {
      programAddress: PROGRAM_ID,
      accounts: [
        { address: vested.address, role: AccountRole.WRITABLE_SIGNER, signer: vested },
        { address: payer.address, role: AccountRole.WRITABLE_SIGNER, signer: payer },
        { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
      ],
      data: concatBytes(DISCRIMINATORS.init_vesting, u64le(0n)),
    };
    expect(isFailure(await send(svm, payer, [initVestedIx]))).to.be.false;

    const vestedOkIx: Instruction = {
      programAddress: PROGRAM_ID,
      accounts: [{ address: vested.address, role: AccountRole.READONLY }],
      data: DISCRIMINATORS.unstake_secure,
    };
    const vestedRes = await send(svm, payer, [vestedOkIx]);
    expect(
      isFailure(vestedRes),
      "a real, fully-vested account must be accepted"
    ).to.be.false;
  });
});
