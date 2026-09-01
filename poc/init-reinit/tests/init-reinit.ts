import { LiteSVM, FailedTransactionMetadata } from "litesvm";
import {
  address,
  type Address,
  AccountRole,
  appendTransactionMessageInstructions,
  createTransactionMessage,
  generateKeyPairSigner,
  getAddressDecoder,
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

// vuln-classes.md #2 — init_if_needed re-initialisation.
//   EXPLOIT           — initialize_insecure, called a second time by an attacker,
//                        overwrites config.authority with the attacker's key.
//   DEFENSE           — initialize_secure (plain init) fails on the attacker's
//                        replay; authority stays with the original owner.
//   POSITIVE CONTROL  — initialize_secure still creates the account on first call
//                        (it is not a blanket reject).

const PROGRAM_ID: Address = address("6Gcu3VQHJFHq4jeM7iRcYsvXBRDzjv4vaxiqUnFfaFn8");
const SYSTEM_PROGRAM: Address = address("11111111111111111111111111111111");
const SO_PATH = path.join(process.cwd(), "target", "deploy", "init_reinit.so");

function disc(name: string): Uint8Array {
  return Uint8Array.from(createHash("sha256").update(`global:${name}`).digest()).slice(0, 8);
}
function isFailure(res: unknown): boolean {
  return res instanceof FailedTransactionMetadata;
}
const addrDecoder = getAddressDecoder();
function readAuthority(data: Uint8Array): Address {
  return addrDecoder.decode(data.subarray(8, 40));
}

async function configPda(): Promise<Address> {
  const [pda] = await getProgramDerivedAddress({
    programAddress: PROGRAM_ID,
    seeds: ["config"],
  });
  return pda;
}

async function fundedSigner(svm: LiteSVM): Promise<TransactionSigner> {
  const s = await generateKeyPairSigner();
  svm.airdrop(s.address, lamports(10_000_000_000n));
  return s;
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

function initIx(
  name: "initialize_insecure" | "initialize_secure",
  config: Address,
  authority: TransactionSigner
): Instruction {
  return {
    programAddress: PROGRAM_ID,
    accounts: [
      { address: config, role: AccountRole.WRITABLE },
      { address: authority.address, role: AccountRole.WRITABLE_SIGNER, signer: authority },
      { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
    ],
    data: disc(name),
  };
}

async function setup(): Promise<{ svm: LiteSVM; config: Address }> {
  const svm = new LiteSVM();
  svm.addProgramFromFile(PROGRAM_ID, SO_PATH);
  return { svm, config: await configPda() };
}

describe("init-reinit (vuln-classes.md #2)", () => {
  it("EXPLOIT — a second initialize_insecure hijacks config.authority", async () => {
    const { svm, config } = await setup();
    const owner = await fundedSigner(svm);
    const attacker = await fundedSigner(svm);

    expect(isFailure(await send(svm, owner, [initIx("initialize_insecure", config, owner)])),
      "owner's first init should succeed").to.be.false;
    expect(readAuthority(svm.getAccount(config)!.data)).to.equal(owner.address);

    // init_if_needed re-runs the body on the already-existing account.
    expect(isFailure(await send(svm, attacker, [initIx("initialize_insecure", config, attacker)])),
      "attacker's re-init should (wrongly) succeed").to.be.false;
    expect(
      readAuthority(svm.getAccount(config)!.data),
      "authority must have been hijacked to the attacker"
    ).to.equal(attacker.address);
  });

  it("DEFENSE — initialize_secure rejects the attacker's replay", async () => {
    const { svm, config } = await setup();
    const owner = await fundedSigner(svm);
    const attacker = await fundedSigner(svm);

    expect(isFailure(await send(svm, owner, [initIx("initialize_secure", config, owner)])),
      "owner's first init should succeed").to.be.false;
    expect(readAuthority(svm.getAccount(config)!.data)).to.equal(owner.address);

    expect(isFailure(await send(svm, attacker, [initIx("initialize_secure", config, attacker)])),
      "attacker's replay of plain init must fail").to.be.true;
    expect(
      readAuthority(svm.getAccount(config)!.data),
      "authority must remain the original owner"
    ).to.equal(owner.address);
  });

  it("POSITIVE CONTROL — initialize_secure still creates the account first time", async () => {
    const { svm, config } = await setup();
    const owner = await fundedSigner(svm);
    expect(isFailure(await send(svm, owner, [initIx("initialize_secure", config, owner)])),
      "a genuine first-time secure init must succeed").to.be.false;
    expect(readAuthority(svm.getAccount(config)!.data)).to.equal(owner.address);
  });
});
