// node --test server/agent.test.mjs
// The agent flow end to end against a fake Solana RPC: quote (402), a proof that
// lacks the memo, a proof that carries it, token-gated polling, replay refusal.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyFromTx, memosOf, USDC_MINT, MEMO_PROGRAM_ID } from "./verify.mjs";

const MERCHANT = "7yMnWMrxzZ3YCtWXRsZEhAFwexHoJzBJy8RgN7Lhvy1P";
const SIG_OK = "5".repeat(88);
const SIG_NO_MEMO = "4".repeat(88);

function fakeTx({ amount = 69_000_000n, memo = null } = {}) {
  const instructions = [];
  if (memo !== null) instructions.push({ program: "spl-memo", programId: MEMO_PROGRAM_ID, parsed: memo, stackHeight: 1 });
  return {
    transaction: { message: { instructions } },
    meta: {
      err: null,
      innerInstructions: [],
      preTokenBalances: [{ accountIndex: 2, mint: USDC_MINT, owner: MERCHANT, uiTokenAmount: { amount: "1000000" } }],
      postTokenBalances: [{ accountIndex: 2, mint: USDC_MINT, owner: MERCHANT, uiTokenAmount: { amount: String(1_000_000n + amount) } }],
    },
  };
}

test("memo binds a payment to its job", () => {
  const tx = fakeTx({ memo: "ssw:abc" });
  assert.deepEqual(memosOf(tx), ["ssw:abc"]);
  assert.equal(verifyFromTx(tx, { amountUsdc: 69, merchant: MERCHANT, memo: "ssw:abc" }).ok, true);
  assert.match(verifyFromTx(tx, { amountUsdc: 69, merchant: MERCHANT, memo: "ssw:other" }).reason, /memo/);
  assert.match(verifyFromTx(fakeTx(), { amountUsdc: 69, merchant: MERCHANT, memo: "ssw:abc" }).reason, /memo/);
  // Without a memo requirement the web flow behaves as before.
  assert.equal(verifyFromTx(fakeTx(), { amountUsdc: 69, merchant: MERCHANT }).ok, true);
});

test("memo sent through a CPI counts", () => {
  const tx = fakeTx();
  tx.meta.innerInstructions = [{ index: 0, instructions: [{ programId: MEMO_PROGRAM_ID, parsed: "ssw:cpi" }] }];
  assert.equal(verifyFromTx(tx, { amountUsdc: 69, merchant: MERCHANT, memo: "ssw:cpi" }).ok, true);
});

test("underpayment is refused even with the right memo", () => {
  const tx = fakeTx({ amount: 68_999_999n, memo: "ssw:abc" });
  assert.equal(verifyFromTx(tx, { amountUsdc: 69, merchant: MERCHANT, memo: "ssw:abc" }).ok, false);
});

// --- end to end ---------------------------------------------------------------
let rpc, srv, base, currentMemo = null;
const port = 18000 + Math.floor(Math.random() * 1000);

before(async () => {
  rpc = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const { params } = JSON.parse(b);
      const result = params[0] === SIG_OK ? fakeTx({ memo: currentMemo }) : params[0] === SIG_NO_MEMO ? fakeTx() : null;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
    });
  });
  await new Promise((r) => rpc.listen(0, r));
  base = `http://127.0.0.1:${port}`;
  const dir = mkdtempSync(join(tmpdir(), "ssw-agent-test-"));
  srv = spawn(process.execPath, [join(dirname(fileURLToPath(import.meta.url)), "index.mjs")], {
    env: {
      ...process.env,
      PORT: String(port),
      JOBS_FILE: join(dir, "jobs.json"),
      MERCHANT_WALLET: MERCHANT,
      SOLANA_RPC_URL: `http://127.0.0.1:${rpc.address().port}`,
      SCAN_PRICE_USD: "69",
      PUBLIC_BASE_URL: base,
      RESEND_API_KEY: "",
    },
    stdio: "ignore",
  });
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(`${base}/health`)).ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("server did not start");
});

after(() => { srv?.kill(); rpc?.close(); });

const post = (body) => fetch(`${base}/agent/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

test("agent flow: quote, pay, poll", async () => {
  const skill = await (await fetch(`${base}/skill.md`)).text();
  assert.match(skill, new RegExp(MERCHANT));
  assert.doesNotMatch(skill, /\{\{/);

  assert.equal((await post({ repo: "not a repo" })).status, 400);

  const q = await post({ repo: "https://github.com/OxToF/solana-security-watch" });
  assert.equal(q.status, 402);
  const quote = await q.json();
  const acc = quote.accepts[0];
  assert.equal(acc.payTo, MERCHANT);
  assert.equal(acc.asset, USDC_MINT);
  assert.equal(acc.maxAmountRequired, "69000000");
  assert.match(acc.extra.memo, /^ssw:/);
  assert.ok(quote.accessToken && quote.jobId);
  currentMemo = acc.extra.memo;

  // The public status endpoint must not leak the memo or the token hash.
  const pub = await (await fetch(`${base}/jobs/${quote.jobId}`)).json();
  assert.equal(pub.memo, undefined);
  assert.equal(pub.accessTokenHash, undefined);

  // A real USDC transfer without the job's memo does not pay for the job.
  const noMemo = await post({ jobId: quote.jobId, signature: SIG_NO_MEMO });
  assert.equal(noMemo.status, 402);
  assert.match((await noMemo.json()).error, /memo/);

  const paid = await post({ jobId: quote.jobId, signature: SIG_OK });
  assert.equal(paid.status, 202);

  // Replay: same proof again, and the same signature on a second job.
  assert.equal((await post({ jobId: quote.jobId, signature: SIG_OK })).status, 409);
  const q2 = await (await post({ repo: "https://github.com/OxToF/solana-security-watch" })).json();
  assert.equal((await post({ jobId: q2.jobId, signature: SIG_OK })).status, 409);

  // The report is readable only with the token handed out at quote time.
  const status = (tok) => fetch(`${base}/agent/jobs/${quote.jobId}`, { headers: tok ? { authorization: `Bearer ${tok}` } : {} });
  assert.equal((await status()).status, 404);
  assert.equal((await status(q2.accessToken)).status, 404);
  const ok = await status(quote.accessToken);
  assert.equal(ok.status, 200);
  assert.ok(["paid", "running", "done", "error"].includes((await ok.json()).status));
  const early = await fetch(`${base}/agent/jobs/${q2.jobId}/report.json`, { headers: { authorization: `Bearer ${q2.accessToken}` } });
  assert.equal(early.status, 409);
});

test("private report links: a wrong token or an unknown job is a 404, never a report", async () => {
  const job = await (await fetch(`${base}/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repo: "https://github.com/OxToF/solana-security-watch", email: "a@b.co" }) })).json();
  assert.equal((await fetch(`${base}/r/${job.jobId}/${"x".repeat(32)}`)).status, 404);
  assert.equal((await fetch(`${base}/r/00000000-0000-0000-0000-000000000000/${"x".repeat(32)}`)).status, 404);
  const pub = await (await fetch(`${base}/jobs/${job.jobId}`)).json();
  assert.equal("viewTokenHash" in pub, false);
});
