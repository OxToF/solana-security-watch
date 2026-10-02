// node --test server/agent.test.mjs
// The agent flow end to end against a fake Solana RPC: quote (402), a proof that
// lacks the memo, a proof that carries it, token-gated polling, replay refusal.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { createHmac } from "node:crypto";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyFromTx, memosOf, USDC_MINT, MEMO_PROGRAM_ID } from "./verify.mjs";
import { routeOf } from "./traffic.mjs";
import { encodeHeader, decodeHeader, SOLANA_MAINNET } from "./x402.mjs";

const MERCHANT = "7yMnWMrxzZ3YCtWXRsZEhAFwexHoJzBJy8RgN7Lhvy1P";
const SIG_OK = "5".repeat(88);
const SIG_NO_MEMO = "4".repeat(88);
const SIG_X402 = "3".repeat(88);
const FEE_PAYER = "CjNFTjvBhbJJd2B5ePPMHRLx1ELZpa8dwQgGL727eKww";

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
let rpc, fac, osv, srv, base, testDir, currentMemo = null, x402Memo = null, osvDown = false, serdeVuln = false;
const osvCalls = [];
// What the fake facilitator was asked to settle against, per call.
const facCalls = [];
const port = 18000 + Math.floor(Math.random() * 1000);

before(async () => {
  rpc = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const { params } = JSON.parse(b);
      const result = params[0] === SIG_OK ? fakeTx({ memo: currentMemo })
        : params[0] === SIG_NO_MEMO ? fakeTx()
        : params[0] === SIG_X402 ? fakeTx({ memo: x402Memo })
        : null;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
    });
  });
  await new Promise((r) => rpc.listen(0, r));
  // Fake facilitator: a transaction "BAD" fails /verify, "NOSETTLE" fails /settle.
  fac = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      if (req.url === "/supported") return res.end(JSON.stringify({ kinds: [{ x402Version: 2, scheme: "exact", network: SOLANA_MAINNET, extra: { feePayer: FEE_PAYER } }], extensions: ["bazaar"] }));
      const body = JSON.parse(b);
      facCalls.push({ path: req.url, body });
      const tx = body.paymentPayload.payload.transaction;
      if (req.url === "/verify") return res.end(JSON.stringify(tx === "BAD" ? { isValid: false, invalidReason: "invalid_exact_svm_payload_transaction" } : { isValid: true, payer: "Payer111" }));
      const settled = { GOOD: SIG_X402, CHK1: "6".repeat(88), CHK2: "7".repeat(88), CHK3: "8".repeat(88), WATCH1: "9".repeat(88) }[tx] || SIG_X402;
      if (req.url === "/settle") return res.end(JSON.stringify(tx === "NOSETTLE"
        ? { success: false, errorReason: "insufficient_funds", transaction: "", network: SOLANA_MAINNET }
        : { success: true, transaction: settled, network: SOLANA_MAINNET, payer: "Payer111" }));
      res.end("{}");
    });
  });
  await new Promise((r) => fac.listen(0, r));
  // Fake OSV: borsh 0.9.3 carries one advisory, everything else is clean.
  osv = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (osvDown) { res.writeHead(500); return res.end(); }
      if (req.url === "/v1/querybatch") {
        const { queries } = JSON.parse(b);
        osvCalls.push({ batch: queries.length });
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify({ results: queries.map((q) => (q.package.name === "borsh" ? { vulns: [{ id: "RUSTSEC-2023-0033" }] }
          : q.package.name === "serde" && serdeVuln ? { vulns: [{ id: "RUSTSEC-2099-0001" }] } : {})) }));
      }
      if (req.url.startsWith("/v1/vulns/")) {
        osvCalls.push({ vuln: req.url });
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify(req.url.endsWith("RUSTSEC-2099-0001")
          ? { id: "RUSTSEC-2099-0001", summary: "serde test advisory", database_specific: { severity: "HIGH" } }
          : { id: "RUSTSEC-2023-0033", aliases: ["GHSA-fjx5-qpf4-xjf2"], summary: "borsh ZST unsound" }));
      }
      const q = JSON.parse(b);
      osvCalls.push(q);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(q.package.name === "borsh" ? { vulns: [{ id: "RUSTSEC-2023-0033", aliases: ["GHSA-fjx5-qpf4-xjf2"], summary: "borsh ZST unsound" }] } : {}));
    });
  });
  await new Promise((r) => osv.listen(0, r));
  base = `http://127.0.0.1:${port}`;
  const dir = testDir = mkdtempSync(join(tmpdir(), "ssw-agent-test-"));
  srv = spawn(process.execPath, [join(dirname(fileURLToPath(import.meta.url)), "index.mjs")], {
    env: {
      ...process.env,
      PORT: String(port),
      JOBS_FILE: join(dir, "jobs.json"),
      MERCHANT_WALLET: MERCHANT,
      SOLANA_RPC_URL: `http://127.0.0.1:${rpc.address().port}`,
      FACILITATOR_URL: `http://127.0.0.1:${fac.address().port}`,
      OSV_QUERY_URL: `http://127.0.0.1:${osv.address().port}`,
      OSV_BATCH_URL: `http://127.0.0.1:${osv.address().port}/v1/querybatch`,
      OSV_VULNS_URL: `http://127.0.0.1:${osv.address().port}/v1/vulns`,
      SCAN_PRICE_USD: "69",
      PUBLIC_BASE_URL: base,
      RESEND_API_KEY: "",
      ADMIN_TOKEN: "test-admin",
      WATCH_ALLOW_PRIVATE_WEBHOOKS: "1",
      WATCH_TICK_MS: "100",
      WATCH_INTERVAL_MS: "0",
    },
    stdio: "ignore",
  });
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(`${base}/health`)).ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("server did not start");
});

after(() => { srv?.kill(); rpc?.close(); fac?.close(); osv?.close(); });

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
  assert.equal(acc.maxAmountRequired, "500000"); // agents: $0.50, not the $69 web price
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

test("x402 v2: quote header, settle through the facilitator, token in the paid response", async () => {
  const repo = "https://github.com/OxToF/solana-security-watch";
  const q = await post({ repo });
  assert.equal(q.status, 402);
  const required = decodeHeader(q.headers.get("payment-required"));
  assert.equal(required.x402Version, 2);
  const [req] = required.accepts;
  assert.equal(req.network, SOLANA_MAINNET);
  assert.equal(req.amount, "500000");
  assert.equal(req.payTo, MERCHANT);
  assert.equal(req.extra.feePayer, FEE_PAYER);
  assert.match(req.extra.memo, /^ssw:/);
  assert.equal(required.extensions.bazaar.info.input.method, "POST");
  assert.ok(required.resource.serviceName.length <= 32 && required.resource.tags.length <= 5);
  x402Memo = req.extra.memo;

  const pay = (transaction, accepted = req, headers = {}) => fetch(`${base}/agent/scan`, {
    method: "POST",
    headers: { "content-type": "application/json", "payment-signature": encodeHeader({ x402Version: 2, resource: required.resource, accepted, payload: { transaction }, extensions: required.extensions }), ...headers },
    body: JSON.stringify({ repo }),
  });

  // A transaction the facilitator rejects: 402 with a fresh quote, job still open.
  const bad = await pay("BAD");
  assert.equal(bad.status, 402);
  assert.ok(bad.headers.get("payment-required"));
  const failed = await pay("NOSETTLE");
  assert.equal(failed.status, 402);
  assert.equal(decodeHeader(failed.headers.get("payment-response")).success, false);

  // A client that lowers the amount in its echo is settled against OUR terms.
  facCalls.length = 0;
  const ok = await pay("GOOD", { ...req, amount: "1", payTo: "Attacker1111111111111111111111111111111111" });
  assert.equal(ok.status, 200);
  for (const c of facCalls) {
    assert.equal(c.body.paymentRequirements.amount, "500000");
    assert.equal(c.body.paymentRequirements.payTo, MERCHANT);
    assert.equal(c.body.paymentRequirements.extra.memo, x402Memo);
  }
  const settled = decodeHeader(ok.headers.get("payment-response"));
  assert.equal(settled.transaction, SIG_X402);
  const paid = await ok.json();
  assert.ok(paid.accessToken);

  // The paid token reads the job; replaying the same payment is refused.
  const st = await fetch(`${base}/agent/jobs/${paid.jobId}`, { headers: { authorization: `Bearer ${paid.accessToken}` } });
  assert.equal(st.status, 200);
  assert.equal((await pay("GOOD")).status, 409);

  // An unknown memo, a malformed header, and a v1 header settle nothing.
  assert.equal((await pay("GOOD", { ...req, extra: { ...req.extra, memo: "ssw:nope" } })).status, 402);
  const junk = await fetch(`${base}/agent/scan`, { method: "POST", headers: { "payment-signature": "%%%" }, body: JSON.stringify({ repo }) });
  assert.equal(junk.status, 400);
  const v1 = await fetch(`${base}/agent/scan`, { method: "POST", headers: { "x-payment": "e30=" }, body: JSON.stringify({ repo }) });
  assert.equal(v1.status, 400);
});

test("ERC-8004 registration file: x402 service, own domain, no registration before one exists", async () => {
  const reg = await (await fetch(`${base}/.well-known/agent-registration.json`)).json();
  assert.equal(reg.type, "https://eips.ethereum.org/EIPS/eip-8004#registration-v1");
  assert.equal(reg.x402Support, true);
  assert.ok(reg.services.some((s) => s.name === "x402" && s.endpoint === `${base}/agent/scan`));
  assert.deepEqual(reg.registrations, []);
  const logo = await fetch(reg.image);
  assert.equal(logo.status, 200);
  assert.match(logo.headers.get("content-type"), /image\/svg\+xml/);
});

test("per-request check: instant answer, settled only once the answer exists", async () => {
  const check = (body, header) => fetch(`${base}/agent/check`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(header ? { "payment-signature": header } : {}) },
    body: JSON.stringify(body),
  });
  const packages = [{ name: "borsh", version: "0.9.3" }, { name: "anchor-lang", version: "0.29.0" }, { name: "borsh", version: "0.9.3" }];

  assert.equal((await check({ packages: [] })).status, 400);
  assert.equal((await check({ packages: [{ name: "a b", version: "1" }] })).status, 400);
  assert.equal((await check({ packages: Array.from({ length: 101 }, () => ({ name: "x", version: "1.0.0" })) })).status, 400);

  const q = await check({ packages });
  assert.equal(q.status, 402);
  const required = decodeHeader(q.headers.get("payment-required"));
  const [req] = required.accepts;
  assert.equal(req.amount, "10000"); // $0.01
  assert.equal(req.extra.memo, undefined);
  assert.equal(req.extra.feePayer, FEE_PAYER);
  assert.equal(required.resource.url, `${base}/agent/check`);
  assert.ok(required.resource.serviceName.length <= 32);
  const pay = (transaction, accepted = req) => encodeHeader({ x402Version: 2, resource: required.resource, accepted, payload: { transaction }, extensions: required.extensions });

  // Rejected payment: no lookup is made.
  osvCalls.length = 0;
  assert.equal((await check({ packages }, pay("BAD"))).status, 402);
  assert.equal(osvCalls.length, 0);

  // Advisory database down: nothing is settled.
  osvDown = true; facCalls.length = 0;
  assert.equal((await check({ packages }, pay("CHK1"))).status, 502);
  assert.deepEqual(facCalls.map((c) => c.path), ["/verify"]);
  osvDown = false;

  // Settled against our amount even if the echo says otherwise; duplicates queried once.
  facCalls.length = 0; osvCalls.length = 0;
  const ok = await check({ packages }, pay("CHK1", { ...req, amount: "1" }));
  assert.equal(ok.status, 200);
  assert.equal(osvCalls.length, 2);
  assert.deepEqual(facCalls.map((c) => c.path), ["/verify", "/settle"]);
  for (const c of facCalls) assert.equal(c.body.paymentRequirements.amount, "10000");
  const out = await ok.json();
  assert.equal(out.checked, 2);
  assert.equal(out.advisories.length, 1);
  assert.equal(out.advisories[0].id, "RUSTSEC-2023-0033");
  assert.equal(decodeHeader(ok.headers.get("payment-response")).transaction, "6".repeat(88));

  // The same signed transfer twice buys one answer.
  assert.equal((await check({ packages }, pay("CHK1"))).status, 409);
  assert.equal((await check({ packages }, pay("CHK2"))).status, 200);
});

test("/agent/check takes a whole Cargo.lock, crates.io packages only, in one batch", async () => {
  const reg = 'source = "registry+https://github.com/rust-lang/crates.io-index"';
  const lock = [
    "version = 3", "",
    "[[package]]", 'name = "borsh"', 'version = "0.9.3"', reg, "",
    "[[package]]", 'name = "serde"', 'version = "1.0.200"', reg, "",
    // Same name as a published crate, but it is ours: must not be checked.
    "[[package]]", 'name = "router"', 'version = "0.1.0"', "",
    "[[package]]", 'name = "anchor-syn"', 'version = "0.31.1"', 'source = "git+https://github.com/x/anchor?rev=abc#abc"', "",
  ].join("\n");
  const check = (body, payment) => fetch(`${base}/agent/check`, {
    method: "POST", headers: { "content-type": "application/json", ...(payment ? { "payment-signature": payment } : {}) }, body: JSON.stringify(body),
  });
  assert.equal((await check({ lockfile: "not a lockfile" })).status, 400);
  assert.equal((await check({ lockfile: lock, packages: [{ name: "borsh", version: "0.9.3" }] })).status, 400);
  assert.equal((await check({ lockfile: "[[package]]\nname = \"router\"\nversion = \"0.1.0\"\n" })).status, 400);

  const q = await check({ lockfile: lock });
  assert.equal(q.status, 402);
  const required = decodeHeader(q.headers.get("payment-required"));
  const [req] = required.accepts;
  assert.equal(req.amount, "10000"); // same price as a package list
  assert.ok(required.extensions.bazaar.schema.properties.input.properties.body.properties.lockfile);
  const pay = (transaction) => encodeHeader({ x402Version: 2, resource: required.resource, accepted: req, payload: { transaction }, extensions: required.extensions });

  osvCalls.length = 0;
  const ok = await check({ lockfile: lock }, pay("CHK3"));
  assert.equal(ok.status, 200);
  assert.deepEqual(osvCalls, [{ batch: 2 }, { vuln: "/v1/vulns/RUSTSEC-2023-0033" }]);
  const out = await ok.json();
  assert.equal(out.checked, 2);
  assert.deepEqual(out.lockfile, { type: "Cargo.lock", packages: 2, skipped: 2 });
  assert.equal(out.advisories.length, 1);
  assert.equal(out.advisories[0].id, "RUSTSEC-2023-0033");
  assert.deepEqual(out.advisories[0].crates, ["borsh 0.9.3"]);

  // A batch the database does not answer: nothing settled.
  osvDown = true; facCalls.length = 0;
  assert.equal((await check({ lockfile: lock }, pay("CHK4"))).status, 502);
  assert.deepEqual(facCalls.map((c) => c.path), ["/verify"]);
  osvDown = false;
});

test("/agent/program: priced apart, a wrong address costs nothing", async () => {
  const call = (body, payment) => fetch(`${base}/agent/program`, {
    method: "POST", headers: { "content-type": "application/json", ...(payment ? { "payment-signature": payment } : {}) }, body: JSON.stringify(body),
  });
  assert.equal((await call({ programId: "not-an-address" })).status, 400);
  const q = await call({ programId: MERCHANT });
  assert.equal(q.status, 402);
  const required = decodeHeader(q.headers.get("payment-required"));
  const [req] = required.accepts;
  assert.equal(req.amount, "50000"); // $0.05
  assert.equal(req.payTo, MERCHANT);
  assert.equal(required.resource.url, `${base}/agent/program`);
  assert.ok(required.resource.serviceName.length <= 32);
  assert.deepEqual(required.extensions.bazaar.schema.properties.input.properties.body.required, ["programId"]);

  // The fake RPC knows no such account: verified, looked up, refused, never settled.
  facCalls.length = 0;
  const pay = encodeHeader({ x402Version: 2, resource: required.resource, accepted: req, payload: { transaction: "PRG1" }, extensions: required.extensions });
  const r = await call({ programId: MERCHANT }, pay);
  assert.equal(r.status, 404);
  assert.match((await r.json()).error, /Nothing charged/);
  assert.deepEqual(facCalls.map((c) => c.path), ["/verify"]);
});

test("/agent/watch: created only once paid, signed webhook on a new advisory, readable and cancellable", async () => {
  const hooks = [];
  const hook = createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { hooks.push({ headers: req.headers, body: b }); res.writeHead(204); res.end(); }); });
  await new Promise((r) => hook.listen(0, r));
  const webhook = `http://127.0.0.1:${hook.address().port}/hook`;
  const reg = 'source = "registry+https://github.com/rust-lang/crates.io-index"';
  const lockfile = ["[[package]]", 'name = "borsh"', 'version = "0.9.3"', reg, "", "[[package]]", 'name = "serde"', 'version = "1.0.200"', reg, ""].join("\n");
  const call = (body, payment) => fetch(`${base}/agent/watch`, {
    method: "POST", headers: { "content-type": "application/json", ...(payment ? { "payment-signature": payment } : {}) }, body: JSON.stringify(body),
  });
  const watchesOnDisk = () => (existsSync(join(testDir, "watches.json")) ? Object.keys(JSON.parse(readFileSync(join(testDir, "watches.json"), "utf8"))).length : 0);
  try {
    assert.equal((await call({ lockfile })).status, 400); // no webhook
    assert.equal((await call({ lockfile, webhook: "ftp://x" })).status, 400);
    const q = await call({ lockfile, webhook });
    assert.equal(q.status, 402);
    const required = decodeHeader(q.headers.get("payment-required"));
    const [req] = required.accepts;
    assert.equal(req.amount, "900000"); // $0.90 for the period
    assert.equal(required.resource.url, `${base}/agent/watch`);
    assert.ok(required.resource.serviceName.length <= 32);
    const pay = (transaction) => encodeHeader({ x402Version: 2, resource: required.resource, accepted: req, payload: { transaction }, extensions: required.extensions });

    // Settlement fails: no watch exists.
    assert.equal((await call({ lockfile, webhook }, pay("NOSETTLE"))).status, 402);
    assert.equal(watchesOnDisk(), 0);

    const ok = await call({ lockfile, webhook }, pay("WATCH1"));
    assert.equal(ok.status, 200);
    const sub = await ok.json();
    assert.equal(watchesOnDisk(), 1);
    assert.ok(sub.watchId && sub.secret && sub.accessToken && sub.expiresAt);
    assert.deepEqual(sub.baseline.advisories.map((a) => a.id), ["RUSTSEC-2023-0033"]);

    // Nothing new: no page. Then an advisory appears for serde.
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(hooks.length, 0);
    serdeVuln = true;
    for (let i = 0; i < 50 && !hooks.length; i++) await new Promise((r) => setTimeout(r, 100));
    assert.equal(hooks.length, 1);
    const { headers, body } = hooks[0];
    assert.equal(headers["x-watchdog-signature"], "sha256=" + createHmac("sha256", sub.secret).update(body).digest("hex"));
    const ev = JSON.parse(body);
    assert.equal(ev.watchId, sub.watchId);
    assert.deepEqual(ev.events.map((e) => [e.type, e.advisory.id]), [["new-advisory", "RUSTSEC-2099-0001"]]);
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(hooks.length, 1); // paged once

    const auth = { authorization: `Bearer ${sub.accessToken}` };
    assert.equal((await fetch(sub.statusUrl)).status, 404);
    const view = await (await fetch(sub.statusUrl, { headers: auth })).json();
    assert.equal(view.status, "active");
    assert.equal(view.events[0].delivered, true);
    assert.equal(view.secret, undefined);
    const del = await fetch(sub.statusUrl, { method: "DELETE", headers: auth });
    assert.equal((await del.json()).status, "cancelled");
  } finally {
    serdeVuln = false;
    hook.close();
  }
});

test("traffic log: who called and where they stopped, with no id, token or IP in it", async () => {
  assert.equal(routeOf("/r/8f0c6a2e-1b7d-4c1e-9d3a-2f5e6b7c8d9e/AbCdEfGhIjKlMnOpQrStUv"), "/r/:id/:token");
  assert.equal(routeOf("/agent/jobs/8f0c6a2e-1b7d-4c1e-9d3a-2f5e6b7c8d9e/report.md"), "/agent/jobs/:id/report.md");

  assert.equal((await fetch(`${base}/admin/traffic`)).status, 401);
  const auth = { authorization: "Bearer test-admin" };
  // The log line is written on "finish": give the last responses a moment.
  await new Promise((r) => setTimeout(r, 100));
  const sum = await (await fetch(`${base}/admin/traffic?hours=1`, { headers: auth })).json();
  assert.ok(sum.total > 0);
  assert.ok(sum.agentFunnel.quoted >= 1, "the 402 quotes of the earlier tests are counted");
  assert.ok(sum.routes["POST /agent/scan"]?.["402"] >= 1);
  assert.equal(Object.keys(sum.routes).some((k) => k.includes("/health")), false);

  const raw = readFileSync(join(testDir, "traffic.jsonl"), "utf8");
  assert.doesNotMatch(raw, /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  assert.doesNotMatch(raw, /127\.0\.0\.1|::1/);
  assert.doesNotMatch(raw, /Bearer/);
});

test("rate limits are per client behind the proxy, not one budget for everyone", async () => {
  const as = (who) => fetch(`${base}/agent/scan`, { method: "POST", headers: { "content-type": "application/json", "fly-client-ip": who }, body: "{}" });
  for (let i = 0; i < 20; i++) assert.notEqual((await as("203.0.113.1")).status, 429);
  assert.equal((await as("203.0.113.1")).status, 429);
  assert.notEqual((await as("203.0.113.2")).status, 429, "another caller keeps its own budget");
});

test("discovery: probes get the 402 terms, never a 404 or 400, and nothing is created or settled", async () => {
  const jobsBefore = existsSync(join(testDir, "jobs.json")) ? Object.keys(JSON.parse(readFileSync(join(testDir, "jobs.json"), "utf8"))).length : 0;
  // Its own client addresses: the rate limit buckets are per client, all routes together.
  const h = { "content-type": "application/json", "fly-client-ip": "198.51.100.7" };
  const prices = { "/agent/program": "50000", "/agent/check": "10000", "/agent/scan": "500000", "/agent/watch": "900000" };
  for (const [path, amount] of Object.entries(prices)) {
    for (const [method, body] of [["GET"], ["HEAD"], ["POST", "{}"], ["POST", ""]]) {
      const r = await fetch(`${base}${path}`, { method, headers: h, body });
      assert.equal(r.status, 402, `${method} ${path} ${JSON.stringify(body)}`);
      const req = decodeHeader(r.headers.get("payment-required"));
      assert.equal(req.x402Version, 2);
      assert.equal(req.accepts[0].amount, amount, `${method} ${path}`);
      assert.equal(req.accepts[0].payTo, MERCHANT);
      assert.equal(req.accepts[0].extra.memo, undefined, "a probe never gets a payable job memo");
      assert.ok(req.extensions.bazaar.info.input.body, "the example body is in the terms");
      if (method !== "HEAD") assert.match((await r.json()).howTo, new RegExp(`POST ${base}${path}`));
    }
  }
  const jobsAfter = existsSync(join(testDir, "jobs.json")) ? Object.keys(JSON.parse(readFileSync(join(testDir, "jobs.json"), "utf8"))).length : 0;
  assert.equal(jobsAfter, jobsBefore, "a probe creates no job");

  // A malformed body is still a 400: only an empty one is a probe.
  assert.equal((await fetch(`${base}/agent/program`, { method: "POST", headers: h, body: JSON.stringify({ programId: "nope" }) })).status, 400);

  // Paying a probe's terms without a real body never reaches /settle.
  const settlesBefore = facCalls.filter((c) => c.path === "/settle").length;
  const accepted = decodeHeader((await fetch(`${base}/agent/scan`, { method: "GET", headers: h })).headers.get("payment-required")).accepts[0];
  const sig = encodeHeader({ x402Version: 2, accepted, payload: { transaction: "GOOD" } });
  for (const path of Object.keys(prices)) {
    const r = await fetch(`${base}${path}`, { method: "POST", headers: { ...h, "fly-client-ip": "198.51.100.8", "payment-signature": sig }, body: "{}" });
    assert.ok([400, 402].includes(r.status), `${path} answered ${r.status}`);
  }
  assert.equal(facCalls.filter((c) => c.path === "/settle").length, settlesBefore, "nothing settled");
});

test("discovery documents: /.well-known/x402, /openapi.json, /llms.txt, /robots.txt", async () => {
  const d = await (await fetch(`${base}/.well-known/x402`)).json();
  assert.equal(d.x402Version, 2);
  assert.deepEqual(d.resources.map((u) => u.replace(base, "")), ["/agent/program", "/agent/check", "/agent/scan", "/agent/watch"]);
  assert.deepEqual(d.services.map((s) => s.priceUsdc), [0.05, 0.01, 0.5, 0.9]);
  assert.ok(d.services.every((s) => s.payTo === MERCHANT && s.network === SOLANA_MAINNET && s.input.example));
  const o = await (await fetch(`${base}/openapi.json`)).json();
  assert.equal(o.openapi, "3.1.0");
  assert.deepEqual(Object.keys(o.paths), ["/agent/program", "/agent/check", "/agent/scan", "/agent/watch"]);
  assert.equal(o.paths["/agent/check"].post["x-x402"].priceUsdc, 0.01);
  const l = await fetch(`${base}/llms.txt`);
  assert.match(l.headers.get("content-type"), /text\/plain/);
  assert.match(await l.text(), /POST .*\/agent\/program, \$0\.05 USDC/);
  assert.match(await (await fetch(`${base}/robots.txt`)).text(), /Disallow: \/admin\//);
});

test("a 400 on a placeholder or broken body still carries the terms; a paid attempt does not", async () => {
  const h = { "content-type": "application/json", "fly-client-ip": "198.51.100.9" };
  const cases = [
    ["/agent/program", JSON.stringify({ programId: "string" }), "50000"],
    ["/agent/scan", JSON.stringify({ repo: "string" }), "500000"],
    ["/agent/watch", JSON.stringify({ webhook: "string", programId: "string" }), "900000"],
    ["/agent/check", "{not json", "10000"],
  ];
  for (const [path, body, amount] of cases) {
    const r = await fetch(`${base}${path}`, { method: "POST", headers: h, body });
    assert.equal(r.status, 400, path);
    const t = decodeHeader(r.headers.get("payment-required"));
    assert.equal(t.accepts[0].amount, amount, path);
    assert.equal(t.accepts[0].payTo, MERCHANT);
    assert.match(t.error, /invalid request body/);
  }
  const paid = await fetch(`${base}/agent/program`, { method: "POST", headers: { ...h, "payment-signature": "e30=" }, body: JSON.stringify({ programId: "string" }) });
  assert.equal(paid.status, 400);
  assert.equal(paid.headers.get("payment-required"), null, "no terms on a request that already pays");
  const other = await fetch(`${base}/agent/jobs/not-a-job`, { headers: h });
  assert.equal(other.headers.get("payment-required"), null, "only paid endpoints carry terms");
});
