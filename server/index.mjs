// Solana Security Watch — scan backend (payment-agnostic MVP).
//
// Flow:  POST /scan {repo,email}  -> creates a pending_payment job, returns payment
//        instructions.  The heavy scan does NOT run yet (no free abuse of compute).
//        POST /confirm {jobId}    -> admin/webhook gate: marks paid, queues the scan,
//        which runs runScan(), emails the report, and marks the job done.
//
// The /confirm gate is where any payment provider plugs in: at first you confirm
// crypto payments by hand (Bearer ADMIN_TOKEN); later a Stripe webhook or an
// on-chain USDC watcher calls the same endpoint.
//
// Zero runtime deps: Node http + fetch only.
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { runScan, parseGithubUrl, fixMailto, WATCHDOG_LOGO, scanDependencies, scanDependenciesBatch, parseCargoLock } from "../bin/scan.mjs";
import { Store } from "./store.mjs";
import { Queue } from "./queue.mjs";
import { sendReport } from "./email.mjs";
import { verifyUsdcPayment, USDC_MINT } from "./verify.mjs";
import { Facilitator, SOLANA_MAINNET, encodeHeader, decodeHeader, bazaarExtension } from "./x402.mjs";
import { PayAIAuth } from "./payai-auth.mjs";
import { Traffic } from "./traffic.mjs";
import { inspectProgram, isPubkey } from "./program.mjs";
import { Watcher, checkWebhookUrl, newSecret, programSnapshot, diffProgram, lockfileSnapshot, diffLockfile } from "./watch.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const PRICE_USD = Number(process.env.SCAN_PRICE_USD || 80); // web: a human, a branded report by email
// Agents buy per request, at volume: both prices sit under the $1 per-payment cap
// x402 clients ship with, so an agent on default settings can pay without a human.
// A PayAI settlement costs about $0.0015 on Solana, so a cent still clears it.
const AGENT_SCAN_PRICE_USD = Number(process.env.AGENT_SCAN_PRICE_USD || 0.5);
const CHECK_PRICE_USD = Number(process.env.CHECK_PRICE_USD || 0.01);
const CHECK_MAX_PACKAGES = 100;
const PROGRAM_PRICE_USD = Number(process.env.PROGRAM_PRICE_USD || 0.05);
// A watch is bought once for a fixed period, under the $1 default cap of x402 clients.
const WATCH_PRICE_USD = Number(process.env.WATCH_PRICE_USD || 0.9);
const WATCH_DAYS = Number(process.env.WATCH_DAYS || 30);
const WATCH_INTERVAL_MS = Number(process.env.WATCH_INTERVAL_MS || 60 * 60 * 1000);
const WATCH_TICK_MS = Number(process.env.WATCH_TICK_MS || 60 * 1000);
const WATCH_ALLOW_PRIVATE = process.env.WATCH_ALLOW_PRIVATE_WEBHOOKS === "1"; // tests only
// A whole Cargo.lock instead of a list: one OSV batch call, so the size barely costs us.
const LOCKFILE_MAX_BYTES = 2_000_000;
const LOCKFILE_MAX_PACKAGES = 5000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "*";
const ALLOW_LOCAL = process.env.ALLOW_LOCAL === "1"; // dev/testing only
const MERCHANT_WALLET = process.env.MERCHANT_WALLET || null; // USDC recipient (Solana)
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const PAY_INSTRUCTIONS =
  process.env.PAY_INSTRUCTIONS ||
  "Payment instructions not configured. Set PAY_INSTRUCTIONS (e.g. a USDC address or a Stripe link).";

const JOBS_FILE = process.env.JOBS_FILE || join(__dirname, "data", "jobs.json");
// Agent jobs have no inbox to email a report to, so their reports are kept here
// (next to the job store, i.e. on the persistent volume in prod).
const REPORTS_DIR = process.env.REPORTS_DIR || join(dirname(JOBS_FILE), "reports");
const CONTACT = process.env.SUPPORT_EMAIL || "solanawatchdog@proton.me";
const PUBLIC_BASE = (process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
// x402 v2 settlement. "off" leaves only the memo flow.
const FACILITATOR_URL = process.env.FACILITATOR_URL || "https://facilitator.payai.network";
// A bad key is never sent: PayAI refuses every payment that carries one. It is not
// fatal either (on 2026-10-01 a masked secret took both apps down at boot): the
// server stays up on the public lane and says so at boot and in /health.
let payaiAuth = null, payaiAuthError = null;
try { payaiAuth = PayAIAuth.fromEnv(); }
catch (e) { payaiAuthError = e.message; }
const facilitator = FACILITATOR_URL === "off" ? null : new Facilitator({ url: FACILITATOR_URL, auth: payaiAuth });
// ERC-8004 identity, once registered on Base: the agentId minted by register().
const ERC8004_REGISTRY = "eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";
const ERC8004_AGENT_ID = process.env.ERC8004_AGENT_ID ? Number(process.env.ERC8004_AGENT_ID) : null;
const LANDING_URL = process.env.LANDING_URL || "https://watchdog.soladrome.finance";
const store = new Store(JOBS_FILE);
const watches = new Store(process.env.WATCHES_FILE || join(dirname(JOBS_FILE), "watches.json"));
const traffic = new Traffic(process.env.TRAFFIC_FILE || join(dirname(JOBS_FILE), "traffic.jsonl"));
const queue = new Queue();

// --- tiny per-IP rate limit (protects the create endpoint) ---
const hits = new Map();
function rateLimited(ip, max = 20, windowMs = 60000) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < windowMs);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > max;
}

function send(res, code, body, extraHeaders = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(code, {
    "content-type": typeof body === "string" ? "text/plain" : "application/json",
    "access-control-allow-origin": ALLOW_ORIGIN,
    "access-control-allow-methods": "POST, GET, DELETE, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, payment-signature",
    "access-control-expose-headers": "payment-required, payment-response",
    // A paid endpoint refusing an unpaid request as malformed still states its price.
    ...(code === 400 && res.x402Terms ? { "payment-required": res.x402Terms } : {}),
    ...extraHeaders,
  });
  res.end(payload);
}

function readBody(req, max = 1e5) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > max) req.destroy(); });
    req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch { reject(new Error("bad json")); } });
    req.on("error", reject);
  });
}

// --- the actual work: run a paid scan and email the report ---
async function runJob(jobId) {
  const job = store.get(jobId);
  if (!job) return;
  store.update(jobId, { status: "running" });
  try {
    const out = mkdtempSync(join(tmpdir(), "ssw-job-"));
    const cta = { contact: CONTACT, ref: jobId };
    const result = await runScan(
      job.local && ALLOW_LOCAL ? { localPath: job.local, out, cta } : { repoUrl: job.repo, out, cta }
    );
    const html = readFileSync(result.htmlPath, "utf8");
    const md = readFileSync(result.mdPath, "utf8");
    // Every report is kept, so the email can link to it: mail clients show an
    // attached .html as source code, not as the branded page.
    mkdirSync(REPORTS_DIR, { recursive: true });
    writeFileSync(join(REPORTS_DIR, `${jobId}.html`), html);
    writeFileSync(join(REPORTS_DIR, `${jobId}.md`), md);
    writeFileSync(join(REPORTS_DIR, `${jobId}.json`), JSON.stringify(summarize(result), null, 2) + "\n");
    const viewToken = randomBytes(24).toString("base64url");
    store.update(jobId, { viewTokenHash: hashToken(viewToken) });
    const viewUrl = `${PUBLIC_BASE}/r/${jobId}/${viewToken}`;
    // Lead with the on-chain bucket, not the raw total: most of a Solana lockfile
    // is CLI/test-validator tooling, so a raw count puts an openssl advisory at
    // the top of the mail and buries the borsh one that actually ships on-chain.
    const bk = result.deps.buckets;
    const onchainN = bk.onchain.length;
    const offchainN = bk.toolchain.length + bk.housekeeping.length;
    const depN = result.deps.advisories.length;
    const leadN = [...result.source.byClass.values()].reduce((s, e) => s + e.total, 0);
    const top = bk.onchain.slice(0, 3).map((a) => `- [${a.severity}] ${a.id} — ${a.summary}`).join("\n");
    if (job.email) await sendReport({
      to: job.email,
      subject: `Your Solana security scan — ${result.meta.owner}/${result.meta.repo}`,
      text: `Scan complete for ${job.repo}.\n\n${onchainN} advisories on the on-chain surface (crates your deployed program links against), ${offchainN} more on toolchain and unmaintained crates, ${leadN} code leads.\n\nOn-chain advisories:\n${top || "(none — clean on the deployed surface)"}\n\nView your report: ${viewUrl}\nWant the findings fixed? Write to ${CONTACT} with reference ${jobId}.\n\nThe report is also attached.`,
      html: `<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:560px;margin:auto;background:#fff;border-radius:14px;overflow:hidden;border:1px solid #eaecf3">
<div style="background:#160b2e;padding:18px 22px;border-bottom:3px solid #14F195">
<span style="color:#fff;font-weight:800;letter-spacing:.5px;font-size:16px">SOLANA <span style="color:#14F195">WATCHDOG</span></span>
<div style="color:#a9b0cf;font-size:12px;margin-top:3px">Dependency &amp; known-class security scan</div></div>
<div style="padding:22px">
<p style="margin:0 0 12px;font-size:15px;color:#1c2030">Scan complete for <b>${result.meta.owner}/${result.meta.repo}</b>.</p>
<p style="margin:0 0 14px;color:#1c2030"><b style="font-size:20px">${onchainN}</b> advisories on your <b>on-chain surface</b> &nbsp;&middot;&nbsp; <b style="font-size:20px">${offchainN}</b> on toolchain / unmaintained crates &nbsp;&middot;&nbsp; <b style="font-size:20px">${leadN}</b> code leads</p>
${top ? `<div style="background:#f7f8fc;border:1px solid #eaecf3;border-radius:10px;padding:12px 14px;font-size:13px;color:#333;white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace">${top.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>` : `<div style="background:#effaf3;border:1px solid #c9eed7;border-radius:10px;padding:12px 14px;font-size:13px;color:#0a7d43;font-weight:600">No advisory affects the crates your deployed program links against.</div>`}
<table role="presentation" cellspacing="0" cellpadding="0" style="margin:18px 0 0"><tr>
<td style="padding:0 8px 8px 0"><a href="${viewUrl}" style="display:inline-block;background:#6d3bd6;color:#ffffff;font-weight:700;text-decoration:none;border-radius:10px;padding:12px 18px">View your report</a></td>
<td style="padding:0 0 8px 0"><a href="${fixMailto(cta, result.meta, `Fix request: ${result.meta.owner}/${result.meta.repo}`, [`On-chain advisories: ${onchainN}`, `Code leads: ${leadN}`])}" style="display:inline-block;background:#ffffff;color:#6d3bd6;font-weight:700;text-decoration:none;border-radius:10px;padding:11px 17px;border:1px solid #6d3bd6">Get the findings fixed</a></td>
</tr></table>
<p style="margin:10px 0 0;color:#5b6178;font-size:13px">The link is private to you. The report is also attached (open the <b>.html</b> in a browser).</p>
<p style="margin:14px 0 0;color:#8189a3;font-size:12px">A hygiene + known-class scan, not an audit. It does not certify the absence of bugs.</p></div></div>`,
      attachments: [
        { filename: `${result.meta.owner}-${result.meta.repo}-scan.html`, content: Buffer.from(html).toString("base64") },
        { filename: `${result.meta.owner}-${result.meta.repo}-scan.md`, content: Buffer.from(md).toString("base64") },
      ],
    });
    store.update(jobId, { status: "done", depAdvisories: depN, onchainAdvisories: onchainN, codeLeads: leadN, deliveredAt: new Date().toISOString() });
  } catch (e) {
    store.update(jobId, { status: "error", error: String(e.message).slice(0, 300) });
    console.error(`[job ${jobId}] failed:`, e.message);
  }
}

// --- agent-payable scan -------------------------------------------------------
// An agent cannot click a wallet button, so it gets the same scan through an
// HTTP 402 handshake: ask, get the price + a one-job memo, pay, prove, poll.
// The job id is written on-chain in the memo, so it is public: reading the
// report takes a separate bearer token, handed out once and stored hashed.

function summarize(result) {
  const bk = result.deps.buckets;
  return {
    repo: `${result.meta.owner}/${result.meta.repo}`,
    date: result.meta.date,
    counts: {
      onchainAdvisories: bk.onchain.length,
      toolchainAdvisories: bk.toolchain.length,
      unmaintainedCrates: bk.housekeeping.length,
      codeLeads: [...result.source.byClass.values()].reduce((s, e) => s + e.total, 0),
    },
    onchainAdvisories: bk.onchain,
    toolchainAdvisories: bk.toolchain,
    unmaintainedCrates: bk.housekeeping,
    hygiene: result.hygiene,
    codeLeads: [...result.source.byClass.entries()].map(([cls, e]) => ({ class: cls, label: e.label, total: e.total, hits: e.hits })),
    disclaimer: "A dependency + known-class scan, not an audit. It does not certify the absence of bugs.",
  };
}

const hashToken = (t) => createHash("sha256").update(String(t)).digest("hex");
function agentAuthorized(req, job) {
  const m = /^Bearer (\S+)$/.exec(req.headers.authorization || "");
  if (!m || !job || !job.accessTokenHash) return false;
  const a = Buffer.from(hashToken(m[1]), "hex");
  const b = Buffer.from(job.accessTokenHash, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

function paymentRequired(job) {
  return {
    error: "payment_required",
    x402Version: 1,
    accepts: [{
      scheme: "exact",
      network: "solana",
      asset: USDC_MINT,
      maxAmountRequired: String(Math.round(job.priceUsd * 1e6)),
      payTo: MERCHANT_WALLET,
      resource: `${PUBLIC_BASE}/agent/scan`,
      description: `Solana Watchdog dependency + known-class scan of ${job.repo}`,
      mimeType: "application/json",
      maxTimeoutSeconds: 3600,
      extra: { decimals: 6, memo: job.memo },
    }],
    jobId: job.id,
    accessToken: job._accessToken,
    amountUsdc: job.priceUsd,
    x402: facilitator
      ? "Standard x402 v2 clients: the requirements are in the PAYMENT-REQUIRED header. Resend this same request with a PAYMENT-SIGNATURE header; the facilitator pays the network fee. The access token then comes back in the paid response."
      : undefined,
    howToPay: `Send ${job.priceUsd} USDC (SPL, mint ${USDC_MINT}) on Solana mainnet to ${MERCHANT_WALLET}, in a transaction that also carries an SPL Memo instruction with the exact text "${job.memo}". Then POST ${PUBLIC_BASE}/agent/scan with {"jobId":"${job.id}","signature":"<tx signature>"}. Keep accessToken: it is shown once and is the only way to read the report.`,
    manual: `${PUBLIC_BASE}/skill.md`,
  };
}

// The same price as x402 v2 PaymentRequirements. Always rebuilt from the job on
// our side: the copy a client echoes back in `accepted` is never what we settle
// against, so a client cannot talk the amount or the recipient down.
function requirementsFor(job, feePayer) {
  return {
    scheme: "exact",
    network: SOLANA_MAINNET,
    amount: String(Math.round(job.priceUsd * 1e6)),
    asset: USDC_MINT,
    payTo: MERCHANT_WALLET,
    maxTimeoutSeconds: 120,
    // The facilitator refuses a transaction whose Memo is not exactly this, so
    // the job binding of the memo flow carries over unchanged.
    extra: { feePayer, memo: job.memo },
  };
}

const SCAN_BAZAAR = bazaarExtension({
  exampleBody: { repo: "https://github.com/solana-developers/program-examples" },
  properties: {
    repo: { type: "string", description: "Public GitHub repository URL, https://github.com/<owner>/<repo>" },
    email: { type: "string", description: "Optional. Also email the report here." },
  },
  required: ["repo"],
  outputExample: {
    jobId: "8f0c6a2e-1b7d-4c1e-9d3a-2f5e6b7c8d9e",
    status: "paid",
    accessToken: "<shown once, send as Authorization: Bearer>",
    statusUrl: `${PUBLIC_BASE}/agent/jobs/8f0c6a2e-1b7d-4c1e-9d3a-2f5e6b7c8d9e`,
  },
});

function x402Required(job, feePayer, error) {
  return {
    x402Version: 2,
    error,
    resource: {
      url: `${PUBLIC_BASE}/agent/scan`,
      description: "Use this before releasing or integrating a Solana/Anchor program from a public GitHub repo: advisories on its exact pinned crates, split into what ships on-chain and what is tooling, build hygiene, and leads for known Solana bug classes with file:line. A scan, not an audit.",
      mimeType: "application/json",
      serviceName: "Solana Watchdog",
      tags: ["security", "solana", "anchor", "dependencies", "code-scan"],
    },
    accepts: [requirementsFor(job, feePayer)],
    extensions: { bazaar: SCAN_BAZAAR },
  };
}

// A facilitator outage must not take the memo flow down with it: no header then.
async function quoteHeaders(job, error = "PAYMENT-SIGNATURE header is required") {
  if (!facilitator) return {};
  try { return { "payment-required": encodeHeader(x402Required(job, await facilitator.feePayer(SOLANA_MAINNET), error)) }; }
  catch (e) { console.error(`[x402] quote without header: ${e.message}`); return {}; }
}

// Settle a PAYMENT-SIGNATURE for the job its memo names. The job is moved to
// "settling" before the first await, so two copies of one payload racing each
// other cannot both reach /settle (the duplicate-settlement case of the spec).
async function settleX402(res, payload) {
  const accepted = payload && payload.accepted;
  const job = accepted && accepted.extra && store.findByMemo(accepted.extra.memo);
  if (!job || !job.agent) return send(res, 402, { error: "payment does not match an open quote: POST /agent/scan {repo} for a new one" });
  if (job.status !== "pending_payment")
    return send(res, 409, { error: `job already ${job.status}`, jobId: job.id });
  const feePayer = await facilitator.feePayer(SOLANA_MAINNET);
  const reqs = requirementsFor(job, feePayer);
  store.update(job.id, { status: "settling" });
  const reopen = async (code, error, extra = {}) => {
    store.update(job.id, { status: "pending_payment" });
    return send(res, code, { error, jobId: job.id }, { ...(await quoteHeaders(job, error)), ...extra });
  };

  let v;
  try { v = await facilitator.verify(payload, reqs); }
  catch (e) { return reopen(502, `facilitator unreachable: ${e.message}`); }
  if (!v.isValid) return reopen(402, `payment not valid: ${v.invalidReason || "rejected by facilitator"}`);

  let s;
  try { s = await facilitator.settle(payload, reqs); }
  catch (e) {
    // Unknown outcome: the transfer may have landed. Do not reopen the quote
    // (a retry could pay twice); support can settle it from the admin list.
    store.update(job.id, { status: "settle_unknown", error: String(e.message).slice(0, 300) });
    return send(res, 502, { error: "settlement outcome unknown, do not pay again", jobId: job.id, contact: CONTACT });
  }
  if (!s.success || !s.transaction) {
    return reopen(402, `settlement failed: ${s.errorReason || "unknown"}`, { "payment-response": encodeHeader(s) });
  }

  // Trust the chain, not the facilitator's word: the same check as the memo flow.
  const chain = await verifyUsdcPayment({
    signature: s.transaction, amountUsdc: job.priceUsd, merchant: MERCHANT_WALLET, rpcUrl: SOLANA_RPC_URL, memo: job.memo,
  });
  if (!chain.ok || store.findBySignature(s.transaction)) {
    store.update(job.id, { status: "settle_unknown", paymentSignature: s.transaction, error: `facilitator settled but chain check failed: ${chain.reason || "signature reused"}` });
    return send(res, 502, { error: "payment reported settled but not confirmed on-chain yet, do not pay again", jobId: job.id, transaction: s.transaction, contact: CONTACT });
  }

  // The quote's token went to whoever asked; a standard x402 client never reads
  // a 402 body, so the paid response carries a fresh one and it replaces the old.
  const accessToken = randomBytes(24).toString("base64url");
  store.update(job.id, {
    status: "paid", paidAt: new Date().toISOString(), paymentSignature: s.transaction,
    payer: s.payer || null, via: "x402", accessTokenHash: hashToken(accessToken),
  });
  queue.enqueue(() => runJob(job.id));
  return send(res, 200, {
    jobId: job.id, status: "paid", repo: job.repo, accessToken,
    statusUrl: `${PUBLIC_BASE}/agent/jobs/${job.id}`,
    poll: "GET statusUrl with Authorization: Bearer <accessToken> every 15s; a scan takes about a minute. accessToken is shown once.",
    transaction: s.transaction,
  }, { "payment-response": encodeHeader(s) });
}

// --- per-request advisory check --------------------------------------------------
// No repo, no job: the pinned packages in the body, their advisories in the
// answer. The payment is verified first and settled only once the answer exists,
// so a lookup that fails costs the agent nothing.

const CHECK_BAZAAR = bazaarExtension({
  exampleBody: { packages: [{ name: "borsh", version: "0.9.3" }, { name: "anchor-lang", version: "0.29.0" }] },
  properties: {
    packages: {
      type: "array", minItems: 1, maxItems: CHECK_MAX_PACKAGES,
      description: "crates.io packages at the exact versions pinned in Cargo.lock. Send this OR lockfile.",
      items: { type: "object", properties: { name: { type: "string" }, version: { type: "string" } }, required: ["name", "version"] },
    },
    lockfile: {
      type: "string", maxLength: LOCKFILE_MAX_BYTES,
      description: `The raw text of a Cargo.lock (up to ${LOCKFILE_MAX_PACKAGES} crates.io packages; workspace and git crates are skipped). Send this OR packages.`,
    },
  },
  outputExample: {
    checked: 2,
    advisories: [{ id: "RUSTSEC-2023-0033", crates: ["borsh 0.9.3"], severity: "MODERATE", summary: "Parsing borsh messages with ZST which are not-copy/clone is unsound", url: "https://rustsec.org/advisories/RUSTSEC-2023-0033.html" }],
    notCheckedCount: 0,
  },
});

// Either {packages} or {lockfile}. Returns the packages and, for a lockfile, what was read.
function parseCheckInput(body) {
  if (body && body.lockfile !== undefined) {
    if (body.packages !== undefined) throw new Error("send packages OR lockfile, not both");
    if (typeof body.lockfile !== "string" || !/^\[\[package\]\]/m.test(body.lockfile))
      throw new Error("lockfile must be the text of a Cargo.lock");
    if (body.lockfile.length > LOCKFILE_MAX_BYTES) throw new Error(`lockfile is over ${LOCKFILE_MAX_BYTES} bytes`);
    const all = parseCargoLock(body.lockfile);
    const packages = parseCargoLock(body.lockfile, { registryOnly: true });
    if (!packages.length) throw new Error("no crates.io package in this Cargo.lock");
    if (packages.length > LOCKFILE_MAX_PACKAGES) throw new Error(`lockfile has over ${LOCKFILE_MAX_PACKAGES} crates.io packages`);
    return { packages, lockfile: { type: "Cargo.lock", packages: packages.length, skipped: all.length - packages.length } };
  }
  return { packages: parsePackages(body) };
}

function parsePackages(body) {
  const pk = body && body.packages;
  if (!Array.isArray(pk) || pk.length === 0 || pk.length > CHECK_MAX_PACKAGES)
    throw new Error(`packages must be a list of 1 to ${CHECK_MAX_PACKAGES} {name, version}`);
  return pk.map((p, i) => {
    const name = p && String(p.name || ""), version = p && String(p.version || "");
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(name) || !/^[0-9A-Za-z.+-]{1,64}$/.test(version))
      throw new Error(`packages[${i}] is not a crates.io {name, version}`);
    return { name, version };
  });
}

const checkRequirements = (feePayer) => ({
  scheme: "exact",
  network: SOLANA_MAINNET,
  amount: String(Math.round(CHECK_PRICE_USD * 1e6)),
  asset: USDC_MINT,
  payTo: MERCHANT_WALLET,
  maxTimeoutSeconds: 120,
  extra: { feePayer },
});

function checkRequired(feePayer, error = "PAYMENT-SIGNATURE header is required") {
  return {
    x402Version: 2,
    error,
    resource: {
      url: `${PUBLIC_BASE}/agent/check`,
      description: `Use this before adding or upgrading a Rust crate, or to triage a Cargo.lock: RustSec/OSV advisories affecting a whole Cargo.lock (or up to ${CHECK_MAX_PACKAGES} listed crates) at their exact pinned versions. Instant, per request.`,
      mimeType: "application/json",
      serviceName: "Solana Watchdog check",
      tags: ["security", "solana", "rust", "advisories", "dependencies"],
    },
    accepts: [checkRequirements(feePayer)],
    extensions: { bazaar: CHECK_BAZAAR },
  };
}

// Payloads in flight: two copies of one signed transfer must not both get an answer.
const checking = new Set();

// One paid answer per request: verify the payment, compute, settle only once the
// answer exists. compute() returns { body, record } or { status, error } (nothing charged).
async function paidRequest(req, res, { feePayer, requirements, required, priceUsd, kind, compute }) {
  const quote = (error) => ({ "payment-required": encodeHeader(required(feePayer, error)) });
  const header = req.headers["payment-signature"];
  if (!header) return send(res, 402, { error: "payment_required", priceUsdc: priceUsd, x402: "Requirements are in the PAYMENT-REQUIRED header; resend with PAYMENT-SIGNATURE.", manual: `${PUBLIC_BASE}/skill.md` }, quote("PAYMENT-SIGNATURE header is required"));
  const payload = decodeHeader(header);
  if (!payload || payload.x402Version !== 2 || !payload.payload || typeof payload.payload.transaction !== "string" || !payload.accepted)
    return send(res, 400, { error: "PAYMENT-SIGNATURE is not a base64 x402 v2 PaymentPayload" });
  if (payload.accepted.network !== SOLANA_MAINNET) return send(res, 402, { error: `this endpoint settles on ${SOLANA_MAINNET} only` }, quote("wrong network"));
  const key = hashToken(payload.payload.transaction);
  if (checking.has(key) || store.find((j) => j.payloadHash === key)) return send(res, 409, { error: "payment already used" });
  checking.add(key);
  try {
    const reqs = requirements(feePayer);
    let v;
    try { v = await facilitator.verify(payload, reqs); }
    catch (e) { return send(res, 502, { error: `facilitator unreachable, nothing charged: ${e.message}` }); }
    if (!v.isValid) {
      const error = `payment not valid: ${v.invalidReason || "rejected by facilitator"}`;
      return send(res, 402, { error }, quote(error));
    }
    const answer = await compute();
    if (answer.error) return send(res, answer.status || 502, { error: answer.error });
    let s;
    try { s = await facilitator.settle(payload, reqs); }
    catch (e) {
      store.create({ kind, agent: true, status: "settle_unknown", payloadHash: key, priceUsd, via: "x402", error: String(e.message).slice(0, 300) });
      return send(res, 502, { error: "settlement outcome unknown, do not pay again", contact: CONTACT });
    }
    if (!s.success || !s.transaction) {
      const error = `settlement failed, nothing charged: ${s.errorReason || "unknown"}`;
      return send(res, 402, { error }, { ...quote(error), "payment-response": encodeHeader(s) });
    }
    if (store.findBySignature(s.transaction)) return send(res, 409, { error: "payment already used" });
    store.create({
      kind, agent: true, status: "done", payloadHash: key, paymentSignature: s.transaction, payer: s.payer || null,
      priceUsd, via: "x402", ...answer.record, paidAt: new Date().toISOString(),
    });
    // Anything that must exist only once paid (a watch) is created here, after settlement.
    const extra = answer.commit ? answer.commit(s) : {};
    return send(res, 200, { ...answer.body, ...extra, transaction: s.transaction }, { "payment-response": encodeHeader(s) });
  } finally {
    checking.delete(key);
  }
}

async function handleCheck(req, res, body) {
  let packages, lockfile;
  try { ({ packages, lockfile } = parseCheckInput(body)); } catch (e) { return send(res, 400, { error: e.message }); }
  return paidRequest(req, res, {
    feePayer: await facilitator.feePayer(SOLANA_MAINNET),
    requirements: checkRequirements, required: checkRequired, priceUsd: CHECK_PRICE_USD, kind: "check",
    compute: async () => {
      const uniq = [...new Map(packages.map((p) => [`${p.name}@${p.version}`, p])).values()];
      const deps = lockfile ? await scanDependenciesBatch(uniq, globalThis.fetch) : await scanDependencies(uniq, globalThis.fetch);
      if (deps.failures === uniq.length) return { status: 502, error: "advisory database unreachable, nothing charged; try again" };
      return {
        record: { packages: uniq.length, advisoriesFound: deps.advisories.length },
        body: {
          checked: uniq.length - deps.failures,
          advisories: deps.advisories,
          notCheckedCount: deps.failures, // packages the advisory database did not answer for: check them again
          ...(lockfile ? { lockfile } : {}),
          disclaimer: "Known advisories for these exact versions. Not an audit of the code that uses them.",
        },
      };
    },
  });
}

// --- per-request program check -----------------------------------------------------
// Who can change a deployed program, and what ties it to public code. See program.mjs.

const PROGRAM_BAZAAR = bazaarExtension({
  exampleBody: { programId: "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc" },
  properties: {
    programId: { type: "string", description: "Address of a deployed Solana mainnet program (base58)." },
  },
  required: ["programId"],
  outputExample: {
    programId: "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
    upgradeable: true,
    authority: { address: "GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV", kind: "squads-v4", threshold: 5, members: 13, timeLockSeconds: 86400, text: "Squads v4 multisig: 5 of 13 members must approve an upgrade, then a 24 h time lock." },
    lastDeploy: { slot: 440170207, at: "2026-08-19T01:28:54.000Z" },
    verifiedBuild: { verified: false, repo: "https://github.com/orca-so/whirlpools" },
    securityTxt: { name: "Whirlpool", contacts: "…" },
    flags: [{ severity: "medium", id: "build-mismatch", text: "A verification was submitted…" }],
  },
});

const programRequirements = (feePayer) => ({ ...checkRequirements(feePayer), amount: String(Math.round(PROGRAM_PRICE_USD * 1e6)) });

function programRequired(feePayer, error = "PAYMENT-SIGNATURE header is required") {
  return {
    x402Version: 2,
    error,
    resource: {
      url: `${PUBLIC_BASE}/agent/program`,
      description: "Use this before signing a transaction for a Solana program: who can change its code (single key, Squads multisig with threshold and time lock, DAO, or immutable), when it last changed, verified build, security.txt. Instant, per request.",
      mimeType: "application/json",
      serviceName: "Solana Watchdog program",
      tags: ["security", "solana", "program", "upgrade-authority", "due-diligence"],
    },
    accepts: [programRequirements(feePayer)],
    extensions: { bazaar: PROGRAM_BAZAAR },
  };
}

const programRpc = async (method, params) => {
  for (let i = 0; ; i++) {
    const r = await fetch(SOLANA_RPC_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    if (r.status === 429 && i < 3) { await new Promise((s) => setTimeout(s, 800 * (i + 1))); continue; }
    const j = await r.json();
    if (j.error) throw new Error(`${method}: ${j.error.message || JSON.stringify(j.error)}`);
    return j.result;
  }
};

async function handleProgram(req, res, body) {
  const programId = body && body.programId;
  if (!isPubkey(programId)) return send(res, 400, { error: "programId must be a base58 Solana address" });
  return paidRequest(req, res, {
    feePayer: await facilitator.feePayer(SOLANA_MAINNET),
    requirements: programRequirements, required: programRequired, priceUsd: PROGRAM_PRICE_USD, kind: "program",
    compute: async () => {
      let r;
      try { r = await inspectProgram(programId, { rpc: programRpc }); }
      catch (e) { return { status: 502, error: `chain lookup failed, nothing charged: ${String(e.message).slice(0, 200)}` }; }
      // Nothing to inspect is not worth a charge: most likely a wrong address.
      if (!r.exists || !r.executable) return { status: r.exists ? 422 : 404, error: `${r.flags[0].text} Nothing charged.` };
      return {
        record: { programId, flags: r.flags.map((f) => f.id) },
        body: { ...r, disclaimer: "Who controls this program and what can be verified about it. Not an audit of its code." },
      };
    },
  });
}

// --- paid watches ------------------------------------------------------------------------
// One payment buys WATCH_DAYS of hourly re-checks of a program or a lockfile; a change that
// matters is POSTed to the agent's webhook, signed with a secret shown once.

const WATCH_BAZAAR = bazaarExtension({
  exampleBody: { programId: "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", webhook: "https://agent.example/hooks/watchdog" },
  properties: {
    programId: { type: "string", description: "Watch a deployed program: authority, multisig rules, code upgrades, verified build. Send this OR lockfile." },
    lockfile: { type: "string", description: "Watch a Cargo.lock: any new RustSec/OSV advisory affecting its pinned crates. Send this OR programId." },
    webhook: { type: "string", description: "https URL that receives a signed POST on every change (header x-watchdog-signature: sha256=HMAC(secret, body))." },
  },
  required: ["webhook"],
  outputExample: { watchId: "…", secret: "shown once", accessToken: "shown once", expiresAt: "…", baseline: { authority: { kind: "squads-v4", threshold: 5, members: 13 } } },
});

const watchRequirements = (feePayer) => ({ ...checkRequirements(feePayer), amount: String(Math.round(WATCH_PRICE_USD * 1e6)) });

function watchRequired(feePayer, error = "PAYMENT-SIGNATURE header is required") {
  return {
    x402Version: 2,
    error,
    resource: {
      url: `${PUBLIC_BASE}/agent/watch`,
      description: `Use this to be told when a Solana program you rely on changes hands or code, or when a new advisory hits your Cargo.lock: ${WATCH_DAYS} days of hourly checks, signed webhook on each change. One payment.`,
      mimeType: "application/json",
      serviceName: "Solana Watchdog watch",
      tags: ["security", "solana", "monitoring", "webhook", "upgrade-authority", "advisories"],
    },
    accepts: [watchRequirements(feePayer)],
    extensions: { bazaar: WATCH_BAZAAR },
  };
}

// Re-read a watch's target: { snapshot, events }. Throws when the answer is not
// trustworthy (RPC down, advisory database down), which is never read as "no change".
async function checkWatch(w) {
  if (w.target === "program") {
    const r = await inspectProgram(w.programId, { rpc: programRpc });
    const snapshot = programSnapshot(r);
    return { snapshot, events: diffProgram(w.snapshot, snapshot) };
  }
  const deps = await scanDependenciesBatch(w.packages, globalThis.fetch);
  if (deps.failures) throw new Error(`advisory database did not answer for ${deps.failures} packages`);
  return { snapshot: lockfileSnapshot(deps.advisories), events: diffLockfile(w.snapshot, lockfileSnapshot(deps.advisories), deps.advisories) };
}

async function handleWatch(req, res, body) {
  if (!body || typeof body.webhook !== "string") return send(res, 400, { error: "webhook (an https URL) is required" });
  let target;
  if (body.programId !== undefined) {
    if (body.lockfile !== undefined) return send(res, 400, { error: "send programId OR lockfile, not both" });
    if (!isPubkey(body.programId)) return send(res, 400, { error: "programId must be a base58 Solana address" });
    target = { target: "program", programId: body.programId, targetSummary: { type: "program", programId: body.programId } };
  } else {
    let parsed;
    try { parsed = parseCheckInput({ lockfile: body.lockfile }); } catch (e) { return send(res, 400, { error: e.message }); }
    target = { target: "lockfile", packages: parsed.packages, targetSummary: { type: "Cargo.lock", packages: parsed.packages.length } };
  }
  try { await checkWebhookUrl(body.webhook, { allowPrivate: WATCH_ALLOW_PRIVATE }); }
  catch (e) { return send(res, 400, { error: e.message }); }
  return paidRequest(req, res, {
    feePayer: await facilitator.feePayer(SOLANA_MAINNET),
    requirements: watchRequirements, required: watchRequired, priceUsd: WATCH_PRICE_USD, kind: "watch",
    compute: async () => {
      // The baseline is taken now, so the first webhook means "changed since you subscribed".
      let baseline, detail;
      try {
        if (target.target === "program") {
          const r = await inspectProgram(target.programId, { rpc: programRpc });
          if (!r.exists || !r.executable) return { status: r.exists ? 422 : 404, error: `${r.flags[0].text} Nothing charged.` };
          baseline = programSnapshot(r); detail = { authority: r.authority, lastDeploy: r.lastDeploy, flags: r.flags };
        } else {
          const deps = await scanDependenciesBatch(target.packages, globalThis.fetch);
          if (deps.failures === target.packages.length) return { status: 502, error: "advisory database unreachable, nothing charged; try again" };
          baseline = lockfileSnapshot(deps.advisories); detail = { advisories: deps.advisories, notCheckedCount: deps.failures };
        }
      } catch (e) { return { status: 502, error: `lookup failed, nothing charged: ${String(e.message).slice(0, 200)}` }; }
      return {
        record: { watchTarget: target.targetSummary },
        body: { baseline: detail, checksEveryMinutes: Math.round(WATCH_INTERVAL_MS / 60000) },
        commit: () => {
          const secret = newSecret(), accessToken = randomBytes(24).toString("base64url");
          const now = new Date();
          const w = watches.create({
            ...target, status: "active", webhook: body.webhook, secret, accessTokenHash: hashToken(accessToken),
            snapshot: baseline, events: [], lastCheckedAt: now.toISOString(),
            expiresAt: new Date(now.getTime() + WATCH_DAYS * 864e5).toISOString(),
          });
          return {
            watchId: w.id, expiresAt: w.expiresAt,
            secret, // HMAC key for x-watchdog-signature: shown once
            accessToken, // for GET / DELETE on statusUrl: shown once
            statusUrl: `${PUBLIC_BASE}/agent/watch/${w.id}`,
            signature: "x-watchdog-signature: sha256=hex(HMAC-SHA256(secret, raw request body))",
          };
        },
      };
    },
  });
}

function watchView(w) {
  return {
    watchId: w.id, status: w.status, target: w.targetSummary, webhook: w.webhook,
    createdAt: w.createdAt, expiresAt: w.expiresAt, lastCheckedAt: w.lastCheckedAt || null,
    lastError: w.lastError || null, events: w.events || [],
  };
}

const watcher = new Watcher({
  store: watches, check: checkWatch, allowPrivate: WATCH_ALLOW_PRIVATE,
  intervalMs: WATCH_INTERVAL_MS, tickMs: WATCH_TICK_MS, log: (m) => console.log(m),
});

function agentJobView(job) {
  const view = {
    jobId: job.id, status: job.status, repo: job.repo, amountUsdc: job.priceUsd,
    createdAt: job.createdAt, paidAt: job.paidAt || null, deliveredAt: job.deliveredAt || null,
  };
  if (job.status === "error") view.error = job.error;
  if (job.status === "done") {
    const base = `${PUBLIC_BASE}/agent/jobs/${job.id}/report`;
    view.summary = { onchainAdvisories: job.onchainAdvisories, totalAdvisories: job.depAdvisories, codeLeads: job.codeLeads };
    view.report = { json: `${base}.json`, markdown: `${base}.md`, html: `${base}.html` };
  }
  return view;
}

// The ERC-8004 registration file: the agentURI the on-chain identity points to.
// Served from the API's own domain, it also proves control of that endpoint.
function agentRegistration() {
  return {
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    name: "Solana Watchdog",
    description: "Security checks for Solana code and programs. Who can change a deployed program (single key, Squads multisig with threshold and time lock, DAO, immutable) before you sign for it; RustSec advisories for a Cargo.lock; a full scan of a public Solana / Anchor GitHub repo with on-chain vs tooling triage, build hygiene and leads for known Solana bug classes. Agents pay per call over x402 (USDC on Solana). Checks, not audits.",
    image: `${PUBLIC_BASE}/logo.svg`,
    services: [
      { name: "web", endpoint: LANDING_URL },
      { name: "x402", endpoint: `${PUBLIC_BASE}/agent/scan` },
      { name: "x402", endpoint: `${PUBLIC_BASE}/agent/program` },
      { name: "x402", endpoint: `${PUBLIC_BASE}/agent/check` },
      { name: "x402", endpoint: `${PUBLIC_BASE}/agent/watch` },
      { name: "agent-manual", endpoint: `${PUBLIC_BASE}/skill.md` },
    ],
    x402Support: true,
    active: true,
    registrations: ERC8004_AGENT_ID === null ? [] : [{ agentId: ERC8004_AGENT_ID, agentRegistry: ERC8004_REGISTRY }],
    supportedTrust: ["reputation"],
  };
}

// --- discovery -------------------------------------------------------------------------
// Crawlers and x402 indexers probe an endpoint with an empty POST, a GET or a HEAD and
// expect a 402 with the terms. They used to get 400 or 404 and never saw a price. Every
// such probe now gets the 402 an empty request deserves: the same requirements and price
// as a real quote, built from the same constants. Nothing is ever settled from it: a
// payment resent without a valid body is refused before the facilitator is asked to settle.

// The scan's payable quote carries a per-job memo, so a probe gets the price without one.
function scanDiscoveryRequired(feePayer, error = "POST a JSON body {repo}: the payable quote carries a per-job memo") {
  return { ...x402Required({ priceUsd: AGENT_SCAN_PRICE_USD }, feePayer, error), accepts: [{ ...checkRequirements(feePayer), amount: String(Math.round(AGENT_SCAN_PRICE_USD * 1e6)) }] };
}

const CATALOG = [
  { path: "/agent/program", name: "program", priceUsd: PROGRAM_PRICE_USD, required: programRequired, bazaar: PROGRAM_BAZAAR },
  { path: "/agent/check", name: "check", priceUsd: CHECK_PRICE_USD, required: checkRequired, bazaar: CHECK_BAZAAR },
  { path: "/agent/scan", name: "scan", priceUsd: AGENT_SCAN_PRICE_USD, required: scanDiscoveryRequired, bazaar: SCAN_BAZAAR },
  { path: "/agent/watch", name: "watch", priceUsd: WATCH_PRICE_USD, required: watchRequired, bazaar: WATCH_BAZAAR },
];
const catalogEntry = (path) => CATALOG.find((e) => e.path === path);
const describe = (e) => e.required("", "").resource;
const exampleOf = (e) => e.bazaar.info.input.body;
const bodySchemaOf = (e) => e.bazaar.schema.properties.input.properties.body;
const isEmptyBody = (b) => !b || (typeof b === "object" && !Array.isArray(b) && Object.keys(b).length === 0);

async function discoveryQuote(res, e) {
  const url = `${PUBLIC_BASE}${e.path}`;
  const error = "send a JSON body; its schema is in extensions.bazaar";
  let headers = {};
  try { headers = { "payment-required": encodeHeader(e.required(await facilitator.feePayer(SOLANA_MAINNET), error)) }; }
  catch (err) { console.error(`[x402] discovery quote without header: ${err.message}`); }
  return send(res, 402, {
    error: "payment_required",
    priceUsdc: e.priceUsd,
    network: SOLANA_MAINNET,
    asset: USDC_MINT,
    payTo: MERCHANT_WALLET,
    description: describe(e).description,
    howTo: `POST ${url} with a JSON body like ${JSON.stringify(exampleOf(e))}. The 402 answer carries x402 v2 terms in the PAYMENT-REQUIRED header; resend the same request with PAYMENT-SIGNATURE.`,
    exampleBody: exampleOf(e),
    manual: `${PUBLIC_BASE}/skill.md`,
  }, headers);
}

// Crawlers fill the schema with placeholders ("programId": "string") and get a 400.
// That 400 now carries the same terms as the 402, so they still see the price; the
// status stays 400 so an agent knows its body is wrong. Nothing becomes payable:
// input is validated before any payment is verified or settled.
const INVALID_BODY = "invalid request body: its schema is in extensions.bazaar";
async function attachTerms(res, e) {
  if (!MERCHANT_WALLET || !facilitator) return;
  try { res.x402Terms = encodeHeader(e.required(await facilitator.feePayer(SOLANA_MAINNET), INVALID_BODY)); }
  catch (err) { console.error(`[x402] terms for a 400 unavailable: ${err.message}`); }
}

function x402Discovery() {
  return {
    x402Version: 2,
    provider: { name: "Solana Watchdog", origin: PUBLIC_BASE, website: LANDING_URL, contact: CONTACT },
    status: "live",
    resources: CATALOG.map((e) => `${PUBLIC_BASE}${e.path}`),
    services: CATALOG.map((e) => ({
      name: e.name,
      endpoint: `${PUBLIC_BASE}${e.path}`,
      method: "POST",
      description: describe(e).description,
      priceUsdc: e.priceUsd,
      network: SOLANA_MAINNET,
      asset: USDC_MINT,
      payTo: MERCHANT_WALLET,
      scheme: "exact",
      tags: describe(e).tags,
      input: { bodyType: "json", example: exampleOf(e), schema: bodySchemaOf(e) },
      output: { example: e.bazaar.info.output.example },
    })),
    manual: `${PUBLIC_BASE}/skill.md`,
    openapi: `${PUBLIC_BASE}/openapi.json`,
    erc8004: `${PUBLIC_BASE}/.well-known/agent-registration.json`,
  };
}

function openApi() {
  const paths = {};
  for (const e of CATALOG) {
    paths[e.path] = { post: {
      operationId: e.name,
      summary: `${describe(e).serviceName}, $${e.priceUsd} USDC per call over x402`,
      description: describe(e).description,
      tags: describe(e).tags,
      requestBody: { required: true, content: { "application/json": { schema: bodySchemaOf(e), example: exampleOf(e) } } },
      responses: {
        200: { description: "Paid answer (scan: 202 with a job to poll)", content: { "application/json": { example: e.bazaar.info.output.example } } },
        402: { description: "Payment required: x402 v2 terms in the PAYMENT-REQUIRED header. Resend with PAYMENT-SIGNATURE." },
      },
      "x-x402": { version: 2, scheme: "exact", priceUsdc: e.priceUsd, network: SOLANA_MAINNET, asset: USDC_MINT, payTo: MERCHANT_WALLET },
    } };
  }
  return {
    openapi: "3.1.0",
    info: { title: "Solana Watchdog x402 API", version: "1.0.0", description: "Security checks for Solana programs and code, paid per call in USDC over x402 v2. Checks, not audits.", contact: { email: CONTACT, url: LANDING_URL } },
    servers: [{ url: PUBLIC_BASE }],
    externalDocs: { description: "Agent manual", url: `${PUBLIC_BASE}/skill.md` },
    paths,
  };
}

function llmsTxt() {
  return [
    "# Solana Watchdog (x402)",
    "",
    "> Security checks for Solana programs and code that AI agents pay for per call, in USDC on Solana, over x402 v2. No account, no API key. Checks, not audits.",
    "",
    "Every endpoint answers 402 with x402 v2 terms in the PAYMENT-REQUIRED header; resend the same request with PAYMENT-SIGNATURE. The facilitator pays the network fee.",
    "",
    "## Endpoints",
    "",
    ...CATALOG.map((e) => `- POST ${PUBLIC_BASE}${e.path}, $${e.priceUsd} USDC: ${describe(e).description} Example body: ${JSON.stringify(exampleOf(e))}`),
    "",
    "## Docs",
    "",
    `- [Agent manual](${PUBLIC_BASE}/skill.md): request and response formats, both payment flows`,
    `- [OpenAPI](${PUBLIC_BASE}/openapi.json)`,
    `- [x402 discovery](${PUBLIC_BASE}/.well-known/x402)`,
    `- [ERC-8004 registration](${PUBLIC_BASE}/.well-known/agent-registration.json)`,
    `- [Website](${LANDING_URL}), also covering the EVM service`,
    "- [MCP server](https://github.com/OxToF/watchdog-mcp): `npx -y watchdog-mcp`",
    "",
  ].join("\n");
}

const ROBOTS_TXT = "User-agent: *\nAllow: /\nDisallow: /r/\nDisallow: /admin/\nDisallow: /agent/jobs/\n";

const SKILL_MD = existsSync(join(__dirname, "skill.md")) ? readFileSync(join(__dirname, "skill.md"), "utf8") : "";

// Provider RPC URLs carry their API key (Helius: ?api-key=): log the host only.
function rpcHost(u) { try { return new URL(u).host; } catch { return "(unparseable RPC URL)"; } }

const server = createServer(async (req, res) => {
  // Behind the Fly proxy the socket peer is the proxy, the same for every caller:
  // keyed on it, the rate limits were one budget shared by everyone.
  const ip = req.headers["fly-client-ip"] || req.socket.remoteAddress || "?";
  const url = new URL(req.url, `http://localhost:${PORT}`);
  traffic.watch(req, res, ip);
  if (req.method === "OPTIONS") return send(res, 204, "");

  try {
    // The API host has no page of its own: people landing here from a search
    // result belong on the site, not on a 404.
    if ((req.method === "GET" || req.method === "HEAD") && url.pathname === "/") return send(res, 301, "", { location: LANDING_URL });
    if (req.method === "GET" && url.pathname === "/health") return send(res, 200, { ok: true, facilitatorLane: payaiAuth ? "payai" : payaiAuthError ? "public-key-ignored" : "public" });

    // The private report link from the email: /r/<jobId>/<token>
    if (req.method === "GET" && url.pathname.startsWith("/r/")) {
      const m = /^\/r\/([0-9a-f-]{36})\/([A-Za-z0-9_-]{20,64})$/.exec(url.pathname);
      const job = m && store.get(m[1]);
      const ok = job && job.viewTokenHash && (() => {
        const a = Buffer.from(hashToken(m[2]), "hex"), b = Buffer.from(job.viewTokenHash, "hex");
        return a.length === b.length && timingSafeEqual(a, b);
      })();
      const f = ok && join(REPORTS_DIR, `${job.id}.html`);
      if (!ok || !existsSync(f)) return send(res, 404, "Report not found. Check the link in your email.");
      return send(res, 200, readFileSync(f, "utf8"), { "content-type": "text/html; charset=utf-8", "x-robots-tag": "noindex, nofollow", "referrer-policy": "no-referrer", "cache-control": "private, no-store" });
    }

    if (req.method === "GET" && url.pathname === "/.well-known/agent-registration.json") {
      return send(res, 200, agentRegistration(), { "cache-control": "public, max-age=300" });
    }
    if (req.method === "GET" && url.pathname === "/logo.svg") {
      return send(res, 200, WATCHDOG_LOGO.replace('width="46" height="46" ', ""), { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400" });
    }

    if (req.method === "GET" && (url.pathname === "/skill.md" || url.pathname === "/agent")) {
      return send(res, 200, SKILL_MD
        .replaceAll("{{BASE}}", PUBLIC_BASE)
        .replaceAll("{{PRICE}}", String(AGENT_SCAN_PRICE_USD))
        .replaceAll("{{CHECK_PRICE}}", String(CHECK_PRICE_USD))
        .replaceAll("{{PROGRAM_PRICE}}", String(PROGRAM_PRICE_USD))
        .replaceAll("{{WATCH_PRICE}}", String(WATCH_PRICE_USD))
        .replaceAll("{{WATCH_DAYS}}", String(WATCH_DAYS))
        .replaceAll("{{CHECK_MAX}}", String(CHECK_MAX_PACKAGES))
        .replaceAll("{{MERCHANT}}", MERCHANT_WALLET || "(not configured)"), { "content-type": "text/markdown; charset=utf-8" });
    }

    if (req.method === "GET" && url.pathname === "/.well-known/x402") return send(res, 200, x402Discovery(), { "cache-control": "public, max-age=300" });
    if (req.method === "GET" && url.pathname === "/openapi.json") return send(res, 200, openApi(), { "cache-control": "public, max-age=300" });
    if (req.method === "GET" && url.pathname === "/llms.txt") return send(res, 200, llmsTxt(), { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=300" });
    if (req.method === "GET" && url.pathname === "/robots.txt") return send(res, 200, ROBOTS_TXT, { "content-type": "text/plain; charset=utf-8" });

    // A GET or HEAD on a paid endpoint is a probe: answer with the terms, never a 404.
    if ((req.method === "GET" || req.method === "HEAD") && catalogEntry(url.pathname)) {
      if (!MERCHANT_WALLET || !facilitator) return send(res, 503, { error: "payments not configured" });
      if (rateLimited(ip, 120)) return send(res, 429, { error: "rate limited" });
      return discoveryQuote(res, catalogEntry(url.pathname));
    }

    if (req.method === "POST" && catalogEntry(url.pathname) && !req.headers["payment-signature"] && !req.headers["x-payment"])
      await attachTerms(res, catalogEntry(url.pathname));

    if (req.method === "POST" && url.pathname === "/agent/scan") {
      if (!MERCHANT_WALLET) return send(res, 503, { error: "payments not configured" });
      if (rateLimited(ip)) return send(res, 429, { error: "rate limited" });
      const body = await readBody(req);

      // x402 v2: the same request resent with the signed, unsent transfer.
      if (req.headers["payment-signature"]) {
        if (!facilitator) return send(res, 400, { error: "x402 settlement is off here; use the memo flow in /skill.md" });
        const payload = decodeHeader(req.headers["payment-signature"]);
        if (!payload || payload.x402Version !== 2 || !payload.payload || !payload.accepted)
          return send(res, 400, { error: "PAYMENT-SIGNATURE is not a base64 x402 v2 PaymentPayload" });
        return settleX402(res, payload);
      }
      // Nothing is settled from a v1 header: say so rather than quote again.
      if (req.headers["x-payment"])
        return send(res, 400, { error: "x402 v1 X-PAYMENT is not accepted: use x402 v2 (PAYMENT-SIGNATURE, requirements in the PAYMENT-REQUIRED header) or the memo flow in /skill.md" });

      // An empty POST is a probe: the price, without creating a job.
      if (isEmptyBody(body) && facilitator) return discoveryQuote(res, catalogEntry("/agent/scan"));

      // Step 2: prove payment for a job created in step 1.
      if (body.jobId || body.signature) {
        const job = store.get(body.jobId);
        if (!job || !job.agent) return send(res, 404, { error: "unknown jobId" });
        if (typeof body.signature !== "string" || !body.signature) return send(res, 400, { error: "signature required" });
        if (job.status !== "pending_payment") return send(res, 409, { error: `job already ${job.status}`, statusUrl: `${PUBLIC_BASE}/agent/jobs/${job.id}` });
        if (store.findBySignature(body.signature)) return send(res, 409, { error: "payment signature already used" });
        const result = await verifyUsdcPayment({
          signature: body.signature,
          amountUsdc: job.priceUsd,
          merchant: MERCHANT_WALLET,
          rpcUrl: SOLANA_RPC_URL,
          memo: job.memo,
        });
        if (!result.ok) return send(res, 402, { error: `payment not verified: ${result.reason}`, jobId: job.id });
        // Re-check after the await: two concurrent proofs must not both win.
        if (store.findBySignature(body.signature) || store.get(job.id).status !== "pending_payment")
          return send(res, 409, { error: "payment already credited" });
        store.update(job.id, { status: "paid", paidAt: new Date().toISOString(), paymentSignature: body.signature });
        queue.enqueue(() => runJob(job.id));
        return send(res, 202, { jobId: job.id, status: "paid", statusUrl: `${PUBLIC_BASE}/agent/jobs/${job.id}`, poll: "GET statusUrl with Authorization: Bearer <accessToken> every 15s; a scan takes about a minute." });
      }

      // Step 1: quote. Creates the job and answers 402 with what to pay.
      let repoInfo;
      try { repoInfo = parseGithubUrl(body.repo || ""); }
      catch (e) { return send(res, 400, { error: e.message }); }
      if (body.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.email))
        return send(res, 400, { error: "email is optional, but this one is not valid" });
      const accessToken = randomBytes(24).toString("base64url");
      const job = store.create({
        repo: repoInfo.url,
        email: body.email || null,
        priceUsd: AGENT_SCAN_PRICE_USD,
        agent: true,
        memo: `ssw:${randomBytes(9).toString("base64url")}`,
        accessTokenHash: hashToken(accessToken),
      });
      return send(res, 402, paymentRequired({ ...job, _accessToken: accessToken }), await quoteHeaders(job));
    }

    if (req.method === "POST" && url.pathname === "/agent/check") {
      if (!MERCHANT_WALLET || !facilitator) return send(res, 503, { error: "payments not configured" });
      if (rateLimited(ip, 120)) return send(res, 429, { error: "rate limited" });
      let body;
      try { body = await readBody(req, LOCKFILE_MAX_BYTES + 1e4); } catch { return send(res, 400, { error: "bad json" }); }
      if (isEmptyBody(body) && !req.headers["payment-signature"]) return discoveryQuote(res, catalogEntry("/agent/check"));
      return handleCheck(req, res, body);
    }

    if (req.method === "POST" && url.pathname === "/agent/program") {
      if (!MERCHANT_WALLET || !facilitator) return send(res, 503, { error: "payments not configured" });
      if (rateLimited(ip, 120)) return send(res, 429, { error: "rate limited" });
      let body;
      try { body = await readBody(req); } catch { return send(res, 400, { error: "bad json" }); }
      if (isEmptyBody(body) && !req.headers["payment-signature"]) return discoveryQuote(res, catalogEntry("/agent/program"));
      return handleProgram(req, res, body);
    }

    if (req.method === "POST" && url.pathname === "/agent/watch") {
      if (!MERCHANT_WALLET || !facilitator) return send(res, 503, { error: "payments not configured" });
      if (rateLimited(ip, 60)) return send(res, 429, { error: "rate limited" });
      let body;
      try { body = await readBody(req, LOCKFILE_MAX_BYTES + 1e4); } catch { return send(res, 400, { error: "bad json" }); }
      if (isEmptyBody(body) && !req.headers["payment-signature"]) return discoveryQuote(res, catalogEntry("/agent/watch"));
      return handleWatch(req, res, body);
    }

    if ((req.method === "GET" || req.method === "DELETE") && url.pathname.startsWith("/agent/watch/")) {
      const m = /^\/agent\/watch\/([0-9a-f-]{36})$/.exec(url.pathname);
      const w = m && watches.get(m[1]);
      if (!w || !agentAuthorized(req, w)) return send(res, 404, { error: "unknown watchId or wrong access token" });
      if (req.method === "DELETE") return send(res, 200, watchView(watches.update(w.id, { status: "cancelled" })));
      return send(res, 200, watchView(w));
    }

    if (req.method === "GET" && url.pathname.startsWith("/agent/jobs/")) {
      const m = /^\/agent\/jobs\/([0-9a-f-]{36})(?:\/report\.(json|md|html))?$/.exec(url.pathname);
      if (!m) return send(res, 404, { error: "not found" });
      const job = store.get(m[1]);
      if (!job || !job.agent || !agentAuthorized(req, job)) return send(res, 404, { error: "unknown jobId or wrong access token" });
      if (!m[2]) return send(res, 200, agentJobView(job));
      if (job.status !== "done") return send(res, 409, { error: `report not ready, job is ${job.status}` });
      const f = join(REPORTS_DIR, `${job.id}.${m[2]}`);
      if (!existsSync(f)) return send(res, 410, { error: "report no longer stored" });
      const types = { json: "application/json", md: "text/markdown; charset=utf-8", html: "text/html; charset=utf-8" };
      return send(res, 200, readFileSync(f, "utf8"), { "content-type": types[m[2]] });
    }

    if (req.method === "POST" && url.pathname === "/scan") {
      if (rateLimited(ip)) return send(res, 429, { error: "rate limited" });
      const body = await readBody(req);
      let repoInfo;
      const isLocal = body.local && ALLOW_LOCAL;
      if (!isLocal) {
        try { repoInfo = parseGithubUrl(body.repo || ""); }
        catch (e) { return send(res, 400, { error: e.message }); }
      }
      if (!body.email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.email))
        return send(res, 400, { error: "valid email required" });
      const job = store.create({
        repo: isLocal ? `local:${body.local}` : repoInfo.url,
        local: isLocal ? body.local : undefined,
        email: body.email,
        priceUsd: PRICE_USD,
      });
      return send(res, 201, {
        jobId: job.id,
        status: job.status,
        amountUsd: PRICE_USD,
        payment: { reference: job.id, instructions: PAY_INSTRUCTIONS },
      });
    }

    if (req.method === "POST" && url.pathname === "/confirm") {
      if (!ADMIN_TOKEN) return send(res, 500, { error: "ADMIN_TOKEN not configured" });
      const auth = req.headers.authorization || "";
      if (auth !== `Bearer ${ADMIN_TOKEN}`) return send(res, 401, { error: "unauthorized" });
      const body = await readBody(req);
      const job = store.get(body.jobId);
      if (!job) return send(res, 404, { error: "unknown jobId" });
      if (job.status === "done" || job.status === "running")
        return send(res, 409, { error: `job already ${job.status}` });
      store.update(job.id, { status: "paid", paidAt: new Date().toISOString() });
      queue.enqueue(() => runJob(job.id));
      return send(res, 202, { jobId: job.id, status: "paid", queued: true });
    }

    if (req.method === "POST" && url.pathname === "/pay/verify") {
      if (!MERCHANT_WALLET) return send(res, 500, { error: "MERCHANT_WALLET not configured" });
      if (rateLimited(ip)) return send(res, 429, { error: "rate limited" });
      const body = await readBody(req);
      const job = store.get(body.jobId);
      if (!job) return send(res, 404, { error: "unknown jobId" });
      if (job.status === "done" || job.status === "running" || job.status === "paid")
        return send(res, 409, { error: `job already ${job.status}` });
      // Replay protection: a signature can pay for exactly one job.
      const dup = store.findBySignature(body.signature);
      if (dup) return send(res, 409, { error: "payment signature already used" });

      const result = await verifyUsdcPayment({
        signature: body.signature,
        amountUsdc: job.priceUsd || PRICE_USD,
        merchant: MERCHANT_WALLET,
        rpcUrl: SOLANA_RPC_URL,
      });
      if (!result.ok) return send(res, 402, { error: `payment not verified: ${result.reason}` });

      store.update(job.id, { status: "paid", paidAt: new Date().toISOString(), paymentSignature: body.signature });
      queue.enqueue(() => runJob(job.id));
      return send(res, 202, { jobId: job.id, status: "paid", queued: true });
    }

    if (req.method === "GET" && url.pathname.startsWith("/jobs/")) {
      const job = store.get(url.pathname.split("/")[2]);
      if (!job) return send(res, 404, { error: "unknown jobId" });
      // don't leak email (or an agent job's token hash / memo) on a public endpoint
      const { email, accessTokenHash, viewTokenHash, memo, ...safe } = job;
      return send(res, 200, safe);
    }

    // Who called, where they stopped: GET /admin/traffic?hours=24
    if (req.method === "GET" && url.pathname === "/admin/traffic") {
      if (!ADMIN_TOKEN || (req.headers.authorization || "") !== `Bearer ${ADMIN_TOKEN}`)
        return send(res, 401, { error: "unauthorized" });
      const hours = Number(url.searchParams.get("hours")) || 24;
      return send(res, 200, traffic.summary(Date.now() - hours * 3600_000));
    }

    if (req.method === "GET" && url.pathname === "/admin/jobs") {
      if (!ADMIN_TOKEN || (req.headers.authorization || "") !== `Bearer ${ADMIN_TOKEN}`)
        return send(res, 401, { error: "unauthorized" });
      return send(res, 200, store.list());
    }

    return send(res, 404, { error: "not found" });
  } catch (e) {
    return send(res, 400, { error: e.message });
  }
});

watcher.start();
server.listen(PORT, () => {
  console.log(`[server] facilitator lane: ${payaiAuth ? `PayAI ${payaiAuth.label()}` : payaiAuthError ? "public, PAYAI KEY IGNORED" : "public (no key)"}`);
  if (payaiAuthError) console.error(`[server] ERROR PayAI key ignored: ${payaiAuthError}`);
  console.log(`[server] solana-security-watch scan backend on :${PORT}`);
  console.log(`[server] admin ${ADMIN_TOKEN ? "enabled" : "DISABLED (set ADMIN_TOKEN)"} · email ${process.env.RESEND_API_KEY ? "Resend" : "DEV mode (disk)"} · price ${PRICE_USD} USDC web · agents ${AGENT_SCAN_PRICE_USD} scan / ${CHECK_PRICE_USD} check`);
  console.log(`[server] payments ${MERCHANT_WALLET ? "on -> " + MERCHANT_WALLET : "OFF (set MERCHANT_WALLET to enable /pay/verify)"} · rpc ${rpcHost(SOLANA_RPC_URL)}`);
});

export { server };
