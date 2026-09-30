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
import { runScan, parseGithubUrl, fixMailto, WATCHDOG_LOGO } from "../bin/scan.mjs";
import { Store } from "./store.mjs";
import { Queue } from "./queue.mjs";
import { sendReport } from "./email.mjs";
import { verifyUsdcPayment, USDC_MINT } from "./verify.mjs";
import { Facilitator, SOLANA_MAINNET, encodeHeader, decodeHeader, bazaarExtension } from "./x402.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const PRICE_USD = Number(process.env.SCAN_PRICE_USD || 80);
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
const facilitator = FACILITATOR_URL === "off" ? null : new Facilitator({ url: FACILITATOR_URL });
// ERC-8004 identity, once registered on Base: the agentId minted by register().
const ERC8004_REGISTRY = "eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";
const ERC8004_AGENT_ID = process.env.ERC8004_AGENT_ID ? Number(process.env.ERC8004_AGENT_ID) : null;
const LANDING_URL = process.env.LANDING_URL || "https://watchdog.soladrome.finance";
const store = new Store(JOBS_FILE);
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
    "access-control-allow-methods": "POST, GET, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, payment-signature",
    "access-control-expose-headers": "payment-required, payment-response",
    ...extraHeaders,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > 1e5) req.destroy(); });
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

function x402Required(job, feePayer, error) {
  return {
    x402Version: 2,
    error,
    resource: {
      url: `${PUBLIC_BASE}/agent/scan`,
      description: "Solana Watchdog: dependency advisories split by on-chain vs toolchain surface, plus known Solana/Anchor bug-class leads, for a public GitHub repo. A scan, not an audit.",
      mimeType: "application/json",
      serviceName: "Solana Watchdog",
      tags: ["security", "solana", "anchor", "dependencies", "code-scan"],
    },
    accepts: [requirementsFor(job, feePayer)],
    extensions: { bazaar: bazaarExtension({ exampleRepo: "https://github.com/solana-developers/program-examples", base: PUBLIC_BASE }) },
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
    description: "Security scan of a public Solana / Anchor GitHub repo: RustSec advisories on the exact pinned versions, split into the on-chain surface and CLI tooling, build hygiene, and leads for known Solana bug classes with file:line. JSON + Markdown + HTML report. Agents pay per call over x402 (USDC on Solana). A scan, not an audit.",
    image: `${PUBLIC_BASE}/logo.svg`,
    services: [
      { name: "web", endpoint: LANDING_URL },
      { name: "x402", endpoint: `${PUBLIC_BASE}/agent/scan` },
      { name: "agent-manual", endpoint: `${PUBLIC_BASE}/skill.md` },
    ],
    x402Support: true,
    active: true,
    registrations: ERC8004_AGENT_ID === null ? [] : [{ agentId: ERC8004_AGENT_ID, agentRegistry: ERC8004_REGISTRY }],
    supportedTrust: ["reputation"],
  };
}

const SKILL_MD = existsSync(join(__dirname, "skill.md")) ? readFileSync(join(__dirname, "skill.md"), "utf8") : "";

// Provider RPC URLs carry their API key (Helius: ?api-key=): log the host only.
function rpcHost(u) { try { return new URL(u).host; } catch { return "(unparseable RPC URL)"; } }

const server = createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || "?";
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method === "OPTIONS") return send(res, 204, "");

  try {
    if (req.method === "GET" && url.pathname === "/health") return send(res, 200, { ok: true });

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
        .replaceAll("{{PRICE}}", String(PRICE_USD))
        .replaceAll("{{MERCHANT}}", MERCHANT_WALLET || "(not configured)"), { "content-type": "text/markdown; charset=utf-8" });
    }

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
        priceUsd: PRICE_USD,
        agent: true,
        memo: `ssw:${randomBytes(9).toString("base64url")}`,
        accessTokenHash: hashToken(accessToken),
      });
      return send(res, 402, paymentRequired({ ...job, _accessToken: accessToken }), await quoteHeaders(job));
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

server.listen(PORT, () => {
  console.log(`[server] solana-security-watch scan backend on :${PORT}`);
  console.log(`[server] admin ${ADMIN_TOKEN ? "enabled" : "DISABLED (set ADMIN_TOKEN)"} · email ${process.env.RESEND_API_KEY ? "Resend" : "DEV mode (disk)"} · price ${PRICE_USD} USDC`);
  console.log(`[server] payments ${MERCHANT_WALLET ? "on -> " + MERCHANT_WALLET : "OFF (set MERCHANT_WALLET to enable /pay/verify)"} · rpc ${rpcHost(SOLANA_RPC_URL)}`);
});

export { server };
