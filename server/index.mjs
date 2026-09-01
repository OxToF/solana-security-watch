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
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { runScan, parseGithubUrl } from "../bin/scan.mjs";
import { Store } from "./store.mjs";
import { Queue } from "./queue.mjs";
import { sendReport } from "./email.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const PRICE_USD = Number(process.env.SCAN_PRICE_USD || 80);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "*";
const ALLOW_LOCAL = process.env.ALLOW_LOCAL === "1"; // dev/testing only
const PAY_INSTRUCTIONS =
  process.env.PAY_INSTRUCTIONS ||
  "Payment instructions not configured. Set PAY_INSTRUCTIONS (e.g. a USDC address or a Stripe link).";

const store = new Store(process.env.JOBS_FILE || join(__dirname, "data", "jobs.json"));
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
    "access-control-allow-headers": "content-type, authorization",
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
    const result = await runScan(
      job.local && ALLOW_LOCAL ? { localPath: job.local, out } : { repoUrl: job.repo, out }
    );
    const html = readFileSync(result.htmlPath, "utf8");
    const md = readFileSync(result.mdPath, "utf8");
    const depN = result.deps.advisories.length;
    const leadN = [...result.source.byClass.values()].reduce((s, e) => s + e.total, 0);
    const top = result.deps.advisories.slice(0, 3).map((a) => `- [${a.severity}] ${a.id} — ${a.summary}`).join("\n");
    await sendReport({
      to: job.email,
      subject: `Your Solana security scan — ${result.meta.owner}/${result.meta.repo}`,
      text: `Scan complete for ${job.repo}.\n\n${depN} dependency advisories on your pinned versions, ${leadN} code leads.\n\nTop advisories:\n${top || "(none)"}\n\nFull report attached.`,
      html: `<p>Scan complete for <b>${result.meta.owner}/${result.meta.repo}</b>.</p>
<p><b>${depN}</b> dependency advisories on your pinned versions, <b>${leadN}</b> code leads.</p>
<pre>${top || "(no advisories on your pinned versions)"}</pre>
<p>The full report is attached (open the .html).</p>
<p style="color:#888;font-size:12px">A hygiene + known-class scan, not an audit.</p>`,
      attachments: [
        { filename: `${result.meta.owner}-${result.meta.repo}-scan.html`, content: Buffer.from(html).toString("base64") },
        { filename: `${result.meta.owner}-${result.meta.repo}-scan.md`, content: Buffer.from(md).toString("base64") },
      ],
    });
    store.update(jobId, { status: "done", depAdvisories: depN, codeLeads: leadN, deliveredAt: new Date().toISOString() });
  } catch (e) {
    store.update(jobId, { status: "error", error: String(e.message).slice(0, 300) });
    console.error(`[job ${jobId}] failed:`, e.message);
  }
}

const server = createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || "?";
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method === "OPTIONS") return send(res, 204, "");

  try {
    if (req.method === "GET" && url.pathname === "/health") return send(res, 200, { ok: true });

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

    if (req.method === "GET" && url.pathname.startsWith("/jobs/")) {
      const job = store.get(url.pathname.split("/")[2]);
      if (!job) return send(res, 404, { error: "unknown jobId" });
      const { email, ...safe } = job; // don't leak email on a public status endpoint
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
  console.log(`[server] admin ${ADMIN_TOKEN ? "enabled" : "DISABLED (set ADMIN_TOKEN)"} · email ${process.env.RESEND_API_KEY ? "Resend" : "DEV mode (disk)"} · price $${PRICE_USD}`);
});

export { server };
