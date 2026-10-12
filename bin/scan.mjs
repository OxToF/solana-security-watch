// `scan` — the per-repo product. Point it at a public GitHub Anchor repo and it
// produces the dated report a paying customer receives:
//   (1) an Anchor-aware analysis of the program source (engine/anchor.mjs),
//   (2) dependency advisories at the EXACT pinned versions, judged by whether the
//       crate compiles into the program for the Solana target (engine/reach.mjs)
//       and whether the defect is reachable on-chain (engine/advisories.mjs),
//   (3) what the chain says about the deployed program (engine/deployed.mjs).
// Deterministic, no LLM: OSV, the crates.io index and an RPC are the only calls.

import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep, dirname } from "node:path";
import { normalize } from "./collect.mjs";
import { onchainClosure, parseManifest } from "./engine/reach.mjs";
import { analyzeAnchor } from "./engine/anchor.mjs";
import { judgeAdvisories } from "./engine/advisories.mjs";
import { inspectDeployed } from "./engine/deployed.mjs";
import { buildModel, renderHtml, renderMarkdown } from "./engine/report.mjs";

const OSV_QUERY = process.env.OSV_QUERY_URL || "https://api.osv.dev/v1/query";
const OSV_BATCH = process.env.OSV_BATCH_URL || "https://api.osv.dev/v1/querybatch";
const OSV_VULNS = process.env.OSV_VULNS_URL || "https://api.osv.dev/v1/vulns";

// Only allow canonical public GitHub HTTPS URLs — no shell, no SSH, no arbitrary
// hosts. Returns { owner, repo, url } or throws.
export function parseGithubUrl(input) {
  const m = String(input).trim().match(
    /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/
  );
  if (!m) throw new Error(`not a public https://github.com/<owner>/<repo> URL: ${input}`);
  return { owner: m[1], repo: m[2], url: `https://github.com/${m[1]}/${m[2]}.git` };
}

// Fetch the repo as a tarball via the GitHub API instead of `git clone`. Anonymous
// git clones from datacenter IPs get throttled (GitHub answers 401 -> git prompts
// for a username -> non-interactive failure). The tarball endpoint is more tolerant
// and, with a GITHUB_TOKEN, gets the authenticated 5000/hr limit. Returns the path
// to the extracted repo directory.
async function fetchRepo(owner, repo, workdir, log, fetchImpl, token) {
  log(`[scan] downloading ${owner}/${repo} tarball`);
  const headers = { "User-Agent": "solana-security-watch", Accept: "application/vnd.github+json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetchImpl(`https://api.github.com/repos/${owner}/${repo}/tarball`, { headers });
  if (!res.ok) throw new Error(`GitHub tarball ${res.status} for ${owner}/${repo}`);
  const tgz = join(workdir, "_repo.tar.gz");
  writeFileSync(tgz, Buffer.from(await res.arrayBuffer()));
  execFileSync("tar", ["-xzf", tgz, "-C", workdir], { stdio: ["ignore", "ignore", "pipe"], timeout: 120000 });
  const sub = readdirSync(workdir, { withFileTypes: true }).find((e) => e.isDirectory());
  if (!sub) throw new Error("empty tarball");
  return join(workdir, sub.name);
}

// Minimal Cargo.lock parser: [[package]] name/version pairs. Good enough to learn
// the repo's exact pinned dependency set.
// With registryOnly, keeps crates.io packages only: a workspace or git crate that
// happens to share a published crate's name would otherwise borrow its advisories.
export function parseCargoLock(text, { registryOnly = false } = {}) {
  if (registryOnly) {
    return text.split(/^\[\[package\]\]/m).slice(1).flatMap((block) => {
      const f = (k) => block.match(new RegExp(`^${k}\\s*=\\s*"([^"]+)"`, "m"))?.[1];
      const name = f("name"), version = f("version"), source = f("source") || "";
      return name && version && source.startsWith("registry+https://github.com/rust-lang/crates.io-index") ? [{ name, version }] : [];
    });
  }
  const out = [];
  let name = null;
  for (const line of text.split("\n")) {
    const n = line.match(/^name\s*=\s*"([^"]+)"/);
    const v = line.match(/^version\s*=\s*"([^"]+)"/);
    if (n) name = n[1];
    else if (v && name) { out.push({ name, version: v[1] }); name = null; }
  }
  return out;
}

function findFiles(dir, predicate, skip = new Set(["target", "node_modules", ".git", "test-ledger"])) {
  const out = [];
  const walk = (d) => {
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!skip.has(e.name)) walk(join(d, e.name));
      } else if (predicate(e.name)) {
        out.push(join(d, e.name));
      }
    }
  };
  walk(dir);
  return out;
}

// Version-filtered OSV: which of the repo's pinned crates carry advisories that
// actually affect the pinned version. Two-phase to keep request count sane: a
// cheap per-crate query, then normalize the hits.
export async function scanDependencies(crates, fetchImpl, log = () => {}) {
  // De-dupe (name@version) and cap to keep a scan quick and polite to OSV.
  const seen = new Set();
  const uniq = [];
  for (const c of crates) {
    const k = `${c.name}@${c.version}`;
    if (!seen.has(k)) { seen.add(k); uniq.push(c); }
  }
  log(`[scan] ${uniq.length} unique pinned crates -> querying OSV (version-filtered)`);

  const rawByCrate = [];
  let failures = 0;
  const CONCURRENCY = 8;
  for (let i = 0; i < uniq.length; i += CONCURRENCY) {
    const batch = uniq.slice(i, i + CONCURRENCY);
    const results = await Promise.all(
      batch.map(async (c) => {
        try {
          const res = await fetchImpl(OSV_QUERY, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ package: { ecosystem: "crates.io", name: c.name }, version: c.version }),
          });
          if (!res.ok) return { c, vulns: null };
          const body = await res.json();
          return { c, vulns: body.vulns || [] };
        } catch {
          return { c, vulns: null };
        }
      })
    );
    for (const r of results) {
      if (r.vulns === null) failures++;
      else if (r.vulns.length) rawByCrate.push([`${r.c.name} ${r.c.version}`, r.vulns]);
    }
  }
  return { advisories: normalize(rawByCrate), failures };
}

// Same answer as scanDependencies, for a whole lockfile: one OSV batch request per
// thousand packages instead of one request each, then the details of each distinct
// advisory once. A batch that fails counts all of its packages as not checked.
export async function scanDependenciesBatch(pkgs, fetchImpl, { ecosystem = "crates.io" } = {}) {
  const uniq = [...new Map(pkgs.map((p) => [`${p.name}@${p.version}`, p])).values()];
  const idsByPkg = [];
  let failures = 0;
  for (let i = 0; i < uniq.length; i += 1000) {
    const chunk = uniq.slice(i, i + 1000);
    let results;
    try {
      const res = await fetchImpl(OSV_BATCH, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ queries: chunk.map((c) => ({ package: { ecosystem, name: c.name }, version: c.version })) }),
      });
      results = res.ok ? (await res.json()).results : null;
    } catch { results = null; }
    if (!Array.isArray(results) || results.length !== chunk.length) { failures += chunk.length; continue; }
    chunk.forEach((c, j) => {
      const ids = (results[j].vulns || []).map((v) => v.id);
      if (ids.length) idsByPkg.push([`${c.name} ${c.version}`, ids]);
    });
  }
  const details = new Map();
  const ids = [...new Set(idsByPkg.flatMap(([, v]) => v))];
  for (let i = 0; i < ids.length; i += 8) {
    await Promise.all(ids.slice(i, i + 8).map(async (id) => {
      try {
        const res = await fetchImpl(`${OSV_VULNS}/${encodeURIComponent(id)}`);
        details.set(id, res.ok ? await res.json() : { id });
      } catch { details.set(id, { id }); }
    }));
  }
  return { advisories: normalize(idsByPkg.map(([k, v]) => [k, v.map((id) => details.get(id))])), failures, packages: uniq.length };
}

function checkHygiene(dir) {
  const out = { overflowChecks: null, anchorVersion: null };
  const cargoToml = findFiles(dir, (n) => n === "Cargo.toml");
  for (const f of cargoToml) {
    const t = readFileSync(f, "utf8");
    if (/\[profile\.release\][\s\S]*?overflow-checks\s*=\s*false/.test(t)) out.overflowChecks = false;
    if (out.overflowChecks === null && /\[profile\.release\][\s\S]*?overflow-checks\s*=\s*true/.test(t)) out.overflowChecks = true;
  }
  const lock = findFiles(dir, (n) => n === "Cargo.lock")[0];
  if (lock) {
    const crates = parseCargoLock(readFileSync(lock, "utf8"));
    const anchor = crates.find((c) => c.name === "anchor-lang");
    if (anchor) out.anchorVersion = anchor.version;
  }
  return out;
}

// "Get this fixed" links: a pre-filled email to the operator, only when the caller
// passes a contact (the paid service does, the open-source CLI does not).
export function fixMailto(cta, meta, subject, lines = []) {
  if (!cta || !cta.contact) return null;
  const body = [
    `Repository: https://github.com/${meta.owner}/${meta.repo}`,
    cta.ref ? `Scan reference: ${cta.ref}` : null,
    ...lines,
    "",
    "What we would like fixed, and any deadline:",
    "",
  ].filter((l) => l !== null).join("\n");
  return `mailto:${cta.contact}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

export const WATCHDOG_LOGO = `<svg width="46" height="46" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Solana Watchdog"><defs><linearGradient id="wg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#9945FF"/><stop offset="1" stop-color="#14F195"/></linearGradient></defs><circle cx="32" cy="32" r="30" fill="url(#wg)"/><path d="M16 24 L21 7 L27 20 Z" fill="#efe7d6"/><path d="M48 24 L43 7 L37 20 Z" fill="#efe7d6"/><path d="M19.5 21 L21.6 12 L24.4 19 Z" fill="#b98cff"/><path d="M44.5 21 L42.4 12 L39.6 19 Z" fill="#b98cff"/><ellipse cx="32" cy="34" rx="15" ry="14" fill="#f4eddd"/><ellipse cx="32" cy="41" rx="8" ry="6.5" fill="#fffaf0"/><path d="M21.5 29 L28 30.5" stroke="#3a3550" stroke-width="1.6" stroke-linecap="round"/><path d="M42.5 29 L36 30.5" stroke="#3a3550" stroke-width="1.6" stroke-linecap="round"/><circle cx="26" cy="33" r="3" fill="#20202f"/><circle cx="38" cy="33" r="3" fill="#20202f"/><circle cx="27" cy="32.1" r=".9" fill="#fff"/><circle cx="39" cy="32.1" r=".9" fill="#fff"/><ellipse cx="32" cy="38.5" rx="2.7" ry="2" fill="#20202f"/><path d="M32 40.5 Q28 44 25 42" stroke="#20202f" stroke-width="1.4" fill="none" stroke-linecap="round"/><path d="M32 40.5 Q36 44 39 42" stroke="#20202f" stroke-width="1.4" fill="none" stroke-linecap="round"/><circle cx="45" cy="45" r="7.5" fill="rgba(255,255,255,.18)" stroke="#20202f" stroke-width="2.4"/><path d="M50.4 50.4 L57 57" stroke="#20202f" stroke-width="3.4" stroke-linecap="round"/></svg>`;


export async function runScan(opts = {}) {
  const {
    repoUrl,
    localPath = null,
    out = "scan-out",
    fetchImpl = globalThis.fetch,
    now = new Date(),
    log = console.log,
    cta = null,
  } = opts;

  let dir, owner, repo, cleanup = null;
  if (localPath) {
    dir = localPath;
    owner = "local"; repo = localPath.split(sep).filter(Boolean).pop() || "repo";
  } else {
    const g = parseGithubUrl(repoUrl);
    owner = g.owner; repo = g.repo;
    const work = mkdtempSync(join(tmpdir(), "ssw-scan-"));
    dir = await fetchRepo(g.owner, g.repo, work, log, fetchImpl, process.env.GITHUB_TOKEN);
    cleanup = work;
  }

  // GitHub names the tarball's top directory <owner>-<repo>-<short sha>: the commit we read.
  const ref = localPath ? null : (/-([0-9a-f]{7,40})$/.exec(dir.split(sep).filter(Boolean).pop() || "") || [])[1] || null;

  const lockFiles = findFiles(dir, (n) => n === "Cargo.lock");
  let crates = [];
  for (const lf of lockFiles) crates = crates.concat(parseCargoLock(readFileSync(lf, "utf8")));
  if (crates.length === 0) log("[scan] no Cargo.lock found — dependency section will be empty");
  const lockSize = new Set(crates.map((c) => `${c.name} ${c.version}`)).size;

  const deps = crates.length
    ? await scanDependencies(crates, fetchImpl, log)
    : { advisories: [], failures: 0 };

  // The program crates (crate-type cdylib), and what really compiles into them.
  const closure = crates.length ? await onchainClosure(dir, { fetchImpl, log }) : null;
  const programs = closure ? closure.programs : findFiles(dir, (n) => n === "Cargo.toml").flatMap((f) => {
    try { const m = parseManifest(readFileSync(f, "utf8")); return m.cdylib && m.name ? [{ name: m.name, dir: dirname(f) }] : []; } catch { return []; }
  });
  const analysis = analyzeAnchor(programs.map((p) => p.dir), dir);
  log(`[scan] ${analysis.stats.structs} account contexts, ${analysis.stats.fields} accounts, ${analysis.stats.handlers} handlers -> ${analysis.findings.length} observations`);
  const programSource = programs.flatMap((p) => findFiles(join(p.dir, "src"), (n) => n.endsWith(".rs")).map((f) => readFileSync(f, "utf8"))).join("\n");
  const judged = judgeAdvisories(deps.advisories, closure, programSource);
  const deployed = await inspectDeployed(analysis.declaredIds, { fetchImpl, log });
  const hygiene = checkHygiene(dir);

  const date = now.toISOString().slice(0, 10);
  const meta = { owner, repo, date, ref };
  const model = buildModel({
    meta, analysis, deployed, deps: judged, closure, lockSize, hygiene,
    programs: programs.map((p) => ({ name: p.name, path: relative(dir, p.dir) || "." })),
  });
  const html = renderHtml(model, { logo: WATCHDOG_LOGO, cta });
  const md = renderMarkdown(model);

  mkdirSync(out, { recursive: true });
  const base = `${owner}-${repo}-${date}`.replace(/[^A-Za-z0-9_.-]/g, "_");
  const mdPath = join(out, `${base}.md`);
  const htmlPath = join(out, `${base}.html`);
  writeFileSync(mdPath, md);
  writeFileSync(htmlPath, html);

  log(`[scan] risk ${model.risk}: ${model.confident.length} to fix, ${model.review.length} to verify · ${judged.onchain.length} advisories reach the program (of ${deps.advisories.length})`);
  log(`[scan] report -> ${mdPath}`);
  log(`[scan] report -> ${htmlPath}`);
  return { meta, model, deps, hygiene, mdPath, htmlPath, cleanup };
}
