// `scan` — the per-repo product. Point it at a public GitHub Anchor repo and it
// produces the dated report a paying customer receives: (1) dependency advisories
// that affect the repo's EXACT pinned versions (RustSec/OSV, version-filtered),
// (2) build-hygiene checks, and (3) code leads mapped to the vuln-class checklist.
// Deterministic and near-zero cost: OSV queries + local grep, no LLM. Leads are
// labelled as leads, not confirmed findings — a scan is a first line, not an audit.

import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { normalize } from "./collect.mjs";

const OSV_QUERY = "https://api.osv.dev/v1/query";

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
export function parseCargoLock(text) {
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
async function scanDependencies(crates, fetchImpl, log) {
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

// Grep-lead patterns mapped to vuln-classes.md. Each hit is a LEAD to confirm by
// reading, never a confirmed finding — this is the skill's own doctrine.
// High-signal patterns only. Two ubiquitous ones (`as uNN`, bare `AccountInfo<'`)
// are deliberately excluded: on a large codebase they produce thousands of hits
// and read as noise, not leads. The truncation risk (#7) is surfaced through the
// `overflow-checks` hygiene check instead.
const LEAD_PATTERNS = [
  { cls: "#1", label: "account substitution / unchecked account", sev: "review", re: /\bUncheckedAccount\b/ },
  { cls: "#3", label: "manual byte deserialisation", sev: "review", re: /\bfrom_le_bytes\b/ },
  { cls: "#2", label: "init_if_needed re-initialisation", sev: "review", re: /\binit_if_needed\b/ },
  { cls: "#4", label: "rounding direction (ceil div)", sev: "review", re: /\bdiv_ceil\b/ },
  { cls: "#11", label: "oracle / price feed usage", sev: "review", re: /\bpyth\b|\bswitchboard\b|get_price|load_price/i },
  { cls: "#13", label: "Token-2022 / TokenInterface", sev: "review", re: /spl_token_2022|Token2022|\bTokenInterface\b/ },
  { cls: "#15", label: "CPI (invoke / invoke_signed)", sev: "review", re: /\binvoke_signed\s*\(|\binvoke\s*\(/ },
  { cls: "#18", label: "PDA bump / create_program_address", sev: "review", re: /create_program_address/ },
];

const PER_CLASS_CAP = 12;

function scanSource(dir) {
  const files = findFiles(dir, (n) => n.endsWith(".rs"));
  const byClass = new Map();
  let scannedFiles = 0;
  for (const f of files) {
    let lines;
    try { lines = readFileSync(f, "utf8").split("\n"); } catch { continue; }
    scannedFiles++;
    const rel = relative(dir, f);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const p of LEAD_PATTERNS) {
        if (p.re.test(line)) {
          if (!byClass.has(p.cls)) byClass.set(p.cls, { label: p.label, hits: [], total: 0 });
          const entry = byClass.get(p.cls);
          entry.total++;
          if (entry.hits.length < PER_CLASS_CAP) {
            entry.hits.push({ file: rel, line: i + 1, text: line.trim().slice(0, 140) });
          }
        }
      }
    }
  }
  return { byClass, scannedFiles, totalFiles: files.length };
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

function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

function renderReport(meta, deps, hygiene, source) {
  const date = meta.date;
  const md = [];
  md.push(`# Security scan — ${meta.owner}/${meta.repo}`);
  md.push("");
  md.push(`**Repo:** https://github.com/${meta.owner}/${meta.repo} · **Scanned:** ${date} · **Files:** ${source.totalFiles} Rust source files`);
  md.push("");
  md.push("> A hygiene + known-class scan, not an audit. Dependency advisories below are matched against your **exact pinned versions**. Code items are **leads to confirm by reading**, not confirmed vulnerabilities. This scan does not certify the absence of bugs.");
  md.push("");

  md.push("## 1. Dependency advisories (your pinned versions)");
  md.push("");
  if (deps.advisories.length === 0) {
    md.push("No RustSec/OSV advisory affects the exact versions pinned in `Cargo.lock`. ✅");
  } else {
    for (const a of deps.advisories) {
      md.push(`- **[${a.severity}]** [${a.id}](${a.url}) — ${a.summary}`);
      md.push(`  affects: ${a.crates.join(", ")}`);
    }
  }
  if (deps.failures) md.push(`\n_(${deps.failures} crate quer${deps.failures === 1 ? "y" : "ies"} could not be reached.)_`);
  md.push("");

  md.push("## 2. Build hygiene");
  md.push("");
  md.push(`- \`overflow-checks\` in \`[profile.release]\`: **${hygiene.overflowChecks === false ? "false — recommend enabling (class #7)" : hygiene.overflowChecks === true ? "true ✅" : "not detected"}**`);
  md.push(`- \`anchor-lang\`: **${hygiene.anchorVersion || "not detected"}**`);
  md.push("");

  md.push("## 3. Code leads by class");
  md.push("");
  md.push("Grep-level leads mapped to the [vuln-class checklist](https://github.com/OxToF/solana-security-watch). Each is a place to look, confirmed by reading the surrounding code.");
  md.push("");
  const classes = [...source.byClass.entries()].sort((a, b) => b[1].total - a[1].total);
  if (classes.length === 0) {
    md.push("No lead patterns matched.");
  } else {
    md.push("| Class | Lead | Hits |");
    md.push("|---|---|---|");
    for (const [cls, e] of classes) md.push(`| ${cls} | ${e.label} | ${e.total} |`);
    md.push("");
    for (const [cls, e] of classes) {
      md.push(`### ${cls} — ${e.label} (${e.total})`);
      for (const h of e.hits) md.push(`- \`${h.file}:${h.line}\` — \`${h.text}\``);
      if (e.total > e.hits.length) md.push(`- … and ${e.total - e.hits.length} more`);
      md.push("");
    }
  }

  md.push("---");
  md.push("");
  md.push("_Generated by [solana-security-watch](https://github.com/OxToF/solana-security-watch). Want continuous coverage instead of a snapshot? A monthly watch diffs new advisories and newly-merged code._");

  const mdText = md.join("\n");
  const html = renderHtml(meta, deps, hygiene, source, classes);
  return { md: mdText, html };
}

export const WATCHDOG_LOGO = `<svg width="46" height="46" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Solana Watchdog"><defs><linearGradient id="wg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#9945FF"/><stop offset="1" stop-color="#14F195"/></linearGradient></defs><path d="M24 3 L42 9.5 V25 C42 35.5 34.4 43.2 24 46 C13.6 43.2 6 35.5 6 25 V9.5 Z" fill="url(#wg)"/><g fill="#fff"><path d="M15.5 14 L20.2 22.5 L13.6 24.2 Z"/><path d="M32.5 14 L27.8 22.5 L34.4 24.2 Z"/><path d="M24 17 C29.4 17 32.2 21.6 32.2 26.8 C32.2 32.2 28.6 36.2 24 36.2 C19.4 36.2 15.8 32.2 15.8 26.8 C15.8 21.6 18.6 17 24 17 Z"/></g><g fill="#13132b"><circle cx="20.5" cy="26.2" r="1.8"/><circle cx="27.5" cy="26.2" r="1.8"/></g><path d="M24 29.4 L26.4 32.4 C25.2 33.4 22.8 33.4 21.6 32.4 Z" fill="#13132b"/></svg>`;

function sevBg(s) {
  const u = String(s).toUpperCase();
  if (u.startsWith("CRIT")) return "#dc2626";
  if (u.startsWith("HIGH")) return "#ea580c";
  if (u.startsWith("MOD") || u.startsWith("MED")) return "#d97706";
  if (u.startsWith("LOW")) return "#2563eb";
  return "#64748b";
}

function renderHtml(meta, deps, hygiene, source, classes) {
  const nAdv = deps.advisories.length;
  const nLeads = classes.reduce((s, [, e]) => s + e.total, 0);
  const worst = deps.advisories.reduce((w, a) => {
    const rank = { CRITICAL: 4, HIGH: 3, MODERATE: 3, MEDIUM: 3, LOW: 2 };
    const r = rank[String(a.severity).toUpperCase().split(" ")[0]] || 1;
    return r > w.r ? { r, label: a.severity } : w;
  }, { r: 0, label: "—" });

  const depCards = nAdv
    ? deps.advisories.map((a) => `<div class="adv">
        <span class="chip" style="background:${sevBg(a.severity)}">${esc(a.severity)}</span>
        <div class="adv-body"><a class="adv-id" href="${esc(a.url)}">${esc(a.id)}</a>
        <div class="adv-sum">${esc(a.summary)}</div>
        <div class="adv-pkg">Affects: ${esc(a.crates.join(", "))}</div></div></div>`).join("")
    : `<div class="clean">✓ &nbsp;No advisory affects the exact versions pinned in your <code>Cargo.lock</code>.</div>`;

  const ocOk = hygiene.overflowChecks === true;
  const ocBad = hygiene.overflowChecks === false;
  const hygieneRows = `
    <div class="hyg"><span class="hyg-badge ${ocBad ? "warn" : ocOk ? "good" : "na"}">${ocBad ? "⚠" : ocOk ? "✓" : "?"}</span>
      <div><b>overflow-checks</b> (release profile)<div class="muted">${ocBad ? "Disabled — enable it to turn silent wrapping into a panic (class #7)." : ocOk ? "Enabled." : "Not detected."}</div></div></div>
    <div class="hyg"><span class="hyg-badge na">◆</span>
      <div><b>anchor-lang</b><div class="muted">${esc(hygiene.anchorVersion || "not detected")}</div></div></div>`;

  const classSections = classes.length
    ? classes.map(([cls, e]) => `<div class="cls">
        <div class="cls-head"><span class="cls-tag">${esc(cls)}</span><span class="cls-label">${esc(e.label)}</span><span class="cls-count">${e.total}</span></div>
        <ul class="samples">${e.hits.map((h) => `<li><span class="loc">${esc(h.file)}:${h.line}</span><code>${esc(h.text)}</code></li>`).join("")}${e.total > e.hits.length ? `<li class="more">… and ${e.total - e.hits.length} more</li>` : ""}</ul></div>`).join("")
    : `<div class="clean">No lead patterns matched.</div>`;

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security scan — ${esc(meta.owner)}/${esc(meta.repo)}</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#eceef4;color:#1c2030;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.doc{max-width:840px;margin:28px auto;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 12px 40px rgba(20,20,50,.12)}
.hd{background:linear-gradient(125deg,#1a0f36 0%,#0e1730 60%,#0a1f2b 100%);color:#fff;padding:26px 34px;display:flex;align-items:center;gap:16px;position:relative}
.hd::after{content:"";position:absolute;left:0;right:0;bottom:0;height:3px;background:linear-gradient(90deg,#9945FF,#14F195)}
.hd .wm{font-weight:800;letter-spacing:.5px;font-size:1.15rem;line-height:1.1}
.hd .wm .g{background:linear-gradient(90deg,#b98cff,#14F195);-webkit-background-clip:text;background-clip:text;color:transparent}
.hd .tl{color:#a9b0cf;font-size:.82rem;margin-top:3px}
.hd .date{margin-left:auto;text-align:right;color:#a9b0cf;font-size:.8rem}
.hd .date b{color:#fff;display:block;font-size:.95rem}
.sub{padding:22px 34px 6px}
.repo{font-size:1.5rem;font-weight:800;margin:0;letter-spacing:-.01em;word-break:break-word}
.repo a{color:inherit;text-decoration:none}
.pills{margin:10px 0 4px;display:flex;gap:8px;flex-wrap:wrap}
.pill{font-size:.74rem;font-weight:700;padding:.22rem .6rem;border-radius:999px;background:#eef0f6;color:#5b6178}
.pill.warn{background:#fff2e8;color:#c2410c}
.body{padding:14px 34px 30px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:18px 0 8px}
.stat{background:#f7f8fc;border:1px solid #eaecf3;border-radius:14px;padding:16px 18px}
.stat .num{font-size:2rem;font-weight:800;line-height:1}
.stat .lab{color:#6b7188;font-size:.8rem;margin-top:6px}
.stat.alert .num{color:#dc2626}
h2{font-size:1.05rem;margin:30px 0 12px;padding-left:12px;border-left:4px solid #9945FF;line-height:1.2}
.adv{display:flex;gap:12px;align-items:flex-start;padding:13px 0;border-top:1px solid #eef0f5}
.adv:first-of-type{border-top:0}
.chip{color:#fff;border-radius:6px;padding:.16rem .5rem;font-size:.68rem;font-weight:800;letter-spacing:.3px;white-space:nowrap;margin-top:2px;flex:none}
.adv-id{font-weight:700;color:#4f2bbd;text-decoration:none;font-size:.95rem}
.adv-id:hover{text-decoration:underline}
.adv-sum{margin:2px 0 3px}
.adv-pkg{color:#8189a3;font-size:.8rem}
.clean{background:#effaf3;border:1px solid #c9eed7;color:#0a7d43;border-radius:12px;padding:14px 16px;font-weight:600}
.hyg{display:flex;gap:12px;align-items:flex-start;padding:10px 0}
.hyg-badge{width:26px;height:26px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:800;flex:none;font-size:.85rem}
.hyg-badge.good{background:#e7f8ee;color:#0a7d43}.hyg-badge.warn{background:#fff2e8;color:#c2410c}
.hyg-badge.na{background:#eef0f6;color:#6b7188}
.cls{border:1px solid #eef0f5;border-radius:12px;padding:12px 14px;margin:10px 0;background:#fbfbfe}
.cls-head{display:flex;align-items:center;gap:10px}
.cls-tag{font-weight:800;color:#4f2bbd;background:#efe8ff;border-radius:6px;padding:.1rem .45rem;font-size:.8rem}
.cls-label{font-weight:600}.cls-count{margin-left:auto;color:#6b7188;font-weight:700}
.samples{list-style:none;margin:10px 0 0;padding:0}
.samples li{padding:5px 0;border-top:1px dashed #eceef4;font-size:.82rem}
.samples .loc{color:#9245ff;font-weight:600;margin-right:8px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.samples code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#f4f4fb;padding:.05rem .3rem;border-radius:4px;color:#333}
.samples .more{color:#9aa0b4;font-style:italic;border-top:0}
.muted{color:#8189a3;font-size:.82rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.scope{background:#f7f8fc;border:1px solid #eaecf3;border-radius:12px;padding:14px 16px;margin:22px 0 4px;font-size:.9rem;color:#4a5069}
.ft{border-top:1px solid #eef0f5;margin-top:24px;padding-top:16px;display:flex;align-items:center;gap:10px;color:#8189a3;font-size:.82rem}
.ft .logo{opacity:.9}
.ft b{color:#4a5069}
a{color:#6d3bd6}
@media print{body{background:#fff}.doc{box-shadow:none;margin:0;max-width:none}}
</style></head><body>
<div class="doc">
  <div class="hd">
    ${WATCHDOG_LOGO}
    <div><div class="wm">SOLANA <span class="g">WATCHDOG</span></div><div class="tl">Dependency &amp; known-class security scan</div></div>
    <div class="date">Report date<b>${esc(meta.date)}</b></div>
  </div>
  <div class="sub">
    <h1 class="repo"><a href="https://github.com/${esc(meta.owner)}/${esc(meta.repo)}">${esc(meta.owner)}/${esc(meta.repo)}</a></h1>
    <div class="pills"><span class="pill">${source.totalFiles} Rust files scanned</span><span class="pill warn">Hygiene scan · not an audit</span></div>
  </div>
  <div class="body">
    <div class="stats">
      <div class="stat ${nAdv ? "alert" : ""}"><div class="num">${nAdv}</div><div class="lab">Dependency advisories<br>on your pinned versions</div></div>
      <div class="stat"><div class="num">${nLeads}</div><div class="lab">Code leads<br>across ${classes.length} classes</div></div>
      <div class="stat"><div class="num">${worst.label === "—" ? "—" : esc(String(worst.label).split(" ")[0])}</div><div class="lab">Highest advisory<br>severity</div></div>
    </div>

    <h2>Dependency advisories</h2>
    <p class="muted">Matched against the exact npm/crate versions pinned in your lockfile.</p>
    ${depCards}

    <h2>Build hygiene</h2>
    ${hygieneRows}

    <h2>Code leads by class</h2>
    <p class="muted">Grep-level leads mapped to the 18-class checklist. Each is a place to look, confirmed by reading the surrounding code — not a confirmed vulnerability.</p>
    ${classSections}

    <div class="scope"><b>What this is not.</b> A full audit is not replaceable. This scan detects known vulnerability classes and dependency issues; it does not certify the absence of bugs. Use it as a first line of defense, not a guarantee.</div>

    <div class="ft"><span class="logo">${WATCHDOG_LOGO.replace('width="46" height="46"', 'width="22" height="22"')}</span><div>Generated by <b>Solana Watchdog</b> · <a href="https://github.com/OxToF/solana-security-watch">open source</a>. Want continuous coverage instead of a snapshot? Ask about the monthly watch.</div></div>
  </div>
</div>
</body></html>`;
}

export async function runScan(opts = {}) {
  const {
    repoUrl,
    localPath = null,
    out = "scan-out",
    fetchImpl = globalThis.fetch,
    now = new Date(),
    log = console.log,
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

  const lockFiles = findFiles(dir, (n) => n === "Cargo.lock");
  let crates = [];
  for (const lf of lockFiles) crates = crates.concat(parseCargoLock(readFileSync(lf, "utf8")));
  if (crates.length === 0) log("[scan] no Cargo.lock found — dependency section will be empty");

  const deps = crates.length
    ? await scanDependencies(crates, fetchImpl, log)
    : { advisories: [], failures: 0 };
  const hygiene = checkHygiene(dir);
  const source = scanSource(dir);

  const date = now.toISOString().slice(0, 10);
  const meta = { owner, repo, date };
  const { md, html } = renderReport(meta, deps, hygiene, source);

  mkdirSync(out, { recursive: true });
  const base = `${owner}-${repo}-${date}`.replace(/[^A-Za-z0-9_.-]/g, "_");
  const mdPath = join(out, `${base}.md`);
  const htmlPath = join(out, `${base}.html`);
  writeFileSync(mdPath, md);
  writeFileSync(htmlPath, html);

  log(`[scan] ${deps.advisories.length} dep advisories · ${[...source.byClass.values()].reduce((s, e) => s + e.total, 0)} code leads · ${source.totalFiles} files`);
  log(`[scan] report -> ${mdPath}`);
  log(`[scan] report -> ${htmlPath}`);
  return { meta, deps, hygiene, source, mdPath, htmlPath, cleanup };
}
