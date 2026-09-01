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

function cloneRepo(url, dir, log) {
  log(`[scan] cloning ${url}`);
  execFileSync("git", ["clone", "--depth", "1", "--quiet", url, dir], {
    stdio: ["ignore", "ignore", "pipe"],
    timeout: 120000,
  });
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

function renderHtml(meta, deps, hygiene, source, classes) {
  const sevColor = (s) => /CRIT/i.test(s) ? "#b00020" : /HIGH/i.test(s) ? "#d1440a" : /MOD|MED/i.test(s) ? "#b8860b" : "#555";
  const depRows = deps.advisories.length
    ? deps.advisories.map((a) =>
        `<tr><td><span class="sev" style="background:${sevColor(a.severity)}">${esc(a.severity)}</span></td>
         <td><a href="${esc(a.url)}">${esc(a.id)}</a><div class="muted">${esc(a.crates.join(", "))}</div></td>
         <td>${esc(a.summary)}</td></tr>`).join("")
    : `<tr><td colspan="3" class="ok">No advisory affects your pinned versions.</td></tr>`;
  const classRows = classes.map(([cls, e]) =>
    `<tr><td>${esc(cls)}</td><td>${esc(e.label)}</td><td>${e.total}</td></tr>`).join("") ||
    `<tr><td colspan="3">No lead patterns matched.</td></tr>`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scan — ${esc(meta.owner)}/${esc(meta.repo)}</title>
<style>
:root{--fg:#1a1a2e;--muted:#6b7280;--bg:#fff;--card:#f7f7fb;--line:#e5e7eb}
body{font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;color:var(--fg);background:var(--bg);margin:0;padding:2rem;max-width:820px;margin:auto}
h1{font-size:1.5rem;margin:0 0 .2rem} h2{font-size:1.15rem;margin:2rem 0 .6rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
.meta{color:var(--muted);font-size:.9rem} .note{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.8rem 1rem;margin:1rem 0;font-size:.92rem}
table{width:100%;border-collapse:collapse;margin:.5rem 0} td,th{text-align:left;padding:.45rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
.sev{color:#fff;border-radius:5px;padding:.1rem .45rem;font-size:.72rem;font-weight:700;white-space:nowrap}
.muted{color:var(--muted);font-size:.82rem} .ok{color:#0a7d33} code{background:var(--card);padding:.05rem .3rem;border-radius:4px;font-size:.85em}
footer{margin-top:2.5rem;color:var(--muted);font-size:.85rem;border-top:1px solid var(--line);padding-top:1rem}
</style></head><body>
<h1>Security scan — ${esc(meta.owner)}/${esc(meta.repo)}</h1>
<div class="meta">Scanned ${esc(meta.date)} · ${source.totalFiles} Rust source files · <a href="https://github.com/${esc(meta.owner)}/${esc(meta.repo)}">repo</a></div>
<div class="note"><strong>A hygiene + known-class scan, not an audit.</strong> Dependency advisories are matched against your exact pinned versions. Code items are leads to confirm by reading, not confirmed vulnerabilities. This scan does not certify the absence of bugs.</div>
<h2>1. Dependency advisories (your pinned versions)</h2>
<table><tr><th>Sev</th><th>ID</th><th>Summary</th></tr>${depRows}</table>
<h2>2. Build hygiene</h2>
<table>
<tr><td><code>overflow-checks</code> (release)</td><td>${hygiene.overflowChecks === false ? '<b style="color:#d1440a">false — enable (class #7)</b>' : hygiene.overflowChecks === true ? '<span class="ok">true</span>' : "not detected"}</td></tr>
<tr><td><code>anchor-lang</code></td><td>${esc(hygiene.anchorVersion || "not detected")}</td></tr>
</table>
<h2>3. Code leads by class</h2>
<table><tr><th>Class</th><th>Lead</th><th>Hits</th></tr>${classRows}</table>
<footer>Generated by <a href="https://github.com/OxToF/solana-security-watch">solana-security-watch</a>. Want continuous coverage instead of a snapshot? Ask about the monthly watch.</footer>
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
    dir = mkdtempSync(join(tmpdir(), "ssw-scan-"));
    cloneRepo(g.url, dir, log);
    cleanup = dir;
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
