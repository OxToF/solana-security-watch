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

// ---------------------------------------------------------------------------
// Advisory triage: on-chain surface vs toolchain.
//
// A Solana Cargo.lock is dominated by crates that never reach the deployed BPF
// binary: solana-cli, solana-client, the test validator and the build tooling
// drag in openssl, quinn, rustls, tokio, hyper... Reporting those next to a
// borsh advisory reads as noise and, worse, invites the reply "openssl isn't in
// our program". So we split the advisories three ways and lead with the one
// bucket that describes deployed on-chain risk.
//
// A crate counts as on-chain when it is either declared by a program crate in
// this repo (one whose Cargo.toml sets crate-type = cdylib) or a known member of
// the solana-program / anchor-lang runtime surface that a program pulls in
// transitively. This is a heuristic, and the report says so: it is a triage aid,
// not a substitute for `cargo tree` on the program crate.
const ONCHAIN_RUNTIME = new Set([
  "solana-program", "solana-security-txt", "anchor-lang", "anchor-spl",
  "anchor-attribute-account", "anchor-attribute-program", "anchor-derive-accounts",
  "borsh", "borsh-derive", "bytemuck", "bytemuck_derive", "arrayref", "zerocopy",
  "num-traits", "num-derive", "num-bigint", "num-integer", "thiserror",
  "serde", "serde_derive", "serde_bytes", "bs58", "base64",
  "sha2", "sha3", "keccak", "blake3", "digest", "hmac",
  "curve25519-dalek", "ed25519-dalek", "libsecp256k1", "bincode",
  "spl-token", "spl-token-2022", "spl-associated-token-account", "spl-memo",
  "spl-pod", "spl-discriminator", "spl-type-length-value",
  "spl-token-metadata-interface", "spl-token-group-interface",
  "hashbrown", "ahash", "itertools", "memoffset", "getrandom",
]);

// RustSec "unmaintained"/"unsound" housekeeping advisories are supply-chain
// signal, not an exploitable defect — they get their own bucket so they never
// inflate the headline number.
const HOUSEKEEPING_RE = /\bunmaintained\b|no longer maintained|is deprecated/i;

// Direct dependencies declared by every program crate in the repo (crate-type
// containing "cdylib"). Minimal TOML walk: we only need dependency NAMES.
export function findProgramDeps(dir) {
  const names = new Set();
  for (const f of findFiles(dir, (n) => n === "Cargo.toml")) {
    let t;
    try { t = readFileSync(f, "utf8"); } catch { continue; }
    if (!/crate-type\s*=\s*\[[^\]]*cdylib/.test(t)) continue;
    let inDeps = false;
    for (const raw of t.split("\n")) {
      const line = raw.trim();
      const header = line.match(/^\[([^\]]+)\]/);
      if (header) {
        const h = header[1];
        // [dependencies], [target.'cfg(..)'.dependencies], [dependencies.foo]
        const sub = h.match(/(?:^|\.)(?:dev-|build-)?dependencies\.(.+)$/);
        if (sub) { names.add(sub[1].replace(/["']/g, "").trim()); inDeps = false; continue; }
        inDeps = /(?:^|\.)dependencies$/.test(h) && !/(?:^|\.)(?:dev|build)-dependencies$/.test(h);
        continue;
      }
      if (!inDeps) continue;
      const m = line.match(/^([A-Za-z0-9_-]+)\s*=/);
      if (m) names.add(m[1]);
    }
  }
  return names;
}

// Split advisories into { onchain, toolchain, housekeeping }. Each advisory keeps
// an `onchain` flag so a housekeeping entry on an on-chain crate can still say so.
export function triageAdvisories(advisories, programDeps) {
  const isOnchain = (a) =>
    a.crates.some((c) => {
      const name = c.replace(/\s+[^\s]+$/, "");
      return ONCHAIN_RUNTIME.has(name) || programDeps.has(name);
    });
  const out = { onchain: [], toolchain: [], housekeeping: [] };
  for (const a of advisories) {
    const flagged = { ...a, onchain: isOnchain(a) };
    if (HOUSEKEEPING_RE.test(a.summary)) out.housekeeping.push(flagged);
    else if (flagged.onchain) out.onchain.push(flagged);
    else out.toolchain.push(flagged);
  }
  return out;
}

function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
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

function renderReport(meta, deps, hygiene, source, cta = null) {
  const date = meta.date;
  const md = [];
  md.push(`# Security scan — ${meta.owner}/${meta.repo}`);
  md.push("");
  md.push(`**Repo:** https://github.com/${meta.owner}/${meta.repo} · **Scanned:** ${date} · **Files:** ${source.totalFiles} Rust source files`);
  md.push("");
  md.push("> A hygiene + known-class scan, not an audit. Dependency advisories below are matched against your **exact pinned versions**. Code items are **leads to confirm by reading**, not confirmed vulnerabilities. This scan does not certify the absence of bugs.");
  md.push("");

  const bk = deps.buckets;
  const line = (a) => [
    `- **[${a.severity}]** [${a.id}](${a.url})${a.onchain ? " · _on-chain crate_" : ""} — ${a.summary}`,
    `  affects: ${a.crates.join(", ")}`,
  ];

  md.push("## 1. Dependency advisories (your pinned versions)");
  md.push("");
  if (deps.advisories.length === 0) {
    md.push("No RustSec/OSV advisory affects the exact versions pinned in `Cargo.lock`. ✅");
  } else {
    md.push(`${deps.advisories.length} advisories affect your pinned versions. They are split by whether the affected crate reaches the **deployed program**, because most of a Solana lockfile is CLI, RPC-client and test-validator tooling that never enters the BPF binary.`);
    md.push("");

    md.push(`### 1a. On-chain surface — ${bk.onchain.length}`);
    md.push("");
    md.push("_Advisories on crates the deployed program links against. Read these first._");
    md.push("");
    if (bk.onchain.length === 0) md.push("None. ✅");
    else for (const a of bk.onchain) md.push(...line(a));
    md.push("");

    md.push(`### 1b. Toolchain & off-chain — ${bk.toolchain.length}`);
    md.push("");
    md.push("_CLI, RPC client, test validator, build tooling. Not in the deployed binary — but they run on your machines and in CI._");
    md.push("");
    if (bk.toolchain.length === 0) md.push("None.");
    else for (const a of bk.toolchain) md.push(...line(a));
    md.push("");

    md.push(`### 1c. Unmaintained crates — ${bk.housekeeping.length}`);
    md.push("");
    md.push("_No known exploitable defect. Supply-chain exposure: an unmaintained crate gets no patch when one is eventually needed._");
    md.push("");
    if (bk.housekeeping.length === 0) md.push("None.");
    else for (const a of bk.housekeeping) md.push(...line(a));
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

  const fixAll = fixMailto(cta, meta, `Fix request: ${meta.owner}/${meta.repo}`, [`On-chain advisories: ${deps.buckets.onchain.length}`, `Code leads: ${classes.reduce((s, [, e]) => s + e.total, 0)}`]);
  if (fixAll) md.push("## Want these fixed?", "", `We open a pull request on your repository: dependency upgrades, and for each code lead a written verdict; each confirmed issue comes with a failing test, the fix, and the test passing. You review and merge. [Get a fix quote](${fixAll})`, "");
  md.push("---");
  md.push("");
  md.push("_Generated by [solana-security-watch](https://github.com/OxToF/solana-security-watch). Want continuous coverage instead of a snapshot? A monthly watch diffs new advisories and newly-merged code._");

  const mdText = md.join("\n");
  const html = renderHtml(meta, deps, hygiene, source, classes, cta);
  return { md: mdText, html };
}

export const WATCHDOG_LOGO = `<svg width="46" height="46" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Solana Watchdog"><defs><linearGradient id="wg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#9945FF"/><stop offset="1" stop-color="#14F195"/></linearGradient></defs><circle cx="32" cy="32" r="30" fill="url(#wg)"/><path d="M16 24 L21 7 L27 20 Z" fill="#efe7d6"/><path d="M48 24 L43 7 L37 20 Z" fill="#efe7d6"/><path d="M19.5 21 L21.6 12 L24.4 19 Z" fill="#b98cff"/><path d="M44.5 21 L42.4 12 L39.6 19 Z" fill="#b98cff"/><ellipse cx="32" cy="34" rx="15" ry="14" fill="#f4eddd"/><ellipse cx="32" cy="41" rx="8" ry="6.5" fill="#fffaf0"/><path d="M21.5 29 L28 30.5" stroke="#3a3550" stroke-width="1.6" stroke-linecap="round"/><path d="M42.5 29 L36 30.5" stroke="#3a3550" stroke-width="1.6" stroke-linecap="round"/><circle cx="26" cy="33" r="3" fill="#20202f"/><circle cx="38" cy="33" r="3" fill="#20202f"/><circle cx="27" cy="32.1" r=".9" fill="#fff"/><circle cx="39" cy="32.1" r=".9" fill="#fff"/><ellipse cx="32" cy="38.5" rx="2.7" ry="2" fill="#20202f"/><path d="M32 40.5 Q28 44 25 42" stroke="#20202f" stroke-width="1.4" fill="none" stroke-linecap="round"/><path d="M32 40.5 Q36 44 39 42" stroke="#20202f" stroke-width="1.4" fill="none" stroke-linecap="round"/><circle cx="45" cy="45" r="7.5" fill="rgba(255,255,255,.18)" stroke="#20202f" stroke-width="2.4"/><path d="M50.4 50.4 L57 57" stroke="#20202f" stroke-width="3.4" stroke-linecap="round"/></svg>`;

function sevBg(s) {
  const u = String(s).toUpperCase();
  if (u.startsWith("CRIT")) return "#dc2626";
  if (u.startsWith("HIGH")) return "#ea580c";
  if (u.startsWith("MOD") || u.startsWith("MED")) return "#d97706";
  if (u.startsWith("LOW")) return "#2563eb";
  return "#64748b";
}

function renderHtml(meta, deps, hygiene, source, classes, cta = null) {
  const nAdv = deps.advisories.length;
  const bk = deps.buckets;
  const nLeads = classes.reduce((s, [, e]) => s + e.total, 0);
  // Highest severity is reported for the ON-CHAIN bucket: a HIGH on an openssl
  // pulled in by the CLI says nothing about the deployed program.
  const worst = bk.onchain.reduce((w, a) => {
    const rank = { CRITICAL: 4, HIGH: 3, MODERATE: 3, MEDIUM: 3, LOW: 2 };
    const r = rank[String(a.severity).toUpperCase().split(" ")[0]] || 1;
    return r > w.r ? { r, label: a.severity } : w;
  }, { r: 0, label: "—" });

  const fix = (subject, lines) => fixMailto(cta, meta, subject, lines);
  const card = (a) => `<div class="adv">
        <span class="chip" style="background:${sevBg(a.severity)}">${esc(a.severity)}</span>
        <div class="adv-body"><a class="adv-id" href="${esc(a.url)}">${esc(a.id)}</a>${a.onchain ? `<span class="oc">on-chain crate</span>` : ""}
        <div class="adv-sum">${esc(a.summary)}</div>
        <div class="adv-pkg">Affects: ${esc(a.crates.join(", "))}</div>${(() => { const l = a.onchain && fix(`Fix request: ${meta.owner}/${meta.repo}: ${a.id}`, [`Advisory: ${a.id} (${a.severity})`, `Affects: ${a.crates.join(", ")}`]); return l ? `<a class="fixlink" href="${esc(l)}">Get this fixed &rarr;</a>` : ""; })()}</div></div>`;

  const group = (title, note, list, emptyText) => `<div class="grp">
      <div class="grp-head"><span class="grp-title">${esc(title)}</span><span class="grp-n">${list.length}</span></div>
      <p class="muted">${note}</p>
      ${list.length ? list.map(card).join("") : `<div class="none">${esc(emptyText)}</div>`}
    </div>`;

  const depCards = nAdv
    ? group("On-chain surface",
        "Advisories on crates the deployed program links against. <b>Read these first.</b>",
        bk.onchain, "None — clean on the deployed surface.") +
      group("Toolchain & off-chain",
        "CLI, RPC client, test validator, build tooling. Not in the deployed binary — but they run on your machines and in CI.",
        bk.toolchain, "None.") +
      group("Unmaintained crates",
        "No known exploitable defect. Supply-chain exposure: an unmaintained crate gets no patch when one is eventually needed.",
        bk.housekeeping, "None.")
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
        <ul class="samples">${e.hits.map((h) => `<li><span class="loc">${esc(h.file)}:${h.line}</span><code>${esc(h.text)}</code></li>`).join("")}${e.total > e.hits.length ? `<li class="more">… and ${e.total - e.hits.length} more</li>` : ""}</ul>${(() => { const l = fix(`Triage request: ${meta.owner}/${meta.repo}: class ${cls} ${e.label}`, [`Class: ${cls} ${e.label} (${e.total} leads)`]); return l ? `<a class="fixlink" href="${esc(l)}">Get these triaged and fixed &rarr;</a>` : ""; })()}</div>`).join("")
    : `<div class="clean">No lead patterns matched.</div>`;
  const fixAll = fix(`Fix request: ${meta.owner}/${meta.repo}`, [`On-chain advisories: ${bk.onchain.length}`, `Code leads: ${nLeads}`]);
  const ctaBox = fixAll ? `<div class="cta"><div><b>Want these fixed?</b><div class="muted">We open a pull request on your repository: dependency upgrades, and for each code lead a written verdict. Each confirmed issue comes with a failing test, the fix, and the test passing. You review and merge.</div></div><a class="cta-btn" href="${esc(fixAll)}">Get a fix quote</a></div>` : "";

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
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0 8px}
@media(max-width:640px){.stats{grid-template-columns:repeat(2,1fr)}}
.grp{margin:18px 0 6px}
.grp-head{display:flex;align-items:center;gap:10px;padding-bottom:2px}
.grp-title{font-weight:700;font-size:1.02rem;color:#1c2030}
.grp-n{background:#eceef4;color:#4a5069;border-radius:999px;padding:1px 10px;font-size:.8rem;font-weight:700}
.none{color:#0a7d43;background:#effaf3;border:1px solid #c9eed7;border-radius:10px;padding:9px 13px;font-size:.88rem;font-weight:600}
.oc{margin-left:8px;background:#f3ecff;color:#5b2bc4;border:1px solid #e0d2ff;border-radius:999px;padding:1px 8px;font-size:.72rem;font-weight:700;vertical-align:1px}
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
.cta{display:flex;gap:16px;align-items:center;justify-content:space-between;background:#f6f1ff;border:1px solid #e2d4ff;border-radius:14px;padding:16px 18px;margin:18px 0 6px}
.cta .muted{margin-top:4px}
.cta-btn{flex:none;background:linear-gradient(90deg,#9945FF,#6d4bd6);color:#fff!important;font-weight:700;border-radius:10px;padding:10px 16px;text-decoration:none;white-space:nowrap}
.fixlink{display:inline-block;margin-top:6px;font-size:.82rem;font-weight:700;color:#6d3bd6;text-decoration:none}
@media (max-width:640px){.cta{flex-direction:column;align-items:flex-start}}
@media print{.cta,.fixlink{display:none}}
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
      <div class="stat ${bk.onchain.length ? "alert" : ""}"><div class="num">${bk.onchain.length}</div><div class="lab">On-chain advisories<br>on the deployed surface</div></div>
      <div class="stat"><div class="num">${bk.toolchain.length + bk.housekeeping.length}</div><div class="lab">Toolchain &amp; unmaintained<br>off the deployed binary</div></div>
      <div class="stat"><div class="num">${nLeads}</div><div class="lab">Code leads<br>across ${classes.length} classes</div></div>
      <div class="stat"><div class="num">${worst.label === "—" ? "—" : esc(String(worst.label).split(" ")[0])}</div><div class="lab">Highest severity<br>on-chain</div></div>
    </div>

    ${ctaBox}
    <h2>Dependency advisories</h2>
    <p class="muted">${nAdv} advisories match the exact crate versions pinned in your lockfile, split by whether the affected crate reaches the deployed program. Most of a Solana lockfile is CLI, RPC-client and test-validator tooling that never enters the BPF binary.</p>
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

  const lockFiles = findFiles(dir, (n) => n === "Cargo.lock");
  let crates = [];
  for (const lf of lockFiles) crates = crates.concat(parseCargoLock(readFileSync(lf, "utf8")));
  if (crates.length === 0) log("[scan] no Cargo.lock found — dependency section will be empty");

  const deps = crates.length
    ? await scanDependencies(crates, fetchImpl, log)
    : { advisories: [], failures: 0 };
  const programDeps = findProgramDeps(dir);
  deps.buckets = triageAdvisories(deps.advisories, programDeps);
  const hygiene = checkHygiene(dir);
  const source = scanSource(dir);

  const date = now.toISOString().slice(0, 10);
  const meta = { owner, repo, date };
  const { md, html } = renderReport(meta, deps, hygiene, source, cta);

  mkdirSync(out, { recursive: true });
  const base = `${owner}-${repo}-${date}`.replace(/[^A-Za-z0-9_.-]/g, "_");
  const mdPath = join(out, `${base}.md`);
  const htmlPath = join(out, `${base}.html`);
  writeFileSync(mdPath, md);
  writeFileSync(htmlPath, html);

  log(`[scan] ${deps.buckets.onchain.length} on-chain advisories (of ${deps.advisories.length} total: ${deps.buckets.toolchain.length} toolchain, ${deps.buckets.housekeeping.length} unmaintained) · ${[...source.byClass.values()].reduce((s, e) => s + e.total, 0)} code leads · ${source.totalFiles} files`);
  log(`[scan] report -> ${mdPath}`);
  log(`[scan] report -> ${htmlPath}`);
  return { meta, deps, hygiene, source, mdPath, htmlPath, cleanup };
}
