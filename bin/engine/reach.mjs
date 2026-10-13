// Which crates actually end up in the deployed program?
//
// A Solana Cargo.lock lists everything the workspace ever builds: the CLI, the RPC
// client, the test validator, proc-macros. Most of it never reaches the BPF binary.
// solana-program itself only pulls curve25519-dalek, rand or ed25519-dalek under
// cfg(not(target_os = "solana")). So "this crate is in the lockfile" says nothing
// about the deployed program, and a report that says otherwise is wrong.
//
// This walks the real graph from each program crate (crate-type cdylib): an edge
// is followed only when the lockfile resolved it AND the dependent's manifest
// declares it as a normal dependency whose target cfg holds for Solana (read from
// the local Cargo.toml for workspace crates, from the crates.io index for the
// rest). Features are not resolved: an optional dependency the lockfile resolved
// for another crate of the workspace is kept, so the set errs on the side of
// including a crate, never of hiding one.

import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";

const CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index";
const INDEX_URL = process.env.CRATES_INDEX_URL || "https://index.crates.io";

// --- Cargo.lock, with its resolved edges -------------------------------------------
export function parseLockGraph(text) {
  const pkgs = [];
  for (const block of text.split(/^\[\[package\]\]/m).slice(1)) {
    const f = (k) => block.match(new RegExp(`^${k}\\s*=\\s*"([^"]+)"`, "m"))?.[1];
    const deps = [];
    const d = block.match(/^dependencies\s*=\s*\[([\s\S]*?)\]/m);
    if (d) for (const m of d[1].matchAll(/"([^"]+)"/g)) deps.push(m[1]);
    pkgs.push({ name: f("name"), version: f("version"), source: f("source") || null, deps });
  }
  return pkgs.filter((p) => p.name && p.version);
}

// "name", "name version" or "name version (source)" -> the package it names.
function resolveDep(spec, byName) {
  const [name, version] = spec.split(" ");
  const cands = byName.get(name) || [];
  if (!version) return cands[0] || null;
  return cands.find((p) => p.version === version) || null;
}

// --- cfg(...) evaluated for the Solana BPF/SBF target -------------------------------
const SOLANA_CFG = {
  target_os: ["solana"], target_arch: ["sbf", "bpf"], target_vendor: ["solana"],
  target_pointer_width: ["64"], target_endian: ["little"], target_family: [], target_env: [""],
};
export function targetMatchesSolana(target) {
  if (!target) return true;
  const t = target.trim();
  if (!t.startsWith("cfg(")) return /solana|sbf|bpf/.test(t); // a plain target triple
  let i = 0;
  const src = t;
  const ws = () => { while (/\s/.test(src[i])) i++; };
  const ident = () => { ws(); const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i)); if (!m) throw new Error("cfg"); i += m[0].length; return m[0]; };
  const str = () => { ws(); if (src[i] !== '"') throw new Error("cfg"); const j = src.indexOf('"', i + 1); const s = src.slice(i + 1, j); i = j + 1; return s; };
  const list = () => { const out = []; ws(); if (src[i] === ")") { i++; return out; } for (;;) { out.push(expr()); ws(); if (src[i] === ",") { i++; ws(); if (src[i] === ")") { i++; return out; } continue; } if (src[i] === ")") { i++; return out; } throw new Error("cfg"); } };
  const expr = () => {
    const id = ident(); ws();
    if (src[i] === "(") {
      i++;
      const args = list();
      if (id === "all") return args.every(Boolean);
      if (id === "any") return args.some(Boolean);
      if (id === "not") return !args[0];
      return false;
    }
    if (src[i] === "=") { i++; const v = str(); if (id === "feature") return true; return (SOLANA_CFG[id] || []).includes(v); }
    // Bare predicates: unix, windows, test, debug_assertions... none hold on Solana.
    return false;
  };
  try { i = 4; const r = expr(); return r; } catch { return true; } // unparseable: keep the edge
}

// --- a workspace crate's own Cargo.toml (enough TOML for dependency tables) ---------
export function parseManifest(text) {
  const out = { name: null, cdylib: false, deps: [] };
  let section = null, sub = null;
  const lines = text.split("\n");
  for (let n = 0; n < lines.length; n++) {
    let line = lines[n].replace(/#.*$/, "").trim();
    if (!line) continue;
    const h = /^\[([^\]]+)\]$/.exec(line);
    if (h) {
      sub = null;
      const head = h[1].trim();
      // [target.'cfg(...)'.dependencies(.name)?] / [dependencies(.name)?] / [dev-dependencies]
      const m = /^(?:target\.(?:'([^']+)'|"([^"]+)"|([^.\s]+))\.)?((?:dev-|build-)?dependencies)(?:\.(.+))?$/.exec(head);
      if (m) {
        section = { target: m[1] || m[2] || m[3] || null, kind: m[4] === "dependencies" ? "normal" : m[4].replace("-dependencies", "") };
        if (m[5]) { sub = { name: m[5].replace(/["']/g, ""), pkg: null }; out.deps.push({ ...section, dep: sub }); }
      } else section = { other: head };
      continue;
    }
    if (!section) continue;
    if (section.other === "package") { const nm = /^name\s*=\s*"([^"]+)"/.exec(line); if (nm) out.name = nm[1]; continue; }
    if (section.other === "lib") { if (/crate-type\s*=.*cdylib/.test(line)) out.cdylib = true; continue; }
    if (section.other) continue;
    if (sub) { const p = /^package\s*=\s*"([^"]+)"/.exec(line); if (p) sub.pkg = p[1]; continue; }
    const kv = /^([A-Za-z0-9_.-]+|"[^"]+")\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    let val = kv[2];
    // An inline table may span lines.
    while ((val.match(/\{/g) || []).length > (val.match(/\}/g) || []).length && n + 1 < lines.length) val += " " + lines[++n].trim();
    const pkg = /package\s*=\s*"([^"]+)"/.exec(val)?.[1];
    out.deps.push({ ...section, dep: { name: kv[1].replace(/"/g, ""), pkg: pkg || null } });
  }
  out.deps = out.deps.map((d) => ({ crate: d.dep.pkg || d.dep.name, kind: d.kind, target: d.target }));
  return out;
}

function findManifests(dir, skip = new Set(["target", "node_modules", ".git", "test-ledger"])) {
  const out = [];
  const walk = (d) => {
    let es; try { es = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of es) {
      if (e.isDirectory()) { if (!skip.has(e.name)) walk(join(d, e.name)); }
      else if (e.name === "Cargo.toml") out.push(join(d, e.name));
    }
  };
  walk(dir);
  return out;
}

// --- crates.io sparse index -----------------------------------------------------------
function indexPath(name) {
  const n = name.toLowerCase();
  if (n.length <= 2) return `${n.length}/${n}`;
  if (n.length === 3) return `3/${n[0]}/${n}`;
  return `${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
}
const indexCache = new Map();
async function indexDeps(name, version, fetchImpl) {
  const key = name.toLowerCase();
  if (!indexCache.has(key)) {
    indexCache.set(key, (async () => {
      try {
        const r = await fetchImpl(`${INDEX_URL}/${indexPath(name)}`);
        if (!r.ok) return null;
        return (await r.text()).split("\n").filter(Boolean).map((l) => JSON.parse(l));
      } catch { return null; }
    })());
  }
  const entries = await indexCache.get(key);
  const v = entries && entries.find((e) => e.vers === version);
  if (!v) return null;
  return v.deps.map((d) => ({ crate: d.package || d.name, kind: d.kind || "normal", target: d.target || null }));
}

// Proc-macros run inside the compiler and never reach the binary, nor do their deps.
// The index does not say which crates are proc-macros, so known shapes are skipped.
const PROC_MACRO = /^(syn|quote|proc-macro2|proc-macro-crate|proc-macro-error.*|darling.*|heck)$|[-_](derive|derive_internals|macros?|attribute-.+|attr|codegen|syn|impl)$/;
export const isProcMacro = (name) => PROC_MACRO.test(name);

// Returns { programs: [names], crates: Set("name version"), approximate: [names] } or
// null when there is no lockfile or no program crate to start from.
export async function onchainClosure(dir, { fetchImpl = globalThis.fetch, log = () => {} } = {}) {
  const manifests = findManifests(dir).map((f) => {
    try { return { file: f, ...parseManifest(readFileSync(f, "utf8")) }; } catch { return null; }
  }).filter(Boolean);
  const local = new Map(manifests.filter((m) => m.name).map((m) => [m.name, m]));
  const programs = manifests.filter((m) => m.cdylib && m.name);
  const lockFile = findManifests(dir).map((f) => join(dirname(f), "Cargo.lock")).find((f) => { try { readFileSync(f); return true; } catch { return false; } });
  if (!programs.length || !lockFile) return null;
  const pkgs = parseLockGraph(readFileSync(lockFile, "utf8"));
  const byName = new Map();
  for (const p of pkgs) { if (!byName.has(p.name)) byName.set(p.name, []); byName.get(p.name).push(p); }

  const seen = new Set();
  const approximate = new Set();
  const queue = programs.map((m) => (byName.get(m.name) || []).find((p) => !p.source)).filter(Boolean);
  for (const p of queue) seen.add(`${p.name} ${p.version}`);
  while (queue.length) {
    // Breadth-first, one wave of index lookups at a time.
    const wave = queue.splice(0, queue.length);
    const allowedLists = await Promise.all(wave.map(async (p) => {
      let declared = null;
      if (!p.source && local.has(p.name)) declared = local.get(p.name).deps;
      else if (p.source === CRATES_IO) declared = await indexDeps(p.name, p.version, fetchImpl);
      if (!declared) { approximate.add(p.name); return null; }
      return new Set(declared.filter((d) => d.kind === "normal" && targetMatchesSolana(d.target)).map((d) => d.crate));
    }));
    wave.forEach((p, k) => {
      const allowed = allowedLists[k];
      for (const spec of p.deps) {
        const q = resolveDep(spec, byName);
        if (!q || (allowed && !allowed.has(q.name)) || isProcMacro(q.name)) continue;
        const id = `${q.name} ${q.version}`;
        if (!seen.has(id)) { seen.add(id); queue.push(q); }
      }
    });
  }
  log(`[scan] on-chain closure: ${seen.size} crates reach ${programs.map((m) => m.name).join(", ")}${approximate.size ? ` (${approximate.size} read from the lockfile alone)` : ""}`);
  return { programs: programs.map((m) => ({ name: m.name, dir: dirname(m.file) })), crates: seen, approximate: [...approximate] };
}
