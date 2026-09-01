// `collect` — pull current RustSec/OSV advisories for the Solana + Anchor program
// dependency surface, diff against the last run, and write a dated report. This is
// the "watch" half of solana-security-watch: run it on a schedule (cron / CI) and
// each run surfaces only what is NEW since last time. Zero runtime dependencies —
// uses Node's built-in fetch (Node >= 18).

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

// The crates a Solana/Anchor program actually pulls into its trust boundary. A
// RustSec advisory on any of these is worth a program author's attention. Extend
// via `--crates a,b,c` on the CLI.
export const DEFAULT_CRATES = [
  "anchor-lang", "anchor-spl", "anchor-attribute-account",
  "solana-program", "solana-sdk", "solana-zk-token-sdk", "solana-security-txt",
  "spl-token", "spl-token-2022", "spl-associated-token-account", "spl-math",
  "borsh", "bytemuck", "arrayref",
  "curve25519-dalek", "ed25519-dalek", "ed25519-dalek-bip32",
  "ring", "aes-gcm", "chacha20poly1305", "zeroize",
];

const OSV_QUERY = "https://api.osv.dev/v1/query";

// Query OSV for a crate. Pass `version` to get only advisories that affect that
// exact pinned version (used by the per-repo scanner); omit it for all advisories
// on the crate (used by the ecosystem watch).
export async function queryCrate(name, fetchImpl, version) {
  const query = { package: { ecosystem: "crates.io", name } };
  if (version) query.version = version;
  const res = await fetchImpl(OSV_QUERY, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(query),
  });
  if (!res.ok) throw new Error(`OSV ${res.status} for ${name}`);
  const body = await res.json();
  return body.vulns || [];
}

// Prefer a RUSTSEC id as the canonical key, then CVE, then GHSA, else the raw id.
function canonicalId(ids) {
  return (
    ids.find((i) => i.startsWith("RUSTSEC-")) ||
    ids.find((i) => i.startsWith("CVE-")) ||
    ids.find((i) => i.startsWith("GHSA-")) ||
    ids[0]
  );
}

function severityOf(v) {
  if (v.database_specific && v.database_specific.severity) {
    return String(v.database_specific.severity).toUpperCase();
  }
  if (Array.isArray(v.severity) && v.severity.length) {
    const cvss = v.severity.find((s) => /CVSS/.test(s.type));
    if (cvss) return cvss.score; // CVSS vector string
  }
  return "UNSPECIFIED";
}

const SEV_RANK = { CRITICAL: 0, HIGH: 1, MODERATE: 2, MEDIUM: 2, LOW: 3, UNSPECIFIED: 4 };
function sevRank(label) {
  const up = String(label).toUpperCase();
  for (const k of Object.keys(SEV_RANK)) if (up.startsWith(k)) return SEV_RANK[k];
  return 5; // CVSS vectors sort after named severities
}

// Collapse OSV's per-crate, GHSA+RUSTSEC-duplicated results into one advisory per
// real issue, keyed by canonical id, carrying the union of affected crates/aliases.
export function normalize(rawByCrate) {
  const byAlias = new Map(); // any id/alias -> advisory object
  for (const [crate, vulns] of rawByCrate) {
    for (const v of vulns) {
      if (v.withdrawn) continue;
      const ids = [v.id, ...(v.aliases || [])];
      let adv = null;
      for (const id of ids) if (byAlias.has(id)) { adv = byAlias.get(id); break; }
      if (!adv) {
        adv = {
          ids: new Set(),
          crates: new Set(),
          summary: v.summary || v.details || "(no summary)",
          severity: severityOf(v),
          published: v.published || null,
          modified: v.modified || null,
        };
      }
      ids.forEach((id) => adv.ids.add(id));
      adv.crates.add(crate);
      // Prefer a named severity over a bare CVSS vector; keep earliest publish.
      if (sevRank(severityOf(v)) < sevRank(adv.severity)) adv.severity = severityOf(v);
      if (v.published && (!adv.published || v.published < adv.published)) adv.published = v.published;
      ids.forEach((id) => byAlias.set(id, adv));
    }
  }
  const advisories = [];
  const seen = new Set();
  for (const adv of byAlias.values()) {
    const cid = canonicalId([...adv.ids]);
    if (seen.has(cid)) continue;
    seen.add(cid);
    advisories.push({
      id: cid,
      aliases: [...adv.ids].filter((i) => i !== cid).sort(),
      crates: [...adv.crates].sort(),
      severity: adv.severity,
      summary: adv.summary.replace(/\s+/g, " ").trim(),
      published: adv.published,
      url: cid.startsWith("RUSTSEC-")
        ? `https://rustsec.org/advisories/${cid}.html`
        : `https://osv.dev/vulnerability/${cid}`,
    });
  }
  advisories.sort(
    (a, b) => sevRank(a.severity) - sevRank(b.severity) || a.id.localeCompare(b.id)
  );
  return advisories;
}

function loadState(stateFile) {
  if (!existsSync(stateFile)) return { seenIds: [], runs: [] };
  try {
    return JSON.parse(readFileSync(stateFile, "utf8"));
  } catch {
    return { seenIds: [], runs: [] };
  }
}

function renderMarkdown(date, advisories, freshIds) {
  const fresh = new Set(freshIds);
  const lines = [];
  lines.push(`# Solana security watch — ${date}`);
  lines.push("");
  lines.push(
    `Advisories across the tracked Solana/Anchor dependency surface: ` +
      `**${advisories.length}** total, **${freshIds.length}** new since last run.`
  );
  lines.push("");
  lines.push("Source: OSV.dev (RustSec advisory-db). Generated by `solana-security-watch collect`.");
  lines.push("");
  if (freshIds.length) {
    lines.push("## 🆕 New since last run");
    lines.push("");
    for (const a of advisories.filter((a) => fresh.has(a.id))) lines.push(renderRow(a));
    lines.push("");
  }
  lines.push("## All current advisories");
  lines.push("");
  for (const a of advisories) lines.push(renderRow(a, fresh.has(a.id)));
  lines.push("");
  return lines.join("\n");
}

function renderRow(a, isNew = false) {
  const tag = isNew ? " 🆕" : "";
  const pub = a.published ? a.published.slice(0, 10) : "—";
  const aliases = a.aliases.length ? ` (${a.aliases.join(", ")})` : "";
  return (
    `- **[${a.severity}]** [${a.id}](${a.url})${tag} — ${a.summary}\n` +
    `  crates: ${a.crates.join(", ")} · published ${pub}${aliases}`
  );
}

export async function runCollect(opts = {}) {
  const {
    out = "watch-reports",
    crates = DEFAULT_CRATES,
    fetchImpl = globalThis.fetch,
    now = new Date(),
    log = console.log,
  } = opts;

  if (typeof fetchImpl !== "function") {
    throw new Error("global fetch unavailable — needs Node >= 18");
  }

  const rawByCrate = [];
  const failures = [];
  for (const crate of crates) {
    try {
      rawByCrate.push([crate, await queryCrate(crate, fetchImpl)]);
    } catch (e) {
      failures.push(`${crate}: ${e.message}`);
    }
  }

  // If every single query failed, this is a network/outage condition — do not
  // overwrite state with an empty result; surface the error instead.
  if (rawByCrate.length === 0) {
    throw new Error(
      `all ${crates.length} advisory queries failed (offline?):\n  ` +
        failures.join("\n  ")
    );
  }

  const advisories = normalize(rawByCrate);
  const date = now.toISOString().slice(0, 10);

  const stateFile = join(out, "state.json");
  const state = loadState(stateFile);
  const seen = new Set(state.seenIds);
  const freshIds = advisories
    .filter((a) => !seen.has(a.id) && !a.aliases.some((x) => seen.has(x)))
    .map((a) => a.id);

  mkdirSync(join(out, "reports"), { recursive: true });
  const md = renderMarkdown(date, advisories, freshIds);
  const reportMd = join(out, "reports", `${date}.md`);
  const reportJson = join(out, "reports", `${date}.json`);
  writeFileSync(reportMd, md);
  writeFileSync(
    reportJson,
    JSON.stringify({ date, total: advisories.length, new: freshIds, advisories }, null, 2) + "\n"
  );

  // Persist the union of everything ever seen (ids + aliases) so a later republish
  // of the same advisory under a different alias is not re-flagged as new.
  const allIds = new Set(state.seenIds);
  for (const a of advisories) { allIds.add(a.id); a.aliases.forEach((x) => allIds.add(x)); }
  const newState = {
    seenIds: [...allIds].sort(),
    runs: [...(state.runs || []), { date, total: advisories.length, new: freshIds.length }].slice(-50),
  };
  writeFileSync(stateFile, JSON.stringify(newState, null, 2) + "\n");

  log(`[collect] ${advisories.length} advisories, ${freshIds.length} new -> ${reportMd}`);
  if (failures.length) log(`[collect] ${failures.length} crate quer${failures.length === 1 ? "y" : "ies"} failed: ${failures.map((f) => f.split(":")[0]).join(", ")}`);
  return { advisories, freshIds, reportMd, reportJson, failures };
}
