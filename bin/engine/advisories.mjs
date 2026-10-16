// Dependency advisories, judged for a Solana program.
//
// "Your lockfile pins a crate with an advisory" is where generic scanners stop. Two
// more questions decide whether anyone should care: does the crate reach the
// deployed binary (reach.mjs answers that from the real graph), and is the defect
// reachable in an on-chain program at all. A timing side channel on secret keys is
// a real bug in a wallet and a non-issue in a program that holds no secret. The
// notes below are written per advisory, only for advisories we have read; any
// other advisory is reported as it is, without a verdict we cannot back.

import { maskRust } from "./anchor.mjs";

const HOUSEKEEPING = /\bunmaintained\b|no longer maintained|is deprecated/i;

// verdict: "not-exploitable" (cannot be triggered on-chain), "not-called" (the defective
// function is never called by the program's code), "conditional" (only if the program
// does X: `check` decides from the code when it can), "exploitable".
const KB = {
  "RUSTSEC-2022-0093": {
    verdict: "not-exploitable",
    note: "The flaw leaks a private key when code signs through ed25519-dalek's API with a mismatched public key. A program never holds a private key and never signs with ed25519; on-chain signature checks go through the Ed25519 precompile.",
  },
  "RUSTSEC-2024-0344": {
    verdict: "not-exploitable",
    note: "A timing side channel on secret scalars. A program handles no secret, and its execution time is not observable by an attacker.",
  },
  "RUSTSEC-2023-0033": {
    verdict: "conditional",
    note: "borsh is unsound when it deserializes a zero-sized type that is not Copy (an empty struct, or an array of length 0), for example many of them in a Vec.",
    check: (files) => borshZst(files),
  },
  "RUSTSEC-2024-0402": {
    verdict: "conditional",
    note: "hashbrown's Borsh encoding of a HashMap depends on iteration order, so two equal maps can serialize differently. It matters only if the program Borsh-serializes a HashMap and relies on the bytes (hashing, comparing, size).",
    check: (files) => {
      const hits = locate(files, /\b(?:HashMap|HashSet)\b/g);
      return hits.length
        ? { verdict: "conditional", note: "The program uses HashMap or HashSet: check that none of them is Borsh-serialized and compared, hashed or sized by its bytes.", evidence: hits }
        : { verdict: "not-exploitable", note: "The program never uses HashMap or HashSet." };
    },
  },
};

// --- evidence from the program's own source ------------------------------------------

// Comments and string literals blanked, positions kept, so a match maps to a real line.
function masked(f) {
  if (f.masked === undefined) f.masked = maskRust(f.raw).replace(/#\[cfg\(test\)\][\s\S]*$/, "");
  return f.masked;
}
const lineOf = (text, idx) => text.slice(0, idx).split("\n").length;
function locate(files, re, limit = 5) {
  const out = [];
  for (const f of files) for (const m of masked(f).matchAll(re)) {
    out.push({ file: f.rel, line: lineOf(masked(f), m.index) });
    if (out.length >= limit) return out;
  }
  return out;
}
function bodyAt(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}" && --depth === 0) return text.slice(open + 1, i);
  }
  return "";
}

// RUSTSEC-2023-0033, decided from the code: which zero-sized types are not Copy, and does
// any type the program deserializes (Borsh/Anchor derive, #[account], #[event], an
// instruction argument) hold one.
export function borshZst(files) {
  const zst = new Map();
  const copyImpl = new Set();
  for (const f of files) {
    const t = masked(f);
    for (const m of t.matchAll(/impl(?:<[^>]*>)?\s+(?:Copy|Clone)\s+for\s+(\w+)/g)) copyImpl.add(m[1]);
    for (const m of t.matchAll(/((?:#\[[^\]]*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w+)\s*(?:;|\{\s*\}|\(\s*\)\s*;)/g)) {
      if (!/\b(?:Copy|Clone)\b/.test(m[1])) zst.set(m[2], { file: f.rel, line: lineOf(t, m.index + m[1].length) });
    }
  }
  for (const n of copyImpl) zst.delete(n);
  const zstType = (ty) => /\[\s*[^;\]]+;\s*0\s*\]/.test(ty) || [...zst.keys()].some((n) => new RegExp(`\\b${n}\\b`).test(ty));
  let types = 0;
  const hits = [];
  for (const f of files) {
    const t = masked(f);
    for (const m of t.matchAll(/((?:#\[[^\]]*\]\s*)+)(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum)\s+(\w+)[^{;]*\{/g)) {
      if (!/(Borsh|Anchor)Deserialize|\bDeserialize\b|#\[account\b|#\[event\]/.test(m[1])) continue;
      types++;
      const open = m.index + m[0].length - 1;
      const body = bodyAt(t, open);
      for (const fm of body.matchAll(/(\w+)\s*:\s*([^,\n]+)/g)) if (zstType(fm[2])) hits.push({ file: f.rel, line: lineOf(t, open + 1 + fm.index), what: `${m[2]}.${fm[1]}: ${fm[2].trim()}` });
      for (const tm of body.matchAll(/\(([^)]*)\)/g)) if (zstType(tm[1])) hits.push({ file: f.rel, line: lineOf(t, open + 1 + tm.index), what: `${m[2]}(${tm[1].trim()})` });
    }
    // Instruction arguments are deserialized by Anchor too.
    for (const m of t.matchAll(/fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(\s*\w+\s*:\s*Context\s*<[^)]*?>\s*,([^)]*)\)/g)) {
      for (const am of m[2].matchAll(/(\w+)\s*:\s*([^,]+)/g)) if (zstType(am[2])) hits.push({ file: f.rel, line: lineOf(t, m.index), what: `${m[1]}(${am[1]}: ${am[2].trim()})` });
    }
  }
  return hits.length
    ? { verdict: "conditional", note: `The program deserializes a zero-sized type that is not Copy: ${hits.slice(0, 3).map((h) => `\`${h.what}\``).join(", ")}. Derive Copy and Clone on it, or upgrade borsh to 0.10.4 / 1.x when it is the program's own copy.`, evidence: hits.slice(0, 5) }
    : { verdict: "not-exploitable", note: `None of the ${types} types the program deserializes (Borsh or Anchor derives, accounts, events, instruction arguments) holds a zero-sized field that is not Copy.` };
}

// RustSec names the functions that carry the defect. Is one of them called by the program's
// own code? A name alone is weak evidence for a generic method, so the crate must also be
// named in the program unless the function name is distinctive.
const GENERIC = /^(new|from|into|len|get|set|read|write|parse|fmt|clone|default|try_from|try_into|deserialize|serialize|decode|encode|to_vec|as_ref|map|next)$/;
export function callsOf(files, fn) {
  const parts = fn.split("::");
  const name = parts[parts.length - 1];
  const crate = parts[0].replace(/-/g, "_");
  if (GENERIC.test(name) && !files.some((f) => new RegExp(`\\b${crate}\\b`).test(masked(f)))) return [];
  return locate(files, new RegExp(`(?:\\.|::|\\b)${name}\\s*(?:::<[^>]*>)?\\s*\\(`, "g"));
}

function fromCode(a, files) {
  if (a.arch && a.arch.length && !a.arch.some((x) => /bpf|sbf/i.test(x)))
    return { verdict: "not-exploitable", note: `The defective code exists only on ${a.arch.join(", ")}. A program is compiled for SBF, where it is not built.` };
  if (a.os && a.os.length)
    return { verdict: "not-exploitable", note: `The defect exists only on ${a.os.join(", ")}. An on-chain program runs on no operating system.` };
  if (a.functions && a.functions.length && files.length) {
    const evidence = a.functions.flatMap((fn) => callsOf(files, fn).map((e) => ({ ...e, what: fn })));
    return evidence.length
      ? { verdict: "conditional", note: `The defect is in \`${[...new Set(evidence.map((e) => e.what))].join("`, `")}\`, which the program calls. Check whether the input that triggers the advisory can reach that call.`, evidence: evidence.slice(0, 5) }
      : { verdict: "not-called", note: `The defect is in \`${a.functions.join("`, `")}\`, which the program's own code never calls. Another crate compiled into the program could still call it.` };
  }
  return null;
}

// Thread-safety defects (data races, unsound Send/Sync) need two threads. A program runs
// on one: the SBF runtime has no threads, so none of them can be triggered on-chain.
const THREADING = /data race|race condition|\bSend\b|\bSync\b|thread[- ]safe|thread[- ]safety|across threads/i;
const THREADING_NOTE = "A thread-safety defect needs two threads sharing memory. A Solana program runs on a single thread (the SBF runtime has none), so it cannot be triggered on-chain.";

export function severityLabel(s) {
  const k = String(s || "").toUpperCase();
  if (k.startsWith("CVSS:")) {
    // Base-score shortcut from the impact metrics, enough to rank: H on any of C/I/A.
    const high = (k.match(/\/[CIA]:H/g) || []).length;
    const network = /AV:N/.test(k) && /PR:N/.test(k);
    return high >= 2 && network ? "HIGH" : high >= 1 ? (network ? "HIGH" : "MEDIUM") : "LOW";
  }
  const w = k.split(" ")[0];
  return ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"].includes(w) ? (w === "MODERATE" ? "MEDIUM" : w) : "UNRATED";
}

// `closure` from reach.mjs (null when the repo has no program crate or no lockfile).
// `programSource`: the program's own Rust source, for the conditional notes.
// Does this on-chain advisory call for action? Not when ruled out on-chain, and not
// when it carries no rating and no verdict either: listed, not escalated.
export const needsAttention = (a) => a.verdict === "exploitable" || a.verdict === "conditional" || (!a.verdict && ["CRITICAL", "HIGH", "MEDIUM"].includes(a.severity));

// `programFiles`: [{ rel, raw }] of the program's own source (a plain string is accepted).
const QUIET = ["not-exploitable", "not-called"];
export function judgeAdvisories(advisories, closure, programFiles = []) {
  const files = typeof programFiles === "string" ? [{ rel: "program", raw: programFiles }] : programFiles;
  const out = { onchain: [], offchain: [], housekeeping: [], reachKnown: !!closure };
  for (const a of advisories) {
    const reaching = closure ? a.crates.filter((c) => closure.crates.has(c)) : [];
    const entry = { ...a, severity: severityLabel(a.severity), onchain: reaching.length > 0, reachingCrates: reaching };
    const kb = KB[a.id] || (a.aliases || []).map((id) => KB[id]).find(Boolean);
    if (kb && entry.onchain) {
      const r = kb.check && files.length ? kb.check(files) : null;
      entry.verdict = r ? r.verdict : kb.verdict;
      entry.note = r ? `${kb.note} ${r.note}` : kb.note;
      if (r && r.evidence) entry.evidence = r.evidence;
    } else if (entry.onchain) {
      const r = fromCode(a, files);
      if (r) Object.assign(entry, r);
      else if (THREADING.test(a.summary)) { entry.verdict = "not-exploitable"; entry.note = THREADING_NOTE; }
    }
    if (HOUSEKEEPING.test(a.summary)) out.housekeeping.push(entry);
    else if (entry.onchain) out.onchain.push(entry);
    else out.offchain.push(entry);
  }
  const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNRATED: 4 };
  for (const k of ["onchain", "offchain", "housekeeping"]) out[k].sort((x, y) => QUIET.includes(x.verdict) - QUIET.includes(y.verdict) || rank[x.severity] - rank[y.severity]);
  return out;
}
