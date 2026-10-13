// Dependency advisories, judged for a Solana program.
//
// "Your lockfile pins a crate with an advisory" is where generic scanners stop. Two
// more questions decide whether anyone should care: does the crate reach the
// deployed binary (reach.mjs answers that from the real graph), and is the defect
// reachable in an on-chain program at all. A timing side channel on secret keys is
// a real bug in a wallet and a non-issue in a program that holds no secret. The
// notes below are written per advisory, only for advisories we have read; any
// other advisory is reported as it is, without a verdict we cannot back.

const HOUSEKEEPING = /\bunmaintained\b|no longer maintained|is deprecated/i;

// verdict: "not-exploitable" (cannot be triggered on-chain), "conditional" (only if
// the program does X: `check` decides when it can), "exploitable".
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
    note: "Unsound only when deserializing a type that contains a zero-sized field that is not Copy. Program state and instruction data almost never do.",
    check: (src) => (/:\s*(?:\(\s*\)|(?:(?:std|core)::marker::)?PhantomData\b)/.test(src) ? null : "No zero-sized field (`()` or `PhantomData`) in the program's types."),
  },
  "RUSTSEC-2024-0402": {
    verdict: "conditional",
    note: "hashbrown's Borsh encoding of a HashMap depends on iteration order, so two equal maps can serialize differently. It matters only if the program Borsh-serializes a HashMap and relies on the bytes (hashing, comparing, size).",
    check: (src) => (/\bHashMap\b|\bHashSet\b/.test(src) ? null : "The program never uses HashMap or HashSet."),
  },
};

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

export function judgeAdvisories(advisories, closure, programSource = "") {
  const out = { onchain: [], offchain: [], housekeeping: [], reachKnown: !!closure };
  for (const a of advisories) {
    const reaching = closure ? a.crates.filter((c) => closure.crates.has(c)) : [];
    const entry = { ...a, severity: severityLabel(a.severity), onchain: reaching.length > 0, reachingCrates: reaching };
    const kb = KB[a.id] || (a.aliases || []).map((id) => KB[id]).find(Boolean);
    if (kb && entry.onchain) {
      const cleared = kb.check ? kb.check(programSource) : null;
      entry.verdict = cleared ? "not-exploitable" : kb.verdict;
      entry.note = cleared ? `${kb.note} ${cleared}` : kb.note;
    }
    if (HOUSEKEEPING.test(a.summary)) out.housekeeping.push(entry);
    else if (entry.onchain) out.onchain.push(entry);
    else out.offchain.push(entry);
  }
  const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNRATED: 4 };
  for (const k of ["onchain", "offchain", "housekeeping"]) out[k].sort((x, y) => (x.verdict === "not-exploitable") - (y.verdict === "not-exploitable") || rank[x.severity] - rank[y.severity]);
  return out;
}
