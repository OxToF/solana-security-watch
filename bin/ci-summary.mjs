#!/usr/bin/env node
// The pull request summary of the GitHub Action: one Markdown block, written to the job
// summary and, on pull requests, kept as a single comment that is edited on every push.
//   node ci-summary.mjs <report.json> <fail-on> <exit-code-of-scan> <scanned-dir> [repo-url] [sha]
import { readFileSync } from "node:fs";
import { gateFailures } from "./engine/report.mjs";
import { needsAttention } from "./engine/advisories.mjs";

const [file, failOn = "high", code = "0", root = ".", repoUrl = "", sha = ""] = process.argv.slice(2);
const inRepo = (p) => (root && root !== "." ? `${root.replace(/^\.\/|\/+$/g, "")}/${p}` : p);
const MARK = "<!-- solana-watchdog -->";

if (code !== "0" && code !== "3") {
  console.log(`${MARK}\n### 🐕 Solana Watchdog\n\nThe scan did not complete (exit code ${code}). See the job log.`);
  process.exit(0);
}

const m = JSON.parse(readFileSync(file, "utf8"));
const RISK = { critical: "🔴 Critical", high: "🟠 High", medium: "🟡 Medium", low: "🔵 Low", clean: "🟢 No issue found" };
const link = (f) => (repoUrl && sha ? `[\`${inRepo(f.file)}:${f.line}\`](${repoUrl}/blob/${sha}/${inRepo(f.file)}#L${f.line})` : `\`${f.file}:${f.line}\``);
const plain = (s) => String(s || "").replace(/\|/g, "\\|");
const failures = gateFailures(m, failOn);
const attention = m.deps.onchain.filter(needsAttention);

const L = [MARK, "### 🐕 Solana Watchdog", ""];
L.push(`**Risk: ${RISK[m.risk] || m.risk}** · ${m.confident.length} to fix · ${m.review.length} to verify · ${attention.length} dependency advisor${attention.length === 1 ? "y" : "ies"} reaching the program`, "");
L.push(failOn === "none" ? "Merge gate: off." : failures.length
  ? `❌ **Merge gate failed**: ${failures.length} finding${failures.length > 1 ? "s" : ""} at or above \`${failOn}\`.`
  : `✅ Merge gate passed: nothing at or above \`${failOn}\`.`, "");
if (m.confident.length) {
  L.push("| | Severity | Issue | Where |", "|---|---|---|---|");
  for (const f of m.confident.slice(0, 15)) L.push(`| ${f.ref} | ${f.severity} | ${plain(f.title)} | ${link(f)} |`);
  if (m.confident.length > 15) L.push("", `…and ${m.confident.length - 15} more in the report.`);
  L.push("");
}
if (attention.length) {
  L.push("**Dependencies compiled into the program:**");
  for (const a of attention.slice(0, 10)) L.push(`- [${a.id}](${a.url}) (${a.crates.join(", ")}): ${plain(a.summary)}`);
  L.push("");
}
L.push(`<sub>${m.coverage.length} vulnerability classes checked across ${m.stats.handlers} handler${m.stats.handlers === 1 ? "" : "s"}. Deterministic static review, not an audit. Full HTML report in the run's artifacts. [Watchdog](https://watchdog.soladrome.finance)</sub>`);
console.log(L.join("\n"));
