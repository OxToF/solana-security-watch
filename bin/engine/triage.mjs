// AI review of each finding, for paid reports only.
//
// The static rules are tuned to stay quiet on production code, but they read syntax, not
// intent. A second reader goes through every finding with the code around it (the
// accounts struct, the handlers that run it) and returns a verdict: confirmed, with the
// concrete attack; ruled out, with the reason; or uncertain. Confirmed notes are promoted,
// ruled-out findings move to their own section with the reasoning, so the customer can
// check the call instead of trusting it.
//
// Provider: OpenAI's Chat Completions API over plain fetch (no dependency). Nothing here
// runs without OPENAI_API_KEY, and any failure leaves the report as the rules wrote it.
// Bounded: at most TRIAGE_MAX findings per scan, one call each, a timeout per call.

import { readFileSync } from "node:fs";
import { join } from "node:path";

const BASE = (process.env.OPENAI_BASE_URL || "https://api.openai.com/v1").replace(/\/$/, "");
const MAX = Number(process.env.TRIAGE_MAX || 15);
const TIMEOUT_MS = Number(process.env.TRIAGE_TIMEOUT_MS || 90_000);

export const triageAvailable = () => !!(process.env.OPENAI_API_KEY && process.env.OPENAI_MODEL);

const SYSTEM = `You are a senior Solana security auditor reviewing findings produced by a static analyzer on an Anchor program.
For each finding you get the rule that fired, the analyzer's explanation, and the relevant source code.
Decide whether the finding is a real, exploitable issue in this code:
- "confirmed": an attacker can actually do harm. Give the concrete attack: who calls what, with which accounts, and what they gain or break.
- "false_positive": the code already prevents it (a constraint, a check in the handler or a helper it calls, the runtime, the program the account is forwarded to). Name the line or mechanism that prevents it.
- "uncertain": the excerpt is not enough to decide. Say what would decide it.
Judge only from the code shown and well-known Solana and Anchor semantics. Do not invent code that is not shown.
Answer with a JSON object: {"verdict": "confirmed" | "false_positive" | "uncertain", "reasoning": string (at most 90 words), "attack": string (only when confirmed, at most 80 words, else "")}.`;

function numbered(text, from, to) {
  const lines = text.split("\n");
  const a = Math.max(1, from), b = Math.min(lines.length, to);
  return lines.slice(a - 1, b).map((l, k) => `${String(a + k).padStart(5)}  ${l}`).join("\n");
}

// The code a reviewer needs: around the finding, plus the body of each handler it names
// (lib.rs wrappers and instruction files alike), capped so one finding stays a few
// thousand tokens.
export function contextFor(finding, repoDir, programFiles) {
  const parts = [];
  const read = (rel) => { try { return readFileSync(join(repoDir, rel), "utf8"); } catch { return null; } };
  const own = read(finding.file);
  if (own) parts.push(`// ${finding.file} (around line ${finding.line})\n${numbered(own, finding.line - 40, finding.line + 40)}`);
  for (const name of (finding.handlers || []).slice(0, 3)) {
    for (const rel of programFiles) {
      const src = read(rel);
      if (!src) continue;
      const i = src.search(new RegExp(`fn\\s+${name}\\b`));
      if (i < 0) continue;
      const line = src.slice(0, i).split("\n").length;
      if (rel === finding.file && Math.abs(line - finding.line) < 40) continue;
      parts.push(`// ${rel}: handler ${name}\n${numbered(src, line, line + 70)}`);
    }
  }
  return parts.join("\n\n").slice(0, 24_000);
}

async function ask(finding, code, fetchImpl) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const r = await fetchImpl(`${BASE}/chat/completions`, {
      method: "POST",
      signal: ctl.signal,
      headers: { "content-type": "application/json", authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: SYSTEM },
          { role: "user", content: `Rule: ${finding.rule}\nSeverity proposed: ${finding.severity}\nFinding: ${finding.title}\nAnalyzer's explanation: ${finding.why}\nLocation: ${finding.file}:${finding.line}${finding.struct ? ` (accounts struct ${finding.struct})` : ""}\n\nCode:\n${code}` },
        ],
      }),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    const out = JSON.parse(j.choices?.[0]?.message?.content || "{}");
    if (!["confirmed", "false_positive", "uncertain"].includes(out.verdict)) throw new Error("no verdict");
    return {
      verdict: out.verdict,
      reasoning: String(out.reasoning || "").slice(0, 800),
      attack: out.verdict === "confirmed" ? String(out.attack || "").slice(0, 800) : "",
      usage: { input: j.usage?.prompt_tokens || 0, output: j.usage?.completion_tokens || 0 },
    };
  } finally {
    clearTimeout(timer);
  }
}

// Mutates each reviewed finding with `ai`, and returns what happened. Findings are
// reviewed most severe first, so the cap never skips a critical one for a note.
export async function triageFindings(findings, { repoDir, programFiles, fetchImpl = globalThis.fetch, log = () => {} } = {}) {
  if (!triageAvailable()) return { ran: false, reason: "no AI reviewer configured" };
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const queue = [...findings].sort((a, b) => (a.confidence === "low") - (b.confidence === "low") || order[a.severity] - order[b.severity]).slice(0, MAX);
  const stats = { ran: true, model: process.env.OPENAI_MODEL, reviewed: 0, confirmed: 0, falsePositive: 0, uncertain: 0, failed: 0, skipped: findings.length - queue.length, usage: { input: 0, output: 0 } };
  // Three at a time: a scan stays around a minute without bursting the account's limits.
  for (let i = 0; i < queue.length; i += 3) {
    await Promise.all(queue.slice(i, i + 3).map(async (f) => {
      try {
        const res = await ask(f, contextFor(f, repoDir, programFiles), fetchImpl);
        f.ai = { verdict: res.verdict, reasoning: res.reasoning, attack: res.attack, model: process.env.OPENAI_MODEL };
        stats.reviewed++;
        stats[{ confirmed: "confirmed", false_positive: "falsePositive", uncertain: "uncertain" }[res.verdict]]++;
        stats.usage.input += res.usage.input;
        stats.usage.output += res.usage.output;
      } catch (e) {
        stats.failed++;
        log(`[triage] ${f.rule} ${f.file}:${f.line} not reviewed: ${String(e.message).slice(0, 120)}`);
      }
    }));
  }
  log(`[triage] ${stats.model}: ${stats.reviewed} reviewed, ${stats.confirmed} confirmed, ${stats.falsePositive} ruled out, ${stats.uncertain} uncertain, ${stats.failed} failed · ${stats.usage.input}+${stats.usage.output} tokens`);
  return stats;
}
