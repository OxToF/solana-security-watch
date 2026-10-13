// The report a customer receives. One model, two renderings (HTML for people, Markdown
// for agents and diffs). Ordered the way a reader decides: the verdict, what to fix,
// what to verify, what the chain says, the dependencies, and what was checked.

import { RULES } from "./anchor.mjs";
import { needsAttention } from "./advisories.mjs";

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
// `code` spans in finding text, escaped first.
const md2html = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");

const SEV = { critical: { label: "Critical", color: "#b91c1c", bg: "#fde8e8" }, high: { label: "High", color: "#c2410c", bg: "#fff1e6" },
  medium: { label: "Medium", color: "#a16207", bg: "#fef7dc" }, low: { label: "Low", color: "#2563eb", bg: "#e8f0fe" }, info: { label: "Info", color: "#4b5563", bg: "#eef0f4" },
  clean: { label: "No issue found", color: "#047857", bg: "#e6f7ef" } };
const ADV_SEV = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", UNRATED: "info" };
const ORDER = ["critical", "high", "medium", "low", "info"];

// Split analysis findings into what to fix and what to verify.
export function partition(findings) {
  const confident = findings.filter((f) => f.confidence !== "low" && ["critical", "high", "medium"].includes(f.severity));
  const review = findings.filter((f) => !confident.includes(f));
  confident.forEach((f, i) => { f.ref = `W-${String(i + 1).padStart(2, "0")}`; });
  return { confident, review };
}

export function riskOf(model) {
  const sevs = model.confident.map((f) => f.severity);
  const mainnetSingleKey = model.deployed.some((d) => d.cluster === "mainnet" && d.authority && d.authority.kind === "single-key");
  const exploitableDeps = model.deps.onchain.filter((a) => a.verdict === "exploitable" || (!a.verdict && ["CRITICAL", "HIGH"].includes(a.severity)));
  for (const s of ["critical", "high"]) if (sevs.includes(s)) return s;
  if (mainnetSingleKey) return "high";
  if (sevs.includes("medium") || exploitableDeps.length) return "medium";
  if (model.review.length || model.deps.onchain.length) return "low";
  return "clean";
}

function summaryText(m) {
  const counts = ORDER.map((s) => [s, m.confident.filter((f) => f.severity === s).length]).filter(([, n]) => n);
  const parts = [];
  parts.push(`Watchdog read ${m.stats.structs} account contexts (${m.stats.fields} accounts) and ${m.stats.handlers} handlers across ${m.stats.files} source files of ${m.programs.map((p) => `\`${p.name}\``).join(", ") || "the repository"}`
    + (m.closure ? `, followed the ${m.closure.size} crates that actually compile into the program out of ${m.lockSize} in the lockfile` : "")
    + (m.deployed.some((d) => d.cluster) ? `, and checked the deployed program on ${[...new Set(m.deployed.filter((d) => d.cluster).map((d) => d.cluster))].join(" and ")}.` : "."));
  parts.push(counts.length
    ? `It found ${counts.map(([s, n]) => `${n} ${SEV[s].label.toLowerCase()}`).join(", ")} issue${m.confident.length > 1 ? "s" : ""} to fix${m.review.length ? `, and ${m.review.length} point${m.review.length > 1 ? "s" : ""} worth a second look` : ""}.`
    : `It found no issue in the patterns it checks${m.review.length ? `; ${m.review.length} point${m.review.length > 1 ? "s are" : " is"} listed for a second look` : ""}.`);
  const live = m.deployed.find((d) => d.cluster === "mainnet") || m.deployed.find((d) => d.cluster);
  if (live && live.authority) parts.push(`On ${live.cluster}, ${live.authority.kind === "none" ? "the program is immutable." : live.authority.kind === "single-key" ? "a single key can replace the program's code at any time, with no delay." : live.authority.text.charAt(0).toLowerCase() + live.authority.text.slice(1)}`);
  const exploitable = m.deps.onchain.filter(needsAttention).length;
  parts.push(m.deps.onchain.length
    ? `${m.deps.onchain.length} dependency advisor${m.deps.onchain.length > 1 ? "ies reach" : "y reaches"} the deployed program; ${exploitable ? `${exploitable} need${exploitable > 1 ? "" : "s"} attention` : "none is exploitable on-chain"}.`
    : `No dependency advisory reaches the deployed program.`);
  return parts.join(" ");
}

export function buildModel({ meta, programs, analysis, deployed, deps, closure, lockSize, hygiene }) {
  const { confident, review } = partition(analysis.findings);
  const m = { meta, programs, confident, review, deployed, deps, closure: closure ? closure.crates : null, lockSize, hygiene, stats: analysis.stats };
  m.risk = riskOf(m);
  m.summary = summaryText(m);
  m.coverage = RULES.map((r) => ({ ...r, scope: r.id === "reinit-takeover" ? `${analysis.stats.initIfNeeded + analysis.findings.filter((f) => f.rule === r.id).length} init_if_needed state accounts` : r.scope, hits: analysis.findings.filter((f) => f.rule === r.id).length, confident: confident.filter((f) => f.rule === r.id).length }));
  return m;
}

function srcLink(meta, file, line) {
  if (!meta.owner || meta.owner === "local") return null;
  return `https://github.com/${meta.owner}/${meta.repo}/blob/${meta.ref || "HEAD"}/${file}#L${line}`;
}

function snippetHtml(sn) {
  if (!sn) return "";
  return `<pre class="code">${sn.lines.map((l, k) => { const n = sn.from + k; return `<span class="ln${n === sn.focus ? " focus" : ""}"><i>${n}</i>${esc(l) || " "}</span>`; }).join("")}</pre>`;
}

export function renderHtml(m, { logo = "", cta = null } = {}) {
  const r = SEV[m.risk];
  const fixMail = (subject, lines) => cta && cta.contact ? `mailto:${cta.contact}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent([`Repository: https://github.com/${m.meta.owner}/${m.meta.repo}`, cta.ref ? `Report reference: ${cta.ref}` : null, ...lines, "", "What we would like fixed, and any deadline:", ""].filter((x) => x !== null).join("\n"))}` : null;
  const chip = (sev) => `<span class="chip" style="color:${SEV[sev].color};background:${SEV[sev].bg}">${SEV[sev].label}</span>`;

  const finding = (f) => {
    const link = srcLink(m.meta, f.file, f.line);
    const mail = fixMail(`Fix request ${f.ref}: ${m.meta.owner}/${m.meta.repo}`, [`Finding: ${f.ref} ${f.title.replace(/`/g, "")}`, `Location: ${f.file}:${f.line}`]);
    return `<article class="finding" id="${f.ref}">
      <header><span class="ref">${f.ref}</span>${chip(f.severity)}<span class="conf">Confidence: ${f.confidence}</span></header>
      <h3>${md2html(f.title)}</h3>
      <div class="loc">${link ? `<a href="${esc(link)}">${esc(f.file)}:${f.line}</a>` : `${esc(f.file)}:${f.line}`}${f.struct ? ` · <code>${esc(f.struct)}</code>` : ""}${f.handlers && f.handlers.length ? ` · handler${f.handlers.length > 1 ? "s" : ""} ${f.handlers.map((h) => `<code>${esc(h)}</code>`).join(", ")}` : ""}</div>
      ${snippetHtml(f.snippet)}
      <div class="kv"><b>Why it matters</b><p>${md2html(f.why)}</p></div>
      <div class="kv"><b>Fix</b><p>${md2html(f.fix)}</p></div>
      ${mail ? `<a class="fixlink" href="${esc(mail)}">Have Watchdog fix it &rarr;</a>` : ""}
    </article>`;
  };

  const reviewGroups = Object.entries(m.review.reduce((g, f) => { (g[f.rule] = g[f.rule] || []).push(f); return g; }, {}));
  const ruleName = (id) => (RULES.find((r) => r.id === id) || { name: id }).name;

  const deployedHtml = m.deployed.length ? m.deployed.map((d) => {
    if (!d.cluster) return `<div class="prog"><div class="prog-h"><code>${esc(d.programId)}</code><span class="tag">not deployed</span></div><p class="muted">Declared in the source, not found on mainnet or devnet.</p></div>`;
    const a = d.authority || {};
    const tone = a.kind === "none" ? "ok" : a.kind === "single-key" ? "bad" : "mid";
    const flags = (d.flags || []).filter((x) => x.id !== "single-key-authority");
    return `<div class="prog ${tone}"><div class="prog-h"><code>${esc(d.programId)}</code><span class="tag">${esc(d.cluster)}</span></div>
      <p class="auth">${esc(a.text || "Upgrade authority unknown.")}</p>
      <dl><dt>Upgrade authority</dt><dd>${a.address ? `<code>${esc(a.address)}</code>` : a.kind === "none" ? "none (immutable)" : "—"}</dd>
      ${a.threshold != null ? `<dt>Approvals</dt><dd>${a.threshold} of ${a.members}${a.timeLockSeconds ? `, ${Math.round(a.timeLockSeconds / 3600)} h time lock` : ", no time lock"}</dd>` : ""}
      <dt>Last code change</dt><dd>${d.lastDeploy && d.lastDeploy.at ? esc(d.lastDeploy.at.slice(0, 10)) : "—"}</dd>
      <dt>Verified build</dt><dd>${d.verifiedBuild && d.verifiedBuild.verified ? `yes${d.verifiedBuild.repo ? ` (${esc(d.verifiedBuild.repo)})` : ""}` : d.verifiedBuild && d.verifiedBuild.repo ? "submitted, does not match the deployed binary" : "none"}</dd>
      <dt>security.txt</dt><dd>${d.securityTxt ? esc(d.securityTxt.contacts || d.securityTxt.name || "present") : "none"}</dd></dl>
      ${flags.length ? `<ul class="flags">${flags.map((x) => `<li>${chip(x.severity === "high" ? "high" : x.severity === "medium" ? "medium" : x.severity === "low" ? "low" : "info")} ${esc(x.text)}</li>`).join("")}</ul>` : ""}</div>`;
  }).join("") : `<p class="muted">No <code>declare_id!</code> found in the program source.</p>`;

  const advRow = (a) => `<div class="adv">
      ${chip(ADV_SEV[a.severity])}
      <div><a href="${esc(a.url)}">${esc(a.id)}</a> <span class="muted">${esc(a.crates.join(", "))}</span>
      <div>${esc(a.summary)}</div>
      ${a.verdict ? `<div class="verdict ${a.verdict}"><b>${a.verdict === "not-exploitable" ? "Not exploitable on-chain." : a.verdict === "conditional" ? "Depends on your code:" : "Exploitable on-chain."}</b> ${esc(a.note)}</div>` : ""}</div></div>`;

  const nCov = m.coverage.filter((c) => !c.hits).length;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Watchdog report · ${esc(m.meta.owner)}/${esc(m.meta.repo)}</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#eceef4;color:#1c2030;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.doc{max-width:880px;margin:28px auto;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 12px 40px rgba(20,20,50,.12)}
.hd{background:linear-gradient(125deg,#1a0f36 0%,#0e1730 60%,#0a1f2b 100%);color:#fff;padding:24px 36px;display:flex;align-items:center;gap:16px;position:relative}
.hd::after{content:"";position:absolute;left:0;right:0;bottom:0;height:3px;background:linear-gradient(90deg,#9945FF,#14F195)}
.wm{font-weight:800;letter-spacing:.5px;font-size:1.1rem;line-height:1.1}.wm .g{background:linear-gradient(90deg,#b98cff,#14F195);-webkit-background-clip:text;background-clip:text;color:transparent}
.tl{color:#a9b0cf;font-size:.8rem;margin-top:3px}.meta{margin-left:auto;text-align:right;color:#a9b0cf;font-size:.78rem;line-height:1.5}.meta b{color:#fff}
main{padding:26px 36px 34px}
h1{font-size:1.55rem;margin:0;letter-spacing:-.01em;word-break:break-word}h1 a{color:inherit;text-decoration:none}
.sub{color:#6b7188;font-size:.85rem;margin-top:2px}
.verdict-box{margin:20px 0 8px;border-radius:14px;padding:18px 20px}
.verdict-box .top{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:6px}
.verdict-box .rating{font-size:.72rem;font-weight:800;letter-spacing:.06em;text-transform:uppercase;opacity:.85}
.verdict-box .big{font-size:1.6rem;font-weight:800;line-height:1.1}
.verdict-box p{margin:0;color:#2a2f45}
@media(max-width:640px){main{padding:20px}}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0 4px}@media(max-width:640px){.cards{grid-template-columns:repeat(2,1fr)}}
.card{background:#f7f8fc;border:1px solid #eaecf3;border-radius:12px;padding:12px 14px}.card .n{font-size:1.5rem;font-weight:800;line-height:1.1}.card .l{color:#6b7188;font-size:.76rem;margin-top:4px;line-height:1.3}
h2{font-size:1.08rem;margin:34px 0 12px;padding-left:12px;border-left:4px solid #9945FF;line-height:1.2}
.muted{color:#6b7188}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86em;background:#f1f2f7;border-radius:5px;padding:.05em .35em;word-break:break-word}
.chip{display:inline-block;border-radius:6px;padding:.12rem .5rem;font-size:.7rem;font-weight:800;letter-spacing:.02em;white-space:nowrap}
.finding{border:1px solid #e6e8f0;border-radius:14px;padding:16px 18px;margin:14px 0}
.finding header{display:flex;gap:8px;align-items:center}.ref{font-weight:800;color:#4f2bbd;font-size:.82rem}.conf{margin-left:auto;color:#8189a3;font-size:.76rem}
.finding h3{margin:8px 0 2px;font-size:1.02rem;line-height:1.35}.loc{font-size:.82rem;color:#5b6178}.loc a{color:#4f2bbd}
pre.code{background:#0f1222;color:#d7dbf0;border-radius:10px;padding:10px 0;margin:10px 0;overflow-x:auto;font:12.5px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}
pre.code .ln{display:block;padding:0 14px;white-space:pre}pre.code .ln i{display:inline-block;width:3.2em;color:#5b6283;font-style:normal;user-select:none}
pre.code .focus{background:rgba(153,69,255,.28);box-shadow:inset 3px 0 0 #b98cff}
.kv{margin-top:8px}.kv b{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:#6b7188}.kv p{margin:2px 0 0}
.fixlink{display:inline-block;margin-top:10px;font-size:.84rem;font-weight:700;color:#6d3bd6;text-decoration:none}
.clean{color:#047857;background:#e6f7ef;border:1px solid #bfe9d5;border-radius:10px;padding:11px 14px;font-weight:600}
details{border:1px solid #e6e8f0;border-radius:12px;padding:10px 14px;margin:10px 0}details summary{cursor:pointer;font-weight:700}
details .item{border-top:1px solid #eef0f5;padding:10px 0}details .item:first-of-type{border-top:0}
.prog{border:1px solid #e6e8f0;border-left-width:4px;border-radius:12px;padding:14px 16px;margin:10px 0}.prog.bad{border-left-color:#dc2626}.prog.mid{border-left-color:#d97706}.prog.ok{border-left-color:#059669}
.prog-h{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.tag{font-size:.72rem;font-weight:800;text-transform:uppercase;background:#eef0f6;color:#4a5069;border-radius:6px;padding:.1rem .45rem}
.auth{margin:8px 0;font-weight:600}dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:6px 0 0;font-size:.88rem}dt{color:#6b7188}dd{margin:0;word-break:break-all}
.flags{list-style:none;padding:0;margin:10px 0 0;font-size:.88rem}.flags li{margin:6px 0}
.adv{display:flex;gap:12px;padding:11px 0;border-top:1px solid #eef0f5}.adv:first-child{border-top:0}.adv a{font-weight:700;color:#4f2bbd}
.verdict{margin-top:5px;font-size:.86rem;border-radius:8px;padding:6px 10px}.verdict.not-exploitable{background:#e6f7ef;color:#065f46}.verdict.conditional{background:#fef7dc;color:#713f12}.verdict.exploitable{background:#fde8e8;color:#7f1d1d}
table{width:100%;border-collapse:collapse;font-size:.88rem}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #eef0f5;vertical-align:top}th{color:#6b7188;font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.03em}
td.res{white-space:nowrap;font-weight:700}td.res.ok{color:#047857}td.res.hit{color:#c2410c}td.res.note{color:#a16207}
.cta{display:flex;gap:16px;align-items:center;justify-content:space-between;background:#f6f1ff;border:1px solid #e2d4ff;border-radius:14px;padding:16px 18px;margin:28px 0 6px}
.cta-btn{flex:none;background:linear-gradient(90deg,#9945FF,#6d4bd6);color:#fff!important;font-weight:700;border-radius:10px;padding:10px 16px;text-decoration:none;white-space:nowrap}
.limits{background:#f7f8fc;border-radius:12px;padding:14px 16px;font-size:.88rem;color:#3a4058}.limits ul{margin:6px 0 0;padding-left:18px}
.ft{display:flex;gap:10px;align-items:center;color:#8189a3;font-size:.78rem;padding:16px 36px;border-top:1px solid #eef0f5}.ft a{color:#6d3bd6}
@media print{body{background:#fff}.doc{box-shadow:none;margin:0;border-radius:0}details{break-inside:avoid}details:not([open])>*:not(summary){display:block}.finding{break-inside:avoid}}
</style></head><body><div class="doc">
<div class="hd">${logo}<div><div class="wm">SOLANA <span class="g">WATCHDOG</span></div><div class="tl">Automated security review</div></div>
<div class="meta">Report <b>${esc(m.meta.date)}</b>${m.meta.ref ? `<br>Commit <b>${esc(m.meta.ref.slice(0, 7))}</b>` : ""}${cta && cta.ref ? `<br>Ref ${esc(cta.ref.slice(0, 8))}` : ""}</div></div>
<main>
<h1>${m.meta.owner === "local" ? esc(m.meta.repo) : `<a href="https://github.com/${esc(m.meta.owner)}/${esc(m.meta.repo)}">${esc(m.meta.owner)}/${esc(m.meta.repo)}</a>`}</h1>
<div class="sub">Program${m.programs.length > 1 ? "s" : ""}: ${m.programs.map((p) => `<code>${esc(p.name)}</code>`).join(", ") || "none found"}</div>

<section class="verdict-box" style="background:${r.bg};border:1px solid ${r.color}33">
  <div class="top"><span class="rating" style="color:${r.color}">Risk rating</span><span class="big" style="color:${r.color}">${r.label}</span></div>
  <p>${md2html(m.summary)}</p>
</section>

<div class="cards">
  <div class="card"><div class="n" style="color:${m.confident.length ? SEV[m.confident[0].severity].color : "#047857"}">${m.confident.length}</div><div class="l">issue${m.confident.length === 1 ? "" : "s"} to fix</div></div>
  <div class="card"><div class="n">${m.review.length}</div><div class="l">point${m.review.length === 1 ? "" : "s"} to verify</div></div>
  <div class="card"><div class="n">${m.deps.onchain.filter(needsAttention).length}<span class="muted" style="font-size:.9rem;font-weight:600"> / ${m.deps.onchain.length}</span></div><div class="l">advisories reaching the program that need attention</div></div>
  <div class="card"><div class="n">${m.coverage.length}</div><div class="l">vulnerability classes checked, ${nCov} clean</div></div>
</div>

<h2>Issues to fix</h2>
${m.confident.length ? m.confident.map(finding).join("") : `<div class="clean">✓ No issue found in the ${m.coverage.length} vulnerability classes checked.</div>`}

${m.review.length ? `<h2>Worth a second look</h2>
<p class="muted">Lower-confidence observations. Each may be handled by an invariant this analysis cannot follow; read the code before acting.</p>
${reviewGroups.map(([rule, fs]) => `<details><summary>${esc(ruleName(rule))} <span class="muted">(${fs.length})</span></summary>
${fs.map((f) => { const link = srcLink(m.meta, f.file, f.line); return `<div class="item"><b>${md2html(f.title)}</b><div class="loc">${link ? `<a href="${esc(link)}">${esc(f.file)}:${f.line}</a>` : `${esc(f.file)}:${f.line}`}${f.struct ? ` · <code>${esc(f.struct)}</code>` : ""}</div><p class="muted" style="margin:4px 0 0">${md2html(f.why)}</p></div>`; }).join("")}</details>`).join("")}` : ""}

<h2>Deployed program</h2>
${deployedHtml}

<h2>Dependencies</h2>
<p class="muted">${m.deps.reachKnown ? `Only crates that compile into the program for the Solana target count as on-chain: ${m.closure ? m.closure.size : "?"} of the ${m.lockSize} crates in the lockfile. The rest (CLI, RPC client, test validator, proc-macros) never reach the deployed binary.` : "No program crate was found, so on-chain reach could not be computed."}</p>
${m.deps.onchain.length ? `<h3 style="font-size:.95rem;margin:16px 0 4px">Reaching the deployed program (${m.deps.onchain.length})</h3>${m.deps.onchain.map(advRow).join("")}` : `<div class="clean">✓ No known advisory affects a crate that reaches the deployed program.</div>`}
${m.deps.offchain.length ? `<details><summary>Tooling and off-chain crates (${m.deps.offchain.length}) <span class="muted">not in the deployed binary; they run on your machines and in CI</span></summary>${m.deps.offchain.map((a) => `<div class="item">${advRow(a)}</div>`).join("")}</details>` : ""}
${m.deps.housekeeping.length ? `<details><summary>Unmaintained crates (${m.deps.housekeeping.length}) <span class="muted">no known defect; no future patches</span></summary>${m.deps.housekeeping.map((a) => `<div class="item">${advRow(a)}</div>`).join("")}</details>` : ""}

<h2>What was checked</h2>
<table><thead><tr><th>Vulnerability class</th><th>Scope</th><th>Result</th></tr></thead><tbody>
${m.coverage.map((c) => `<tr><td>${esc(c.name)}</td><td class="muted">${esc(c.scope)}</td><td class="res ${c.confident ? "hit" : c.hits ? "note" : "ok"}">${c.confident ? `${c.confident} to fix` : c.hits ? `${c.hits} to verify` : "✓ clean"}</td></tr>`).join("")}
<tr><td>overflow-checks in release profile</td><td class="muted">Cargo.toml</td><td class="res ${m.hygiene.overflowChecks === false ? "hit" : m.hygiene.overflowChecks ? "ok" : "note"}">${m.hygiene.overflowChecks === false ? "off" : m.hygiene.overflowChecks ? "✓ on" : "not set"}</td></tr>
<tr><td>Dependency advisories (RustSec / OSV)</td><td class="muted">${m.lockSize} pinned crates, exact versions</td><td class="res ${m.deps.onchain.some(needsAttention) ? "hit" : "ok"}">${m.deps.onchain.length} reach the program</td></tr>
<tr><td>Upgrade authority, verified build, security.txt</td><td class="muted">mainnet, then devnet</td><td class="res ${m.deployed.some((d) => d.authority && d.authority.kind === "single-key") ? "hit" : "ok"}">${m.deployed.filter((d) => d.cluster).length} program${m.deployed.filter((d) => d.cluster).length === 1 ? "" : "s"} found</td></tr>
</tbody></table>

<div class="limits"><b>Method and limits.</b><ul>
<li>Static analysis of the program source as Anchor reads it: account contexts, constraints, and the handlers and helpers that use them. A rule reports only when no guard is visible in the constraints or in the code the handler runs.</li>
<li>Dependency reach follows the real dependency graph for the Solana target (target-specific dependencies, dev-dependencies and proc-macros excluded), from the lockfile and the crates.io index.</li>
<li>Benchmarked on every change against coral-xyz/sealevel-attacks (13 of 13 vulnerable programs caught, none of the 22 fixed versions flagged) and on audited production protocols (no false issue raised).</li>
<li>Economic logic (rounding direction, price and reward math, oracle use) is not judged: those bugs live in what the numbers mean, not in the account wiring.</li>
<li>It does not execute the program, prove its economics, or replace a manual audit. A clean section means none of the listed patterns was found, not that no bug exists.</li>
</ul></div>

${fixMail(`Fix request: ${m.meta.owner}/${m.meta.repo}`, [`Risk rating: ${r.label}`, `Issues: ${m.confident.map((f) => f.ref).join(", ") || "none"}`]) ? `<div class="cta"><div><b>Want these fixed?</b><div class="muted">We open a pull request on your repository: each confirmed issue comes with a failing test, the fix, and the test passing. You review and merge.</div></div><a class="cta-btn" href="${esc(fixMail(`Fix request: ${m.meta.owner}/${m.meta.repo}`, [`Risk rating: ${r.label}`, `Issues: ${m.confident.map((f) => f.ref).join(", ") || "none"}`]))}">Get a fix quote</a></div>` : ""}
</main>
<div class="ft">${logo.replace(/width="\d+" height="\d+"/, 'width="20" height="20"')}<div>Generated by <b>Solana Watchdog</b> · <a href="https://watchdog.soladrome.finance">watchdog.soladrome.finance</a> · engine open source on <a href="https://github.com/OxToF/solana-security-watch">GitHub</a></div></div>
</div></body></html>`;
}

export function renderMarkdown(m) {
  const L = [];
  L.push(`# Watchdog report · ${m.meta.owner}/${m.meta.repo}`, "");
  L.push(`${m.meta.date}${m.meta.ref ? ` · commit ${m.meta.ref.slice(0, 7)}` : ""} · programs: ${m.programs.map((p) => p.name).join(", ") || "none"}`, "");
  L.push(`**Risk rating: ${SEV[m.risk].label}.** ${m.summary}`, "");
  L.push("## Issues to fix", "");
  if (!m.confident.length) L.push("No issue found in the vulnerability classes checked.", "");
  for (const f of m.confident) {
    L.push(`### ${f.ref} · ${SEV[f.severity].label} · ${f.title}`, "", `\`${f.file}:${f.line}\`${f.struct ? ` · \`${f.struct}\`` : ""} · confidence ${f.confidence}`, "");
    if (f.snippet) L.push("```rust", ...f.snippet.lines, "```", "");
    L.push(`**Why it matters.** ${f.why}`, "", `**Fix.** ${f.fix}`, "");
  }
  if (m.review.length) {
    L.push("## Worth a second look", "");
    for (const f of m.review) L.push(`- ${f.title} (\`${f.file}:${f.line}\`)`);
    L.push("");
  }
  L.push("## Deployed program", "");
  for (const d of m.deployed) L.push(d.cluster ? `- \`${d.programId}\` on ${d.cluster}: ${d.authority ? d.authority.text : "authority unknown"}${d.lastDeploy && d.lastDeploy.at ? ` Last code change ${d.lastDeploy.at.slice(0, 10)}.` : ""}` : `- \`${d.programId}\`: not deployed on mainnet or devnet.`);
  L.push("", "## Dependencies reaching the program", "");
  if (!m.deps.onchain.length) L.push("None.");
  for (const a of m.deps.onchain) L.push(`- [${a.severity}] ${a.id} (${a.crates.join(", ")}): ${a.summary}${a.verdict ? ` **${a.verdict}**: ${a.note}` : ""}`);
  L.push("", `Off-chain tooling advisories: ${m.deps.offchain.length}. Unmaintained crates: ${m.deps.housekeeping.length}.`, "");
  L.push("## What was checked", "");
  for (const c of m.coverage) L.push(`- ${c.name}: ${c.confident ? `${c.confident} to fix` : c.hits ? `${c.hits} to verify` : "clean"}`);
  L.push("", "_Automated static review. It does not replace a manual audit; a clean section means none of the listed patterns was found._");
  return L.join("\n");
}
