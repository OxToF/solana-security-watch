import React, { useEffect, useRef, useState } from "react";
import { API_BASE, DEFAULT_PRICE, DEFAULT_PRICE_SOL, RISK, PreviewBody, Unlock, hasLocked, isAddress, isRepo, runFreeScan, sev, short } from "./report.jsx";

// Addresses checked against mainnet (executable) on 2026-10-12.
const PICKS = [
  { name: "Jupiter", id: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4" },
  { name: "Orca", id: "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc" },
  { name: "Raydium CLMM", id: "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK" },
  { name: "Drift", id: "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH" },
  { name: "Kamino Lend", id: "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD" },
  { name: "Marinade", id: "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD" },
];

function verdictOf(r) {
  if (r.flags.some((f) => f.severity === "high")) return { tone: "high", title: "High risk", line: r.authority?.text };
  if (r.authority?.kind === "none") return { tone: "ok", title: "Immutable", line: r.authority.text };
  if (r.flags.some((f) => f.severity === "medium")) return { tone: "medium", title: "Check before you deposit", line: r.authority?.text };
  return { tone: "ok", title: "Upgrades need several approvals", line: r.authority?.text };
}

function ProgramCheck() {
  const [pid, setPid] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);

  async function check(id = pid.trim()) {
    setErr(null); setRes(null);
    if (!isAddress(id)) return setErr("Paste a Solana program address.");
    setPid(id); setBusy(true);
    try {
      const r = await fetch(`${API_BASE}/free/program`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ programId: id }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || "The check failed. Try again.");
      setRes(j);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  const v = res && verdictOf(res);
  return (
    <div className="tool">
      <p className="tool-lead">Who can change this program's code tomorrow, and could they drain it? Paste any Solana program address. <b>Free, no wallet needed.</b></p>
      <div className="row">
        <input className="fld" placeholder="Program address" value={pid} onChange={(e) => setPid(e.target.value)} spellCheck={false} autoCapitalize="off" />
        <button className="btn" onClick={() => check()} disabled={busy}>{busy ? "Checking…" : "Check"}</button>
      </div>
      <div className="picks">
        <span className="hint">Try:</span>
        {PICKS.map((p) => <button key={p.id} type="button" className="pick" onClick={() => check(p.id)} disabled={busy}>{p.name}</button>)}
      </div>
      {err && <div className="msg err">{err}</div>}
      {res && (
        <div className={`result tone-${v.tone}`}>
          <div className="verdict"><span className={`dot ${v.tone}`} />{v.title}</div>
          <p className="vline">{v.line}</p>
          {res.authority?.address && <div className="kv"><span>Upgrade authority</span><code>{short(res.authority.address)}</code></div>}
          {res.authority?.threshold != null && <div className="kv"><span>Approvals needed</span><b>{res.authority.threshold} of {res.authority.members}</b></div>}
          {res.authority?.kind === "squads-v4" && <div className="kv"><span>Time lock</span><b>{res.authority.timeLockSeconds ? `${Math.round(res.authority.timeLockSeconds / 3600)} h` : "none"}</b></div>}
          {res.lastDeploy?.at && <div className="kv"><span>Last code change</span><b>{res.lastDeploy.at.slice(0, 10)}</b></div>}
          <div className="kv"><span>Verified build</span><b>{res.verifiedBuild ? (res.verifiedBuild.verified ? "yes" : "does not match") : "none"}</b></div>
          <div className="kv"><span>Security contact</span><b>{res.securityTxt ? (res.securityTxt.name || "published") : "none"}</b></div>
          {res.flags.length > 0 && (
            <ul className="flags">
              {res.flags.map((f) => <li key={f.id}><span className={`chip ${sev(f.severity)}`}>{f.severity}</span>{f.text}</li>)}
            </ul>
          )}
          <p className="hint">{res.disclaimer}</p>
        </div>
      )}
    </div>
  );
}

function RepoScan() {
  const [repo, setRepo] = useState("");
  const [state, setState] = useState(null); // { status, preview, error, unlockPriceUsd }
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const poll = useRef(null);
  useEffect(() => () => clearTimeout(poll.current), []);

  async function scan(target = repo.trim()) {
    setErr(null); setState(null);
    if (!isRepo(target)) return setErr("Enter a public https://github.com/org/repo URL.");
    setRepo(target);
    setBusy(true);
    try { await runFreeScan(target, setState, poll); }
    catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  const price = state?.unlockPriceUsd ?? DEFAULT_PRICE;
  const priceSol = state?.unlockPriceSol ?? DEFAULT_PRICE_SOL;
  const p = state?.preview?.risk ? state.preview : null;
  return (
    <div className="tool">
      <p className="tool-lead">Reads the program as Anchor does: every account, constraint and handler, the dependencies that really compile into it, and the deployed program on-chain. <b>The preview is free</b>; the full report unlocks for {priceSol} SOL.</p>
      <div className="row">
        <input className="fld" type="url" placeholder="https://github.com/org/repo" value={repo} onChange={(e) => setRepo(e.target.value)} spellCheck={false} autoCapitalize="off" />
        <button className="btn" onClick={() => scan()} disabled={busy}>{busy && !p ? "Scanning…" : "Free scan"}</button>
      </div>
      <div className="picks">
        <span className="hint">Try:</span>
        <button type="button" className="pick" disabled={busy} onClick={() => scan("https://github.com/OxToF/solana-security-watch")}>planted bugs</button>
        <button type="button" className="pick" disabled={busy} onClick={() => scan("https://github.com/solana-developers/program-examples")}>program-examples</button>
      </div>
      {err && <div className="msg err">{err}</div>}
      {state && !p && state.status !== "error" && <div className="msg">Cloning and scanning. About a minute…</div>}
      {state?.status === "error" && <div className="msg err">{state.error}</div>}
      {p && (
        <div className={`result tone-${RISK[p.risk].tone}`}>
          <PreviewBody p={p} />
          {hasLocked(p) && <Unlock repo={repo} price={price} priceSol={priceSol} />}
          <p className="hint">{p.disclaimer}</p>
        </div>
      )}
    </div>
  );
}

export default function FreeTools() {
  const [tab, setTab] = useState("program");
  return (
    <div className="scanbox">
      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === "program"} className={tab === "program" ? "on" : ""} onClick={() => setTab("program")}>Check a program <span className="free">free</span></button>
        <button role="tab" aria-selected={tab === "repo"} className={tab === "repo" ? "on" : ""} onClick={() => setTab("repo")}>Scan a repo <span className="free">free preview</span></button>
      </div>
      {tab === "program" ? <ProgramCheck /> : <RepoScan />}
    </div>
  );
}
