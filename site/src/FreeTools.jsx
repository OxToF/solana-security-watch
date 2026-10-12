import React, { useEffect, useRef, useState } from "react";
import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { PublicKey, SystemProgram, Transaction, TransactionInstruction } from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  createTransferCheckedInstruction,
  createAssociatedTokenAccountIdempotentInstruction,
} from "@solana/spl-token";

const API_BASE = import.meta.env.VITE_API_BASE || "https://solana-security-watchdog-scan.fly.dev";
const WALLET = import.meta.env.VITE_MERCHANT_WALLET || "7yMnWMrxzZ3YCtWXRsZEhAFwexHoJzBJy8RgN7Lhvy1P";
// The server's price wins once a preview has loaded; this is only the first paint.
// VITE_AMOUNT_USDC is not read: it may still hold the old 69 paywall price.
const DEFAULT_PRICE = 9;
const DEFAULT_PRICE_SOL = 0.1;
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

const isRepo = (s) => /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/.test(s);
const isEmail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);
const isAddress = (s) => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s);

// Addresses checked against mainnet (executable) on 2026-10-12.
const PICKS = [
  { name: "Jupiter", id: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4" },
  { name: "Orca", id: "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc" },
  { name: "Raydium CLMM", id: "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK" },
  { name: "Drift", id: "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH" },
  { name: "Kamino Lend", id: "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD" },
  { name: "Marinade", id: "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD" },
];

const short = (a) => (a && a.length > 12 ? `${a.slice(0, 4)}…${a.slice(-4)}` : a);
const sev = (s) => {
  const k = String(s || "").toLowerCase().split(" ")[0];
  return k === "critical" || k === "high" ? "high" : k === "medium" || k === "moderate" ? "medium" : k === "low" ? "low" : "info";
};

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

function Blurred({ n, kind }) {
  // Placeholder text only: the real rows never reach the browser.
  const rows = Array.from({ length: Math.min(n, 3) }, (_, i) => i);
  return (
    <div className="locked">
      {rows.map((i) => (
        <div className="blur-row" key={i} aria-hidden="true">
          {kind === "advisory" ? "RUSTSEC-2026-0000 · crate-name 0.0.0 · summary of the advisory hidden here" : "programs/src/instructions/handler.rs:000 · let account = ctx.accounts.hidden"}
        </div>
      ))}
      <div className="lock-note">🔒 {n} more {kind === "advisory" ? (n === 1 ? "advisory" : "advisories") : (n === 1 ? "code lead" : "code leads")} in the full report</div>
    </div>
  );
}

function RepoScan() {
  const { connection } = useConnection();
  const { publicKey, sendTransaction, connected } = useWallet();
  const [repo, setRepo] = useState("");
  const [email, setEmail] = useState("");
  const [state, setState] = useState(null); // { status, preview, error, unlockPriceUsd }
  const [err, setErr] = useState(null);
  const [payMsg, setPayMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const poll = useRef(null);
  useEffect(() => () => clearTimeout(poll.current), []);

  async function scan(target = repo.trim()) {
    setErr(null); setState(null); setPayMsg(null);
    if (!isRepo(target)) return setErr("Enter a public https://github.com/org/repo URL.");
    setRepo(target);
    setBusy(true);
    try {
      const r = await fetch(`${API_BASE}/free/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repo: target }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || "Could not start the scan.");
      setState({ status: j.status });
      const tick = async () => {
        try {
          const s = await (await fetch(j.statusUrl)).json();
          setState(s);
          if (s.status === "done" || s.status === "error") return setBusy(false);
        } catch {}
        poll.current = setTimeout(tick, 3000);
      };
      tick();
    } catch (e) { setErr(e.message); setBusy(false); }
  }

  const price = state?.unlockPriceUsd ?? DEFAULT_PRICE;
  const priceSol = state?.unlockPriceSol ?? DEFAULT_PRICE_SOL;

  async function unlock(currency) {
    setPayMsg(null);
    if (!isEmail(email)) return setPayMsg({ kind: "err", text: "Enter the email the report goes to." });
    if (!connected || !publicKey) return setPayMsg({ kind: "err", text: "Connect your wallet first." });
    setBusy(true);
    let ordered = false;
    try {
      setPayMsg({ kind: "", text: "Creating your order…" });
      const r = await fetch(`${API_BASE}/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repo: repo.trim(), email, currency }) });
      if (!r.ok) throw new Error("Could not create the order. Try again.");
      const order = await r.json();
      const { jobId } = order;
      ordered = true;
      const unit = order.currency || "USDC";
      const amount = order.amount ?? (unit === "SOL" ? priceSol : price);
      const merchant = new PublicKey(WALLET);
      // The job id rides in a memo: the server only accepts a payment that names its job.
      const memo = new TransactionInstruction({ keys: [], programId: new PublicKey(MEMO_PROGRAM), data: Buffer.from(jobId) });
      const tx = new Transaction();
      if (unit === "SOL") {
        tx.add(SystemProgram.transfer({ fromPubkey: publicKey, toPubkey: merchant, lamports: Math.round(amount * 1e9) }), memo);
      } else {
        const mint = new PublicKey(USDC_MINT);
        const merchantAta = getAssociatedTokenAddressSync(mint, merchant);
        tx.add(
          createAssociatedTokenAccountIdempotentInstruction(publicKey, merchantAta, merchant, mint),
          createTransferCheckedInstruction(getAssociatedTokenAddressSync(mint, publicKey), mint, merchantAta, publicKey, BigInt(Math.round(amount * 1e6)), 6),
          memo
        );
      }
      setPayMsg({ kind: "", text: `Approve the ${amount} ${unit} payment in your wallet…` });
      const signature = await sendTransaction(tx, connection);
      setPayMsg({ kind: "", text: "Payment sent. Verifying on-chain…" });
      const v = await fetch(`${API_BASE}/pay/verify`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jobId, signature }) });
      if (!v.ok) {
        const e = await v.json().catch(() => ({}));
        throw new Error(`Payment sent, still confirming (${e.error || "unknown"}). Signature: ${signature}.`);
      }
      setPayMsg({ kind: "ok", text: `Paid. The full report arrives by email in a few minutes. Signature: ${signature}` });
    } catch (e) {
      // The server also finds the payment on-chain by its memo: a paid order is
      // delivered even when the page lost the hand during the wallet round-trip.
      const note = ordered ? " If the payment went through, the report still reaches your inbox within a few minutes." : "";
      setPayMsg({ kind: "err", text: (e?.message || "Payment failed or was cancelled.") + note });
    }
    finally { setBusy(false); }
  }

  const p = state?.preview;
  return (
    <div className="tool">
      <p className="tool-lead">Known advisories in its dependencies, build hygiene and known Solana bug classes. <b>The preview is free</b>; the full report with every file and line unlocks for {priceSol} SOL.</p>
      <div className="row">
        <input className="fld" type="url" placeholder="https://github.com/org/repo" value={repo} onChange={(e) => setRepo(e.target.value)} spellCheck={false} autoCapitalize="off" />
        <button className="btn" onClick={() => scan()} disabled={busy}>{busy && !p ? "Scanning…" : "Free scan"}</button>
      </div>
      <div className="picks">
        <span className="hint">Try:</span>
        <button type="button" className="pick" disabled={busy} onClick={() => scan("https://github.com/coral-xyz/anchor")}>coral-xyz/anchor</button>
        <button type="button" className="pick" disabled={busy} onClick={() => scan("https://github.com/solana-developers/program-examples")}>program-examples</button>
      </div>
      {err && <div className="msg err">{err}</div>}
      {state && !p && state.status !== "error" && <div className="msg">Cloning and scanning. About a minute…</div>}
      {state?.status === "error" && <div className="msg err">{state.error}</div>}
      {p && (
        <div className="result">
          <div className="verdict">{p.repo}</div>
          <div className="counts">
            <div><b>{p.counts.onchainAdvisories}</b><span>advisories on the deployed program</span></div>
            <div><b>{p.counts.toolchainAdvisories + p.counts.unmaintainedCrates}</b><span>in tooling or unmaintained crates</span></div>
            <div><b>{p.counts.codeLeads}</b><span>code leads to read</span></div>
          </div>
          <div className="kv"><span>overflow-checks (release)</span><b>{p.hygiene.overflowChecks === false ? "off: turn it on" : p.hygiene.overflowChecks ? "on" : "not set"}</b></div>
          <div className="kv"><span>anchor-lang</span><b>{p.hygiene.anchorVersion || "not used"}</b></div>

          <h4>Advisories</h4>
          {p.shown.advisory ? (
            <div className="adv"><span className={`chip ${sev(p.shown.advisory.severity)}`}>{p.shown.advisory.severity}</span>
              <div><a href={p.shown.advisory.url} target="_blank" rel="noreferrer">{p.shown.advisory.id}</a>{p.shown.advisory.onchain && <span className="oc">on-chain</span>}<div className="hint">{p.shown.advisory.summary}</div><div className="hint">{p.shown.advisory.crates.join(", ")}</div></div></div>
          ) : <div className="msg ok">No known advisory at the pinned versions.</div>}
          {p.hidden.advisories > 0 && <Blurred n={p.hidden.advisories} kind="advisory" />}

          <h4>Code leads</h4>
          {p.classes.length ? <div className="classes">{p.classes.map((c) => <span key={c.class} className="cls">{c.label} <b>{c.total}</b></span>)}</div> : <div className="msg ok">No known bug-class pattern matched.</div>}
          {p.shown.lead && <div className="lead"><code>{p.shown.lead.file}:{p.shown.lead.line}</code><pre>{p.shown.lead.text}</pre></div>}
          {p.hidden.leads > 0 && <Blurred n={p.hidden.leads} kind="lead" />}

          {(p.hidden.advisories > 0 || p.hidden.leads > 0) && (
            <div className="unlock">
              <h4>Unlock the full report: {priceSol} SOL</h4>
              <p className="hint">Every advisory and every lead with file and line, by email, as a page you can share with your team.</p>
              <div className="connect-row"><WalletMultiButton /></div>
              <input className="fld" type="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
              <button className="btn pay" onClick={() => unlock("SOL")} disabled={busy}>{busy ? "Working…" : `Pay ${priceSol} SOL`}</button>
              <button className="btn ghost pay" onClick={() => unlock("USDC")} disabled={busy}>{`or pay ${price} USDC`}</button>
              {payMsg && <div className={`msg ${payMsg.kind}`}>{payMsg.text}</div>}
            </div>
          )}
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
