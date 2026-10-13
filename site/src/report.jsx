import React, { useState } from "react";
import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { PublicKey, SystemProgram, Transaction, TransactionInstruction } from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  createTransferCheckedInstruction,
  createAssociatedTokenAccountIdempotentInstruction,
} from "@solana/spl-token";

// The repo-scan preview and its unlock, shared by the landing's free tools and the dashboard.

export const API_BASE = import.meta.env.VITE_API_BASE || "https://solana-security-watchdog-scan.fly.dev";
const WALLET = import.meta.env.VITE_MERCHANT_WALLET || "7yMnWMrxzZ3YCtWXRsZEhAFwexHoJzBJy8RgN7Lhvy1P";
// The server's price wins once a preview has loaded; this is only the first paint.
// VITE_AMOUNT_USDC is not read: it may still hold the old 69 paywall price.
export const DEFAULT_PRICE = 9;
export const DEFAULT_PRICE_SOL = 0.1;
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

export const isRepo = (s) => /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/.test(s);
export const isEmail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);
export const isAddress = (s) => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s);
export const short = (a) => (a && a.length > 12 ? `${a.slice(0, 4)}…${a.slice(-4)}` : a);

export const sev = (s) => {
  const k = String(s || "").toLowerCase().split(" ")[0];
  return k === "critical" || k === "high" ? "high" : k === "medium" || k === "moderate" ? "medium" : k === "low" ? "low" : "info";
};

export const RISK = {
  critical: { label: "Critical risk", tone: "high" }, high: { label: "High risk", tone: "high" },
  medium: { label: "Medium risk", tone: "medium" }, low: { label: "Low risk", tone: "ok" }, clean: { label: "No issue found", tone: "ok" },
};

// Severity of every issue to fix: the one shown in full plus the hidden ones.
export function severityCounts(p) {
  const all = [...(p.shown.finding ? [p.shown.finding] : []), ...p.hidden.findings];
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of all) {
    const k = String(f.severity || "").toLowerCase();
    if (k in c) c[k] += 1;
  }
  return c;
}

// Starts a free scan and polls it. onState receives each status; resolves on done or error.
export async function runFreeScan(repo, onState, poll) {
  const r = await fetch(`${API_BASE}/free/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repo }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || "Could not start the scan.");
  onState({ status: j.status, jobId: j.jobId });
  return new Promise((resolve) => {
    const tick = async () => {
      try {
        const s = await (await fetch(j.statusUrl)).json();
        if (s.status === "expired") return resolve(runFreeScan(repo, onState, poll)); // cached before the current engine
        onState(s);
        if (s.status === "done" || s.status === "error") return resolve(s);
      } catch {}
      poll.current = setTimeout(tick, 3000);
    };
    tick();
  });
}

// `code` spans in the engine's text.
export function Md({ text }) {
  return String(text || "").split(/(`[^`]+`)/).map((part, i) => (part.startsWith("`") && part.endsWith("`") ? <code key={i}>{part.slice(1, -1)}</code> : part));
}

export function Finding({ f, note }) {
  return (
    <div className="finding">
      <div className="fhead"><span className={`chip ${sev(f.severity)}`}>{note ? "to verify" : f.severity}</span>{f.ref && <span className="hint">{f.ref}</span>}<span className="hint" style={{ marginLeft: "auto" }}>confidence {f.confidence}</span></div>
      <div className="ftitle"><Md text={f.title} /></div>
      <code className="floc">{f.file}:{f.line}</code>
      {f.snippet && <pre className="fcode">{f.snippet.lines.map((l, k) => <span key={k} className={f.snippet.from + k === f.snippet.focus ? "focus" : ""}>{String(f.snippet.from + k).padStart(4)}  {l}{"\n"}</span>)}</pre>}
      <p className="hint"><b>Why it matters.</b> <Md text={f.why} /></p>
      <p className="hint"><b>Fix.</b> <Md text={f.fix} /></p>
    </div>
  );
}

export const hasLocked = (p) => p.hidden.findings.length > 0 || p.hidden.advisories > 0 || p.hidden.review > 0;

// Everything the free preview shows, from the verdict to the locked counts.
export function PreviewBody({ p }) {
  return (
    <>
      <div className="hint">{p.repo}{p.commit ? ` · ${p.commit.slice(0, 7)}` : ""}</div>
      <div className="verdict"><span className={`dot ${RISK[p.risk].tone}`} />{RISK[p.risk].label}</div>
      <p className="vline"><Md text={p.summary} /></p>
      <div className="counts">
        <div><b>{p.counts.issues}</b><span>issue{p.counts.issues === 1 ? "" : "s"} to fix</span></div>
        <div><b>{p.counts.review}</b><span>to verify</span></div>
        <div><b>{p.counts.onchainAdvisoriesNeedingAttention}</b><span>dependency advisories to act on</span></div>
      </div>

      {p.shown.finding && <Finding f={p.shown.finding} />}
      {!p.shown.finding && p.shown.review && <Finding f={p.shown.review} note />}
      {p.hidden.findings.length > 0 && (
        <div className="locked">
          {p.hidden.findings.slice(0, 3).map((h, i) => (
            <div className="blur-row lockrow" key={i} aria-hidden="true"><span className={`chip ${sev(h.severity)}`}>{h.severity}</span><span className="blurtxt">programs/src/instructions/handler.rs:000 · title of this issue is hidden</span></div>
          ))}
          <div className="lock-note">🔒 {p.hidden.findings.length} more issue{p.hidden.findings.length > 1 ? "s" : ""} to fix in the full report ({Object.entries(p.hidden.findings.reduce((c, h) => ({ ...c, [h.severity]: (c[h.severity] || 0) + 1 }), {})).map(([k, n]) => `${n} ${k}`).join(", ")})</div>
        </div>
      )}

      {p.deployed.filter((d) => d.cluster).map((d) => (
        <div className="kv" key={d.programId}><span>Deployed on {d.cluster}</span><b>{d.authority ? (d.authority.kind === "single-key" ? "one key can replace it" : d.authority.kind === "none" ? "immutable" : d.authority.kind) : "unknown"}</b></div>
      ))}
      <div className="kv"><span>Vulnerability classes checked</span><b>{p.coverage.length}, {p.coverage.filter((c) => !c.toFix && !c.toVerify).length} clean</b></div>
      <div className="kv"><span>Crates compiled into the program</span><b>{p.counts.cratesInProgram ?? "?"} of {p.counts.cratesInLockfile}</b></div>

      {p.shown.advisory && (
        <div className="adv"><span className={`chip ${sev(p.shown.advisory.severity)}`}>{p.shown.advisory.severity}</span>
          <div><a href={p.shown.advisory.url} target="_blank" rel="noreferrer">{p.shown.advisory.id}</a>{p.shown.advisory.onchain && <span className="oc">in the program</span>}<div className="hint">{p.shown.advisory.summary}</div>{p.shown.advisory.note && <div className="hint"><b>{p.shown.advisory.verdict === "not-exploitable" ? "Not exploitable on-chain. " : p.shown.advisory.verdict === "conditional" ? "Depends on your code: " : ""}</b><Md text={p.shown.advisory.note} /></div>}</div></div>
      )}
      {p.hidden.advisories > 0 && <div className="lock-note">🔒 {p.hidden.advisories} more dependency advisor{p.hidden.advisories > 1 ? "ies" : "y"}, each judged for on-chain reach, in the full report</div>}
      {p.hidden.review > 0 && <div className="lock-note">🔒 {p.hidden.review} point{p.hidden.review > 1 ? "s" : ""} to verify, with code and reasoning</div>}
    </>
  );
}

// Pay for the full report from the connected wallet. onPaid({ jobId, signature }) once the server accepted it.
export function Unlock({ repo, price, priceSol, onPaid }) {
  const { connection } = useConnection();
  const { publicKey, sendTransaction, connected } = useWallet();
  const [email, setEmail] = useState("");
  const [payMsg, setPayMsg] = useState(null);
  const [busy, setBusy] = useState(false);

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
      onPaid?.({ jobId, signature, confirmed: false });
      setPayMsg({ kind: "", text: "Payment sent. Verifying on-chain…" });
      const v = await fetch(`${API_BASE}/pay/verify`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jobId, signature }) });
      if (!v.ok) {
        const e = await v.json().catch(() => ({}));
        throw new Error(`Payment sent, still confirming (${e.error || "unknown"}). Signature: ${signature}.`);
      }
      onPaid?.({ jobId, signature, confirmed: true });
      setPayMsg({ kind: "ok", text: `Paid. The full report arrives by email in a few minutes. Signature: ${signature}` });
    } catch (e) {
      // The server also finds the payment on-chain by its memo: a paid order is
      // delivered even when the page lost the hand during the wallet round-trip.
      const note = ordered ? " If the payment went through, the report still reaches your inbox within a few minutes." : "";
      setPayMsg({ kind: "err", text: (e?.message || "Payment failed or was cancelled.") + note });
    }
    finally { setBusy(false); }
  }

  return (
    <div className="unlock">
      <h4>Unlock the full report: {priceSol} SOL</h4>
      <p className="hint">Every issue with its code, why it is exploitable and how to fix it, the deployed program, and every dependency judged for on-chain reach. By email, as a page you can share with your team.</p>
      <div className="connect-row"><WalletMultiButton /></div>
      <input className="fld" type="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
      <button className="btn pay" onClick={() => unlock("SOL")} disabled={busy}>{busy ? "Working…" : `Pay ${priceSol} SOL`}</button>
      <button className="btn ghost pay" onClick={() => unlock("USDC")} disabled={busy}>{`or pay ${price} USDC`}</button>
      {payMsg && <div className={`msg ${payMsg.kind}`}>{payMsg.text}</div>}
    </div>
  );
}
