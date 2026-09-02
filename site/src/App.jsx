import React, { useState } from "react";
import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { PublicKey, Transaction, TransactionInstruction } from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  createTransferCheckedInstruction,
  createAssociatedTokenAccountIdempotentInstruction,
} from "@solana/spl-token";

const API_BASE = import.meta.env.VITE_API_BASE || "https://solana-security-watchdog-scan.fly.dev";
const WALLET = import.meta.env.VITE_MERCHANT_WALLET || "7yMnWMrxzZ3YCtWXRsZEhAFwexHoJzBJy8RgN7Lhvy1P";
const AMOUNT = Number(import.meta.env.VITE_AMOUNT_USDC || 0.1);
const CONTACT = import.meta.env.VITE_CONTACT || "solanawatchdog@proton.me";
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

const isRepo = (s) => /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/.test(s);
const isEmail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);

export default function App() {
  const { connection } = useConnection();
  const { publicKey, sendTransaction, connected } = useWallet();
  const [repo, setRepo] = useState("");
  const [email, setEmail] = useState("");
  const [msg, setMsg] = useState(null); // { kind, text }
  const [busy, setBusy] = useState(false);

  async function pay() {
    setMsg(null);
    if (!isRepo(repo)) return setMsg({ kind: "err", text: "Enter a valid https://github.com/org/repo URL (public repo)." });
    if (!isEmail(email)) return setMsg({ kind: "err", text: "Enter a valid email." });
    if (!connected || !publicKey) return setMsg({ kind: "err", text: "Connect your wallet first (button above)." });

    setBusy(true);
    try {
      setMsg({ kind: "", text: "Creating your scan order..." });
      const r = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ repo, email }),
      });
      if (!r.ok) throw new Error("Could not create the order. Try again.");
      const { jobId } = await r.json();

      const mint = new PublicKey(USDC_MINT);
      const merchant = new PublicKey(WALLET);
      const payerAta = getAssociatedTokenAddressSync(mint, publicKey);
      const merchantAta = getAssociatedTokenAddressSync(mint, merchant);
      const base = BigInt(Math.round(AMOUNT * 1e6)); // USDC = 6 decimals

      const tx = new Transaction().add(
        createAssociatedTokenAccountIdempotentInstruction(publicKey, merchantAta, merchant, mint),
        createTransferCheckedInstruction(payerAta, mint, merchantAta, publicKey, base, 6),
        new TransactionInstruction({ keys: [], programId: new PublicKey(MEMO_PROGRAM), data: Buffer.from(jobId) })
      );

      setMsg({ kind: "", text: `Approve the ${AMOUNT} USDC payment in your wallet...` });
      // wallet-adapter fills the blockhash + fee payer, signs, and sends via the RPC.
      const signature = await sendTransaction(tx, connection);

      setMsg({ kind: "", text: "Payment sent. Verifying on-chain and starting your scan..." });
      const v = await fetch(`${API_BASE}/pay/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jobId, signature }),
      });
      if (!v.ok) {
        const e = await v.json().catch(() => ({}));
        throw new Error(`Payment sent but verification failed: ${e.error || "unknown"}. Email us the signature: ${signature}`);
      }
      setMsg({ kind: "ok", text: `Paid. Your report will arrive by email shortly. Signature: ${signature}` });
      setRepo(""); setEmail("");
    } catch (err) {
      setMsg({ kind: "err", text: err?.message || "Payment failed or was cancelled." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="wrap">
      <header>
        <div className="brand">Solana <span>Security Watch</span></div>
        <nav className="nav">
          <a href="#offers">Offers</a>
          <a href="#proof">Proof</a>
          <a href="https://github.com/OxToF/solana-security-watch">GitHub</a>
        </nav>
      </header>

      <div className="hero">
        <h1>Harden your Solana program <em>before</em> someone else does</h1>
        <p className="sub">Paste your public repo. We check your dependencies against RustSec and OSV advisories on your exact pinned versions, and your code against 18 Solana and Anchor vulnerability classes. Dated report, severity, file and line.</p>

        <div className="scanbox">
          <div className="connect-row"><WalletMultiButton /></div>
          <input className="fld" type="url" placeholder="https://github.com/your-org/your-repo" value={repo} onChange={(e) => setRepo(e.target.value)} />
          <input className="fld" type="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
          <button className="btn pay" onClick={pay} disabled={busy}>{busy ? "Working..." : `Pay ${AMOUNT} USDC & scan`}</button>
          <div className="price">On-demand scan, <b>{AMOUNT} USDC</b> on Solana. Public repo. Connect any Solana wallet.</div>
          {msg && <div className={`msg ${msg.kind}`}>{msg.text}</div>}
          <div className="hint">No install. We only clone public code, never your secrets.</div>
        </div>
      </div>

      <section id="how">
        <h2>How it works</h2>
        <div className="steps">
          <div className="step"><div className="n">01</div><h3>Connect + paste the repo</h3><p>Connect a Solana wallet and paste a public GitHub URL. Nothing to install.</p></div>
          <div className="step"><div className="n">02</div><h3>You pay in USDC</h3><p>One click, one signature. No card, no account.</p></div>
          <div className="step"><div className="n">03</div><h3>You get the report</h3><p>A clear, dated document with severity, location, and fix pointers, by email.</p></div>
        </div>
      </section>

      <section id="offers">
        <h2>Two ways to work together</h2>
        <div className="offers">
          <div className="offer mark">
            <div className="tag">ON DEMAND</div>
            <h3>The scan</h3>
            <div className="p">{AMOUNT} USDC <small>per scan</small></div>
            <ul>
              <li>RustSec and OSV advisories on your exact versions</li>
              <li>Build hygiene (overflow-checks, Anchor version)</li>
              <li>Code leads mapped to the 18 known classes</li>
              <li>Dated report, severity and file:line</li>
            </ul>
            <a className="btn" href="#top" onClick={(e) => { e.preventDefault(); window.scrollTo({ top: 0, behavior: "smooth" }); }}>Run a scan</a>
          </div>
          <div className="offer">
            <div className="tag">CONTINUOUS</div>
            <h3>The watch</h3>
            <div className="p">custom <small>per month</small></div>
            <ul>
              <li>Daily monitoring of your dependency tree</li>
              <li>Human pass on every newly merged commit</li>
              <li>Private report and a dedicated alert channel</li>
              <li>Alerted the day a flaw lands, not later in a post mortem</li>
            </ul>
            <a className="btn ghost" href={`mailto:${CONTACT}?subject=${encodeURIComponent("Continuous Solana security watch")}`}>Talk about the watch</a>
          </div>
        </div>
      </section>

      <section>
        <div className="scope">
          <strong>What this is not.</strong> A full audit is not replaceable. This service detects known vulnerability classes and dependency issues, it does not certify the absence of bugs. It is a first line of defense, not a guarantee.
        </div>
      </section>

      <section id="proof" className="proof">
        <h2>Proof before promise</h2>
        <p>Every class we cover is backed by an executable proof, not a paragraph. Everything is public, so you can verify before you pay.</p>
        <ul>
          <li><a href="https://github.com/OxToF/solana-security-watch/blob/main/examples/sample-scan-report.html">See a sample scan report</a></li>
          <li><a href="https://github.com/OxToF/solana-security-watch/blob/main/examples/watch-orca-whirlpools-2026-09-01.md">See a watch pass on a real protocol</a></li>
          <li><a href="https://github.com/OxToF/solana-security-watch">The open source toolkit (5 executable proofs, 18 classes)</a></li>
        </ul>
      </section>

      <footer>Solana Security Watch. Open source under the MIT license. The scan is a hardening aid, not a certified audit.</footer>
    </div>
  );
}
