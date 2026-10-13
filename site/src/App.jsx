import React, { useEffect, useState } from "react";
import FreeTools from "./FreeTools.jsx";

const API_BASE = import.meta.env.VITE_API_BASE || "https://solana-security-watchdog-scan.fly.dev";
const EVM_BASE = import.meta.env.VITE_EVM_API_BASE || "https://evm-watchdog-scan.fly.dev";

// Launched from the Android app (Seeker / Solana dApp Store): its start URL
// carries ?app=seeker, and a Trusted Web Activity runs in standalone mode.
// /agents is the agent page (x402, MCP, endpoints); / is for people.
const IS_AGENTS = typeof window !== "undefined" && /^\/agents\/?$/.test(window.location.pathname);

const IN_APP =
  typeof window !== "undefined" &&
  (new URLSearchParams(window.location.search).get("app") === "seeker" ||
    window.matchMedia?.("(display-mode: standalone)").matches);


const MCP_CMD = "claude mcp add watchdog -e WATCHDOG_SOLANA_PRIVATE_KEY=<base58 key> -e WATCHDOG_EVM_PRIVATE_KEY=<hex key> -- npx -y watchdog-mcp";
const MCP_JSON = `{
  "mcpServers": {
    "watchdog": {
      "command": "npx",
      "args": ["-y", "watchdog-mcp"],
      "env": {
        "WATCHDOG_SOLANA_PRIVATE_KEY": "…",
        "WATCHDOG_EVM_PRIVATE_KEY": "…",
        "WATCHDOG_BUDGET_USD": "5"
      }
    }
  }
}`;
const CURL = `curl -i -X POST ${API_BASE}/agent/program \\
  -H 'content-type: application/json' \\
  -d '{"programId":"whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"}'

HTTP/2 402
payment-required: eyJ4NDAyVmVyc2lvbiI6Mi…   # x402 v2 terms: $0.05 USDC on Solana`;
const SAMPLE = `{
  "programId": "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
  "upgradeable": true,
  "authority": {
    "kind": "squads-v4",
    "threshold": 5, "members": 13, "timeLockSeconds": 86400,
    "text": "Squads v4 multisig: 5 of 13 members must approve an upgrade, then a 24 h time lock.",
    "proof": "vault PDA re-derived from the multisig"
  },
  "lastDeploy": { "at": "2026-08-19T01:28:54Z" },
  "securityTxt": { "name": "Orca Whirlpool program", "…": "…" },
  "flags": [{ "severity": "medium", "id": "build-mismatch", "text": "…" }]
}`;

const MOMENTS = [
  { when: "Before signing", who: "Trading and DeFi agents", what: "Who can replace this program or contract tomorrow? Single key, multisig threshold and time lock, or immutable.", price: "$0.05", tool: "solana_program_authority · evm_contract_control" },
  { when: "Before adding a dependency", who: "Coding agents", what: "Known advisories for a whole Cargo.lock, package-lock.json or yarn.lock, at exact pinned versions.", price: "$0.01", tool: "dependency_advisories" },
  { when: "Before merging", who: "Agents that ship code", what: "A full scan of a public repo: on-chain vs tooling advisories, build hygiene, known bug-class leads with file:line.", price: "$0.50", tool: "scan_repo" },
  { when: "All month", who: "Treasury and portfolio agents", what: "Signed webhook the moment a program changes hands or code, a Safe weakens, or a new advisory hits your lockfile.", price: "$0.90 / 30 days", tool: "watch_create" },
];

const ENDPOINTS = [
  { svc: "Solana", path: "/agent/program", price: "0.05", net: "Solana", what: "Upgrade authority (single key, Squads v4 proved, Squads v3, DAO, immutable), last deploy, verified build, security.txt" },
  { svc: "Solana", path: "/agent/check", price: "0.01", net: "Solana", what: "RustSec / OSV advisories for a Cargo.lock or up to 100 crates" },
  { svc: "Solana", path: "/agent/scan", price: "0.50", net: "Solana", what: "Full scan of a public Rust / Anchor repo" },
  { svc: "Solana", path: "/agent/watch", price: "0.90", net: "Solana", what: "30 days of hourly checks of a program or a Cargo.lock, signed webhooks" },
  { svc: "EVM", path: "/agent/contract", price: "0.05", net: "Base", what: "Proxy kind, live implementation, upgrade controller and owner (key, Safe, timelock), Sourcify. Base and Robinhood Chain" },
  { svc: "EVM", path: "/agent/check", price: "0.01", net: "Base", what: "GitHub / OSV advisories for a package-lock.json, yarn.lock or up to 100 packages" },
  { svc: "EVM", path: "/agent/scan", price: "0.50", net: "Base", what: "Full scan of a public Solidity repo (Foundry or Hardhat)" },
  { svc: "EVM", path: "/agent/watch", price: "0.90", net: "Base", what: "30 days of hourly checks of a contract or an npm lockfile, signed webhooks" },
];

function Logo({ size = 34 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" aria-label="Watchdog x402">
      <defs><linearGradient id="wgl" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#9945FF" /><stop offset="1" stopColor="#14F195" /></linearGradient></defs>
      <circle cx="32" cy="32" r="30" fill="url(#wgl)" />
      <path d="M16 24 L21 7 L27 20 Z" fill="#efe7d6" /><path d="M48 24 L43 7 L37 20 Z" fill="#efe7d6" />
      <path d="M19.5 21 L21.6 12 L24.4 19 Z" fill="#b98cff" /><path d="M44.5 21 L42.4 12 L39.6 19 Z" fill="#b98cff" />
      <ellipse cx="32" cy="34" rx="15" ry="14" fill="#f4eddd" /><ellipse cx="32" cy="41" rx="8" ry="6.5" fill="#fffaf0" />
      <path d="M21.5 29 L28 30.5" stroke="#3a3550" strokeWidth="1.6" strokeLinecap="round" /><path d="M42.5 29 L36 30.5" stroke="#3a3550" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="26" cy="33" r="3" fill="#20202f" /><circle cx="38" cy="33" r="3" fill="#20202f" />
      <circle cx="27" cy="32.1" r="0.9" fill="#fff" /><circle cx="39" cy="32.1" r="0.9" fill="#fff" />
      <ellipse cx="32" cy="38.5" rx="2.7" ry="2" fill="#20202f" />
      <path d="M32 40.5 Q28 44 25 42" stroke="#20202f" strokeWidth="1.4" fill="none" strokeLinecap="round" /><path d="M32 40.5 Q36 44 39 42" stroke="#20202f" strokeWidth="1.4" fill="none" strokeLinecap="round" />
      <circle cx="45" cy="45" r="7.5" fill="rgba(255,255,255,.18)" stroke="#20202f" strokeWidth="2.4" /><path d="M50.4 50.4 L57 57" stroke="#20202f" strokeWidth="3.4" strokeLinecap="round" />
    </svg>
  );
}

function Code({ text, label }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }
    catch { setCopied(false); }
  }
  return (
    <div className="code">
      <div className="code-head"><span>{label}</span><button type="button" className="copy" onClick={copy}>{copied ? "Copied" : "Copy"}</button></div>
      <pre>{text}</pre>
    </div>
  );
}

export default function App() {
  const scope = (
    <section>
      <div className="scope">
        <strong>What this is not.</strong> These are checks, not an audit. Watchdog reports who controls a program, known advisories and known vulnerability classes; it does not certify the absence of bugs.
      </div>
    </section>
  );

  // The phone app is for a person checking before they put money in: the program
  // check is free, a repo scan shows a free preview, the full report is paid with
  // the wallet on the device. The agent pages stay on the website.
  if (IN_APP) {
    return (
      <div className="wrap app">
        <header>
          <div className="brand"><Logo size={34} /><span className="bt"><span className="g">Watchdog</span></span><span className="chains">Solana</span></div>
        </header>
        <section id="browser">
          <h1>Check a Solana program before you put money in</h1>
          <p className="lead">See who can change a program's code, and how fast, in seconds. Scan the source of a project for known vulnerabilities. Both are free to try.</p>
          <FreeTools />
        </section>
        {scope}
        <footer>Solana Watchdog. Open source under the MIT license. Checks, not a certified audit. <a href="/terms">Terms</a> · <a href="/privacy">Privacy</a></footer>
      </div>
    );
  }

  if (IS_AGENTS) return <Agents scope={scope} />;

  return (
    <div className="wrap">
      <header>
        <div className="brand"><Logo size={34} /><span className="bt"><span className="g">Watchdog</span></span><span className="chains">Solana</span></div>
        <nav className="nav">
          <a href="#tools">Free check</a>
          <a href="#report">The report</a>
          <a href="#measured">Benchmark</a>
          <a href="/sample-report.html">Sample</a>
          <a href="#pricing">Pricing</a>
          <a href="/agents">For agents</a>
        </nav>
      </header>

      <div className="hero">
        <div className="eyebrow">Security review for Solana programs</div>
        <h1>Check a Solana program <em>before</em> you put money in</h1>
        <p className="sub">See in seconds who can replace a program's code, and how fast. Scan a project's source the way an auditor reads it first: every account, every constraint, every dependency that ships on-chain. Free to try, no account.</p>
      </div>

      <section id="tools">
        <FreeTools />
      </section>

      <section id="report">
        <h2>What the full report covers</h2>
        <div className="moments">
          <div className="moment">
            <div className="when">The code</div>
            <h3>Every Anchor account, read like an auditor</h3>
            <p>Missing signers, accounts passed twice, re-initialization takeovers, unchecked CPI targets, data trusted from an account of unknown owner, bounds checked on a truncated value. Each issue comes with the code, why it is exploitable, and the fix.</p>
          </div>
          <div className="moment">
            <div className="when">The dependencies</div>
            <h3>Only what ships on-chain</h3>
            <p>The crates that really compile into the program for the Solana target, out of hundreds in the lockfile, each advisory judged for on-chain reach. No noise from the CLI or the test validator.</p>
          </div>
          <div className="moment">
            <div className="when">The chain</div>
            <h3>The program as deployed</h3>
            <p>Who can upgrade it (one key, a multisig and its time lock, or nobody), when it last changed, whether the binary matches public source, and how to report a bug.</p>
          </div>
          <div className="moment">
            <div className="when">Proof</div>
            <h3>A real report, anonymized</h3>
            <p>A Solana DeFi protocol of about 11,000 lines of Anchor, at a commit where a write-back bug was still present. Watchdog found it, the same one a manual review had found.</p>
            <div className="buy"><a className="btn ghost" href="/sample-report.html">Read the sample report</a></div>
          </div>
        </div>
      </section>

      <section id="measured">
        <h2>Measured, not claimed</h2>
        <div className="moments">
          <div className="moment">
            <div className="when">Every known bug class</div>
            <h3>13 of 13 caught, 0 false alarms</h3>
            <p>On <a href="https://github.com/coral-xyz/sealevel-attacks">sealevel-attacks</a>, the Anchor team's catalogue of Solana bugs: every vulnerable program flagged with the right class, none of the 22 fixed versions flagged. Run on every change to the engine.</p>
          </div>
          <div className="moment">
            <div className="when">Audited protocols</div>
            <h3>0 false issues on production code</h3>
            <p>Orca Whirlpools, Raydium CLMM, marginfi v2, Drift v2 and Marinade, scanned from their public repositories: no issue raised that was not there. A scanner that cries wolf is one nobody reads.</p>
          </div>
          <div className="moment">
            <div className="when">A real bug</div>
            <h3>The one a manual review found</h3>
            <p>In a live DeFi protocol, a pool account that could be passed twice and revert its own reserves. Watchdog flags it at the vulnerable commit and stops once it is fixed.</p>
            <div className="buy"><a className="btn ghost" href="/sample-report.html">See that report</a></div>
          </div>
        </div>
      </section>

      <section id="pricing">
        <h2>Pricing</h2>
        <div className="moments">
          <div className="moment">
            <div className="when">First one free, then 0.1 SOL</div>
            <h3>Program check</h3>
            <p>Upgrade authority, multisig rules, last code change, verified build, security contact. Any program on mainnet. The examples are always free.</p>
          </div>
          <div className="moment">
            <div className="when">Free</div>
            <h3>Repo preview</h3>
            <p>The full scan runs: risk rating, counts, coverage, the deployed program and the first issue in full.</p>
          </div>
          <div className="moment">
            <div className="when">1 SOL or 99 USDC</div>
            <h3>Full report</h3>
            <p>Every issue with its code and fix, every note to verify, every dependency judged. By email, as a page you can share with your team.</p>
          </div>
          <div className="moment">
            <div className="when">On quote</div>
            <h3>Get it fixed</h3>
            <p>A pull request on your repository: for each confirmed issue, a failing test, the fix, and the test passing. You review and merge.</p>
          </div>
        </div>
      </section>

      {scope}

      <section id="proof" className="proof">
        <h2>Verify before you pay</h2>
        <ul>
          <li><a href="https://github.com/OxToF/solana-security-watch">solana-security-watch</a>: the scanner and 5 executable proofs of known Solana bug classes</li>
          <li><a href="https://github.com/OxToF/solana-security-watch/blob/main/skills/solana-security-watch/solidity-to-anchor.md">Porting Solidity to Anchor: the traps</a></li>
          <li><a href="/sample-report.html">A real report, anonymized</a>: a Solana DeFi protocol in which the engine found the write-back bug a manual review had found</li>
        </ul>
      </section>

      <section className="agents-cta">
        <div className="scope"><strong>Building an agent?</strong> Watchdog also sells each check per call over x402, from a few cents, with an MCP server for Claude and Cursor. <a href="/agents">See the agent API</a>.</div>
      </section>

      <footer>Solana Watchdog. Open source under the MIT license. Checks, not a certified audit. <a href="/agents">For agents</a> · <a href="/terms">Terms</a> · <a href="/privacy">Privacy</a></footer>
    </div>
  );
}

function Agents({ scope }) {
  useEffect(() => { document.title = "Watchdog x402: Solana and EVM security checks your agent pays for"; }, []);
  return (
    <div className="wrap">
      <header>
        <div className="brand"><Logo size={34} /><span className="bt"><span className="g">Watchdog</span> x402</span><span className="chains">Solana · EVM</span></div>
        <nav className="nav">
          <a href="#mcp">MCP</a>
          <a href="#endpoints">Endpoints</a>
          <a href="/">For people</a>
          <a href="https://github.com/OxToF/watchdog-mcp">GitHub</a>
        </nav>
      </header>

      <div className="hero">
        <div className="eyebrow">Security checks for Solana and EVM, paid by agents per call over x402</div>
        <h1>Your agent checks the code <em>before</em> it signs</h1>
        <p className="sub">Who can replace this program? Does this lockfile carry a known advisory? Your agent asks Watchdog at the moment it decides, pays a few cents in USDC on its own over x402, and gets the answer in the same request. No account, no API key.</p>
        <div className="cta">
          <a className="btn" href="#mcp">Install the MCP server</a>
          <a className="btn ghost" href={`${API_BASE}/skill.md`}>Agent manual</a>
        </div>
        <div className="badges">
          <span className="badge">x402 v2</span>
          <span className="badge">Listed in the PayAI Bazaar</span>
          <a className="badge" href={`${API_BASE}/.well-known/agent-registration.json`}>ERC-8004 agent #96652</a>
          <a className="badge" href={`${EVM_BASE}/.well-known/agent-registration.json`}>ERC-8004 agent #96653</a>
          <a className="badge" href="https://registry.modelcontextprotocol.io/v0/servers?search=watchdog-mcp">MCP Registry</a>
        </div>
      </div>

      <section id="moments">
        <h2>Four moments an agent pays for</h2>
        <div className="moments">
          {MOMENTS.map((m) => (
            <div className="moment" key={m.when}>
              <div className="when">{m.when}</div>
              <h3>{m.who}</h3>
              <p>{m.what}</p>
              <div className="buy"><b>{m.price}</b> <code>{m.tool}</code></div>
            </div>
          ))}
        </div>
      </section>

      <section id="mcp">
        <h2>One MCP server, both chains</h2>
        <p className="lead">The <a href="https://github.com/OxToF/watchdog-mcp">watchdog-mcp</a> server gives Claude, Cursor or any MCP client eight tools that pay for themselves from a wallet you provide. Use a dedicated wallet holding a little USDC: no SOL or ETH is needed, the facilitator pays the network fee.</p>
        <Code label="Claude Code" text={MCP_CMD} />
        <Code label="Claude Desktop, Cursor and other clients" text={MCP_JSON} />
        <ul className="checks">
          <li>Pays only the Watchdog merchant wallet, in USDC, on the expected network. A server asking to be paid elsewhere is refused.</li>
          <li>A per-call cap and a session budget you set, enforced before anything is signed.</li>
          <li>Without a key, a tool returns the price instead of paying.</li>
        </ul>
      </section>

      <section id="endpoints">
        <h2>Or call the x402 endpoints directly</h2>
        <p className="lead">Every endpoint answers <code>402</code> with x402 v2 terms in the <code>PAYMENT-REQUIRED</code> header. Any x402 client pays and retries; under $1, <code>@x402/fetch</code> does it with its default settings. An address that holds no program or contract is not charged, and a check is settled only once its answer exists.</p>
        <div className="table">
          <table>
            <thead><tr><th>Endpoint</th><th>USDC</th><th>Paid on</th><th>Answer</th></tr></thead>
            <tbody>
              {ENDPOINTS.map((e) => (
                <tr key={e.svc + e.path}>
                  <td className="mono"><span className={`svc ${e.svc.toLowerCase()}`}>{e.svc}</span> POST {e.path}</td>
                  <td className="mono">{e.price}</td>
                  <td>{e.net}</td>
                  <td>{e.what}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="small">Base URLs: <code>{API_BASE}</code> and <code>{EVM_BASE}</code>. Manuals for agents: <a href={`${API_BASE}/skill.md`}>Solana</a>, <a href={`${EVM_BASE}/skill.md`}>EVM</a>.</p>
        <div className="two">
          <Code label="The first call returns the terms" text={CURL} />
          <Code label="What the agent gets for $0.05 (Orca Whirlpools)" text={SAMPLE} />
        </div>
      </section>

      {scope}

      <section className="proof">
        <h2>Verify before you pay</h2>
        <ul>
          <li><a href="https://github.com/OxToF/watchdog-mcp">watchdog-mcp</a>: the MCP server, open source, with its payment guards tested</li>
          <li><a href="https://github.com/OxToF/solana-security-watch">solana-security-watch</a>: the engine and 5 executable proofs of known Solana bug classes</li>
        </ul>
        <p className="small">Checking a program or a repo yourself? <a href="/">The free tools are here</a>.</p>
      </section>

      <footer>Solana Watchdog and EVM Watchdog. Open source under the MIT license. Checks, not a certified audit. <a href="/">Home</a> · <a href="/terms">Terms</a> · <a href="/privacy">Privacy</a></footer>
    </div>
  );
}
