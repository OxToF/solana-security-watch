import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useWallet } from "@solana/wallet-adapter-react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { Connection, PublicKey } from "@solana/web3.js";
import { API_BASE, DEFAULT_PRICE, DEFAULT_PRICE_SOL, RISK, PreviewBody, Unlock, hasLocked, isAddress, isRepo, severityCounts, short } from "./report.jsx";
import "./dashboard.css";

// The dashboard: projects (a repo plus the programs it deploys), their scans by
// commit, and each scan's report. Projects live in this browser, filed under the
// connected wallet; the scans themselves live on the server and are re-read by id.

const CLUSTERS = {
  devnet: "https://api.devnet.solana.com",
  testnet: "https://api.testnet.solana.com",
};
const CLUSTER_LABEL = { "mainnet-beta": "Mainnet", devnet: "Devnet", testnet: "Testnet" };

// --- routing: /app, /app/new, /app/p/<id>, /app/p/<id>/scan/<jobId> ---
function parse(path) {
  const m = /^\/app(?:\/(new|p)(?:\/([^/]+)(?:\/scan\/([0-9a-f-]{36}))?)?)?\/?$/.exec(path);
  if (!m) return { view: "home" };
  if (m[1] === "new") return { view: "new" };
  if (m[1] === "p" && m[3]) return { view: "scan", projectId: m[2], jobId: m[3] };
  if (m[1] === "p") return { view: "project", projectId: m[2] };
  return { view: "home" };
}
function useRoute() {
  const [route, setRoute] = useState(() => parse(window.location.pathname));
  useEffect(() => {
    const on = () => setRoute(parse(window.location.pathname));
    window.addEventListener("popstate", on);
    return () => window.removeEventListener("popstate", on);
  }, []);
  const go = useCallback((path) => {
    window.history.pushState(null, "", path);
    setRoute(parse(path));
    window.scrollTo(0, 0);
  }, []);
  return [route, go];
}
function Link({ to, go, className, children, ...rest }) {
  return <a href={to} className={className} onClick={(e) => { if (e.metaKey || e.ctrlKey || e.shiftKey) return; e.preventDefault(); go(to); }} {...rest}>{children}</a>;
}

// --- storage: one list of projects per wallet, in this browser ---
const keyFor = (owner) => `watchdog.projects.v1.${owner || "guest"}`;
function load(owner) {
  try { return JSON.parse(localStorage.getItem(keyFor(owner)) || "[]"); } catch { return []; }
}
function save(owner, projects) {
  try { localStorage.setItem(keyFor(owner), JSON.stringify(projects)); } catch {}
}
function useProjects(owner) {
  const [projects, setProjects] = useState(() => load(owner));
  useEffect(() => {
    let list = load(owner);
    // Projects made before connecting move to the wallet the first time it connects.
    if (owner && list.length === 0) {
      const guest = load(null);
      if (guest.length) { list = guest; save(owner, list); save(null, []); }
    }
    setProjects(list);
  }, [owner]);
  const update = useCallback((fn) => {
    setProjects((prev) => { const next = fn(prev); save(owner, next); return next; });
  }, [owner]);
  return [projects, update];
}
const newId = () => Math.random().toString(36).slice(2, 10);
const repoName = (url) => (url.match(/github\.com\/[^/]+\/([^/]+)/) || [])[1]?.replace(/\.git$/, "") || "project";
const ago = (iso) => {
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
};

// --- program lookup: mainnet through the server's full check, other clusters read directly ---
async function inspectOn(cluster, id) {
  if (cluster === "mainnet-beta") {
    const r = await fetch(`${API_BASE}/free/program`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ programId: id }) });
    if (r.status === 404) return null;
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || "Mainnet did not answer.");
    return { cluster, executable: true, authority: j.authority?.address || null, authorityText: j.authority?.text || null };
  }
  const conn = new Connection(CLUSTERS[cluster], "confirmed");
  const info = await conn.getAccountInfo(new PublicKey(id));
  if (!info) return null;
  if (!info.executable) return { cluster, executable: false };
  let authority = null, authorityText = "Not upgradeable (legacy loader).";
  if (info.owner.toBase58() === "BPFLoaderUpgradeab1e11111111111111111111111" && info.data.length >= 36) {
    const programData = new PublicKey(info.data.subarray(4, 36));
    const pd = await conn.getAccountInfo(programData, { dataSlice: { offset: 0, length: 45 } });
    if (pd && pd.data[12] === 1) {
      authority = new PublicKey(pd.data.subarray(13, 45)).toBase58();
      authorityText = `Upgradeable by ${short(authority)}.`;
    } else authorityText = "Immutable: no upgrade authority.";
  }
  return { cluster, executable: true, authority, authorityText };
}
async function inspectProgram(cluster, id) {
  const here = await inspectOn(cluster, id);
  if (here) return { ...here, elsewhere: [] };
  // Not on the cluster asked for: say where it does live instead of a bare "not found".
  const others = Object.keys(CLUSTER_LABEL).filter((c) => c !== cluster);
  const found = (await Promise.all(others.map((c) => inspectOn(c, id).catch(() => null)))).filter(Boolean);
  return { cluster, missing: true, elsewhere: found.map((f) => f.cluster) };
}

// --- small pieces ---
function Shield() {
  return <svg aria-hidden="true" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z" /><path d="M9 12l2 2 4-4" /></svg>;
}
function Plus() {
  return <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M12 5v14M5 12h14" /></svg>;
}
function SevChips({ s }) {
  if (!s) return <span className="d-muted">…</span>;
  return (
    <span className="d-sevs">
      <span className="d-sev c">C {s.critical}</span><span className="d-sev h">H {s.high}</span>
      <span className="d-sev m">M {s.medium}</span><span className="d-sev l">L {s.low}</span>
    </span>
  );
}
function Tile({ label, value, sub, tone }) {
  return <div className="d-tile"><span className="d-label">{label}</span><span className={`d-num ${tone || ""}`}>{value}</span>{sub && <span className="d-muted">{sub}</span>}</div>;
}

// --- views ---
function Home({ projects, go }) {
  return (
    <div className="d-empty">
      <h1>Your projects</h1>
      <p className="d-muted">A project is a repo and the programs it deploys. Each scan is pinned to a commit, so you can scan again after a fix and compare.</p>
      {projects.length === 0 ? (
        <Link to="/app/new" go={go} className="btn"><Plus /> Create your first project</Link>
      ) : (
        <div className="d-cards">
          {projects.map((p) => {
            const last = p.scans[0];
            return (
              <Link key={p.id} to={`/app/p/${p.id}`} go={go} className="d-card">
                <b>{p.name}</b>
                <span className="d-muted d-mono">{p.repo.replace("https://github.com/", "")}</span>
                {last ? <SevChips s={last.sev} /> : <span className="d-muted">No scan yet</span>}
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

function Project({ project, go, rescan }) {
  const last = project.scans[0];
  const issues = last?.sev ? last.sev.critical + last.sev.high + last.sev.medium + last.sev.low : null;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  async function again() {
    setBusy(true); setErr(null);
    try { await rescan(project); } catch (e) { setErr(e.message); setBusy(false); }
  }
  return (
    <>
      <div className="d-head">
        <div>
          <div className="d-crumb"><Link to="/app" go={go}>Projects</Link> / {project.name}</div>
          <h1>{project.name}</h1>
          <div className="d-muted"><a href={project.repo} target="_blank" rel="noreferrer">{project.repo.replace("https://", "")}</a> · {project.programs.length} program{project.programs.length === 1 ? "" : "s"}</div>
        </div>
        <button type="button" className="btn" onClick={again} disabled={busy}><Plus /> {busy ? "Starting…" : "New scan"}</button>
      </div>
      {err && <div className="msg err">{err}</div>}

      <div className="d-tiles">
        <Tile label="ISSUES TO FIX" value={issues ?? "–"} sub="on the latest scan" />
        <Tile label="CRITICAL + HIGH" value={last?.sev ? last.sev.critical + last.sev.high : "–"} sub="fix before mainnet" tone={last?.sev && last.sev.critical + last.sev.high > 0 ? "bad" : ""} />
        <Tile label="LAST SCAN" value={last ? ago(last.at) : "–"} sub={last?.commit ? `commit ${last.commit.slice(0, 7)}` : null} />
        <Tile label="RISK" value={last?.risk ? RISK[last.risk].label.replace(" risk", "") : "–"} sub={last?.risk ? "engine verdict" : null} />
      </div>

      <section className="d-sec" aria-labelledby="progs">
        <h2 id="progs">Programs</h2>
        {project.programs.length === 0 && <p className="d-muted">No program added. The scan still reads the repo and finds the program it declares.</p>}
        {project.programs.map((pr) => (
          <div className="d-prog" key={pr.cluster + pr.id}>
            <span className="d-mono d-grow">{pr.id}</span>
            <span className="d-pill ok">{CLUSTER_LABEL[pr.cluster]}</span>
            <span className="d-muted">{pr.authorityText}</span>
          </div>
        ))}
      </section>

      <section className="d-sec" aria-labelledby="hist">
        <h2 id="hist">Scan history</h2>
        {project.scans.length === 0 ? <p className="d-muted">No scan yet.</p> : (
          <div className="d-table">
            <table>
              <thead><tr><th scope="col">Commit</th><th scope="col">Date</th><th scope="col">Issues</th><th scope="col">Report</th><th scope="col"><span className="d-sr">Open</span></th></tr></thead>
              <tbody>
                {project.scans.map((s) => (
                  <tr key={s.jobId}>
                    <td className="d-mono">{s.commit ? s.commit.slice(0, 7) : "…"}</td>
                    <td className="d-muted">{ago(s.at)}</td>
                    <td><SevChips s={s.sev} /></td>
                    <td><span className={`d-pill ${s.paid ? "ok" : "pre"}`}>{s.paid ? (s.paid.confirmed ? "Paid, by email" : "Payment confirming") : "Free preview"}</span></td>
                    <td className="d-right"><Link to={`/app/p/${project.id}/scan/${s.jobId}`} go={go}>Open</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

const STEPS = ["Source", "Programs", "Scope", "Results"];
function Stepper({ step }) {
  return (
    <ol className="d-steps">
      {STEPS.map((s, i) => (
        <li key={s} className={i < step ? "done" : i === step ? "on" : ""} aria-current={i === step ? "step" : undefined}>
          <span className="d-dot">{i < step ? "✓" : i + 1}</span>{s}
        </li>
      ))}
    </ol>
  );
}

function NewScan({ go, create }) {
  const [step, setStep] = useState(0);
  const [repo, setRepo] = useState("");
  const [name, setName] = useState("");
  const [programs, setPrograms] = useState([]);
  const [cluster, setCluster] = useState("devnet");
  const [pid, setPid] = useState("");
  const [look, setLook] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  function next() {
    setErr(null);
    if (step === 0) {
      const r = repo.trim().replace(/\/$/, "");
      if (!isRepo(r)) return setErr("Enter a public https://github.com/org/repo URL.");
      setRepo(r);
      if (!name.trim()) setName(repoName(r));
    }
    setStep(step + 1);
  }
  async function fetchProgram() {
    setErr(null); setLook(null);
    const id = pid.trim();
    if (!isAddress(id)) return setErr("Paste a Solana program address.");
    setBusy(true);
    try {
      const r = await inspectProgram(cluster, id);
      setLook(r);
      if (!r.missing && r.executable && !programs.some((p) => p.id === id && p.cluster === r.cluster)) {
        setPrograms([...programs, { id, cluster: r.cluster, authority: r.authority, authorityText: r.authorityText }]);
        setPid("");
      }
    } catch (e) { setErr(e.message || "The cluster did not answer. Try again."); }
    finally { setBusy(false); }
  }
  async function run() {
    setBusy(true); setErr(null);
    try { await create({ name: name.trim() || repoName(repo), repo, programs }); }
    catch (e) { setErr(e.message); setBusy(false); }
  }

  return (
    <>
      <div className="d-head">
        <div>
          <div className="d-crumb"><Link to="/app" go={go}>Projects</Link> / New scan</div>
          <h1>Start a new scan</h1>
          <div className="d-muted">Point us at the code and the deployed program. The summary is free; you pay only to unlock the full report.</div>
        </div>
      </div>
      <div className="d-split">
        <section className="d-panel" aria-label="Scan setup">
          <Stepper step={step} />
          <div className="d-body">
            <span className="d-label">STEP {step + 1} OF 4</span>
            {step === 0 && (
              <>
                <h2>Where is the code?</h2>
                <p className="d-muted">A public Rust / Anchor repo on GitHub. The scan reads the default branch at its latest commit.</p>
                <label className="d-field"><span>Repository</span><input className="fld" type="url" placeholder="https://github.com/org/repo" value={repo} onChange={(e) => setRepo(e.target.value)} spellCheck={false} autoCapitalize="off" /></label>
                <label className="d-field"><span>Project name</span><input className="fld" placeholder={repo ? repoName(repo) : "my-protocol"} value={name} onChange={(e) => setName(e.target.value)} /></label>
              </>
            )}
            {step === 1 && (
              <>
                <h2>Add the deployed programs</h2>
                <p className="d-muted">Optional. Any cluster, devnet included: we read who can upgrade each one. Not deployed yet? Skip this step.</p>
                <div className="d-row">
                  <label className="d-field"><span>Cluster</span>
                    <select className="fld" value={cluster} onChange={(e) => setCluster(e.target.value)}>
                      {Object.entries(CLUSTER_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                    </select>
                  </label>
                  <label className="d-field d-grow"><span>Program ID</span><input className="fld d-mono" value={pid} onChange={(e) => setPid(e.target.value)} spellCheck={false} autoCapitalize="off" /></label>
                  <button type="button" className="btn d-light" onClick={fetchProgram} disabled={busy}>{busy ? "Fetching…" : "Fetch"}</button>
                </div>
                {look?.missing && (
                  <div className="msg err">
                    Not found on {CLUSTER_LABEL[look.cluster]}.
                    {look.elsewhere.length > 0 ? <> It lives on {look.elsewhere.map((c) => CLUSTER_LABEL[c]).join(" and ")}: <button type="button" className="d-linkbtn" onClick={() => { setCluster(look.elsewhere[0]); setLook(null); }}>switch to {CLUSTER_LABEL[look.elsewhere[0]]}</button>.</> : " Not on any other cluster either."}
                  </div>
                )}
                {look && !look.missing && !look.executable && <div className="msg err">This address is an account, not a program.</div>}
                {programs.map((p) => (
                  <div className="d-prog ok" key={p.cluster + p.id}>
                    <span aria-hidden="true">✓</span><span className="d-mono d-grow">{short(p.id)}</span>
                    <span className="d-pill ok">{CLUSTER_LABEL[p.cluster]}</span><span className="d-muted">{p.authorityText}</span>
                    <button type="button" className="d-linkbtn" onClick={() => setPrograms(programs.filter((x) => x !== p))} aria-label={`Remove ${p.id}`}>Remove</button>
                  </div>
                ))}
              </>
            )}
            {step === 2 && (
              <>
                <h2>What gets checked</h2>
                <ul className="checks">
                  <li>Every Anchor account, constraint and handler, against the known Solana bug classes (account substitution, missing signer, duplicate mutable accounts, unchecked casts, re-initialisation, rounding).</li>
                  <li>The dependencies that really compile into the program, each advisory judged for on-chain reach.</li>
                  <li>The deployed program: who can upgrade it, and whether the build is verified.</li>
                </ul>
                <p className="d-muted">These are checks, not an audit: Watchdog does not certify the absence of bugs.</p>
              </>
            )}
            {step === 3 && (
              <>
                <h2>Ready</h2>
                <p className="d-muted">The scan takes about a minute. You get the risk verdict, every count and the first issue in full, free.</p>
              </>
            )}
            {err && <div className="msg err">{err}</div>}
          </div>
          <div className="d-foot">
            {step === 0 ? <Link to="/app" go={go} className="btn ghost">Cancel</Link> : <button type="button" className="btn ghost" onClick={() => { setErr(null); setStep(step - 1); }}>Back</button>}
            {step < 3 ? <button type="button" className="btn" onClick={next}>{step === 1 && programs.length === 0 ? "Skip" : "Continue"}</button>
              : <button type="button" className="btn" onClick={run} disabled={busy}>{busy ? "Starting…" : "Run free scan"}</button>}
          </div>
        </section>
        <aside className="d-aside">
          <div className="d-panel d-pad">
            <span className="d-label">SCAN SUMMARY</span>
            <dl className="d-dl">
              <dt>Project</dt><dd>{name || (repo && isRepo(repo) ? repoName(repo) : "–")}</dd>
              <dt>Source</dt><dd className="d-mono">{repo && isRepo(repo) ? repo.replace("https://github.com/", "") : "–"}</dd>
              <dt>Programs</dt><dd>{programs.length ? programs.map((p) => CLUSTER_LABEL[p.cluster]).join(", ") : "–"}</dd>
            </dl>
          </div>
          <div className="d-panel d-pad">
            <span className="d-label">PRICING</span>
            <div className="d-price"><span>Summary + 1 issue in full</span><b className="okc">Free</b></div>
            <div className="d-price"><span>Full report, file:line, fixes</span><b>{DEFAULT_PRICE_SOL} SOL</b></div>
            <div className="d-price d-muted"><span>or in stablecoin</span><span>{DEFAULT_PRICE} USDC</span></div>
          </div>
        </aside>
      </div>
    </>
  );
}

function Report({ project, jobId, go, onUpdate }) {
  const [state, setState] = useState(null);
  const [gone, setGone] = useState(false);
  const poll = useRef(null);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await fetch(`${API_BASE}/free/scan/${jobId}`);
        if (r.status === 404) { if (alive) setGone(true); return; }
        const s = await r.json();
        if (!alive) return;
        setState(s);
        if (s.status === "expired") return setGone(true);
        if (s.status === "done" && s.preview) return onUpdate(jobId, { commit: s.preview.commit, risk: s.preview.risk, sev: severityCounts(s.preview) });
        if (s.status === "error") return onUpdate(jobId, { error: true });
      } catch {}
      if (alive) poll.current = setTimeout(tick, 3000);
    };
    tick();
    return () => { alive = false; clearTimeout(poll.current); };
  }, [jobId]); // eslint-disable-line react-hooks/exhaustive-deps

  const p = state?.preview?.risk ? state.preview : null;
  const scan = project.scans.find((s) => s.jobId === jobId);
  const c = p && severityCounts(p);
  return (
    <>
      <div className="d-head">
        <div>
          <div className="d-crumb"><Link to="/app" go={go}>Projects</Link> / <Link to={`/app/p/${project.id}`} go={go}>{project.name}</Link> / Scan {p?.commit ? p.commit.slice(0, 7) : ""}</div>
          <h1>Scan results</h1>
          <div className="d-muted d-mono">{project.repo.replace("https://github.com/", "")}{p?.commit ? ` @ ${p.commit.slice(0, 7)}` : ""}</div>
        </div>
        <span className={`d-pill ${scan?.paid ? "ok" : "pre"}`}>{scan?.paid ? "Paid: full report by email" : "Free preview"}</span>
      </div>

      {gone && <div className="msg err">This preview is no longer stored. Start a new scan from the project page.</div>}
      {!gone && !p && state?.status !== "error" && <div className="d-panel d-pad d-wait"><span className="d-spin" aria-hidden="true" />Cloning and scanning. About a minute…</div>}
      {state?.status === "error" && <div className="msg err">{state.error}</div>}

      {p && (
        <>
          <div className="d-tiles">
            <Tile label="CRITICAL" value={c.critical} tone={c.critical ? "c" : ""} />
            <Tile label="HIGH" value={c.high} tone={c.high ? "h" : ""} />
            <Tile label="MEDIUM" value={c.medium} tone={c.medium ? "m" : ""} />
            <Tile label="LOW" value={c.low} tone={c.low ? "l" : ""} />
          </div>
          <div className="d-split">
            <div className={`result tone-${RISK[p.risk].tone} d-grow`}>
              <PreviewBody p={p} />
              <p className="hint">{p.disclaimer}</p>
            </div>
            {hasLocked(p) && (
              <aside className="d-aside">
                <div className="d-panel d-pad d-unlock">
                  {scan?.paid ? (
                    <p className="msg ok">{scan.paid.confirmed ? "Paid. The full report is on its way to your inbox." : "Payment sent. The report reaches your inbox once it confirms."}</p>
                  ) : (
                    <Unlock repo={project.repo} price={state.unlockPriceUsd ?? DEFAULT_PRICE} priceSol={state.unlockPriceSol ?? DEFAULT_PRICE_SOL} onPaid={(paid) => onUpdate(jobId, { paid })} />
                  )}
                </div>
              </aside>
            )}
          </div>
        </>
      )}
    </>
  );
}

export default function Dashboard() {
  const { publicKey } = useWallet();
  const owner = publicKey?.toBase58() || null;
  const [projects, update] = useProjects(owner);
  const [route, go] = useRoute();
  const current = useMemo(() => projects.find((p) => p.id === route.projectId), [projects, route.projectId]);

  async function startScan(projectId, repo) {
    const r = await fetch(`${API_BASE}/free/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repo }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || "Could not start the scan.");
    update((ps) => ps.map((p) => p.id === projectId ? { ...p, scans: [{ jobId: j.jobId, at: new Date().toISOString() }, ...p.scans.filter((s) => s.jobId !== j.jobId)] } : p));
    go(`/app/p/${projectId}/scan/${j.jobId}`);
  }
  async function create({ name, repo, programs }) {
    const id = newId();
    update((ps) => [{ id, name, repo, programs, scans: [], createdAt: new Date().toISOString() }, ...ps]);
    await startScan(id, repo);
  }
  const onUpdate = useCallback((jobId, patch) => {
    update((ps) => ps.map((p) => p.id !== route.projectId ? p : { ...p, scans: p.scans.map((s) => s.jobId === jobId ? { ...s, ...patch } : s) }));
  }, [update, route.projectId]);

  let body;
  if (route.view === "new") body = <NewScan go={go} create={create} />;
  else if ((route.view === "project" || route.view === "scan") && !current) body = <div className="d-empty"><h1>Project not found</h1><p className="d-muted">Projects are kept in the browser they were made in, under the wallet that was connected.</p><Link to="/app" go={go} className="btn">All projects</Link></div>;
  else if (route.view === "project") body = <Project project={current} go={go} rescan={(p) => startScan(p.id, p.repo)} />;
  else if (route.view === "scan") body = <Report key={route.jobId} project={current} jobId={route.jobId} go={go} onUpdate={onUpdate} />;
  else body = <Home projects={projects} go={go} />;

  return (
    <div className="dash">
      <nav className="d-side" aria-label="Main">
        <a href="/" className="d-brand"><Shield /><span>Watchdog</span></a>
        <div className="d-wallet"><WalletMultiButton /></div>
        <p className="d-note">{owner ? <>Projects are saved in this browser under {short(owner)}.</> : "Connect a wallet to keep your projects under your address. They stay in this browser."}</p>
        <div className="d-nav">
          <span className="d-label">PROJECTS</span>
          {projects.map((p) => (
            <Link key={p.id} to={`/app/p/${p.id}`} go={go} className={`d-navi ${p.id === route.projectId ? "on" : ""}`}>
              <span className="d-bullet" aria-hidden="true" /><span className="d-grow">{p.name}</span>
              <span className="d-mini">{p.programs[0] ? CLUSTER_LABEL[p.programs[0].cluster] : "repo"}</span>
            </Link>
          ))}
          <Link to="/app/new" go={go} className="d-navi d-add"><Plus /> New project</Link>
        </div>
        <div className="d-bottom">
          <a href="/#mcp" className="d-navi">API &amp; MCP for agents</a>
          <a href="/terms" className="d-navi">Terms</a>
        </div>
      </nav>
      <main className="d-main">{body}</main>
    </div>
  );
}
