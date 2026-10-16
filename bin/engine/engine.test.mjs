// node --test bin/engine/engine.test.mjs
// The analysis engine against code whose answer is known: the five planted-bug PoCs of
// this repo, and small fixtures of guard styles seen in real programs. A rule that stops
// firing on its PoC, or starts firing on a guarded fixture, fails here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeAnchor, maskRust } from "./anchor.mjs";
import { targetMatchesSolana, parseManifest, parseLockGraph } from "./reach.mjs";
import { judgeAdvisories, severityLabel } from "./advisories.mjs";
import { buildModel } from "./report.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const poc = (name) => analyzeAnchor([join(ROOT, "poc", name, "programs", name)], join(ROOT, "poc", name));
const rules = (r) => r.findings.filter((f) => f.confidence !== "low").map((f) => `${f.severity}:${f.rule}`);

test("each planted PoC bug is reported, at the right severity", () => {
  assert.deepEqual(rules(poc("duplicate-mutable")), ["high:duplicate-mutable-accounts"]);
  assert.deepEqual(rules(poc("init-reinit")), ["critical:reinit-takeover"]);
  assert.deepEqual(rules(poc("account-substitution")), ["high:unverified-account-data"]);
  assert.deepEqual(rules(poc("unbounded-cast")), ["high:truncated-bound-check"]);
});

test("a check in one handler does not cover another handler of the same struct", () => {
  const [f] = poc("duplicate-mutable").findings;
  assert.deepEqual(f.handlers, ["transfer_insecure"]);
  assert.match(f.fix, /transfer_secure/);
});

function fixture(src) {
  const dir = mkdtempSync(join(tmpdir(), "wd-fixture-"));
  mkdirSync(join(dir, "programs", "p", "src"), { recursive: true });
  writeFileSync(join(dir, "programs", "p", "src", "lib.rs"), src);
  return analyzeAnchor([join(dir, "programs", "p")], dir);
}
const POOLS = `
#[account] pub struct Pool { pub reserve: u64 }
#[derive(Accounts)]
pub struct Route<'info> {
    pub cranker: Signer<'info>,
    #[account(mut)] pub sell_pool: Box<Account<'info, Pool>>,
    #[account(mut)] pub hop_pool: Option<Box<Account<'info, Pool>>>,
}`;

test("duplicate accounts: unguarded is reported, guards in the styles real code uses are seen", () => {
  assert.equal(fixture(`${POOLS}
pub fn route(ctx: Context<Route>) -> Result<()> { ctx.accounts.sell_pool.reserve += 1; Ok(()) }`).findings.length, 1);
  // Through a closure on the Option, with a tuple-destructured alias.
  assert.equal(fixture(`${POOLS}
pub fn route(ctx: Context<Route>) -> Result<()> {
    let a = &mut ctx.accounts;
    let (sell,) = (a.sell_pool.key(),);
    require!(a.hop_pool.as_ref().is_none_or(|h| h.key() != sell), E::X);
    Ok(())
}`).findings.length, 0);
  // In a helper the handler calls.
  assert.equal(fixture(`${POOLS}
fn check(a: &Route) -> Result<()> { require_keys_neq!(a.sell_pool.key(), a.hop_pool.as_ref().unwrap().key()); Ok(()) }
pub fn route(ctx: Context<Route>) -> Result<()> { check(&ctx.accounts)?; Ok(()) }`).findings.length, 0);
});

test("missing signer: an authority bound by has_one but never signing is critical", () => {
  const r = fixture(`
#[account] pub struct Vault { pub authority: Pubkey }
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)] pub vault: Account<'info, Vault>,
    /// CHECK: compared by has_one
    pub authority: UncheckedAccount<'info>,
}
pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }`);
  assert.deepEqual(rules(r), ["critical:missing-signer"]);
  assert.equal(fixture(`
#[account] pub struct Vault { pub authority: Pubkey }
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)] pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}`).findings.length, 0);
});

test("comments and strings never confuse the parser", () => {
  const m = maskRust(`let s = "{ not a brace }"; // } nor this\nlet c = '{';`);
  assert.equal((m.match(/[{}]/g) || []).length, 0);
});

test("cfg(...) is evaluated for the Solana target", () => {
  assert.equal(targetMatchesSolana(null), true);
  assert.equal(targetMatchesSolana(`cfg(not(target_os = "solana"))`), false);
  assert.equal(targetMatchesSolana(`cfg(target_os = "solana")`), true);
  assert.equal(targetMatchesSolana(`cfg(any(target_arch = "x86_64", target_arch = "aarch64"))`), false);
  assert.equal(targetMatchesSolana(`cfg(all(target_os = "solana", not(feature = "x")))`), false);
  assert.equal(targetMatchesSolana(`cfg(unix)`), false);
  assert.equal(targetMatchesSolana("x86_64-unknown-linux-gnu"), false);
});

test("manifests: target tables, renames and dev-dependencies", () => {
  const m = parseManifest(`[package]
name = "prog"
[lib]
crate-type = ["cdylib", "lib"]
[dependencies]
anchor-lang = { version = "0.30", features = [
  "init-if-needed",
] }
borsh_renamed = { package = "borsh", version = "1" }
[target.'cfg(not(target_os = "solana"))'.dependencies]
rand = "0.8"
[dev-dependencies]
proptest = "1"`);
  assert.equal(m.name, "prog");
  assert.equal(m.cdylib, true);
  assert.deepEqual(m.deps.map((d) => [d.crate, d.kind, d.target]), [
    ["anchor-lang", "normal", null], ["borsh", "normal", null],
    ["rand", "normal", `cfg(not(target_os = "solana"))`], ["proptest", "dev", null],
  ]);
  const g = parseLockGraph(`[[package]]\nname = "a"\nversion = "1.0.0"\ndependencies = [\n "b",\n "c 2.0.0",\n]\n`);
  assert.deepEqual(g[0].deps, ["b", "c 2.0.0"]);
});

test("advisories: only crates in the program count, and a known non-issue says why", () => {
  const advs = [
    { id: "RUSTSEC-2024-0344", aliases: [], severity: "LOW", summary: "timing", crates: ["curve25519-dalek 3.2.0"], url: "u" },
    { id: "RUSTSEC-2024-0402", aliases: [], severity: "HIGH", summary: "borsh HashMap", crates: ["hashbrown 0.15.0"], url: "u" },
    { id: "X-1", aliases: [], severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", summary: "quinn", crates: ["quinn-proto 0.11.14"], url: "u" },
    { id: "X-2", aliases: [], severity: "UNSPECIFIED", summary: "foo is unmaintained", crates: ["foo 1.0.0"], url: "u" },
  ];
  const closure = { crates: new Set(["curve25519-dalek 3.2.0", "hashbrown 0.15.0"]) };
  const j = judgeAdvisories(advs, closure, "pub struct S { a: u64 }");
  assert.deepEqual(j.onchain.map((a) => [a.id, a.verdict]), [["RUSTSEC-2024-0402", "not-exploitable"], ["RUSTSEC-2024-0344", "not-exploitable"]]);
  assert.match(j.onchain[0].note, /never uses HashMap/);
  assert.equal(judgeAdvisories(advs, closure, "use std::collections::HashMap;").onchain[0].verdict, "conditional");
  assert.deepEqual(j.offchain.map((a) => a.id), ["X-1"]);
  assert.deepEqual(j.housekeeping.map((a) => a.id), ["X-2"]);
  assert.equal(severityLabel("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), "HIGH");
  assert.equal(severityLabel("UNSPECIFIED"), "UNRATED");
});

test("risk rating: a mainnet single key is high even with clean code", () => {
  const base = { meta: { owner: "o", repo: "r", date: "d" }, programs: [], analysis: { findings: [], stats: { files: 1, structs: 1, fields: 1, handlers: 1, initIfNeeded: 0 } }, deps: { onchain: [], offchain: [], housekeeping: [], reachKnown: true }, closure: null, lockSize: 0, hygiene: {} };
  assert.equal(buildModel({ ...base, deployed: [] }).risk, "clean");
  assert.equal(buildModel({ ...base, deployed: [{ cluster: "mainnet", authority: { kind: "single-key", text: "t" } }] }).risk, "high");
  assert.equal(buildModel({ ...base, deployed: [{ cluster: "devnet", authority: { kind: "single-key", text: "t" } }] }).risk, "clean");
});

test("precision: no finding for a hard-coded CPI target, forwarded proofs, or a recorded admin", () => {
  const CNFT = `
#[derive(Accounts)]
pub struct Burn<'info> {
    pub owner: Signer<'info>,
    /// CHECK: listed for the CPI
    pub bubblegum_program: UncheckedAccount<'info>,
}`;
  // program_id hard-coded, proof nodes only passed along: real code from program-examples.
  assert.equal(fixture(`${CNFT}
pub fn burn(ctx: Context<Burn>) -> Result<()> {
    let mut accounts = vec![];
    for acc in ctx.remaining_accounts.iter() { accounts.push(AccountMeta::new_readonly(acc.key(), false)); }
    let ix = Instruction { program_id: MPL_BUBBLEGUM_ID, accounts, data: vec![] };
    invoke(&ix, &[ctx.accounts.bubblegum_program.to_account_info()])?;
    Ok(())
}`).findings.length, 0);
  // The same account as the call's target is reported.
  assert.deepEqual(rules(fixture(`${CNFT}
pub fn burn(ctx: Context<Burn>) -> Result<()> {
    let ix = Instruction { program_id: ctx.accounts.bubblegum_program.key(), accounts: vec![], data: vec![] };
    invoke(&ix, &[])?;
    Ok(())
}`)), ["high:arbitrary-cpi"]);
  // remaining_accounts whose bytes are read here, unchecked, are reported.
  assert.deepEqual(rules(fixture(`${CNFT}
pub fn burn(ctx: Context<Burn>) -> Result<()> {
    let d = ctx.remaining_accounts[0].try_borrow_data()?;
    Ok(())
}`)), ["high:unchecked-remaining-accounts"]);
  // An admin only recorded at creation authorizes nothing: not a missing signer.
  assert.equal(fixture(`
#[account] pub struct Amm { pub admin: Pubkey }
#[derive(Accounts)]
pub struct CreateAmm<'info> {
    #[account(init, payer = payer, space = 40)] pub amm: Account<'info, Amm>,
    /// CHECK: read only
    pub admin: AccountInfo<'info>,
    #[account(mut)] pub payer: Signer<'info>,
}
pub fn create(ctx: Context<CreateAmm>) -> Result<()> { ctx.accounts.amm.admin = ctx.accounts.admin.key(); Ok(()) }`).findings.length, 0);
});

test("a thread-safety advisory is not exploitable in a single-threaded program", () => {
  const j = judgeAdvisories([{ id: "RUSTSEC-2020-0137", aliases: [], severity: "HIGH", summary: "Data races in lever", crates: ["lever 0.1.0"], url: "u" }], { crates: new Set(["lever 0.1.0"]) });
  assert.equal(j.onchain[0].verdict, "not-exploitable");
});

test("production patterns: keeper-signed authority is a note, delegated remaining_accounts and mocks are left alone", () => {
  // Drift-style: the user's authority is identified (has_one), a keeper signs.
  const r = fixture(`
#[account] pub struct User { pub authority: Pubkey }
#[derive(Accounts)]
pub struct ForceDelete<'info> {
    #[account(mut, has_one = authority)] pub user: Account<'info, User>,
    /// CHECK: receives the rent
    #[account(mut)] pub authority: AccountInfo<'info>,
    pub keeper: Signer<'info>,
}
pub fn force_delete(ctx: Context<ForceDelete>) -> Result<()> { Ok(()) }`);
  assert.deepEqual(rules(r), []);
  assert.deepEqual(r.findings.map((f) => `${f.confidence}:${f.rule}`), ["low:missing-signer"]);
  // remaining_accounts handed to a loader that validates them.
  assert.equal(fixture(`
#[derive(Accounts)]
pub struct Swap<'info> { pub user: Signer<'info> }
pub fn swap(ctx: Context<Swap>) -> Result<()> { let maps = load_maps(ctx.remaining_accounts)?; Ok(()) }`).findings.length, 0);
  // A plain transfer next to transfer_checked: the classic-SPL branch, deliberate.
  assert.equal(fixture(`
pub fn send(a: u64) -> Result<()> {
    if is_2022 { token_interface::transfer_checked(cpi, a, d) } else { token_interface::transfer(cpi, a) }
}`).findings.length, 0);
});

test("SARIF and merge gate: issues are alerts at the scanned path, points to verify never block", async () => {
  const { renderSarif, gateFailures } = await import("./report.mjs");
  const m = {
    confident: [{ ref: "W-01", rule: "missing-signer", severity: "high", confidence: "high", title: "`authority` never signs", why: "w", fix: "f", file: "src/lib.rs", line: 16, struct: "S" }],
    review: [{ rule: "unchecked-mut-account", severity: "high", confidence: "low", title: "t", why: "w", file: "src/lib.rs", line: 30 }],
    deps: { onchain: [{ id: "RUSTSEC-0000-0001", severity: "MEDIUM", crates: ["borsh"], summary: "s", url: "u", verdict: "exploitable", note: "n" }] },
  };
  const s = renderSarif(m, { root: "programs/x", lockLine: () => ({ file: "Cargo.lock", line: 7 }) });
  const r = s.runs[0].results;
  assert.equal(r.length, 3);
  assert.equal(r[0].level, "error");
  assert.equal(r[0].locations[0].physicalLocation.artifactLocation.uri, "programs/x/src/lib.rs");
  assert.equal(r[1].level, "note");
  assert.equal(r[2].locations[0].physicalLocation.artifactLocation.uri, "programs/x/Cargo.lock");
  assert.ok(s.runs[0].tool.driver.rules.some((x) => x.id === "RUSTSEC-0000-0001"));
  assert.equal(gateFailures(m, "high").length, 1);
  assert.equal(gateFailures(m, "medium").length, 2);
  assert.equal(gateFailures(m, "critical").length, 0);
  assert.equal(gateFailures(m, "none").length, 0);
  assert.throws(() => gateFailures(m, "bogus"));
});

test("math: rounding up a payout, rewards without precision, division before multiplication", () => {
  const rules = (src) => fixture(src).findings.map((f) => `${f.confidence}:${f.rule}`);
  // The rounding PoC: the ceiling in redeem_insecure only.
  const poc = analyzeAnchor([join(ROOT, "poc", "rounding-arbitrage", "programs", "rounding-arbitrage")], join(ROOT, "poc", "rounding-arbitrage")).findings;
  assert.deepEqual(poc.map((f) => `${f.confidence}:${f.rule}:${f.line}`), ["medium:rounding-up-payout:38"]);
  // Funding side rounds up on purpose; a gross-up for a fee too.
  assert.deepEqual(rules(`pub fn set_reward_params(x: u64, d: u64) -> u64 { let reward_amount = x.div_ceil(d); reward_amount }`), []);
  assert.deepEqual(rules(`pub fn redeem(x: u128, d: u128) -> u128 { let payout = x.checked_mul(10).unwrap().div_ceil(d - fee); payout }`), []);
  // Reward per share: unscaled is lost on small emissions, scaled is fine.
  const acc = (scale) => `pub fn update(pool: &mut Pool, rewards: u128) {
    let delta = rewards${scale} / (pool.total_staked as u128);
    pool.reward_per_share += delta;
  }`;
  assert.deepEqual(rules(acc("")), ["medium:reward-accumulator-precision"]);
  assert.deepEqual(rules(acc(" * REWARD_PRECISION")), []);
  // Division before multiplication between state values; flooring to a week is deliberate.
  assert.deepEqual(rules(`pub fn share(r: u64, total: u64, bal: u64) -> u64 { let owed_now = r / total * bal; owed_now }`), ["low:divide-before-multiply"]);
  assert.deepEqual(rules(`pub fn lock_end(now: i64, d: i64) -> i64 { let end = (now + d) / WEEK * WEEK; end }`), []);
  assert.deepEqual(rules(`pub fn px(a: u128, d: u32) -> u128 { let p = a.safe_div(10_u128.pow(d)).unwrap().safe_mul(PRICE_PRECISION).unwrap(); p }`), []);
});

test("advisories judged from the code: borsh ZST, called functions, target arch", async () => {
  const { judgeAdvisories, borshZst } = await import("./advisories.mjs");
  const closure = { crates: new Set(["borsh 0.10.3", "anyhow 1.0.99", "keccak 0.1.4"]) };
  const adv = (id, crate, extra = {}) => ({ id, aliases: [], severity: "MEDIUM", summary: "s", crates: [crate], url: "u", ...extra });
  const files = (raw) => [{ rel: "programs/p/src/lib.rs", raw }];
  const zstSrc = `pub struct Marker;\n#[derive(AnchorSerialize, AnchorDeserialize)]\npub struct Args {\n  pub tags: Vec<Marker>,\n}`;
  assert.equal(borshZst(files(zstSrc)).verdict, "conditional");
  assert.equal(borshZst(files(zstSrc)).evidence[0].line, 4);
  assert.equal(borshZst(files(zstSrc.replace("pub struct Marker;", "#[derive(Clone, Copy)]\npub struct Marker;"))).verdict, "not-exploitable");
  // () and PhantomData are Copy: no longer a reason to worry.
  assert.equal(borshZst(files(`#[account]\npub struct S { pub a: u64, pub p: PhantomData<u8> }`)).verdict, "not-exploitable");
  const j = judgeAdvisories([
    adv("RUSTSEC-2023-0033", "borsh 0.10.3"),
    adv("RUSTSEC-2026-0190", "anyhow 1.0.99", { functions: ["anyhow::Error::downcast_mut"] }),
    adv("RUSTSEC-9999-0001", "keccak 0.1.4", { arch: ["aarch64"] }),
  ], closure, files(`use anyhow::Error;\nfn f(e: &mut Error) { e.downcast_mut::<u8>(); }`));
  const by = Object.fromEntries(j.onchain.map((a) => [a.id, a]));
  assert.equal(by["RUSTSEC-2023-0033"].verdict, "not-exploitable");
  assert.equal(by["RUSTSEC-2026-0190"].verdict, "conditional");
  assert.equal(by["RUSTSEC-2026-0190"].evidence[0].line, 2);
  assert.equal(by["RUSTSEC-9999-0001"].verdict, "not-exploitable");
  const k = judgeAdvisories([adv("RUSTSEC-2026-0190", "anyhow 1.0.99", { functions: ["anyhow::Error::downcast_mut"] })], closure, files(`fn f() {}`));
  assert.equal(k.onchain[0].verdict, "not-called");
});
