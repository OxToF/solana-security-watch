// node --test server/watch.test.mjs
// What counts as a change, the webhook guards, and the scheduler.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac } from "node:crypto";
import { Store } from "./store.mjs";
import { Watcher, diffProgram, diffLockfile, lockfileSnapshot, isPrivateAddress, checkWebhookUrl, sign } from "./watch.mjs";

const squads = (threshold, members, timeLockSeconds, address = "VAULT") => ({ exists: true, executable: true, authority: { kind: "squads-v4", address, threshold, members, timeLockSeconds }, deploySlot: 100, verified: true });
const ids = (events) => events.map((e) => e.type);

test("program changes that matter, and nothing else", () => {
  assert.deepEqual(diffProgram(squads(5, 13, 86400), squads(5, 13, 86400)), []);
  assert.deepEqual(ids(diffProgram(squads(5, 13, 86400), { ...squads(5, 13, 86400), deploySlot: 200 })), ["code-upgraded"]);
  const toKey = diffProgram(squads(5, 13, 86400), { ...squads(5, 13, 86400), authority: { kind: "single-key", address: "KEY" } });
  assert.deepEqual(ids(toKey), ["authority-changed"]);
  assert.equal(toKey[0].severity, "high");
  const weaker = diffProgram(squads(5, 13, 86400), squads(1, 13, 86400));
  assert.deepEqual(ids(weaker), ["multisig-changed"]);
  assert.equal(weaker[0].severity, "high");
  assert.equal(diffProgram(squads(5, 13, 86400), squads(5, 13, 0))[0].severity, "high"); // time lock removed
  assert.equal(diffProgram(squads(3, 5, 0), squads(4, 5, 0))[0].severity, "medium");
  assert.deepEqual(ids(diffProgram(squads(5, 13, 0), { ...squads(5, 13, 0), verified: false })), ["verification-lost"]);
  assert.deepEqual(ids(diffProgram(squads(5, 13, 0), { exists: false, executable: false, authority: null, deploySlot: null, verified: null })), ["program-closed", "authority-changed"]);
});

test("the same authority read as unidentified is not a change, and keeps its known rules", () => {
  const unknown = { ...squads(5, 13, 86400), authority: { kind: "program-controlled", address: "VAULT" } };
  assert.deepEqual(diffProgram(squads(5, 13, 86400), unknown), []);
  assert.equal(unknown.authority.kind, "squads-v4"); // baseline keeps 5 of 13
  assert.deepEqual(diffProgram({ ...squads(5, 13, 86400), authority: { kind: "program-controlled", address: "VAULT" } }, squads(5, 13, 86400)), []);
  // A different address is a change even if unidentified.
  assert.deepEqual(ids(diffProgram(squads(5, 13, 86400), { ...squads(5, 13, 86400), authority: { kind: "program-controlled", address: "OTHER" } })), ["authority-changed"]);
});

test("lockfile: only advisories that were not there", () => {
  const before = lockfileSnapshot([{ id: "RUSTSEC-1" }]);
  const now = [{ id: "RUSTSEC-1", crates: ["a 1"] }, { id: "RUSTSEC-2", crates: ["b 2"], severity: "HIGH", summary: "bad" }];
  const ev = diffLockfile(before, lockfileSnapshot(now), now);
  assert.deepEqual(ids(ev), ["new-advisory"]);
  assert.equal(ev[0].advisory.id, "RUSTSEC-2");
  assert.equal(ev[0].severity, "high");
});

test("webhook guards: https, public addresses only, no credentials", async () => {
  for (const ip of ["10.1.2.3", "127.0.0.1", "169.254.169.254", "172.31.0.1", "192.168.0.1", "100.64.1.1", "0.0.0.0", "::1", "fc00::1", "fe80::1", "::ffff:10.0.0.1"])
    assert.equal(isPrivateAddress(ip), true, ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700::1111"]) assert.equal(isPrivateAddress(ip), false, ip);
  const dns = (map) => async (host) => map[host] || [];
  const resolve = dns({ "hooks.example": [{ address: "93.184.216.34" }], "evil.example": [{ address: "93.184.216.34" }, { address: "10.0.0.5" }], "meta.example": [{ address: "169.254.169.254" }] });
  await checkWebhookUrl("https://hooks.example/x", { resolve });
  for (const [url, why] of [["http://hooks.example/x", /https/], ["https://evil.example/x", /public/], ["https://meta.example/", /public/], ["https://127.0.0.1/", /public/], ["https://u:p@hooks.example/", /credentials/], ["https://nowhere.example/", /resolve/], ["not a url", /URL/]])
    await assert.rejects(checkWebhookUrl(url, { resolve }), why, url);
});

function harness({ check }) {
  const store = new Store(join(mkdtempSync(join(tmpdir(), "ssw-watch-")), "watches.json"));
  const posts = [];
  const post = async (url, headers, body) => { posts.push({ url, headers, body }); return { status: 200 }; };
  const w = new Watcher({ store, check, post, allowPrivate: true, intervalMs: 1000 });
  const t0 = Date.parse("2026-10-01T00:00:00Z");
  const watch = store.create({ status: "active", target: "program", targetSummary: { type: "program" }, webhook: "https://hooks.example/x", secret: "s3cret", snapshot: squads(5, 13, 86400), events: [], lastCheckedAt: new Date(t0).toISOString(), expiresAt: new Date(t0 + 10_000).toISOString() });
  return { store, posts, w, t0, watch };
}

test("scheduler: due watches only, signed webhook, baseline moves, one page per change", async () => {
  let snap = squads(5, 13, 86400);
  const { store, posts, w, t0, watch } = harness({ check: async (x) => ({ snapshot: snap, events: diffProgram(x.snapshot, snap) }) });
  await w.tick(t0 + 500); // not due yet
  assert.equal(posts.length, 0);
  snap = { ...snap, deploySlot: 999 };
  await w.tick(t0 + 1500);
  assert.equal(posts.length, 1);
  const { headers, body } = posts[0];
  assert.equal(headers["x-watchdog-signature"], "sha256=" + createHmac("sha256", "s3cret").update(body).digest("hex"));
  assert.equal(sign("s3cret", body), headers["x-watchdog-signature"]);
  assert.deepEqual(JSON.parse(body).events.map((e) => e.type), ["code-upgraded"]);
  const after = store.get(watch.id);
  assert.equal(after.snapshot.deploySlot, 999);
  assert.equal(after.events[0].delivered, true);
  await w.tick(t0 + 3000); // same state: no second page
  assert.equal(posts.length, 1);
  await w.tick(t0 + 20_000); // past expiry
  assert.equal(store.get(watch.id).status, "expired");
});

test("a failed lookup is not a change", async () => {
  const { store, posts, w, t0, watch } = harness({ check: async () => { throw new Error("rpc 429"); } });
  await w.tick(t0 + 1500);
  assert.equal(posts.length, 0);
  const after = store.get(watch.id);
  assert.equal(after.checkFailures, 1);
  assert.equal(after.snapshot.deploySlot, 100);
  assert.match(after.lastError, /429/);
});
