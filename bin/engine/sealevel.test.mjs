// node --test bin/engine/sealevel.test.mjs
// The public benchmark: coral-xyz/sealevel-attacks, the Anchor team's catalogue of Solana
// bug classes, each as an insecure program and its fixed versions. Downloaded at a pinned
// commit (the repository has no license, so it is not copied here). The engine must catch
// every insecure version with the rule of its class, and raise that rule on no fixed one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeAnchor } from "./anchor.mjs";

const SHA = "24555d044802db4022112a94d6d70e74291a4b6d";
const EXPECT = {
  0: "missing-signer", 1: "unmatched-account-data", 2: "unverified-account-data", 3: "type-cosplay",
  4: "reinit-takeover", 5: "arbitrary-cpi", 6: "duplicate-mutable-accounts", 7: "bump-canonicalization",
  8: "pda-sharing", 9: "manual-close-revival", 10: "unchecked-sysvar",
};

test("sealevel-attacks: every insecure version caught, no fixed version flagged", async (t) => {
  let root;
  try {
    const r = await fetch(`https://codeload.github.com/coral-xyz/sealevel-attacks/tar.gz/${SHA}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const dir = mkdtempSync(join(tmpdir(), "sealevel-"));
    writeFileSync(join(dir, "t.tgz"), Buffer.from(await r.arrayBuffer()));
    execFileSync("tar", ["-xzf", join(dir, "t.tgz"), "-C", dir, "--strip-components", "1"]);
    root = dir;
  } catch (e) {
    return t.skip(`benchmark not downloadable: ${e.message}`);
  }
  const missed = [], falseAlarms = [];
  let insecure = 0, fixed = 0;
  for (const cls of readdirSync(join(root, "programs"))) {
    const want = EXPECT[parseInt(cls)];
    for (const v of readdirSync(join(root, "programs", cls))) {
      const rules = analyzeAnchor([join(root, "programs", cls, v)], root).findings.filter((f) => f.confidence !== "low").map((f) => f.rule);
      if (v.startsWith("insecure")) { insecure++; if (!rules.includes(want)) missed.push(`${cls}/${v}`); }
      else { fixed++; if (rules.includes(want)) falseAlarms.push(`${cls}/${v}`); }
    }
  }
  assert.equal(insecure, 13);
  assert.equal(fixed, 22);
  assert.deepEqual(missed, [], `missed: ${missed.join(", ")}`);
  assert.deepEqual(falseAlarms, [], `false alarms: ${falseAlarms.join(", ")}`);
});
