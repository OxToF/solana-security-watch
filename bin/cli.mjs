#!/usr/bin/env node
// solana-security-watch CLI.
//
//   solana-security-watch install [--project | --target <dir>] [--yes]
//       Copy the skill, the /security-watch command, and the security-auditor
//       agent into a Claude Code config base (global ~/.claude by default).
//
//   solana-security-watch collect [--out <dir>] [--crates a,b,c]
//       Pull current RustSec/OSV advisories for the Solana/Anchor dependency
//       surface, diff against the last run, and write a dated report under
//       <out>/reports/. Run it on a schedule to get a continuous watch.
//
//   solana-security-watch scan <github-url> | --local <dir>
//       [--out <dir>] [--sarif <file>] [--json <file>] [--fail-on critical|high|medium|low|none]
//       Review an Anchor repository. --sarif writes alerts for GitHub code scanning;
//       --fail-on exits with code 3 when an issue to fix (or a dependency advisory that
//       reaches the program) is at or above that severity: the pull request gate.
//
// With no subcommand, `install` runs (backwards-compatible with earlier versions).

import { existsSync, cpSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runCollect, DEFAULT_CRATES } from "./collect.mjs";
import { runScan } from "./scan.mjs";
import { gateFailures } from "./engine/report.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..");

function parseFlags(argv) {
  const f = { project: false, target: null, yes: false, out: "watch-reports", crates: null, repo: null, local: null, sarif: null, json: null, failOn: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--project") f.project = true;
    else if (a === "--yes") f.yes = true;
    else if (a === "--target") f.target = argv[++i];
    else if (a === "--out") f.out = argv[++i];
    else if (a === "--local") f.local = argv[++i];
    else if (a === "--sarif") f.sarif = argv[++i];
    else if (a === "--json") f.json = argv[++i];
    else if (a === "--fail-on") f.failOn = argv[++i];
    else if (a === "--crates") f.crates = argv[++i].split(",").map((s) => s.trim()).filter(Boolean);
    else if (!a.startsWith("--") && !f.repo) f.repo = a; // positional repo URL for `scan`
  }
  return f;
}

function install(flags) {
  const base = flags.target
    ? flags.target
    : flags.project
      ? join(process.cwd(), ".claude")
      : join(homedir(), ".claude");

  const targets = [
    { label: "skill", src: join(repoRoot, "skills", "solana-security-watch"), dest: join(base, "skills", "solana-security-watch") },
    { label: "command", src: join(repoRoot, "commands", "security-watch.md"), dest: join(base, "commands", "security-watch.md") },
    { label: "agent", src: join(repoRoot, "agents", "security-auditor.md"), dest: join(base, "agents", "security-auditor.md") },
  ];

  console.log("=".repeat(67));
  console.log("  solana-security-watch · install");
  console.log("=".repeat(67));
  for (const t of targets) console.log(`  ${t.label.padEnd(7)} -> ${t.dest}`);
  console.log();

  if (!flags.yes && !process.stdin.isTTY) {
    console.log("No interactive terminal detected; proceeding (pass --yes to skip this notice).");
  }

  targets.forEach((t, i) => {
    mkdirSync(dirname(t.dest), { recursive: true });
    cpSync(t.src, t.dest, { recursive: true, force: true });
    console.log(`[${i + 1}/${targets.length}] [OK] ${t.label.padEnd(7)} -> ${dirname(t.dest)}${existsSync(t.dest) ? "/" : ""}`);
  });

  console.log();
  console.log("Installation complete. Restart Claude Code, then try:");
  console.log("  /security-watch .");
  console.log("  Run a security watch pass over this repo");
}

async function collect(flags) {
  try {
    await runCollect({ out: flags.out, crates: flags.crates || DEFAULT_CRATES });
  } catch (e) {
    console.error(`[collect] failed: ${e.message}`);
    process.exit(1);
  }
}

async function scan(flags) {
  if (!flags.repo && !flags.local) {
    console.error("scan needs a public repo URL: solana-security-watch scan https://github.com/<owner>/<repo>");
    process.exit(1);
  }
  let result;
  try {
    if (flags.failOn) gateFailures({ confident: [], deps: { onchain: [] } }, flags.failOn); // reject a bad value before scanning
    result = await runScan({
      repoUrl: flags.repo,
      localPath: flags.local,
      out: flags.out === "watch-reports" ? "scan-out" : flags.out,
      sarif: flags.sarif,
      sarifRoot: flags.local ? relative(process.cwd(), resolve(flags.local)) : "",
      json: flags.json,
    });
  } catch (e) {
    console.error(`[scan] failed: ${e.message}`);
    process.exit(1);
  }
  if (flags.failOn) {
    const failures = gateFailures(result.model, flags.failOn);
    if (failures.length) {
      console.error(`[gate] ${failures.length} finding${failures.length > 1 ? "s" : ""} at or above ${flags.failOn}:`);
      for (const f of failures) console.error(`  - ${f}`);
      process.exit(3);
    }
    console.log(`[gate] passed: nothing at or above ${flags.failOn}`);
  }
}

function usage() {
  console.log("Usage:");
  console.log("  solana-security-watch install [--project | --target <dir>] [--yes]");
  console.log("  solana-security-watch collect [--out <dir>] [--crates a,b,c]");
  console.log("  solana-security-watch scan <https://github.com/owner/repo> | --local <dir> [--out <dir>]");
  console.log("        [--sarif <file>] [--json <file>] [--fail-on critical|high|medium|low|none]");
}

const [cmd, ...rest] = process.argv.slice(2);
const flags = parseFlags(rest);

switch (cmd) {
  case undefined:
  case "install":
    install(flags);
    break;
  case "collect":
    await collect(flags);
    break;
  case "scan":
    await scan(flags);
    break;
  case "help":
  case "--help":
  case "-h":
    usage();
    break;
  default:
    // Back-compat: bare flags like `--project` used to mean install.
    if (cmd.startsWith("--")) install(parseFlags(process.argv.slice(2)));
    else { console.error(`Unknown command: ${cmd}\n`); usage(); process.exit(1); }
}
