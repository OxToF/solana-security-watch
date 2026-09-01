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
// With no subcommand, `install` runs (backwards-compatible with earlier versions).

import { existsSync, cpSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runCollect, DEFAULT_CRATES } from "./collect.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..");

function parseFlags(argv) {
  const f = { project: false, target: null, yes: false, out: "watch-reports", crates: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--project") f.project = true;
    else if (a === "--yes") f.yes = true;
    else if (a === "--target") f.target = argv[++i];
    else if (a === "--out") f.out = argv[++i];
    else if (a === "--crates") f.crates = argv[++i].split(",").map((s) => s.trim()).filter(Boolean);
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

function usage() {
  console.log("Usage:");
  console.log("  solana-security-watch install [--project | --target <dir>] [--yes]");
  console.log("  solana-security-watch collect [--out <dir>] [--crates a,b,c]");
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
