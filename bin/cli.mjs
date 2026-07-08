#!/usr/bin/env node
// Installer for solana-security-watch: copies the skill, the /security-watch
// command, and the security-auditor agent into a Claude Code config base
// (global ~/.claude by default, project-local ./.claude with --project, or a
// custom directory with --target <dir>).

import { existsSync, cpSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..");

function parseArgs(argv) {
  const args = { project: false, target: null, yes: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--project") args.project = true;
    else if (argv[i] === "--yes") args.yes = true;
    else if (argv[i] === "--target") args.target = argv[++i];
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const base = args.target
  ? args.target
  : args.project
    ? join(process.cwd(), ".claude")
    : join(homedir(), ".claude");

const targets = [
  {
    label: "skill",
    src: join(repoRoot, "skills", "solana-security-watch"),
    dest: join(base, "skills", "solana-security-watch"),
  },
  {
    label: "command",
    src: join(repoRoot, "commands", "security-watch.md"),
    dest: join(base, "commands", "security-watch.md"),
  },
  {
    label: "agent",
    src: join(repoRoot, "agents", "security-auditor.md"),
    dest: join(base, "agents", "security-auditor.md"),
  },
];

console.log("=".repeat(67));
console.log("  solana-security-watch");
console.log("=".repeat(67));
for (const t of targets) {
  console.log(`  ${t.label.padEnd(7)} -> ${t.dest}`);
}
console.log();

if (!args.yes && !process.stdin.isTTY) {
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
