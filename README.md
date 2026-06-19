# Solana Security Watch — a Claude Code skill

> Continuous security monitoring for Solana / Anchor programs. Not a one-shot
> audit — a daily **watch** loop that pulls fresh ecosystem disclosures and
> re-confronts your program's code against each new exploit technique.

Audits are point-in-time; exploit techniques surface weekly. This skill turns
security into a repeatable loop:

> **Collect** fresh disclosures (exploits, CVEs, RUSTSEC, auditor advisories) →
> **Confront** them against your program's code → **Report** a dated finding with
> severity, `file:line`, and a *proposed* fix. Propose only — never auto-patch
> production code.

It ships an executable `/security-watch` command that scans a target Anchor repo
for known vulnerability classes (account substitution, `init_if_needed` re-init,
rounding arbitrage, donation attacks, unbounded casts, governance capture, oracle
manipulation, supply-chain risk) and emits a dated report.

## What's inside

```
solana-security-watch/
├── SKILL.md                    # entry hub (progressive disclosure)
├── skill/
│   ├── daily-watch.md          # the collect → confront → report procedure + severity rubric
│   ├── vuln-classes.md         # 14 Solana/Anchor bug classes with grep patterns + safe patterns
│   └── case-studies.md         # anonymised real findings (HIGH/MEDIUM/LOW/INFO) for calibration
├── commands/
│   └── security-watch.md       # executable slash command: deps + grep + advisories → report
└── README.md
```

## Install

**As a Claude Code skill** — drop this folder into your skills directory (e.g.
`~/.claude/skills/solana-security-watch/`), or add it to the
[Solana AI Kit](https://github.com/solanabr/solana-ai-kit) skill registry.

**As a slash command** — copy `commands/security-watch.md` to
`~/.claude/commands/security-watch.md` (user-level) or
`.claude/commands/security-watch.md` (project-level).

## Use

```
/security-watch .                 # one watch pass over the current repo
/loop 1d /security-watch .        # self-paced daily watch
```

Or point a scheduled agent / cron job at the command with the repo path as
argument, appending each run to the repo's `SECURITY_WATCH.md` journal.

## Design principles

- **Continuous, not point-in-time** — complements one-shot audit skills; keeps you
  current as new techniques drop.
- **Bug *classes*, not signatures** — an EVM exploit this week becomes a Solana
  checklist item, because the class (rounding, donation, oracle, capture) transposes.
- **Diff the siblings** — most real findings are a context that drifted from a
  correct peer instruction, not a novel bug.
- **Propose, don't apply** — on production code, flag and propose; a human gates
  every change. After any account-context change, the IDL must be rebuilt first.

## License

MIT — see headers. Author: OxToF.
