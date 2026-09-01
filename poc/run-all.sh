#!/usr/bin/env bash
# Run every PoC's test suite. Each PoC ships its compiled program (target/deploy/
# *.so), so this needs only Node + yarn — no `anchor build`, no validator.
set -uo pipefail
cd "$(dirname "$0")"
fail=0
for dir in */; do
  [ -f "${dir}package.json" ] || continue
  echo "═══════════════════════════════════════════════════════"
  echo "  PoC: ${dir%/}"
  echo "═══════════════════════════════════════════════════════"
  ( cd "$dir" && yarn install --silent --ignore-engines && yarn test ) || fail=1
done
echo
if [ "$fail" -eq 0 ]; then echo "✅ all PoC suites passed"; else echo "❌ one or more PoC suites failed"; fi
exit "$fail"
