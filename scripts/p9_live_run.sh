#!/usr/bin/env bash
# Phase 9 live run (D-036, D-038), local model only (D-034).
#   1. R4: analyze-one on every root in the walk list (each root's no-context prompt, D-038).
#   2. R5: the roots walk over runs/p9-real/programs.txt, without --with-baseline (D-038).
# Resumable: run it again after any interruption; finished calls replay from the LLM cache at no cost.
set -u
cd "$(dirname "$0")/.."
LIST=runs/p9-real/programs.txt
mkdir -p runs/p9-real/r4-logs
echo "start $(date -Is)"
grep -v '^#' "$LIST" | while read -r prog roots; do
  [ -n "$prog" ] || continue
  for a in ${roots//,/ }; do
    log="runs/p9-real/r4-logs/$(basename "$prog" .json)_$a.log"
    taintwalk analyze-one --program "$prog" --addr "$a" --provider ollama --run-dir runs/p9-real/r4 \
      < /dev/null > "$log" 2>&1
    echo "r4 $(basename "$prog" .json) $a exit $? $(tail -1 "$log")"
  done
done
echo "r4 done $(date -Is)"
taintwalk walk --all --programs "$LIST" --run-dir runs/p9-real/walk --provider ollama --jobs 1 < /dev/null
echo "walk exit $? $(date -Is)"