#!/usr/bin/env bash
# Phase 10 mini-step 12: the scored runs, then offline replays. Safe to rerun: a rerun resumes through
# the cache (finished calls replay at zero cost). Refuses to run unless HEAD is the p10-freeze tag and
# the tree is clean, so nothing unfrozen can produce a scored verdict.
# Historical record: this ran from runs/p10-spike/ at tag p10-freeze. Committed in Phase 11 with only this
# note and the cd path changed. Because of the freeze check it now always stops; to re-verify the scored
# runs, replay them offline (see README, "Reproducing the results").
set -u
cd "$(dirname "$0")/.." || exit 1
source .venv/bin/activate

want=$(git rev-list -n1 p10-freeze 2>/dev/null)
head=$(git rev-parse HEAD)
if [ -z "$want" ] || [ "$want" != "$head" ]; then echo "STOP: HEAD $head is not p10-freeze ($want)"; exit 1; fi
if [ -n "$(git status --short)" ]; then echo "STOP: uncommitted changes"; git status --short; exit 1; fi
echo "frozen at $(git describe --tags --exact-match)  $(date -Is)"

JULIET=runs/p10/scored.programs.txt
REAL=runs/p9-real/programs.txt
declare -A RC

run() {   # label policy programs run_dir
  local label=$1 policy=$2 programs=$3 dir=$4
  echo "=== START $label  $(date -Is)"
  taintwalk walk --all --mode agent --policy "$policy" --programs "$programs" \
    --run-dir "$dir" --provider ollama --jobs 1 < /dev/null 2>&1 | tee "$dir.out"
  local rc=${PIPESTATUS[0]}          # captured on the very next line (the Phase 9 $? lesson)
  RC[$label]=$rc
  echo "=== END $label rc=$rc  $(date -Is)"
}

replay() {   # label policy programs run_dir
  local label=$1 policy=$2 programs=$3 dir=$4 s=0 a=0 n=0
  rm -rf "$dir-replay"
  taintwalk walk --all --mode agent --policy "$policy" --programs "$programs" \
    --run-dir "$dir-replay" --provider ollama --offline --jobs 4 < /dev/null > "$dir-replay.out" 2>&1
  for d in "$dir"/*/; do
    c=$(basename "$d"); [ "$c" = logs ] && continue; n=$((n+1))
    cmp -s "$d/summaries.json" "$dir-replay/$c/summaries.json" && s=$((s+1)) || echo "SUMMARIES DIFF $label $c"
    cmp -s "$d/agent.json" "$dir-replay/$c/agent.json" && a=$((a+1)) || echo "AGENT DIFF $label $c"
  done
  echo "$label replay identical: summaries $s/$n  agent.json $a/$n  ($(tail -1 "$dir-replay.out"))"
}

mkdir -p runs/p10-scored runs/p10-real
run  "A2-juliet" llm      "$JULIET" runs/p10-scored/llm
run  "A1-juliet" scripted "$JULIET" runs/p10-scored/scripted
run  "A2-real"   llm      "$REAL"   runs/p10-real/llm
run  "A1-real"   scripted "$REAL"   runs/p10-real/scripted

echo; echo "=== REPLAYS (offline, no GPU)  $(date -Is)"
replay "A2-juliet" llm      "$JULIET" runs/p10-scored/llm
replay "A1-juliet" scripted "$JULIET" runs/p10-scored/scripted
replay "A2-real"   llm      "$REAL"   runs/p10-real/llm
replay "A1-real"   scripted "$REAL"   runs/p10-real/scripted

echo; echo "=== SUMMARY  $(date -Is)"
for l in A2-juliet A1-juliet A2-real A1-real; do echo "$l rc=${RC[$l]:-?}"; done
for f in runs/p10-scored/llm runs/p10-scored/scripted runs/p10-real/llm runs/p10-real/scripted; do
  echo "$f: $(tail -1 "$f.out")"
done