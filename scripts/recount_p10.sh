#!/usr/bin/env bash
# Phase 10 independent recount: labels + summaries.json + jq only, no scorer code. Compares the A1/A2
# Juliet cells and the A1/A2 real-code pair outcomes with what agent_score wrote. Exit 0 only if all match.
set -u
cd "$(dirname "$0")/.." || exit 1
SC=runs/p10-scored/eval/agent.json
[ -s "$SC" ] || { echo "STOP: no $SC (run the scorer first)"; exit 1; }
ok=0
for rung in A1 A2; do
  policy=$([ "$rung" = A1 ] && echo scripted || echo llm)
  out=/tmp/p10-recount-$rung.txt; : > "$out"
  while read -r p roots; do
    c=$(basename "$p" .json)
    jq -r --slurpfile s "runs/p10-scored/$policy/$c/summaries.json" '
      .functions[] | select((.label == "bad" and .role == "entry") or (.label == "good" and .role == "path"))
      | .label as $l | ($s[0][.addr]) as $r
      | (if $r == null then "A" elif $r.summary.verdict.vulnerable then "F" else "C" end) as $o
      | {bad: {F: "TP", C: "FN", A: "FN_abstain"}, good: {F: "FP", C: "TN", A: "abstain"}}[$l][$o]' \
      "runs/p2-extract/labels/$c.json" >> "$out"
  done < runs/p10/scored.programs.txt
  mine=$(sort "$out" | uniq -c | awk '{print $2"="$1}' | sort | tr '\n' ' ')
  theirs=$(jq -r --arg r "$rung" '.cells[$r] | to_entries[]
      | select(.key | IN("TP", "FN", "FN_abstain", "FP", "TN", "abstain")) | select(.value > 0)
      | "\(.key)=\(.value)"' "$SC" | sort | tr '\n' ' ')
  if [ "$mine" = "$theirs" ]; then echo "JULIET $rung RECOUNT SAME ($(wc -l < "$out") roots): $mine"
  else echo "JULIET $rung DIFF: recount [$mine] scorer [$theirs]"; ok=1; fi

  jq -r '.pairs[] | select(.excluded_by == null) | "\(.pair_id) \(.pre) \(.pre_addr) \(.post) \(.post_addr)"' \
    corpus/real/manifest.json |
  while read -r pid pre pa post pb; do
    a=$(jq -r --arg a "$pa" '.[$a] | if . == null then "A" elif .summary.verdict.vulnerable then "F" else "C" end' \
      "runs/p10-real/$policy/$pre/summaries.json")
    b=$(jq -r --arg a "$pb" '.[$a] | if . == null then "A" elif .summary.verdict.vulnerable then "F" else "C" end' \
      "runs/p10-real/$policy/$post/summaries.json")
    echo "$pid $a/$b"
  done | sort > "/tmp/p10-real-recount-$rung.txt"
  jq -r --arg r "$rung" '.real.pairs_detail[] | "\(.pair_id) \(.pre[$r])/\(.post[$r])"' "$SC" \
    | sed 's/flagged/F/g; s/clear/C/g; s/abstain/A/g' | sort > "/tmp/p10-real-scored-$rung.txt"
  if diff "/tmp/p10-real-recount-$rung.txt" "/tmp/p10-real-scored-$rung.txt"; then
    echo "REAL $rung RECOUNT SAME: $(wc -l < "/tmp/p10-real-recount-$rung.txt") pairs"
  else echo "REAL $rung DIFF (above: < recount, > scorer)"; ok=1; fi
done
[ "$ok" -eq 0 ] && echo "RECOUNT SAME: all" || echo "RECOUNT FAILED"
exit "$ok"