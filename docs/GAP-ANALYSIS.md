# Phase 9 gap analysis: where TaintWalk breaks on real code

**Disclosure (D-035 applies).** Every R5 error at a real-code root was coded by an AI assistant (Claude) from
the generated worksheet (`python -m taintwalk.eval.real_gap worksheet`), then reviewed and applied by the
author with `real_gap tally`, which accepts only codebook categories. The codebook was fixed before any
real-code model output existed: D-032's categories, the two D-035 found missing, and the two the Phase 9
pre-registration added. Abstentions are coded mechanically by the pipeline's failure name (D-040 item 4).
No inter-rater agreement was measured, an AI labelled another model's mistakes, and the same assistant built
the pipeline being analysed.

## Scope

R5 is the TaintWalk walk on the local model (ornith:9b, prompt v2, callee context v1). The corpus is 12 real
CVE fix pairs from mujs, md4c, giflib and Lua: 24 roots, each the one function its fix changed, built before
and after the fix. The scored numbers are in the Phase 9 section of `docs/RESULTS.md`.

R5 made 16 errors at the roots:

- 8 false positives, all on post-fix roots, hand-coded;
- 8 abstentions (4 pre-fix, 4 post-fix), all `max_tokens`, coded mechanically.

There is no hand-coded false negative: R5 flagged every pre-fix root it answered.

## Counts

| cell | code | roots |
|---|---|---|
| FN_abstain | abstained: max_tokens | 4 |
| FP | context-induced: a callee summary said vulnerable | 5 |
| FP | ignored guard | 1 |
| FP | other | 2 |
| abstain | abstained: max_tokens | 4 |

## Findings

### 1. Nothing separates a function from its own fix

Pair-correct (pre flagged, post clear) is 0 of 12 for every rung, R1 to R5. Specificity is 0 of 12 for both
model rungs: R4 and R5 flag every post-fix root they answer. On Juliet the same rungs cleared 67% (R4) and
48% (R5) of the safe roots. R5's recall of 8 of 12 is therefore not detection: a rung that flags everything it
answers has the recall of its coverage. Where R5 answered both halves of a pair (7 pairs), it gave both the
same verdict.

### 2. Callee verdicts are copied, and in real closures they are almost all "vulnerable" (5 of 8 FPs)

In the five context-induced false positives the callee block summarised 6 of 9, 2 of 3, 2 of 2, 2 of 2 and
5 of 5 callees as vulnerable, and the root's verdict restates them. rp-02's post-fix root saw 12 of 13
summarised callees marked vulnerable. A context that marks nearly every function vulnerable carries no signal
that could separate a patched root from an unpatched one.

The cause is the shape of the summaries. Each answers "could this function be dangerous for some input?"
without knowing what its caller passes (context-insensitive). For almost any real function the answer is yes,
so "vulnerable" saturates upward through the call graph. This is the Phase 8 finding (15 of 20 false positives
were context-induced) at a larger scale. The varargs error helper that formats with `vsnprintf` is again
summarised as an untrusted format string, as the print helpers were on Juliet.

### 3. Without callees, the model distrusts every parameter (3 of 8 FPs)

The three false positives with no callee block (rp-04, rp-05, rp-06) share one pattern: every pointer, index or
bound the caller supplies is treated as attacker-controlled. `js_strtod`'s scan of a NUL-terminated string is
called an unbounded read; `md_split_simple_pairing_mark`'s index is flagged as unchecked, which it is in both
versions; `md_is_named_entity_contents` bounds every read with `off < max_end` (the fix itself), and the model
dismisses the check because `max_end` is a parameter. Real library code is safe because its callers keep
invariants, and a per-function prompt cannot see them.

### 4. The patched line is never examined

No false-positive reason mentions the operation the fix changed: the corrected allocation size, the month
index guard, the exponent cap, the index arithmetic, the read bound, the byte-count check, the call counter, the
added code-generation call. The true positives are not evidence of the opposite (an observation, not coded):
no R5 reason on a pre-fix root names the defect its fix addressed; rp-05's comes closest, an unchecked index
into the mark array, without identifying the arithmetic. The pre-registered "patch too small to see" (failure
mode 2) appears in a stronger form: the patch is not looked at.

### 5. The output budget, not the context window, is the binding limit

All 8 R5 abstentions at the roots, and all 5 R4 abstentions, are answers cut off at the frozen 2,048-token
output limit (`max_tokens`). None is a context overflow. Over the 3,183 walked functions, 423 final summaries
are missing for `max_tokens` against 25 for context overflow. Each missing summary also reaches every caller
as "no summary". The pre-registration predicted context overflow (failure mode 3), not truncated answers; this
is an observed failure mode, not a predicted one.

## The pre-registered failure modes, checked

| # | Predicted | Observed |
|---|---|---|
| 1 | Roots that only lack a check are missed | Not observed: no answered pre-fix root was cleared, so the code was never used |
| 2 | Patch too small to see | Observed, stronger: both halves get the same verdict, and no reason mentions the patched operation |
| 3 | Context overflow | Not at any root; output truncation (`max_tokens`) instead, 8 of 24 R5 roots |
| 4 | The input rule (R2) flags nearly everything | Wrong in direction: R2 flags 0 of 24 roots; real bug sites take data through parameters |
| 5 | Indirect calls leave closures incomplete | Present: 12 of 24 roots reach 116 indirect call sites; no error was traced to a missing edge |

The D-018 sanitizer-literal shortcut could not be tested: 0 of 12 fixes added a string literal to the root.

## What this points to (frozen under the held-out rule; Phase 10 or later, by ADR)

- Summaries that state conditions ("safe if `param_2 < len`") instead of verdicts: context-sensitive summaries
  in the IFDS / Sharir-Pnueli sense.
- Callee blocks that carry flows, sinks and guards but not the callee's verdict (already a Phase 8 candidate;
  finding 2 strengthens it).
- An output budget or a terser schema sized for real functions (finding 5).
- Correct leaf summaries for print and error helpers (a Phase 8 candidate that recurs).

## Every coded root

| item | binary | addr | cell | code | note |
|---|---|---|---|---|---|
| rp-01/post | rw-0002 | 0x16fbc | FP | context-induced: a callee summary said vulnerable | restates 6 of 9 callees' vulnerable summaries; the corrected allocation size n + 1 is never discussed |
| rp-02/post | rw-0004 | 0x28581 | abstain | abstained: max_tokens | - |
| rp-03/post | rw-0003 | 0xd926 | FP | context-induced: a callee summary said vulnerable | copies two callees' divide_by_zero verdicts although the root passes a year, not a divisor; the month-index guard (0 <= im < 12) is never mentioned |
| rp-04/post | rw-0007 | 0x11e70 | FP | other | parameter distrust: treats scanning a NUL-terminated string as unbounded reads; never assesses the exponent arithmetic the fix capped |
| rp-05/post | rw-0009 | 0x19991 | FP | other | parameter distrust: flags the unchecked caller-supplied index, unchecked in both versions; never evaluates the -1 to -n arithmetic the fix changed |
| rp-06/post | rw-0011 | 0x13b00 | FP | ignored guard | every read is bounded by off < max_end (the fix itself); dismissed because max_end is a parameter |
| rp-07/pre | rw-0012 | 0x15132 | FN_abstain | abstained: max_tokens | - |
| rp-07/post | rw-0010 | 0x15132 | abstain | abstained: max_tokens | - |
| rp-08/pre | rw-0013 | 0x30b1 | FN_abstain | abstained: max_tokens | - |
| rp-08/post | rw-0014 | 0x30b1 | abstain | abstained: max_tokens | - |
| rp-10/post | rw-0018 | 0x4c5d | FP | context-induced: a callee summary said vulnerable | copies the GCB writer's out-of-bounds write verdict; the ByteCount < 4 check right before that call is never mentioned |
| rp-12/post | rw-0022 | 0x17924 | FP | context-induced: a callee summary said vulnerable | restates both callees' out-of-bounds verdicts; the C-call counter the fix rebalances is never discussed |
| rp-13/pre | rw-0023 | 0x17d6c | FN_abstain | abstained: max_tokens | - |
| rp-13/post | rw-0024 | 0x17d6c | abstain | abstained: max_tokens | - |
| rp-14/pre | rw-0025 | 0x28a70 | FN_abstain | abstained: max_tokens | - |
| rp-14/post | rw-0026 | 0x28a70 | FP | context-induced: a callee summary said vulnerable | all 5 callees are summarised vulnerable and the verdict restates them; the added call is never discussed |

## Limitations

- 12 pairs: every interval is wide (a 0 of 12 has a 95% upper bound of 0.24). Descriptive only, by
  pre-registration.
- One local 9B model; the cloud rungs are deferred (D-034).
- The corpus is 50% vulnerable by construction, so precision and F1 do not describe real code.
- One coder, an AI, reviewed by the author; no agreement statistic.
