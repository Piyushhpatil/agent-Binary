# TaintWalk — Phase 8 Pre-registration

**Written:** 2026-09-29, before any Phase 8 code, run or metric exists. The git history of this file is its timestamp.
**Source of record:** ADRs D-030 (rungs, tests, strata), D-031 (headline cloud model), D-032 (freeze, runs, codebook, gate).

Any deviation from this document is logged as a new ADR and disclosed in `docs/RESULTS.md`, with its reason.

## What is measured

- **Corpus:** 240 stripped Juliet 1.3 binaries, 13 CWE classes, 9 flow variants.
- **Unit:** the path root. 636 roots: 240 bad (`bad`/`entry`) and 396 good (`good`/`path`). The usual
  "any function on the path" rule is printed beside, never tested.
- **Strata:** external-source (192 binaries) and fixed-sink (48) are reported separately, pooled beside.
- **Breakdowns:** per CWE class, and per flow variant pooled over classes; never class × flow.
  95% Wilson intervals on recall, specificity, precision and coverage.
- **No answer** (model failure, overflow, not walked) counts against recall and is never a true negative.

Survey facts this plan relies on (label-free, `program.json` only): 11,029 in-scope functions, 2,322 walked,
8,707 isolated, 2,755 call edges, no recursion. 1,783 walked functions carry a callee block; for the other 539
the walk prompt and the no-context prompt are byte-identical.

## Frozen pipeline

Prompt v2, callee context v1, local model ornith:9b (digest `a75697c14589`, thinking off), `program.json` and
`sanitize.py` unchanged. Not adopted, and listed as limitations: a grounding rule for rendered callee fields,
`.rodata` string resolution, collapsing alloca probe loops.

## The seven rungs

Each rung emits one flag per walked function: vulnerable, not vulnerable, or no answer. All seven are scored by
the same code at the same 636 roots.

### R1 — flawfinder, per function
Each function's raw decompiled pseudo-C, after the alias adapter, in its own file. Pinned flawfinder version,
default options. Flagged if flawfinder reports at least one hit. Ordinal score: highest hit level (0 if none).

### R2 — input rule, per function
Flagged if the function itself calls a member of list I (after the alias adapter). No ordinal score.

### R3 — reachability of an R1 hit
Flagged if any function reachable from it in the in-scope call graph, itself included, is R1-flagged.
Ordinal score: highest R1 level over that set.

### R4 — per-function LLM, local (Baseline B)
The walk prompt with the callee block removed (byte-identical to `analyze-one`), on ornith:9b.

### R5 — TaintWalk, local
The bottom-up walk, on ornith:9b.

### R6 — per-function LLM, cloud (Baseline B)
As R4, on Claude Sonnet 5.5.

### R7 — TaintWalk, cloud (headline)
As R5, on Claude Sonnet 5.5.

For R4–R7 the flag is the summary's `verdict.vulnerable`, and the ordinal score is the confidence in the stated
verdict (confidence if vulnerable, 1 − confidence otherwise). The typed ladder (mechanism, exact CWE) and
calibration error exist for R4–R7 only; AUROC for R1, R3 and R4–R7.

**Alias adapter (R1–R3 only).** `\b__isoc(99|23)_(\w+)` → `\2`, in pseudo-C text and import names. The decompiler
shows glibc's versioned names (`__isoc23_fscanf`), which a lexical tool would otherwise miss. Nothing else is rewritten.

**List I (closed).** read, pread, recv, recvfrom, recvmsg, fread, fgets, fgetws, fgetc, fgetwc, getc, getwc,
getchar, getwchar, gets, getline, getdelim, scanf, wscanf, fscanf, fwscanf, vscanf, vfscanf, getenv, secure_getenv,
rand. Functions that bring data in from outside the process, plus `rand()`, which Juliet and the prompt treat as a
source. Present in this corpus: recv, fgets, fgetws, fscanf, getenv, rand.

**Rejected:** cppcheck (it needs a type shim for decompiler types, another tuning knob); a hand-written
dangerous-call list (a researcher degree of freedom; flawfinder's database is published).

## Pre-registered tests

Primary rule only. Exact two-sided McNemar test on paired root outcomes, run separately on bad roots (right =
flagged) and on good roots (right = not flagged). No answer counts as wrong. Holm–Bonferroni over all 10 tests,
family-wise α = 0.05. Every other comparison is descriptive.

| Test | Comparison | Question |
|---|---|---|
| C1 | R7 vs R6 | Does callee context help the headline model? (the ablation) |
| C2 | R5 vs R4 | Does callee context help the local model? |
| C3 | R7 vs R3 | Is the walk more than graph reachability? |
| C4 | R7 vs R2 | Does it beat "reads input ⇒ vulnerable"? |
| C5 | R7 vs R5 | Cloud model vs local model |

## Ablation strata

- **S0:** the root's walk prompt is byte-identical to its baseline prompt. The two arms must agree; any difference
  is a bug and fails the scorer.
- **S1:** the root has callees, but its path has one member.
- **S2:** the root's path has more than one member. Only here can context show the model the rest of the path.

C1 and C2 are tested over all roots (McNemar ignores roots where the arms agree, so S0 cannot dilute them); the
strata are printed beside. A byte-identity audit checks, for every walked function on both providers, that the
walk prompt minus its callee block equals the baseline prompt.

## Headline cloud model

Claude Sonnet 5.5 (`claude-sonnet-5-5`), every parameter sent explicitly, prompt caching on. Thinking is decided
once, on cost only: a label-free probe on 40 development functions runs adaptive thinking at effort `high`; if its
projected cost for both cloud arms exceeds $150, the configuration switches to no up-front thinking
(`between_tools`). The probe records schema validity, failures, refusals, tokens and cost. It computes no accuracy.

## Error analysis

A seeded sample of 20 false-positive and 20 false-negative roots from R7 (all of them, if fewer), read by hand and
coded:

- **False positives:** ignored guard; context-induced (a callee summary said vulnerable); ignored constant argument;
  decompiler artifact; invented sink or source; other.
- **False negatives:** missed sink; hallucinated guard; context-induced (a callee summary said safe); decompiler
  artifact; other.

Also measured per provider: how often a stated reason repeats few-shot text, and whether sanitizer error-message
literals alone predict a "safe" verdict.

## Disclosure

Seen during development and kept in the corpus, named again in `docs/RESULTS.md`:
- tw-0015 (the Phase 6 gate binary) and twelve Phase 7 scorer-shakedown binaries: tw-0022, tw-0065, tw-0066,
  tw-0091, tw-0125, tw-0135, tw-0151, tw-0166, tw-0175, tw-0178, tw-0188, tw-0237;
- the Phase 5 development and held-out samples (20 functions each), which shaped prompt v2 and the local model choice.
## Deviation D-034 (2026-09-29, before any Phase 8 number existed)

**Reason:** no funding for cloud API credits. Nothing here was chosen after seeing a result: no Phase 8 metric
had been computed when this was written, and this file's git history is the timestamp.

**What changes:**
- Rungs R6 and R7 (Claude Sonnet 5.5) are deferred until the API is funded. Everything they need is built and
  tested offline: the D-031 configuration is in `config/providers.yaml`, and `taintwalk eval --cloud ROOT` adds them.
- Phase 8 reports R1-R5. The headline rung is R5 (TaintWalk on the local 9B model).
- The pre-registered family for the local-only report, fixed now:

| Test | Comparison | Question |
|---|---|---|
| C2 | R5 vs R4 | Does callee context help the local model? (the ablation) |
| C3L | R5 vs R3 | Is the local walk more than graph reachability? |
| C4L | R5 vs R2 | Does it beat "reads input => vulnerable"? |

  Exact McNemar per label as before; Holm-Bonferroni over these 6 tests, family-wise alpha = 0.05. C1, C3, C4
  and C5 (all involving R7) run as the full family of 10 once the cloud rungs exist.
- The error-analysis sample (same seed, same codebook) is drawn from R5.

**Future work (waiting for funding):** run R6/R7 on Claude Sonnet 5.5 (G-CLOUD, the 40-function probe and its
cost rule, the full cloud walk), then report the full family of 10 tests and the provider comparison.
