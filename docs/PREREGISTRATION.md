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

## Deviation D-035 (2026-09-30, after RESULTS.md v1, while coding the error sample)

**Reason:** the author asked for help coding the sampled errors.

**What changes:**
- The error sample (R5, seed 20260930, 20 false positives and 20 false negatives) and the codebook are unchanged.
- The 40 errors were coded by an AI assistant (Claude) from the worksheet and reviewed by the author, instead of by
  the author alone. No inter-rater agreement was measured.
- Two tie-break rules were added while coding the first ten errors and applied to all 40:
  1. context-induced: for a false positive, the model inherited a callee's vulnerable verdict, even when the root
     passes a constant; for a false negative, a callee summary was wrong (a lost flow or sink, or a false guard) and
     the model relied on it. "ignored constant argument" is used only when a constant reaches a sink in the root's
     own code.
  2. other: no category fits; the note names the pattern.

---

# TaintWalk — Phase 9 Pre-registration (real-code generalization)

**Written:** 2026-10-01, before the census ran, before any real-code binary was built, and before any
real-code model call. The git history of this file is its timestamp.
**Source of record:** ADRs D-009 (corpus, census, screens, labels) and D-036 (walk scope, scorer,
statistics), logged in `DECISIONS.md` at the Phase 9 hand-off.
**Amends D-008:** the path-root definition, for real code only. See "The root" below.

Any deviation is logged as a new ADR and disclosed in `docs/RESULTS.md`, with its reason.

## The question

Do the Phase 8 Juliet results transfer to real open-source C code? Phase 8's headline rung R5 is
statistically indistinguishable from flawfinder plus reachability (C3L), and a one-line input rule has
the best F1. This phase measures whether that picture holds, improves or collapses off Juliet.

This corpus is **held out**. No prompt, callee renderer, sanitizer, schema or model setting is changed
because of anything measured here. A code bug may be fixed by ADR and the run repeated; prompts never
change.

## What is measured

- **Unit: the pair.** One vulnerable function and its patched self, compiled from the fix commit's first
  parent and from the fix commit. Both halves of a pair are the same function in the same project with
  the same build recipe, so the only difference is the patch.
- **The root is the fix site**, the one function the fix commit changed, **not** the function the
  advisory names. Verified in the census review: CVE-2016-7563's advisory names `chartorune` while the
  fix changed `lexcomment`; CVE-2018-12112's advisory names `md_build_attribute` while the fix changed
  `md_rollback`. A real-code label is a claim about the function the patch changed.
  - This **amends D-008** for real code. D-008's literal rule (the lowest function from which source and
    unsafe operation are both in view) puts every real-code root at the CLI's `main`, which is not a
    claim about any function's own code.
- **Positives** are pre-fix roots; **negatives** are post-fix roots. Target 10-20 pairs.
- Results are reported in their own section of `docs/RESULTS.md` and are **never pooled with Juliet**.

## Project selection (fixed)

mujs, md4c, giflib, jbig2dec. Criteria, all required: pure C; builds from a file list with plain gcc and
no generated configuration header; an in-tree command-line program; at least five memory-safety CVEs with
commit-level fix references.

**Reserve, pre-registered:** if fewer than 10 pairs survive the screens, Lua is added under the same rules
and the shortfall is disclosed. No other project may be added.

**Rejected:** libexpat, because it needs a generated config header, and because its 2.4.3 fix patches six
functions in one commit with several new checks inside `#if UINT_MAX >= SIZE_MAX`, which is false on
x86_64 — so "the patch changed F" would not imply "F's binary changed".

## Census (D-009)

Fully mechanical, from recorded snapshots, with every exclusion reason written out.

**Sources, snapshotted and hashed:** the NVD API 2.0 keyword query per project; each project's git
repository at a recorded HEAD; GitHub issue-event JSON where used. mujs is read from Codeberg, which is
canonical since 2025 and contains the whole GitHub history.

**Project match:** a CPE whose product field is the project name, or the project name as a whole word in
the description. Anything else is "other product".

**Scope, two signals.** Signal A is the advisory's CWE set and description; signal B is the fix commit's
message. Each signal is in-scope, out-of-scope or silent.
- In-scope CWEs: 78, 119, 120, 121, 122, 124, 125, 126, 127, 129, 131, 134, 190, 191, 193, 369, 606, 680,
  787, 788, 789, 805, 806, 823. In-scope words: buffer overflow, buffer over-read, buffer overrun,
  out-of-bounds, integer overflow, integer underflow, divide by zero, format string, off-by-one.
- Out-of-scope CWEs: 400, 401, 415, 416, 457, 476, 617, 674, 704, 772, 835, 843, 908. Out-of-scope words:
  use-after-free, double free, null pointer, memory leak, infinite loop, recursion, stack exhaustion,
  assertion.
- **A candidate is in scope only if no signal is out-of-scope and at least one is in-scope.** An
  out-of-scope signal from either side excludes, whatever the other says.
  - This rule exists because NVD's CWE alone is wrong often enough to matter: CVE-2022-44789 carries
    CWE-787, while the advisory and the maintainer both describe a use-after-free.
  - The rule is one-directional by design. An out-of-scope advisory is never pulled back in by a
    promising commit message, because that would be hand-picking.
- Rejected classes and why: use-after-free, double free, NULL dereference, memory leaks, unbounded
  recursion and infinite loops have no D-021 mechanism, and adding one would change the frozen prompt.

**Resolution of the fix commit**, first source that yields any commit touching a `.c` file:
1. a commit hash in an NVD reference URL;
2. the CVE id in a commit message;
3. GitHub's closed-by-commit event for a referenced issue of that project;
4. the referenced bug or issue number in a commit message.

Exactly one such commit is `unique`; more than one is `ambiguous`; none is `none`. Only `unique` proceeds.
Source 4 is the weakest and the only one observed to fail, which the next two rules contain.

**Exclusions after resolution:**
- **Incomplete-fix follow-ups.** A description saying the CVE exists because of an incomplete fix for
  another CVE is excluded: its advisory cites the superseded bug, so the resolved commit is the one it
  says was insufficient. CVE-2016-9109 is the observed instance.
- **Shared fix commits collapse to one pair.** Two CVEs resolving to the same commit are the same code
  change; the lowest CVE id is kept and the other recorded as an alias.

**Cap and draw:** at most 5 candidates per project. Where a project has more, the kept set is drawn with
seed 20261001 over the sorted candidate ids. Drawn and undrawn are both recorded.

**Not a screen:** function size. A root whose prompt overflows the context stays in and counts as an
abstention, and coverage is reported as a result. Dropping large functions would quietly build an easy
corpus.

## Screens (D-009), all before any model call

- **S1** the fix commit resolves in the recorded repository.
- **S2** the fix changes exactly one C function, decided by mapping changed line ranges through each
  build's DWARF line table. The hunk-header function names recorded by the census are a preview only and
  decide nothing.
- **S3** both versions build under gcc 15 with the D-014 flags plus `-g -O0 -fno-inline`; `cp` then
  `strip` (G1); `.text` address, size and byte hash identical across the pair's own two files (G2).
- **S4** Ghidra recovers the root in both builds and it joins by address.
- **S5** the root's pseudo-C differs between pre and post, after normalising the addresses inside
  `FUN_`/`DAT_`/`LAB_` names. This is what the libexpat case showed is necessary: a patched source line
  need not change the compiled function the model sees.
- **S6** the leak gate passes on every prompt in the root's walk closure.

A candidate failing any screen is excluded with that screen named. No candidate is excluded by judgement.

## Build and binary shape

Each version is statically linked into the project's own command-line program, so the stripped binary
exposes no exported function names in `.dynsym`. A stripped shared object would keep every exported
symbol, and the model would read real function names instead of `FUN_...`.

## Leak gate on real code

- Per-binary denylist: the root's name, its source file name and stem, and the CVE ids.
- `util/leakcheck.py` gains a pattern rejecting CVE ids, and learns to resolve a binary through either the
  Juliet manifest or the real-code manifest. There is still no bypass and no warn mode (D-017).
- A pair tripping the gate is excluded at S6, before any model call.
- No layer can detect a model that memorised a famous CVE. The pair design is the only defence: a model
  recalling "this function had a CVE" flags both halves, which scores as both-vulnerable, never as a
  correct pair. The rate of both-vulnerable pairs is reported.

## Walk scope and rung alignment (D-036)

- The walk covers each root's downward closure only. A function's prompt depends on its callees alone, so
  closure walking gives the roots prompts byte-identical to a whole-program walk, at a fraction of the
  calls. Proven by replaying the Juliet runs offline and requiring identical `summaries.json`.
- `plan_walk` skips functions with no in-scope caller and no in-scope callee. Inside a closure a root has
  no caller, so a leaf root would be skipped; the closure walk forces every root into the plan.
- R1, R2 and R3 are computed over exactly the set the walk analysed, not over whole programs, so every
  rung answers for the same functions (I6).

## Statistics (D-036), pre-registered

Descriptive only. At 10-20 pairs there are no p-values, and none will be computed.

- Per rung R1-R5: recall, specificity, precision and coverage, each with a 95% Wilson interval.
- **Pair outcomes**, the paired-evaluation convention: pair-correct (pre flagged, post clear),
  both-vulnerable, both-clear, reversed.
- **Gap table** against Phase 8 on recall and specificity, which do not depend on the positive rate.
  Precision and F1 are shown with an explicit base-rate note: Juliet roots are 38% positive and this
  corpus is 50% positive by construction, and neither resembles real code.
- Also reported: how many post-fix roots gained a string literal the pre-fix root lacked, which tests the
  D-018 sanitizer-literal shortcut on real code.

## Predicted failure modes

Written down now so that none of them can be presented afterwards as an explanation that happens to
excuse the result.

1. **Roots that only lack a check.** Where the fix added a guard in a caller of the crash site, the
   pre-fix root contains no unsafe operation. A model reasoning about that function alone has little to
   find. Observed in the census for CVE-2016-7563 and CVE-2018-12112.
2. **Patch too small to see.** A one-comparison fix may leave the decompiled function nearly identical, so
   both halves get the same verdict.
3. **Context overflow.** Real functions are far larger than Juliet's 4,347-character maximum. Overflows
   count as abstentions against recall.
4. **The input rule generalises badly in the other direction.** In real code almost everything is
   reachable from input, so R2 should flag nearly everything and lose the F1 lead it held on Juliet.
5. **Indirect calls.** Real code uses function-pointer tables that Ghidra may not resolve, leaving the
   closure incomplete. Reported as a count.

## Gap analysis codebook

Every R5 error is coded with the D-032 codebook, plus the two categories D-035 found missing
("`rand()` treated as trusted", "declined a correct callee verdict"), plus two for real code:
"abstained: context overflow" and "root only lacks a check" (failure mode 1). Coding is AI-assisted and
author-reviewed, disclosed exactly as D-035 requires.

## Disclosure

- Nothing in this corpus was seen before the census ran. The projects were chosen by the criteria above;
  the CVEs by the census rules.
- Three candidates were excluded during the census review, before any build: CVE-2022-44789
  (use-after-free despite CWE-787), CVE-2016-9109 (incomplete-fix follow-up, wrong commit), CVE-2019-11412
  (no in-scope mechanism). Each is recorded in `census.json` with its rule.
- The two seed examples read while choosing projects, CVE-2021-33797 (mujs) and CVE-2019-15133 (giflib),
  are disclosed here and are not exempt from any screen.

## Deviation D-037 (2026-10-01, after the census ran, before any build or model call)

**Reason:** the approved Stage 2 plan included "one CVE per function, the latest" (decision 4). The Phase 9
text above left it out. The census then kept two pairs on the same function twice:

| Project | Root function | CVEs |
|---|---|---|
| giflib | `DumpScreen2RGB` | CVE-2022-28506 (fixed 2024), CVE-2025-31344 (fixed 2026) |
| md4c | `md_is_link_label` | CVE-2018-11545, CVE-2018-11547 (same day; git ancestry orders them) |

For the earlier fix of each, the "patched" function still contains the later bug, so labelling it clean
would be false. No binary had been built and no model had been called when this was written.

**What changes:**

1. **New screen S7: the patched root must be known-clean.** A pair is excluded when either holds:
   - another census CVE, of any scope, has a fix commit that descends from this pair's fix commit and
     changes the same root function. "Fix commit" uses the census's own four sources for every
     project-matched CVE; "changes the same root function" uses the S2 mapping on that later commit. A
     later commit that cannot be mapped (it does not build) excludes the pair as "S7 undecidable";
   - an incomplete-fix follow-up names this CVE as the one it supersedes.

   S7 is stronger than the approved rule on purpose: a later use-after-free fix in the same function
   means its patched half was not clean either, although use-after-free is out of scope.
2. **S7 runs after the seeded draw and frees no slot.** The committed draw stays exactly as it is, so
   nothing about the candidate list is re-chosen.
3. **S2, stated precisely.** A changed line inside a function counts toward that function. A changed line
   outside every function is ignored only when it is blank or its stripped text begins with `//`, `/*`,
   `*` or `*/`. Any other line outside a function (a macro, a struct field, a global, a preprocessor
   line) fails S2, because it can change code outside the root.
4. **Build hygiene.** Each version is compiled from the root of an exported tree with relative source
   paths, in a directory with an opaque name. `__FILE__` then embeds only names such as `jsdtoa.c`, so no
   CVE id can reach a binary through a path.

**Clarification (no change):** "statically linked into the project's own command-line program" means the
project's own sources are compiled into the executable instead of being loaded from a shared object.
libc stays dynamic, exactly as in the Juliet corpus (PIE, D-014). `-static` would put libc into `.text`,
and every library call would become an unnamed `FUN_`.

**Known limit, stated now:** a negative is clean only with respect to the CVEs in the census. A later bug
fixed silently, without a CVE, is invisible to S7.

## Deviation D-038 (2026-10-02, after screens S1-S5 and S7, before S6 and before any model call)

**Reason:** operational points the Phase 9 text leaves open, settled before any model output exists.

1. **S6, operationally.** Callee blocks are model output, so they do not exist before the walk. S6 gates
   the full base prompt (the system prompt plus the function's own numbered code) of every function in
   each root's downward closure, with both layers. Callee blocks are gated live during the walk, as in
   every phase since D-026; a violation aborts the walk and is handled by an ADR, never a bypass.
2. **R4 at the roots only.** R4 is the root's no-context prompt, which D-026 makes byte-identical to
   `analyze-one`. It is computed with `analyze-one` on each root, not with `--with-baseline` over the
   whole closure: only roots are scored, and the closure-wide baseline would roughly double the GPU time
   for rows that are never scored.
3. **R1-R3 over whole programs.** At a root, R1 and R2 read only the root, and R3 reads only the functions
   reachable from it, which is exactly the walk's closure. Computing them over the whole program therefore
   gives the same root values, and reuses the Phase 8 code unchanged.
4. **A descriptive breakdown.** A root whose walk prompt carries no callee block gets the same prompt in R4
   and R5 by construction (Phase 8's S0). The screens show three such roots among the 11 pairs that passed
   S1-S5 and S7 (`js_strtod`, `md_split_simple_pairing_mark`, `md_is_named_entity_contents`); the walk
   confirms it from `context_chars`. Pair outcomes are printed with these pairs set apart.
5. **Not run: the typed ladder.** The Phase 9 statistics do not register it, and the real CWEs (787, 125,
   119, ...) lie outside the D-021 table. No mechanism labels are made.

## Deviation D-039 (2026-10-02, after S6, before any model call): the Lua reserve is triggered

**Reason:** S6 excluded two of the 11 pairs that passed S1-S5 and S7, leaving 9. Both hits were real names
inside string literals of the root itself: jbig2dec's error messages name their own function
(`jbig2_build_huffman_table`, CVE-2017-7975), and giflib's `DumpScreen2RGB` (CVE-2025-31344) prints the
program name `gif2rgb`, which is also its source file's stem. The pre-registration adds Lua when fewer than 10
pairs survive the screens.

**What changes:**
1. **Lua joins under the same rules:** project criteria, census (two-signal scope, four ordered resolution
   sources, exclusions, cap 5, seed 20261001), screens S1-S7, and the D-037 and D-038 rules, all unchanged.
2. **Lua is censused on its own.** The census draws with one random generator across projects in name order,
   and `lua` sorts before `mujs`, so adding Lua to the same run would change the committed mujs draw. Lua gets
   its own census (`runs/p9-census-lua/`), and the original census, re-run from its snapshots, must reproduce
   byte for byte.
3. **Lua's build recipe is validated on non-candidate trees first**, as for the other projects.
4. **Lua's pairs and binaries are numbered after the existing ones**, so no committed pair or binary changes.
5. **If the corpus is still below 10 pairs afterwards, it stays as it is** and the shortfall is disclosed. No
   other project may be added.

## Deviation D-040 (2026-10-03, during the live run, before any real-code verdict was read)

**Reason:** the scorer needs rules the Phase 9 text leaves open. They are fixed here, in git, before anyone
reads a real-code verdict. When this was written, R4 rows existed for the roots and the walk was running;
the only model output displayed was run status, token counts and one R4 failure (`max_tokens`, no summary).

1. **The judge.** D-008's primary rule at the root, detection level only. A root is flagged when its row
   says vulnerable, clear when it says not vulnerable, and abstains when there is no summary. The cells are
   Phase 8's own (`eval/metrics._cell`): an abstaining pre-fix root counts against recall (FN_abstain) and an
   abstaining post-fix root is never a TN. No mechanism match is required; D-038 drops the typed ladder.
2. **A fifth pair outcome.** A pair where either root abstained is "abstained". It is never pair-correct,
   and it is reported beside the four pre-registered outcomes.
3. **Checks that fail the run.** Every root of every included pair has a row in R1-R5. R4 and R5 come from
   the same provider and prompt version. At every root whose walk prompt had no callee block, the R4 and R5
   rows are identical (D-038 item 4). Pairs with no callee block at either root are shown apart.
4. **Abstention reasons** at the roots are counted per LLM rung under the pipeline's own names. Output
   truncated at the frozen 2,048-token limit (`max_tokens`) is an abstention like a context overflow
   (failure mode 3), counted under its own name and never recoded.
5. **Literal gain** is the set of string literals in the post-fix root's pseudo-C that the pre-fix root's
   pseudo-C lacks. Reported: how many post-fix roots gained one, and their outcomes per rung.
6. **Entry point:** `python -m taintwalk.eval.real_score`, CPU only and model-free. It writes
   `runs/p9-real/eval/real.json`, byte-identical on unchanged input, and splices a marked Phase 9 section
   into `docs/RESULTS.md`. The gap table reads Phase 8's `runs/p8-eval/scores/R1.json`..`R5.json` unchanged.

## Deviation D-041 (2026-10-05, after the live run, before any replay of it)

**Reason:** a context overflow is never cached (D-022), and offline mode raised OfflineMiss at the cache miss,
before the preflight ran. An offline replay of a run with overflows therefore stopped instead of reproducing
them, so Phase 8's replay check could not be applied to the Phase 9 walks.

**Fix:** in offline mode the local preflight (a character count, no I/O) runs before the miss is raised. A
prompt it rejects raises ContextOverflow and is recorded exactly as on the live path. The live path, the
prompts, the cache keys and every stored result are unchanged, and no real-code result is re-run. This is
complete because every Phase 9 overflow came from the preflight (checked: no row records the post-check).
Phase 8's offline replay is re-run as the regression check.

<!-- phase10-prereg -->
## Phase 10: agentic evidence gathering (pre-registered 2026-10-06, before any agent code; D-042)

Committed before `analysis/agent.py` exists. Every later change is a numbered deviation below,
committed before the data it governs.

### Question
Does letting the model choose which callee code and summaries to read change root verdicts, compared
with no evidence (R4), a scripted read of every direct callee (A1), and the fixed bottom-up walk (R5)?

### Disclosure
The Phase 8 and Phase 9 results were known when this was designed (Phase 9: pair-correct 0/12 on every
rung). The Juliet corpus and the Phase 9 pairs are development data for any new pipeline, so no
generalization claim is made from them. Fresh held-out pairs are future work.

### Rungs (one judge for all)
- R4: no evidence. Unchanged from Phase 8 (`runs/p8-local`) and Phase 9 (`runs/p9-real/r4`).
- A1, scripted policy: read the no-context summary of every direct in-scope callee, in address order,
  then stop. No model call chooses anything.
- A2, model policy: up to 8 actions chosen by the model from list_callees, read_code, read_summary, finish.
- R5: the fixed walk. Unchanged from Phases 8 and 9.

The A1 and A2 verdicts come from the frozen prompt-v2 judge: `build_prompt(root, callee_context=<evidence>)`.
The evidence block is the only input that differs from R4. A root with an empty evidence block must
reproduce its R4 row exactly; the scorer fails closed otherwise.

### Actions
Each step is one constrained-JSON completion `{reason, action, target}` through `LLMProvider.complete()`,
so every step passes the leak gate, disk cache, preflight, single repair and usage record (D-019) and
replays byte for byte (I2). Spike (`runs/p10-spike/m2-spike.json`; hand-written synthetic functions, no
corpus data): 3/3 schema-valid, 3/3 valid targets. Ollama native tool calling also returned a well-formed
call. It is not used, by design: one pipeline, one cache-key format and one replay path for every step,
and no second provider method.

### Tools (label-free, scoped to the root's downward closure, D-036)
- list_callees(addr): internal callees by address, each readable, no_code or out_of_scope.
- read_code(addr): pseudo-C prepared as the judge prepares it (literal redaction, zero-fill collapse),
  unnumbered so it cannot shift evidence_line, cut at whole lines at 4,000 characters.
- read_summary(addr): the callee's no-context summary, i.e. the R4 prompt, rendered by the D-026 renderer.
- finish.

The root itself is never a read target. Invalid actions (outside the scope, the root, a repeat) cost a
step and are counted.

### Caps (hard; values fixed at the freeze)
- Per root: 8 actions (finish included), 20 model calls, 150,000 metered tokens.
- Metered tokens = ceil(characters / 2.0) over every prompt and reply, cache hits included, so a replay
  gets exactly the live run's budget.
- Per run: a metered-token ceiling, set at the freeze from the development run.
- Gathering stops at finish, at a cap, at a step prompt over the preflight budget, or at a failed step.
  The judge then runs on what was gathered. A failed judge is an abstention named by its failure; a
  budget too small for the judge is the abstention `agent:budget`.

### Data
- Development: the 13 Juliet binaries used in Phase 7 (the 12 shakedown binaries and tw-0015). The step
  prompt, the evidence rendering and the cap values may change only here, before the tag `p10-freeze`.
  The judge, the tools' contract, the scoring rules and the data split never change.
- Scored: the path roots of the other 227 Juliet binaries, and the 24 Phase 9 roots. Roots reach the
  analysis side as address lists, numerically sorted.
- Runtime rule: if the development run projects more than 24 h per policy for the scored Juliet set, a
  seeded subsample of binaries (seed 20261006) is scored instead, fixed and committed before any scored run.

### Statistics
- Juliet: the D-008 primary cell and typed ladder at the path roots. Exact two-sided McNemar on bad roots
  and on good roots for A2 vs R5, A2 vs A1 and A2 vs R4: 6 tests, Holm at family-wise 0.05. Abstentions
  count as incorrect.
- Real code: D-040 pair outcomes, descriptive only.
- Also reported:
  - per root, metered and real tokens and model time (median, p90, max), both in full and beyond R4;
  - from the transcripts: action counts, stop reasons, invalid and repeated actions.
- The scorer's rules are committed before any scored verdict exists.

### Deviations and development-run record (frozen 2026-10-13, before the tag `p10-freeze`)

All changes below were made on the 13 development binaries only, before any scored run, and are of
the kinds the Data rule permits (step prompt, evidence rendering, cap values) or are bookkeeping and
reporting that no model input depends on. The judge, the tools' contract, the scoring rules and the
data split are unchanged.

**1. Step prompt v1 -> v2 (`AGENT_PROMPT_VERSION = 2`, commit `3eb0d8f`).** In the v1 development
run, A2 gathered nothing on 35 of 35 roots: every non-finish action was refused. The step prompt
showed callees only by their Ghidra names (`FUN_00101c04`), whose number carries the image base,
while the tools take program.json addresses (`0x1c04`, D-016). v2 lists each direct callee as
`target 0x1c04 = FUN_00101c04 (status)`, tells the model to copy targets from those lines, and names
the valid targets when an action is refused. v2 development run: 4 invalid actions in 137 steps, 0 of
35 roots with nothing gathered. The v1 runs are kept in `runs/p10-dev-v1`. A constrained target
schema was considered and not adopted: it would change the pre-registered action schema and remove
the invalid-action count.

**2. Bookkeeping (commits `3eb0d8f`, `4150ae3`).** `cache_hit` was removed from `agent.json` (it
differs between a live run and its replay), and each root now records `call_keys`, the cache key of
every model call it made. Neither is a model input. Both policies replay byte for byte (summaries.json
and agent.json, 13/13), and verdicts were unchanged by either change.

**3. Reporting, all before any scored verdict (commits `04c8aae`, `92538f8`, `cc02420`, `4150ae3`).**
Real-code D-040 pair outcomes through Phase 9's own loaders (reproducing Phase 9's R4/R5 pairs 12/12);
abstentions named by their failure; agent mode prints the `tokens (this run)` line; the scorer reads
metrics' nested cell counts; a cost table.

**4. Deviation: model time is reported per run, not per root.** The pre-registration asks for real
tokens and model time per root, in full and beyond R4. Real and metered tokens are reported per root
as registered: real tokens are read from the cache entry of every call a root made, so a cache hit
costs what its live call cost (cost as from an empty cache), and "beyond R4" subtracts the root's own
R4 call. The cache stores no timing, so model time is the per-run sum of the programs'
`tokens (this run)` lines; a resumed program counts only its last process.

**5. Cap values: unchanged.** 8 actions, 20 model calls and 150,000 metered tokens per root;
read_code 4,000 characters; evidence 12,000 characters.

**6. Run ceiling: `max_tokens_per_run = 18,000,000`.** Rule: twice the larger development projection
to the 601 scored Juliet roots, rounded up to the next million. Development means per root: A1 13,584
and A2 14,566 metered tokens, projecting to 8,164,516 and 8,754,457. The same value serves the
real-code runs, where the per-root cap already bounds a run at 150,000 x 24 = 3,600,000.

**7. Runtime rule: the full scored set runs.** Development A2 took about 21.7 s per root over its 26
live roots, projecting about 3.6 h for A2 on the scored Juliet set, under 24 h per policy. No
subsample is drawn; seed 20261006 is unused.

**Development observations (not results).** A2 read code 64 times and summaries 10 times over the 35
development roots. One judge call ended at its output budget (`max_tokens`; tw-0091 0x18dd), a named
abstention under the existing rule. No development verdict was used to change anything above.

### Deviation (2026-10-15, after the scored runs, before any scored number was computed or read): R4 lookup

The first scoring run failed closed (`no R4 row for 0x19dd`, tw-0001) before writing any output. Cause:
`walk --with-baseline` writes a separate no-context row only for functions that have a callee block;
for the others the walk prompt is the no-context prompt, so Phase 8 kept one cache entry and one row,
the walk's own (D-026, D-030; stratum S0). The scorer looked only in `baseline/`, and the development
slice never exposed it (none of its 35 roots lacks a callee block). Fix: for such a root the scorer
reads R4's row, prompt and system text from the walk itself, and fails closed unless that row carries
no callee context. 17 of the 601 scored roots are affected. This changes where R4 is read from, not
what R4 is: no scoring rule, cap, prompt, agent code or run changed, and nothing was re-run.
