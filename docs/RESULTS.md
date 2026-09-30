# TaintWalk results (Phase 8)

> **Status:** Phase 8 local-only results (D-034). Hand-coded error analysis pending (mini-step 16).

- Rungs scored: R1, R2, R3, R4, R5. Every rung is scored by the same D-008 code at the same path roots (I6).
- Rungs, tests, strata and codebook were fixed before any number existed: `docs/PREREGISTRATION.md` (with Deviation D-034: cloud rungs deferred pending funding).
- Every cell with its 95% Wilson interval, and every root row: `scores/<rung>.json` beside `eval.json`.

## Main table

Primary rule: one scored function per path, the path root; pooled over strata.

| rung | what | precision | recall | specificity | coverage | F1 | AUROC |
|---|---|---|---|---|---|---|---|
| R1 | flawfinder | 0.482 [0.427,0.538] 148/307 | 0.617 [0.554,0.676] 148/240 | 0.598 [0.549,0.646] 237/396 | 1.000 [0.994,1.000] 636/636 | 0.541 | 0.606 |
| R2 | input rule | 0.552 [0.496,0.606] 171/310 | 0.713 [0.652,0.766] 171/240 | 0.649 [0.601,0.694] 257/396 | 1.000 [0.994,1.000] 636/636 | 0.622 | - |
| R3 | reachability of an R1 hit | 0.463 [0.415,0.512] 186/402 | 0.775 [0.718,0.823] 186/240 | 0.455 [0.406,0.504] 180/396 | 1.000 [0.994,1.000] 636/636 | 0.579 | 0.613 |
| R4 | per-function LLM, local | 0.512 [0.451,0.572] 133/260 | 0.554 [0.491,0.616] 133/240 | 0.674 [0.627,0.719] 267/396 | 0.997 [0.989,0.999] 634/636 | 0.532 | 0.675 |
| R5 | TaintWalk, local | 0.488 [0.439,0.536] 197/404 | 0.821 [0.767,0.864] 197/240 | 0.477 [0.429,0.526] 189/396 | 1.000 [0.994,1.000] 636/636 | 0.612 | 0.697 |

## By stratum

External-source cases and fixed-sink cases (no untrusted input), reported separately (D-023).

| rung | stratum | precision | recall | specificity | coverage |
|---|---|---|---|---|---|
| R1 | external | 0.480 [0.422,0.539] 134/279 | 0.698 [0.630,0.758] 134/192 | 0.583 [0.531,0.634] 203/348 | 1.000 [0.993,1.000] 540/540 |
| R1 | fixed_sink | 0.500 [0.326,0.674] 14/28 | 0.292 [0.182,0.432] 14/48 | 0.708 [0.568,0.818] 34/48 | 1.000 [0.962,1.000] 96/96 |
| R2 | external | 0.552 [0.496,0.606] 171/310 | 0.891 [0.839,0.927] 171/192 | 0.601 [0.548,0.651] 209/348 | 1.000 [0.993,1.000] 540/540 |
| R2 | fixed_sink | - | 0.000 [0.000,0.074] 0/48 | 1.000 [0.926,1.000] 48/48 | 1.000 [0.962,1.000] 96/96 |
| R3 | external | 0.455 [0.402,0.508] 150/330 | 0.781 [0.718,0.834] 150/192 | 0.483 [0.431,0.535] 168/348 | 1.000 [0.993,1.000] 540/540 |
| R3 | fixed_sink | 0.500 [0.387,0.613] 36/72 | 0.750 [0.612,0.851] 36/48 | 0.250 [0.149,0.388] 12/48 | 1.000 [0.962,1.000] 96/96 |
| R4 | external | 0.513 [0.449,0.577] 118/230 | 0.615 [0.544,0.681] 118/192 | 0.672 [0.621,0.720] 234/348 | 0.996 [0.987,0.999] 538/540 |
| R4 | fixed_sink | 0.500 [0.332,0.668] 15/30 | 0.312 [0.199,0.453] 15/48 | 0.688 [0.547,0.801] 33/48 | 1.000 [0.962,1.000] 96/96 |
| R5 | external | 0.483 [0.430,0.535] 166/344 | 0.865 [0.809,0.906] 166/192 | 0.489 [0.436,0.541] 170/348 | 1.000 [0.993,1.000] 540/540 |
| R5 | fixed_sink | 0.517 [0.393,0.638] 31/60 | 0.646 [0.504,0.766] 31/48 | 0.396 [0.270,0.537] 19/48 | 1.000 [0.962,1.000] 96/96 |

## Secondary rule

A path counts as flagged if any function on it is flagged (the usual convention). Never the headline.

| rung | precision | recall | specificity |
|---|---|---|---|
| R1 | 0.463 [0.415,0.512] 186/402 | 0.775 [0.718,0.823] 186/240 | 0.455 [0.406,0.504] 180/396 |
| R2 | 0.552 [0.499,0.603] 192/348 | 0.800 [0.745,0.846] 192/240 | 0.606 [0.557,0.653] 240/396 |
| R3 | 0.463 [0.415,0.512] 186/402 | 0.775 [0.718,0.823] 186/240 | 0.455 [0.406,0.504] 180/396 |
| R4 | 0.437 [0.393,0.482] 207/474 | 0.863 [0.813,0.900] 207/240 | 0.321 [0.277,0.368] 127/396 |
| R5 | 0.418 [0.376,0.461] 219/524 | 0.912 [0.870,0.942] 219/240 | 0.227 [0.189,0.271] 90/396 |

## Typed ladder

LLM rungs only: detection, right mechanism, exact CWE (D-021 table).

| rung | level | TP | precision | recall |
|---|---|---|---|---|
| R4 | detection | 133 | 0.512 [0.451,0.572] 133/260 | 0.554 [0.491,0.616] 133/240 |
| R4 | mechanism | 52 | 0.200 [0.156,0.253] 52/260 | 0.217 [0.169,0.273] 52/240 |
| R4 | exact | 29 | 0.112 [0.079,0.156] 29/260 | 0.121 [0.085,0.168] 29/240 |
| R5 | detection | 197 | 0.488 [0.439,0.536] 197/404 | 0.821 [0.767,0.864] 197/240 |
| R5 | mechanism | 78 | 0.193 [0.158,0.234] 78/404 | 0.325 [0.269,0.387] 78/240 |
| R5 | exact | 53 | 0.131 [0.102,0.168] 53/404 | 0.221 [0.173,0.277] 53/240 |

## Confidence

AUROC: does the score rank bad roots above good ones (0.5 = no signal). ECE: calibration, for probability-scale rungs only.

| rung | answered | AUROC | ECE |
|---|---|---|---|
| R1 | 636 | 0.606 | - |
| R3 | 636 | 0.613 | - |
| R4 | 634 | 0.675 | 0.242 |
| R5 | 636 | 0.697 | 0.263 |

## Pre-registered tests

Family D-034 local-only: C2, C3L, C4L on bad and good roots, 6 tests. Exact McNemar on paired roots; right = TP on bad roots, TN on good roots; an abstention is wrong. Holm-Bonferroni over the complete family.

| test | A | B | n | A right | B right | A only | B only | p | p (Holm) | reject |
|---|---|---|---|---|---|---|---|---|---|---|
| C2-bad | R5 | R4 | 240 | 197 | 133 | 72 | 8 | 0.000 | 0.000 | yes |
| C2-good | R5 | R4 | 396 | 189 | 267 | 21 | 99 | 0.000 | 0.000 | yes |
| C3L-bad | R5 | R3 | 240 | 197 | 186 | 31 | 20 | 0.161 | 0.322 | no |
| C3L-good | R5 | R3 | 396 | 189 | 180 | 71 | 62 | 0.488 | 0.488 | no |
| C4L-bad | R5 | R2 | 240 | 197 | 171 | 47 | 21 | 0.002 | 0.007 | yes |
| C4L-good | R5 | R2 | 396 | 189 | 257 | 27 | 95 | 0.000 | 0.000 | yes |

## Ablation

Walk arm (A) against the no-context arm (B): same model, same prompts except the callee block. S0: no callee block, so both arms are identical by construction; S1: callee block, one-member path; S2: multi-member path. Roots per stratum: local: S0 17, S1 124, S2 495.

| provider | stratum | label | n | A right | B right | A only | B only | p |
|---|---|---|---|---|---|---|---|---|
| local | all | bad | 240 | 197 | 133 | 72 | 8 | 0.000 |
| local | all | good | 396 | 189 | 267 | 21 | 99 | 0.000 |
| local | S0 | bad | 6 | 6 | 6 | 0 | 0 | 1.000 |
| local | S0 | good | 11 | 9 | 9 | 0 | 0 | 1.000 |
| local | S1 | bad | 47 | 41 | 37 | 5 | 1 | 0.219 |
| local | S1 | good | 77 | 39 | 48 | 2 | 11 | 0.022 |
| local | S2 | bad | 187 | 150 | 90 | 67 | 7 | 0.000 |
| local | S2 | good | 308 | 141 | 210 | 19 | 88 | 0.000 |

## Provider comparison

Deferred pending API funding (D-034): the cloud rungs R6/R7 have not been run. See Future work.

_No rows._

## By CWE class

TaintWalk, local (R5) with 95% Wilson intervals, then every rung as recall / specificity. Never class x flow (D-011).

| class | roots | recall | specificity | precision |
|---|---|---|---|---|
| CWE-78 | 36 | 1.000 [0.824,1.000] 18/18 | 0.611 [0.386,0.797] 11/18 | 0.720 [0.524,0.857] 18/25 |
| CWE-121 | 49 | 0.700 [0.481,0.855] 14/20 | 0.586 [0.407,0.745] 17/29 | 0.538 [0.355,0.712] 14/26 |
| CWE-122 | 45 | 0.833 [0.608,0.942] 15/18 | 0.444 [0.276,0.627] 12/27 | 0.500 [0.332,0.668] 15/30 |
| CWE-124 | 45 | 0.611 [0.386,0.797] 11/18 | 0.556 [0.373,0.724] 15/27 | 0.478 [0.292,0.670] 11/23 |
| CWE-126 | 47 | 0.789 [0.567,0.915] 15/19 | 0.607 [0.424,0.764] 17/28 | 0.577 [0.389,0.745] 15/26 |
| CWE-127 | 45 | 0.667 [0.437,0.837] 12/18 | 0.407 [0.245,0.593] 11/27 | 0.429 [0.265,0.609] 12/28 |
| CWE-134 | 57 | 1.000 [0.832,1.000] 19/19 | 0.447 [0.301,0.603] 17/38 | 0.475 [0.329,0.625] 19/40 |
| CWE-190 | 57 | 0.737 [0.512,0.882] 14/19 | 0.579 [0.422,0.721] 22/38 | 0.467 [0.302,0.639] 14/30 |
| CWE-191 | 54 | 0.833 [0.608,0.942] 15/18 | 0.500 [0.345,0.655] 18/36 | 0.455 [0.298,0.620] 15/33 |
| CWE-369 | 54 | 0.778 [0.548,0.910] 14/18 | 0.472 [0.320,0.630] 17/36 | 0.424 [0.272,0.592] 14/33 |
| CWE-606 | 57 | 0.895 [0.686,0.971] 17/19 | 0.158 [0.074,0.304] 6/38 | 0.347 [0.229,0.487] 17/49 |
| CWE-680 | 36 | 0.889 [0.672,0.969] 16/18 | 0.667 [0.437,0.837] 12/18 | 0.727 [0.518,0.868] 16/22 |
| CWE-789 | 54 | 0.944 [0.742,0.990] 17/18 | 0.389 [0.248,0.551] 14/36 | 0.436 [0.293,0.590] 17/39 |

| class | R1 | R2 | R3 | R4 | R5 |
|---|---|---|---|---|---|
| CWE-78 | 1.00 / 0.00 | 0.89 / 1.00 | 1.00 / 0.00 | 0.67 / 0.22 | 1.00 / 0.61 |
| CWE-121 | 0.40 / 0.72 | 0.40 / 0.72 | 0.80 / 0.45 | 0.30 / 0.69 | 0.70 / 0.59 |
| CWE-122 | 0.50 / 0.67 | 0.44 / 0.70 | 0.78 / 0.48 | 0.44 / 0.70 | 0.83 / 0.44 |
| CWE-124 | 0.56 / 0.63 | 0.44 / 0.70 | 0.78 / 0.48 | 0.50 / 0.78 | 0.61 / 0.56 |
| CWE-126 | 0.53 / 0.64 | 0.42 / 0.71 | 0.89 / 0.39 | 0.42 / 0.71 | 0.79 / 0.61 |
| CWE-127 | 0.50 / 0.67 | 0.44 / 0.70 | 0.67 / 0.56 | 0.50 / 0.70 | 0.67 / 0.41 |
| CWE-134 | 0.95 / 0.21 | 0.89 / 0.55 | 1.00 / 0.00 | 0.68 / 0.61 | 1.00 / 0.45 |
| CWE-190 | 0.42 / 0.79 | 0.89 / 0.55 | 0.47 / 0.76 | 0.53 / 0.71 | 0.74 / 0.58 |
| CWE-191 | 0.39 / 0.81 | 0.89 / 0.56 | 0.50 / 0.75 | 0.33 / 0.92 | 0.83 / 0.50 |
| CWE-369 | 0.61 / 0.69 | 0.89 / 0.56 | 0.72 / 0.64 | 0.50 / 0.75 | 0.78 / 0.47 |
| CWE-606 | 0.95 / 0.26 | 0.89 / 0.55 | 1.00 / 0.00 | 0.79 / 0.47 | 0.89 / 0.16 |
| CWE-680 | 0.78 / 1.00 | 0.89 / 1.00 | 0.83 / 1.00 | 0.72 / 0.89 | 0.89 / 0.67 |
| CWE-789 | 0.44 / 0.69 | 0.89 / 0.56 | 0.61 / 0.50 | 0.83 / 0.56 | 0.94 / 0.39 |

## By flow variant

TaintWalk, local (R5) with 95% Wilson intervals, then every rung as recall / specificity. Never class x flow (D-011).

| flow | roots | recall | specificity | precision |
|---|---|---|---|---|
| 01 | 69 | 0.923 [0.759,0.979] 24/26 | 0.558 [0.411,0.696] 24/43 | 0.558 [0.411,0.696] 24/43 |
| 31 | 72 | 0.852 [0.675,0.941] 23/27 | 0.533 [0.391,0.671] 24/45 | 0.523 [0.379,0.662] 23/44 |
| 41 | 72 | 0.815 [0.633,0.918] 22/27 | 0.511 [0.370,0.650] 23/45 | 0.500 [0.358,0.642] 22/44 |
| 42 | 69 | 0.808 [0.621,0.915] 21/26 | 0.349 [0.224,0.498] 15/43 | 0.429 [0.300,0.567] 21/49 |
| 44 | 69 | 0.808 [0.621,0.915] 21/26 | 0.558 [0.411,0.696] 24/43 | 0.525 [0.375,0.671] 21/40 |
| 45 | 69 | 0.808 [0.621,0.915] 21/26 | 0.372 [0.244,0.521] 16/43 | 0.438 [0.307,0.577] 21/48 |
| 52 | 73 | 0.821 [0.644,0.921] 23/28 | 0.533 [0.391,0.671] 24/45 | 0.523 [0.379,0.662] 23/44 |
| 54 | 71 | 0.815 [0.633,0.918] 22/27 | 0.500 [0.358,0.642] 22/44 | 0.500 [0.358,0.642] 22/44 |
| 63 | 72 | 0.741 [0.553,0.868] 20/27 | 0.378 [0.251,0.524] 17/45 | 0.417 [0.288,0.557] 20/48 |

| flow | R1 | R2 | R3 | R4 | R5 |
|---|---|---|---|---|---|
| 01 | 0.77 / 0.47 | 0.81 / 0.60 | 0.77 / 0.47 | 0.81 / 0.67 | 0.92 / 0.56 |
| 31 | 0.78 / 0.42 | 0.81 / 0.60 | 0.78 / 0.42 | 0.81 / 0.62 | 0.85 / 0.53 |
| 41 | 0.63 / 0.60 | 0.81 / 0.60 | 0.74 / 0.51 | 0.44 / 0.80 | 0.81 / 0.51 |
| 42 | 0.27 / 0.81 | 0.00 / 1.00 | 0.77 / 0.47 | 0.69 / 0.30 | 0.81 / 0.35 |
| 44 | 0.65 / 0.63 | 0.81 / 0.60 | 0.88 / 0.40 | 0.46 / 0.67 | 0.81 / 0.56 |
| 45 | 0.58 / 0.63 | 0.81 / 0.60 | 0.69 / 0.51 | 0.42 / 0.67 | 0.81 / 0.37 |
| 52 | 0.61 / 0.60 | 0.75 / 0.62 | 0.82 / 0.38 | 0.39 / 0.76 | 0.82 / 0.53 |
| 54 | 0.52 / 0.66 | 0.78 / 0.61 | 0.74 / 0.48 | 0.48 / 0.75 | 0.81 / 0.50 |
| 63 | 0.74 / 0.58 | 0.81 / 0.60 | 0.78 / 0.47 | 0.48 / 0.80 | 0.74 / 0.38 |

## Cost and runtime

Tokens from cache entries (the original calls, deduplicated per arm); dollars at 2026-09-29 list prices. Runtime from the live runs: local: 133 programs, 2420 calls (455 cache hits), model time 19612 s, wall 19658 s.

| provider | arm | calls | missing | input | cache write | cache read | output | USD |
|---|---|---|---|---|---|---|---|---|
| local | walk | 1902 | 0 | 6868090 | 0 | 6041115 | 854509 | 0.00 |
| local | baseline | 1789 | 0 | 6016803 | 0 | 5522411 | 581568 | 0.00 |
| local | union | 3530 | 0 | 12342218 | 0 | 11072089 | 1375844 | 0.00 |

## Error analysis

Hand-coding sample: R5 (walk arm), seed 20260930: 20 false positives and 20 false negatives; worksheet in `errors/`.

### Few-shot parroting

A reason counts as parroted when it shares 8 or more consecutive words with a few-shot reason (D-025).

| rung | answered | parroted | rate |
|---|---|---|---|
| R4 | 2320 | 8 | 0.003 |
| R5 | 2315 | 14 | 0.006 |

### Sanitizer-literal shortcut

Outcomes at roots whose own pseudo-C holds a sanitizer error message (D-018), and at the rest.

| rung | label | roots | n | flagged | clear | abstain |
|---|---|---|---|---|---|---|
| R4 | bad | with literal | 21 | 16 | 5 | 0 |
| R4 | bad | without literal | 219 | 117 | 102 | 0 |
| R4 | good | with literal | 43 | 23 | 19 | 1 |
| R4 | good | without literal | 353 | 104 | 248 | 1 |
| R5 | bad | with literal | 21 | 18 | 3 | 0 |
| R5 | bad | without literal | 219 | 179 | 40 | 0 |
| R5 | good | with literal | 43 | 30 | 13 | 0 |
| R5 | good | without literal | 353 | 177 | 176 | 0 |

### Abstentions

Rows with no summary, by failure kind (every walked function, not only roots).

| rung | failure kinds |
|---|---|
| R4 | max_tokens 2 |
| R5 | max_tokens 6, schema 1 |

### Hand-coded analysis

_Not written yet (mini-step 16)._

## Development-set disclosure

Seen during development and kept in the corpus: tw-0015, tw-0022, tw-0065, tw-0066, tw-0091, tw-0125, tw-0135, tw-0151, tw-0166, tw-0175, tw-0178, tw-0188, tw-0237 (the Phase 6 gate binary and the Phase 7 scorer shakedown), and the Phase 5 development and held-out samples (20 functions each), which shaped prompt v2 and the local model choice.

## Future work

- Cloud rungs R6/R7 on Claude Sonnet 5.5 are deferred until the API is funded (D-034). Everything they need is built and tested offline: the D-031 configuration is in `config/providers.yaml`, and `taintwalk eval --cloud ROOT` adds them.
- Once funded: G-CLOUD pings, the label-free 40-function probe and its cost rule (D-031), the full cloud walk with `--with-baseline`, then the full family of 10 pre-registered tests (D-030) and the provider comparison.

## Limitations

- Local 9B model only: the cloud headline (R7) is deferred pending API funding (D-034), so every LLM number here comes from ornith:9b.
- Juliet is synthetic and stylized; every claim here is provisional until Phase 9 measures real code.
- Frozen pipeline (D-032): no grounding rule for rendered callee fields, `.rodata` strings unresolved, alloca probe loops not collapsed.
- R1's statically-sized-array rule fires on `char buf[N]` but not on `undefined1 buf[N]`, so part of its recall depends on the decompiler's type recovery, not on flawfinder.
- `rand()` counts as an input source (Juliet's convention, the prompt's, and R2's list).
- CWE-78, 134 and 606 are effectively char-only: their wchar_t variants did not compile (D-013).
- Flow 44's function pointers resolve to call edges at -O0; an unresolved computed call would give no edge.
