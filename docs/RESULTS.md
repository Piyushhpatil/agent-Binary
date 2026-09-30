# TaintWalk results (Phase 8)

> **Status:** Phase 8 gate: local-only results (D-034); cloud rungs deferred pending funding.

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

Tokens from cache entries (the original calls, deduplicated per arm); dollars at 2026-09-29 list prices. Runtime from the live runs: local: 133 programs, 2420 calls (455 cache hits), model time 19612 s, wall 19658 s (the last resumed segment only: 133 of 240 programs; earlier segments were interrupted and resumed from the cache).

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

#### Hand-coded error analysis (R5: TaintWalk on ornith:9b)

Sample: 20 false positives and 20 false negatives drawn with seed 20260930 (`runs/p8-eval/errors/worksheet-R5.md`). Coded with the pre-registered codebook (D-032), one category per error, by an AI assistant (Claude) working from the worksheet and reviewed by the author. The plan was author coding; the change, and two tie-break rules added while coding, are disclosed as Deviation D-035 in `docs/PREREGISTRATION.md`. An AI labelling another model's mistakes, with no second coder, is a limitation of this analysis.

- FP categories: ignored guard; context-induced; ignored constant argument; decompiler artifact; invented sink/source; other
- FN categories: missed sink; hallucinated guard; context-induced; decompiler artifact; other

| # | error (worksheet heading) | kind | category | note |
|---|---|---|---|---|
| 1 | FP-01 tw-0012 0x1b2a FUN_00101b2a | FP | context-induced | passes the fixed command ls *.* via a global; inherited the callee's execlp verdict |
| 2 | FP-02 tw-0028 0x1aba FUN_00101aba | FP | context-induced | passes a large zeroed stack buffer; inherited the callee's vulnerable verdict |
| 3 | FP-03 tw-0090 0x1b3f FUN_00101b3f | FP | ignored guard | recv capped at 13 bytes into a 14-byte buffer; claimed an overflow |
| 4 | FP-04 tw-0109 0x19b1 FUN_001019b1 | FP | context-induced | reason calls the 400-byte buffer safe, then defers to the callee verdict |
| 5 | FP-05 tw-0118 0x1b77 FUN_00101b77 | FP | context-induced | fixed-format print callee summarized as a format-string sink; also claimed an unchecked fgetws return that is checked |
| 6 | FP-06 tw-0142 0x1a5e FUN_00101a5e | FP | context-induced | rand value to a number-printing callee summarized as a format-string sink |
| 7 | FP-07 tw-0147 0x1911 FUN_00101911 | FP | context-induced | rand byte to a printf helper summarized as a format-string sink |
| 8 | FP-08 tw-0160 0x19df FUN_001019df | FP | context-induced | rand value via a global to print helpers summarized as format-string sinks |
| 9 | FP-09 tw-0161 0x19d1 FUN_001019d1 | FP | context-induced | reason says the constant is trusted, then defers to the callee verdict |
| 10 | FP-10 tw-0168 0x1b4f FUN_00101b4f | FP | ignored guard | recv capped at 13 bytes; claimed an overflow; never considered the real divide-by-zero check |
| 11 | FP-11 tw-0184 0x19bb FUN_001019bb | FP | context-induced | int from stdin passed to a callee whose print-helper call was summarized as a format-string sink |
| 12 | FP-12 tw-0194 0x1d9f FUN_00101d9f | FP | context-induced | passes the fixed string 15 (Ghidra shows 0x3531); inherited the callee verdict |
| 13 | FP-13 tw-0195 0x1c9e FUN_00101c9e | FP | context-induced | callee summary shows its real sink guarded (< 10000); verdict came from a print-helper call |
| 14 | FP-14 tw-0196 0x1d1f FUN_00101d1f | FP | context-induced | fixed string 15 via a global; reason cites the callee's printf verdict |
| 15 | FP-15 tw-0200 0x1b34 FUN_00101b34 | FP | context-induced | file input to a callee chain summarized as a format-string sink |
| 16 | FP-16 tw-0211 0x1a6d FUN_00101a6d | FP | ignored constant argument | allocation size is a constant from a no-taint source; reason admits no untrusted data |
| 17 | FP-17 tw-0216 0x1a86 FUN_00101a86 | FP | context-induced | sets a global to 20, then inherits the callee's malloc verdict |
| 18 | FP-18 tw-0221 0x1984 FUN_00101984 | FP | context-induced | passes a pointer to the constant 20 (misread as a 20-byte buffer); inherited the callee verdict |
| 19 | FP-19 tw-0224 0x1ac0 FUN_00101ac0 | FP | ignored guard | checks 6 <= n <= 99 before malloc; argued the allocation is unbounded if the check fails |
| 20 | FP-20 tw-0229 0x1c1f FUN_00101c1f | FP | ignored constant argument | allocation size from a no-taint source returning a fixed value; assumed it could be huge |
| 21 | FN-01 tw-0020 0x189d FUN_0010189d | FN | missed sink | loop writes 100 ints into a 52-int array; model read it as a safe 52-element copy |
| 22 | FN-02 tw-0024 0x1957 FUN_00101957 | FN | context-induced | callee writes into its parameter but its summary lists flows: none and not vulnerable |
| 23 | FN-03 tw-0025 0x1961 FUN_00101961 | FN | missed sink | ignored the source callee's returns taint: yes; array write checked only against < 0 |
| 24 | FN-04 tw-0035 0x18fd FUN_001018fd | FN | context-induced | pass-through callee in a 5-function chain summarized as no sinks; downstream copy lost |
| 25 | FN-05 tw-0038 0x18dd FUN_001018dd | FN | other | fixed-sink size bug with no input; cleared because nothing untrusted flows in |
| 26 | FN-06 tw-0049 0x19ce FUN_001019ce | FN | context-induced | callee summary missed the global flow and the real heap sink (listed only print calls) |
| 27 | FN-07 tw-0069 0x189d FUN_0010189d | FN | other | treated rand() as not user-controlled; reason describes taint reaching a sink, verdict says safe |
| 28 | FN-08 tw-0070 0x18dd FUN_001018dd | FN | decompiler artifact | data = buffer - 8 shown by Ghidra as a separate stack variable, hiding the underwrite |
| 29 | FN-09 tw-0094 0x189d FUN_0010189d | FN | hallucinated guard | treated a one-sided index < 10 check as a full bound; negative index under-reads |
| 30 | FN-10 tw-0098 0x194a FUN_0010194a | FN | context-induced | callee summary marked a one-sided < 10 check as sanitized; negative index slips through |
| 31 | FN-11 tw-0105 0x195c FUN_0010195c | FN | other | declined a correct vulnerable callee verdict: root exposes no new sink of its own |
| 32 | FN-12 tw-0107 0x18bd FUN_001018bd | FN | decompiler artifact | data = buffer - 8 shown as a pointer to a separate stack variable; chain summary also lost the sink |
| 33 | FN-13 tw-0136 0x18c3 FUN_001018c3 | FN | other | treated rand() as trusted despite the prompt; callee correctly flagged |
| 34 | FN-14 tw-0139 0x1955 FUN_00101955 | FN | context-induced | source callee summarized as returns no taint; the squaring overflow was never considered |
| 35 | FN-15 tw-0148 0x189d FUN_0010189d | FN | other | misread the rand() arithmetic as seeding a PRNG; ignored the callee's vulnerable verdict |
| 36 | FN-16 tw-0157 0x18f3 FUN_001018f3 | FN | missed sink | integer underflow data - 1 on fscanf input is the sink; deferred to the print helper's verdict |
| 37 | FN-17 tw-0177 0x18c1 FUN_001018c1 | FN | other | declined a correct divide_by_zero callee verdict: nothing dangerous in this function itself |
| 38 | FN-18 tw-0184 0x18dd FUN_001018dd | FN | context-induced | callee summary missed its division sink and said not vulnerable |
| 39 | FN-19 tw-0192 0x1b7a FUN_00101b7a | FN | missed sink | tainted loop bound from swscanf is the CWE-606 sink; only the print call was considered |
| 40 | FN-20 tw-0216 0x1987 FUN_00101987 | FN | other | declined a correct malloc-size callee verdict; the same binary's good root was flagged (FP-17) |

#### Counts

| kind | category | errors |
|---|---|---|
| FP | context-induced | 15 |
| FP | ignored guard | 3 |
| FP | ignored constant argument | 2 |
| FN | other | 7 |
| FN | context-induced | 6 |
| FN | missed sink | 4 |
| FN | decompiler artifact | 2 |
| FN | hallucinated guard | 1 |

#### Observations

- **Verdict inheritance drives the false positives.** 15 of 20 are context-induced: the root copies a callee's `vulnerable` verdict although the callee block states that each summary ignores what the caller passes. Six roots pass a hard-coded value (FP-01, FP-09, FP-12, FP-14, FP-17, FP-18); FP-09's own reason calls the constant trusted and flags it anyway.
- **One wrong leaf summary spreads upward.** Print helpers that call printf or wprintf were summarized as format-string sinks, so callers passing them a number or buffer inherited a false alarm (FP-05 to FP-08, FP-11, FP-13, FP-15).
- **Context is used inconsistently.** The model inherits wrong `vulnerable` verdicts but declines correct ones: FN-11, FN-17 and FN-20 clear a root whose callee is correctly summarized as vulnerable, because the root itself exposes no new sink. The same binary shows both: tw-0216 flags the good root that passes 20 (FP-17) and clears the bad root that passes rand() (FN-20); tw-0184 flags the guarded good path (FP-11) and clears the unguarded division (FN-18).
- **Summaries lose information along chains.** Pass-through functions in 3- and 5-function flows were summarized with no sinks (FN-04, FN-12), a callee writing into its parameter listed no flows (FN-02), and a one-sided `< 10` check was recorded as sanitizing (FN-10). A summary cannot carry what its own analysis missed, so these errors compound up the walk.
- **The taint framing misses some bug shapes.** rand() was treated as trusted despite the prompt (FN-07, FN-13, FN-15); arithmetic and loop-bound bugs were not treated as sinks (FN-16, FN-19); a fixed-size bug with no input was cleared because nothing untrusted flows (FN-05); and two underwrites were invisible because Ghidra renders `buffer - 8` as a separate stack variable (FN-08, FN-12). Seven of 20 false negatives needed `other`: three treat rand() as trusted, three decline a correct callee verdict, one is the fixed-size bug. The codebook had no category for the first two.
- **What this suggests (future work; the prompt is frozen under D-032):** show callee flows, sinks and guards but not the callee's own verdict; correct the leaf summaries of print helpers; add arithmetic and loop-bound sinks to the prompt's taxonomy.

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
