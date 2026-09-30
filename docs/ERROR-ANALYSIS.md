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
