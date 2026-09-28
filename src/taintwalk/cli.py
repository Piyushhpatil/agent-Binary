"""TaintWalk command-line entry point: `taintwalk <command>`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any


def _cmd_doctor(args: argparse.Namespace) -> int:
    from taintwalk.doctor import run_doctor
    return run_doctor()


def _cmd_smoke(args: argparse.Namespace) -> int:
    from taintwalk.smoke import run_smoke
    return run_smoke()


def _split(values: list[str] | None) -> list[str]:
    """Accept '121 122', '121,122', or 'CWE-121'."""
    out: list[str] = []
    for v in values or []:
        out.extend(x for x in v.replace(",", " ").split() if x)
    return out


def _corpus_cfg(args: argparse.Namespace) -> dict[str, Any]:
    """Config corpus section with any CLI overrides applied."""
    from taintwalk.corpus.select import corpus_cfg
    c = corpus_cfg()
    if getattr(args, "cwe", None):
        c["cwes"] = [int(x.upper().removeprefix("CWE-").removeprefix("CWE")) for x in _split(args.cwe)]
    if getattr(args, "variants", None):
        c["flows"] = [f"{int(x):02d}" for x in _split(args.variants)]
    if getattr(args, "total", None) is not None:
        c["total"] = args.total
    return c


def _cmd_corpus_select(args: argparse.Namespace) -> int:
    from taintwalk.corpus.select import select, summarize
    for line in summarize(select(_corpus_cfg(args))):
        print(line)
    return 0


def _cmd_corpus_build(args: argparse.Namespace) -> int:
    from taintwalk.corpus.build import build_corpus
    from taintwalk.corpus.groundtruth import write_manifest
    c = _corpus_cfg(args)
    rc = build_corpus(c, jobs=args.jobs)
    return rc if rc != 0 else write_manifest(c)


def _cmd_corpus_manifest(args: argparse.Namespace) -> int:
    from taintwalk.corpus.groundtruth import write_manifest
    return write_manifest(_corpus_cfg(args))


def _cmd_corpus_verify(args: argparse.Namespace) -> int:
    from taintwalk.corpus.verify import verify_corpus
    return verify_corpus(args.manifest)


def _cmd_extract(args: argparse.Namespace) -> int:
    from taintwalk.config import REPO_ROOT
    from taintwalk.extract.ghidra_runner import extract_cfg, extract_many, extract_one
    from taintwalk.extract.report import load_manifest, report, sample_case_ids

    ecfg = extract_cfg()
    decompile_timeout = args.decompile_timeout or ecfg["decompile_timeout_s"]
    binary_timeout = args.timeout or ecfg["binary_timeout_s"]
    jobs = args.jobs or ecfg["jobs"]

    if args.all:
        out_dir = Path(args.out or ecfg["out_dir"])
        if not out_dir.is_absolute():
            out_dir = REPO_ROOT / out_dir
        manifest = load_manifest()
        case_ids = sample_case_ids(manifest, args.sample)
        by_id = {e["case_id"]: e for e in manifest["entries"]}
        targets = [(cid, REPO_ROOT / by_id[cid]["stripped"]) for cid in case_ids]
        print(f"extracting {len(targets)} binaries -> {out_dir} (jobs={jobs})")
        results = extract_many(
            targets, out_dir, jobs=jobs,
            decompile_timeout=decompile_timeout,
            binary_timeout=binary_timeout,
            force=args.force,
        )
        bad = [r for r in results if not r.ok]
        print(f"\nextracted {len(results) - len(bad)}/{len(results)} "
              f"(cached {sum(r.status == 'cached' for r in results)})")
        if bad:
            for r in bad:
                print(f"  {r.status}: {r.target.name} {r.detail}")
            return 1
        return report(out_dir, case_ids, manifest) if args.report else 0

    if not args.path:
        print("give a path to a stripped ELF, or use --all", file=sys.stderr)
        return 2
    target = Path(args.path)
    if not target.is_absolute():
        target = REPO_ROOT / target
    out_dir = Path(args.out or ecfg["smoke_dir"])
    if not out_dir.is_absolute():
        out_dir = REPO_ROOT / out_dir
    res = extract_one(
        target, out_dir / "program.json",
        decompile_timeout=decompile_timeout,
        binary_timeout=binary_timeout,
        force=args.force,
    )
    if res.status == "cached":
        print(f"{target.name}: CACHED -> {(out_dir / 'program.json')}")
    elif res.detail:
        print(res.detail)
    if not res.ok:
        print(f"{res.status}: {res.detail}", file=sys.stderr)
    return 0 if res.ok else 1


def _cmd_label(args: argparse.Namespace) -> int:
    from taintwalk.config import REPO_ROOT
    from taintwalk.eval.join import run_label
    run_dir = Path(args.run_dir)
    if not run_dir.is_absolute():
        run_dir = REPO_ROOT / run_dir
    manifest = Path(args.manifest) if args.manifest else None
    return run_label(run_dir, report=args.report, manifest_path=manifest)


def _cmd_selftest(args: argparse.Namespace) -> int:
    if not args.leak:
        print("nothing selected; use --leak", file=sys.stderr)
        return 2
    from taintwalk.config import REPO_ROOT
    from taintwalk.eval.selftest import run_leak_selftest
    from taintwalk.extract.ghidra_runner import extract_cfg
    d = Path(args.programs) if args.programs else Path(extract_cfg()["out_dir"]) / "programs"
    if not d.is_absolute():
        d = REPO_ROOT / d
    manifest = Path(args.manifest) if args.manifest else None
    return run_leak_selftest(d, manifest_path=manifest)


def _cmd_llm_ping(args: argparse.Namespace) -> int:
    from taintwalk.llm.ping import run_ping
    return run_ping(
        args.provider,
        use_cache=not args.no_cache,
        retry_failed=args.retry_failed,
        run_dir=args.run_dir,
    )


def _cmd_analyze_one(args: argparse.Namespace) -> int:
    """Phase 5: one TaintSummary per function, no call graph. cli.py is glue: the eval side
    (sample selection, agreement) and the analysis side (runner) never import each other's
    ground truth; only sample.json, which holds (sha256, addr) pairs, crosses over."""
    import json

    from taintwalk.analysis.analyze_one import (
        analysis_report,
        load_programs,
        load_sample,
        run_analyze,
    )
    from taintwalk.config import REPO_ROOT
    from taintwalk.extract.ghidra_runner import extract_cfg
    from taintwalk.llm.base import LLMError
    from taintwalk.llm.registry import get_provider, write_usage

    def _abs(p: str | Path) -> Path:
        p = Path(p)
        return p if p.is_absolute() else REPO_ROOT / p

    run_dir = _abs(args.run_dir)
    if args.program:
        if not args.addr or args.sample:
            print("single mode needs --program PATH --addr ADDR, without --sample", file=sys.stderr)
            return 2
        prog = json.loads(_abs(args.program).read_text(encoding="utf-8"))
        programs = {prog["binary"]["sha256"]: prog}
        sample = [(prog["binary"]["sha256"], args.addr)]
    elif args.sample:
        from taintwalk.eval.sample import DEFAULT_SEED, select_sample, write_sample
        seed = args.seed if args.seed is not None else DEFAULT_SEED
        labels_dir = _abs(args.labels) if args.labels else _abs(Path(extract_cfg()["out_dir"]) / "labels")
        s, key = select_sample(labels_dir, args.sample, seed)
        sample = load_sample(write_sample(run_dir, s, key, seed=seed))
        programs_dir = _abs(args.programs) if args.programs else _abs(Path(extract_cfg()["out_dir"]) / "programs")
        programs = load_programs(programs_dir)
    else:
        print("give --sample N, or --program PATH --addr ADDR", file=sys.stderr)
        return 2

    try:
        provider = get_provider(args.provider, use_cache=not args.no_cache)
    except LLMError as e:
        print(f"ANALYZE FAIL: {type(e).__name__}: {e}")
        return 1
    print(f"provider: {provider.name}  model {provider.model}  "
          f"cache {'on' if provider.cache is not None else 'OFF'}  run dir {run_dir}")
    try:
        rows = run_analyze(provider, sample, programs, run_dir, retry_failed=args.retry_failed)
    except LLMError as e:
        write_usage(run_dir, [provider])
        print(f"ANALYZE FAIL: {type(e).__name__}: {e}")
        return 1
    write_usage(run_dir, [provider])
    rc = analysis_report(rows, run_dir)
    if args.report and args.sample:
        from taintwalk.eval.sample import agreement
        agreement(run_dir)
    return rc


def _add_scope_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--cwe", nargs="+", help="CWE classes (default: config corpus.cwes)")
    p.add_argument("--variants", nargs="+", help="Juliet flow variants (default: config corpus.flows)")
    p.add_argument("--total", type=int, help="total binaries (default: config corpus.total)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="taintwalk",
        description="LLM-driven interprocedural taint analysis over stripped ELF binaries.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="check every toolchain dependency and print a table")
    doctor.set_defaults(func=_cmd_doctor)

    smoke = sub.add_parser("smoke", help="compile, strip a copy, decompile with Ghidra headless")
    smoke.set_defaults(func=_cmd_smoke)

    corpus = sub.add_parser("corpus", help="build and verify the labeled Juliet corpus")
    csub = corpus.add_subparsers(dest="corpus_command", required=True)

    sel = csub.add_parser("select", help="print the deterministic selection summary (no compile)")
    _add_scope_args(sel)
    sel.set_defaults(func=_cmd_corpus_select)

    bld = csub.add_parser("build", help="compile, strip a copy, extract labels, write manifest")
    _add_scope_args(bld)
    bld.add_argument("--jobs", type=int, help="parallel compiles (default: config corpus.jobs)")
    bld.set_defaults(func=_cmd_corpus_build)

    man = csub.add_parser("manifest", help="re-extract labels and rewrite manifest (no compile)")
    man.set_defaults(func=_cmd_corpus_manifest)

    ver = csub.add_parser("verify", help="prove G1/G2 for every manifest entry")
    ver.add_argument("--manifest", help="manifest path (default: config corpus.manifest)")
    ver.set_defaults(func=_cmd_corpus_verify)

    ext = sub.add_parser("extract", help="stripped ELF -> program.json via Ghidra headless")
    ext.add_argument("path", nargs="?", help="a stripped ELF (omit with --all)")
    ext.add_argument("-o", "--out", help="output directory")
    ext.add_argument("--all", action="store_true", help="extract every manifest entry")
    ext.add_argument("--sample", type=int, help="with --all: seeded random subset of N binaries")
    ext.add_argument("--report", action="store_true", help="with --all: join to manifest and measure recovery")
    ext.add_argument("--jobs", type=int, help="parallel extractions (default: config extract.jobs)")
    ext.add_argument("--timeout", type=int, help="wall seconds per binary")
    ext.add_argument("--decompile-timeout", type=int, help="seconds per function")
    ext.add_argument("--force", action="store_true", help="re-extract even if program.json is current")
    ext.set_defaults(func=_cmd_extract)

    lab = sub.add_parser("label", help="join program.json to ground truth by address (eval side)")
    lab.add_argument("run_dir", help="run dir holding program.json or programs/*.json")
    lab.add_argument("--report", action="store_true", help="per-case table + label_report.json")
    lab.add_argument("--manifest", help="manifest path (default: config corpus.manifest)")
    lab.set_defaults(func=_cmd_label)

    st = sub.add_parser("selftest", help="self-checks over real pipeline data")
    st.add_argument("--leak", action="store_true", help="leak gate over every in-scope prompt input")
    st.add_argument("--programs", help="dir of program.json files (default: <extract.out_dir>/programs)")
    st.add_argument("--manifest", help="manifest path (default: config corpus.manifest)")
    st.set_defaults(func=_cmd_selftest)

    llm = sub.add_parser("llm", help="LLM backends: health checks through the full provider pipeline")
    lsub = llm.add_subparsers(dest="llm_command", required=True)

    ping = lsub.add_parser("ping", help="one structured call: leak gate, cache, send, validate, usage")
    ping.add_argument("--provider", help="provider name from config/providers.yaml (default: its 'default')")
    ping.add_argument("--no-cache", action="store_true", help="bypass the disk cache and always call the model")
    ping.add_argument("--retry-failed", action="store_true", help="re-call instead of replaying a cached failure")
    ping.add_argument("--run-dir", help="where usage.json goes (default: runs/p4-ping)")
    ping.set_defaults(func=_cmd_llm_ping)

    ao = sub.add_parser("analyze-one", help="one taint summary per function, no call graph (Phase 5)")
    ao.add_argument("--sample", type=int, help="N functions picked on the eval side (flows 01/31, half bad)")
    ao.add_argument("--program", help="single mode: a program.json")
    ao.add_argument("--addr", help="single mode: function address as in program.json, e.g. 0x189d")
    ao.add_argument("--provider", help="provider name from config/providers.yaml (default: its 'default')")
    ao.add_argument("--run-dir", default="runs/p5-analyze", help="output dir (default: runs/p5-analyze)")
    ao.add_argument("--seed", type=int, help="sample seed (default: eval.sample.DEFAULT_SEED)")
    ao.add_argument("--labels", help="dir of label files (default: <extract.out_dir>/labels)")
    ao.add_argument("--programs", help="dir of program.json files (default: <extract.out_dir>/programs)")
    ao.add_argument("--report", action="store_true", help="with --sample: verdict agreement vs labels")
    ao.add_argument("--no-cache", action="store_true", help="bypass the disk cache and always call the model")
    ao.add_argument("--retry-failed", action="store_true", help="re-call instead of replaying a cached failure")
    ao.set_defaults(func=_cmd_analyze_one)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())