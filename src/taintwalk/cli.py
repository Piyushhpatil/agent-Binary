"""TaintWalk command-line entry point: `taintwalk <command>`."""
from __future__ import annotations

import argparse
import sys
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

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
