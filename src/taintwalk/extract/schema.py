"""program.json schema (Phase 2).

Address convention
------------------
`addr` is the ELF virtual address with Ghidra's image base subtracted, rendered as
a lowercase `0x` hex string. For the PIE binaries this corpus builds, that equals
the link-time vaddr recorded in `corpus/manifest.json` (`functions[].addr_hex`), so
the Phase 3 join is an exact integer lookup (Invariant I4). `ghidra_addr` keeps the
raw rebased value for debugging and for `--explain` output later.

Scope convention (D-015 option A)
---------------------------------
Extraction never consults ground truth. `in_scope` is decided from the binary alone:
a function is in scope iff it lives in .text, is not a thunk, is not external, and is
not reachable-only-from-CRT startup code. Juliet support code (io.c) therefore stays
in scope here; excluding it is an evaluation-harness concern handled in Phase 3.

Derived fields
--------------
`Program.counts` is computed from `functions`. It is written to program.json for
convenience (`jq .counts`) and dropped again on load, so a stale value in a file can
never disagree with the functions it summarizes.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

SCHEMA_VERSION = 1

HexAddr = Annotated[str, Field(pattern=r"^0x[0-9a-f]+$")]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

ExcludeReason = Literal["non_text", "thunk", "external", "plt", "crt"]


class CalleeRef(BaseModel):
    """One outgoing call edge.

    kind="internal" -> `addr` is a function in this binary (a Phase 6 graph edge).
    kind="external" -> `name` is a dynamic import (no summary exists to fetch).
    `via_thunk` records the .plt.sec / .plt.got stub the call physically went through.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["internal", "external"]
    addr: HexAddr | None = None
    name: str | None = None
    via_thunk: HexAddr | None = None

    @model_validator(mode="after")
    def _consistent(self) -> "CalleeRef":
        if self.kind == "internal" and self.addr is None:
            raise ValueError("internal callee requires addr")
        if self.kind == "external" and not self.name:
            raise ValueError("external callee requires name")
        return self


class Function(BaseModel):
    model_config = ConfigDict(extra="forbid")

    addr: HexAddr                       # join key (I4)
    ghidra_addr: HexAddr
    ghidra_name: str                    # FUN_00101xxx, or a name Ghidra derived structurally
    size: int = Field(ge=0)
    block: str                          # memory block: .text, .plt.sec, EXTERNAL, ...
    is_thunk: bool = False
    is_external: bool = False
    thunk_target: str | None = None
    in_scope: bool
    excluded_reason: ExcludeReason | None = None
    pseudo_c: str | None = None         # populated for in-scope functions only
    decompile_failed: bool = False
    decompile_error: str | None = None
    callees: list[CalleeRef] = Field(default_factory=list)
    callers: list[HexAddr] = Field(default_factory=list)
    indirect_call_sites: int = 0        # computed-target calls; ~always 0 outside thunks/CRT

    @model_validator(mode="after")
    def _scope_consistent(self) -> "Function":
        if self.in_scope and self.excluded_reason is not None:
            raise ValueError(f"{self.addr}: in_scope with excluded_reason={self.excluded_reason}")
        if not self.in_scope and self.excluded_reason is None:
            raise ValueError(f"{self.addr}: excluded without a reason")
        if self.in_scope and not self.decompile_failed and self.pseudo_c is None:
            raise ValueError(f"{self.addr}: in-scope function has neither pseudo_c nor a failure flag")
        return self


class BinaryRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: Sha256
    image_base: HexAddr
    text_addr: HexAddr
    text_size: int = Field(ge=0)


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = SCHEMA_VERSION
    exporter_sha256: Sha256             # hash of ghidra_export.py + schema.py; part of the cache key
    generated_utc: str
    ghidra_version: str
    pyghidra_version: str
    python_version: str
    analysis: str = "pyghidra open_program(analyze=True), Ghidra default analyzers"
    decompile_timeout_s: int
    analyze_seconds: float
    decompile_seconds: float


class Program(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provenance: Provenance
    binary: BinaryRef
    functions: list[Function] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _drop_derived(cls, data: Any) -> Any:
        """`counts` is serialized for convenience but always recomputed on load."""
        if isinstance(data, dict) and "counts" in data:
            data = {k: v for k, v in data.items() if k != "counts"}
        return data

    @computed_field  # type: ignore[prop-decorator]
    @property
    def counts(self) -> dict[str, int]:
        return {
            "total": len(self.functions),
            "in_scope": sum(f.in_scope for f in self.functions),
            "thunk": sum(f.excluded_reason == "thunk" for f in self.functions),
            "external": sum(f.excluded_reason == "external" for f in self.functions),
            "plt": sum(f.excluded_reason == "plt" for f in self.functions),
            "crt": sum(f.excluded_reason == "crt" for f in self.functions),
            "non_text": sum(f.excluded_reason == "non_text" for f in self.functions),
            "decompile_failed": sum(f.decompile_failed for f in self.functions),
            "indirect_call_sites_in_scope": sum(
                f.indirect_call_sites for f in self.functions if f.in_scope
            ),
        }

    def in_scope_addrs(self) -> set[str]:
        return {f.addr for f in self.functions if f.in_scope}

    def excluded_addrs(self, reason: ExcludeReason) -> set[str]:
        return {f.addr for f in self.functions if f.excluded_reason == reason}