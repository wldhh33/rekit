# -*- coding: utf-8 -*-
"""`rekit xref`：交叉引用插件。"""

from __future__ import annotations

from ..contract import error_entry
from ..core.elf import ElfError
from ..core.files import expand_paths
from ..core.funcs import FuncsUnavailable
from ..core.pe import PEError
from ..core.xref import XrefUnavailable, analyze_xref

NAME = "xref"
DESCRIPTION = "交叉引用：谁引用了这个字符串 / 地址 / 函数 / 常量（确定与疑似分列）"
PLANNED_VERSION = "0.3"

CSV_FIELDS = ("file", "target_kind", "target_input", "target_va", "ref_type",
              "confidence", "va", "mnemonic", "text", "function", "section",
              "detail")


def run(paths: list[str], specs: list[dict], *, byte_scan: bool = False,
        pointers: bool = True, utf16: bool = False,
        allow_large: bool = False) -> dict:
    results, errors = [], []
    for path in expand_paths(paths):
        try:
            results.append(analyze_xref(
                path, specs, byte_scan=byte_scan, pointers=pointers,
                utf16=utf16, allow_large=allow_large))
        except (PEError, ElfError, OSError, ValueError, FuncsUnavailable,
                XrefUnavailable) as e:
            errors.append(error_entry(path, e))
    return {"analyzer": NAME, "results": results, "errors": errors}


def csv_rows(payload: dict) -> list[dict]:
    out = []
    for t in payload["targets"]:
        kind = t["input"]["kind"]
        raw = t["input"]["value"]
        for block in t["blocks"]:
            for r in block["refs"]:
                out.append({
                    "file": payload["file"], "target_kind": kind,
                    "target_input": raw,
                    "target_va": "-" if block["va"] is None else f"0x{block['va']:X}",
                    "ref_type": r["ref_type"], "confidence": r["confidence"],
                    "va": f"0x{r['va']:X}", "mnemonic": r["mnemonic"],
                    "text": r["text"],
                    "function": "-" if r["function"] is None else f"0x{r['function']:X}",
                    "section": r["section"] or "-", "detail": r["detail"],
                })
    return out
