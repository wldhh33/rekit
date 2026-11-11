# -*- coding: utf-8 -*-
"""`rekit funcs`：函数边界发现插件。"""

from __future__ import annotations

from ..contract import error_entry
from ..core.elf import ElfError
from ..core.files import expand_paths
from ..core.funcs import FuncsUnavailable, analyze_image
from ..core.pe import PEError

NAME = "funcs"
DESCRIPTION = "函数边界：权威表 + 递归下降 + 指针表 + 穷举，每条入口带证据来源"
PLANNED_VERSION = "0.3"


def run(paths: list[str], *, pointers: bool = True,
        data_sections: list[str] | None = None, exhaust: str | None = None,
        profile: str = "auto", use_eh_frame: bool = True,
        allow_large: bool = False, reference: str | None = None,
        cold: bool = False) -> dict:
    results, errors = [], []
    for path in expand_paths(paths):
        try:
            results.append(analyze_image(
                path, pointers=pointers, data_sections=data_sections,
                exhaust=exhaust, profile=profile, use_eh_frame=use_eh_frame,
                allow_large=allow_large, reference=reference, cold=cold))
        except (PEError, ElfError, OSError, ValueError, FuncsUnavailable) as e:
            errors.append(error_entry(path, e))
    return {"analyzer": NAME, "results": results, "errors": errors}
