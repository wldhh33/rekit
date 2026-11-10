# -*- coding: utf-8 -*-
"""map 分析器 —— 加载器怎么把文件摆进内存。

回答 D4 的问题：同一个节，文件里占多大、内存里占多大、多出来的部分谁补；
某个 RVA 到底在文件里、在内存补零区、还是根本没有。
判据全部来自节表与可选头，不执行样本。
"""

from __future__ import annotations

from typing import Any

from ..core.files import expand_paths
from ..core.pe import PE, PEError

NAME = "map"
DESCRIPTION = "加载器映射：节 RVA↔FOA 对照、内存补零/文件松弛、RVA 探针"
VERSION = "0.2.0"


def run(paths: list[str], probes: list[int] | None = None) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    files = expand_paths(paths)
    if not files:
        return {"analyzer": NAME, "results": [], "errors": [{
            "file": ", ".join(paths),
            "error": "NoFilesFound: 没有匹配到可分析的文件（检查路径、扩展名或通配符）",
        }]}
    for path in files:
        try:
            results.append(PE(path).format_map(probes))
        except (PEError, OSError) as e:
            errors.append({"file": path, "error": f"{type(e).__name__}: {e}"})
    return {"analyzer": NAME, "results": results, "errors": errors}
