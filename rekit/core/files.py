# -*- coding: utf-8 -*-
"""输入路径展开：文件 / 目录 / 通配符 → 文件列表（各分析器共用）。"""

from __future__ import annotations

import glob
import os

from .pe import PE_EXTS


def expand_paths(paths: list[str]) -> list[str]:
    """展开目录（只取 PE 扩展名）与通配符；普通路径原样保留。"""
    out: list[str] = []
    for p in paths:
        if any(ch in p for ch in "*?["):
            out.extend(sorted(glob.glob(p)))
        elif os.path.isdir(p):
            out.extend(sorted(
                os.path.join(p, n) for n in os.listdir(p)
                if os.path.isfile(os.path.join(p, n)) and n.lower().endswith(PE_EXTS)
            ))
        else:
            out.append(p)
    return out
