"""分析器插件层。

v0.1 只有 triage；unpack / symbols 是空实现，接口先定下来，避免以后改 CLI。
每个插件暴露 `NAME` / `DESCRIPTION` / `run(paths) -> dict`。
"""

from __future__ import annotations

from . import map, symbols, triage, unpack

REGISTRY = {
    triage.NAME: triage,
    unpack.NAME: unpack,
    map.NAME: map,
    symbols.NAME: symbols,
}

__all__ = ["REGISTRY", "triage", "unpack", "map", "symbols"]
