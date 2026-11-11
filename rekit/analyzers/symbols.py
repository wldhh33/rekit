"""symbols 分析器 —— Ghidra headless 出函数边界（v0.3 目标，当前为空实现）。

刻意不把 Ghidra 写进核心依赖：CI 只跑不需要 Ghidra 的部分，
本模块在 v0.3 通过 `GHIDRA_INSTALL_DIR` 探测可用性，缺失时降级并明确报错。
"""

from __future__ import annotations

NAME = "symbols"
DESCRIPTION = "函数边界与调用图（Ghidra headless）—— v0.3 未实现，计划 0.4"
PLANNED_VERSION = "0.4.0"
REQUIRES = "Ghidra headless (analyzeHeadless) + JDK"


def run(paths: list[str]) -> dict:
    raise NotImplementedError(
        f"symbols 在 v{PLANNED_VERSION} 实现，需要 {REQUIRES}。"
    )
