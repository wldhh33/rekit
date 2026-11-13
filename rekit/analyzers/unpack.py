"""unpack 分析器 —— 静态脱壳 UPX（PE32+ / NRV2B / NRV2E / LZMA）。

不调用 ``upx -d``：PackHeader → 解压 → 反过滤 → IAT/重定位重建 → 按原布局写文件，
每一步都输出"通过/失败 + 证据"。实现与学习项目的 ``工具库/pe/unpack_upx.py``
共用同一份代码（后者现在是 ``rekit.core.upx`` 的薄包装），避免两份实现漂移。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.upx import unpack_many

NAME = "unpack"
DESCRIPTION = "静态脱壳（UPX / PE32+）：PackHeader → NRV2B/NRV2E/LZMA → 反过滤 → IAT/重定位重建"
VERSION = "0.3.0"


def run(paths: list[str], out_dir: str | None = None,
        verify_only: bool = False) -> dict[str, Any]:
    payload = unpack_many(paths, Path(out_dir) if out_dir else None, verify_only=verify_only)
    return {"analyzer": NAME, "results": payload["results"], "errors": payload["errors"]}
