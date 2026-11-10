"""unpack 分析器 —— 静态脱壳（v0.2 目标，当前为空实现）。

接口先定死，v0.2 用学习项目里已验证的探针实现：
`实践/2026-11-10-samples/upx_static_probe.py` 已证明纯静态可解出 UPX PackHeader、
NRV2B 解压、filter 0x49 反过滤，`.text` / `.pdata` 与原件逐字节相同。
v0.2 还差 rebuildImports / rebuildRelocs / rebuildTls 与按原布局写文件。
"""

from __future__ import annotations

NAME = "unpack"
DESCRIPTION = "静态脱壳（UPX 优先）：OEP 定位 + 解压 + IAT 重建 —— v0.2 未实现"
PLANNED_VERSION = "0.2.0"


def run(paths: list[str]) -> dict:
    raise NotImplementedError(
        f"unpack 在 v{PLANNED_VERSION} 实现；当前版本只提供 triage。"
    )
