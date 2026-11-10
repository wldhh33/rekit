# -*- coding: utf-8 -*-
"""把 triage 结果渲染成 Markdown（可交付报告的一期形态）。"""

from __future__ import annotations

from datetime import datetime
from typing import Any

RULE_TABLE = """\
| 信号 | 权重 | 判据 | 为什么 |
|---|---|---|---|
| S1 UPX 节名成对 | +4 | 同时存在 `UPX0` 与 `UPX1` | UPX 的默认外观；改名即可绕过，故只给 4 分 |
| S2 UPX 类节名 | +2 | 仅命中一个 UPX 类节名 | 残缺/变种，单独不足以定案 |
| S3 零 Raw 可执行节 | +3 | `VirtualSize>0`、`RawSize=0`、含 `MEM_EXECUTE` | 磁盘无内容、内存是解压区，加壳的强特征 |
| S4 高熵节 | +2 | 任一节 `RawSize>=4096` 且熵>7.8 | 压缩/加密数据；单独也可能是压缩资源 |
| S5 导入表截断 | +3 | DLL≥3 且 函数数/DLL < 2.0 | UPX 5 保留 DLL 名但截断函数表 |
| S6 导入表为空 | +1 | 导入函数数=0 | **仅参考**：静态链接的 Go/Rust 也可能为空 |

置信度：≥9 高 / 5–8 中 / 2–4 低 / <2 无。S4、S6 单独都不构成结论。
"""


def _cell(v: Any) -> str:
    s = str(v).replace("|", "\\|")
    return s if s else "-"


def render_triage(payload: dict[str, Any], tool_version: str = "0.1.0") -> str:
    results = payload.get("results", [])
    errors = payload.get("errors", [])
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines: list[str] = [
        "# rekit triage 报告",
        "",
        f"- 生成时间：{ts}",
        f"- 工具：rekit {tool_version}（analyzer = triage）",
        f"- 输入：{len(results) + len(errors)} 个文件，成功 {len(results)}，失败 {len(errors)}",
        "",
        "## 1. 总览",
        "",
        "| 文件 | 判定 | 置信度 | 分数 | 壳/打包判断 | 节数 | 导入(函数/DLL) | 函数/DLL | 最高熵 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {_cell(r['file'])} | {_cell(r['verdict'])} | {_cell(r['confidence'])} | "
            f"{r['score']} | {_cell(r['shell_guess'])} | {r['sections']} | "
            f"{r['imports']}/{r['dlls']} | {r['funcs_per_dll']} | "
            f"{r['max_entropy']}({_cell(r['max_entropy_section'])}) |"
        )

    # 章节号按实际出现的章节递增，避免没有失败文件时出现 1 → 3 的断号
    n = 1
    if errors:
        n += 1
        lines += ["", f"## {n}. 失败文件", "", "| 文件 | 原因 |", "|---|---|"]
        lines += [f"| {_cell(e['file'])} | {_cell(e['error'])} |" for e in errors]

    n += 1
    lines += ["", f"## {n}. 逐文件证据", ""]
    for r in results:
        lines += [
            f"### {r['file']}",
            "",
            f"- 大小 {r['size']} 字节，SHA256 `{r['sha256']}`",
            f"- {r['format']} / {r['arch']}，EP `{r['entry_rva']}` 在 `{r['entry_section']}`",
            f"- 判定 `{r['verdict']}`（{r['confidence']}，{r['score']} 分）：{r['shell_guess']}",
            "",
            "| 信号 | 权重 | 命中 | 证据 |",
            "|---|---|---|---|",
        ]
        for s in r["signals"]:
            lines.append(
                f"| {s['id']} | +{s['weight']} | {'✓' if s['hit'] else '—'} | {_cell(s['evidence'])} |"
            )
        lines.append("")

    lines += [
        "---",
        "",
        f"## {n + 1}. 判据说明与边界",
        "",
        RULE_TABLE,
        "",
        "**已知会被骗过的情况**：改节名的 UPX（只剩 6 分/中）；Themida / VMProtect / Enigma"
        "（保留完整导入表，S5 不触发）；ASPack / PECompact / MPRESS（节名不同）；"
        "NSIS/Inno 安装器与 .NET 单文件 bundle（只有高熵）；把压缩数据塞进 `.rsrc` 的样本。",
        "",
        "**可复现**：同一输入、同一命令、同一版本，输出字节一致（除生成时间）。",
        "",
    ]
    return "\n".join(lines)
