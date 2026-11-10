# -*- coding: utf-8 -*-
"""triage 分析器 —— 文件是什么、有没有壳/异常、我有多确定。

判据迁移自学习项目里的 `工具库/pe/pe_anomaly.py`（资产 PE-007），并补上证据链：
每条信号都带 `evidence`，写明它是从哪个文件偏移/哪个字段推出来的。

v0.1 是 PE 加壳/结构异常的启发式，不是"是恶意软件"的结论。
"""

from __future__ import annotations

import glob
import os
from dataclasses import asdict, dataclass, field
from typing import Any

from ..core.pe import PE, PE_EXTS, PEError

NAME = "triage"
DESCRIPTION = "PE 概览 + 加壳/结构异常评分（组合判据，带置信度与证据偏移）"

# 权重与阈值都来自实测（见 docs/rules.md 的样本表），改这里必须同步改测试
W_UPX_PAIR = 4
W_UPX_ANY = 2
W_ZERO_RAW_EXEC = 3
W_HIGH_ENTROPY = 2
W_IMPORT_TRUNCATED = 3
W_IMPORT_EMPTY = 1

HIGH_ENTROPY = 7.8
MIN_ENTROPY_SECTION = 4096
MIN_DLLS_FOR_RATIO = 3
TRUNCATED_RATIO = 2.0


@dataclass
class Signal:
    id: str
    weight: int
    hit: bool
    evidence: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TriageResult:
    file: str
    size: int
    sha256: str
    format: str
    arch: str
    entry_rva: str
    entry_section: str
    sections: int
    section_names: list[str]
    imports: int
    dlls: int
    funcs_per_dll: float
    max_entropy: float
    max_entropy_section: str
    verdict: str
    shell_guess: str
    confidence: str
    score: int
    signals: list[Signal] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["signals"] = [s for s in d["signals"]]
        return d


def _confidence(score: int) -> str:
    if score >= 9:
        return "高"
    if score >= 5:
        return "中"
    if score >= 2:
        return "低"
    return "无"


def analyze_file(path: str) -> TriageResult:
    pe = PE(path)
    names = [s.name for s in pe.sections]
    imports = pe.imports()
    funcs = len(imports)
    dlls = len({i.dll for i in imports})
    ratio = round(funcs / dlls, 2) if dlls else 0.0

    big = [s for s in pe.sections if s.size_of_raw_data >= MIN_ENTROPY_SECTION]
    top = max(big, key=lambda s: s.entropy) if big else None
    max_ent = round(top.entropy, 3) if top else 0.0

    has_upx0 = any(n.upper().startswith("UPX0") for n in names)
    has_upx1 = any(n.upper().startswith("UPX1") for n in names)
    upx_names = [n for n in names if n.upper().startswith("UPX")]
    zero_raw_exec = [s for s in pe.sections
                     if s.virtual_size > 0 and s.size_of_raw_data == 0 and s.is_executable]

    signals = [
        Signal("S1_upx_section_pair", W_UPX_PAIR, has_upx0 and has_upx1,
               f"节表 FO 0x{pe.section_table_offset:X}：节名 {names}"),
        Signal("S2_upx_section_any", W_UPX_ANY, bool(upx_names) and not (has_upx0 and has_upx1),
               f"UPX 类节名：{upx_names or '无'}（成对时由 S1 计分，此条只补残缺/变种）"),
        Signal("S3_zero_raw_exec_section", W_ZERO_RAW_EXEC, bool(zero_raw_exec),
               "；".join(f"{s.name} 节头 FO 0x{s.header_offset:X}：VirtualSize=0x{s.virtual_size:X} "
                        f"但 RawSize=0、含 MEM_EXECUTE（磁盘无内容，内存是解压区）"
                        for s in zero_raw_exec) or "无此类节"),
        Signal("S4_high_entropy_section", W_HIGH_ENTROPY, max_ent > HIGH_ENTROPY,
               f"最高熵节 {top.name if top else '-'} = {max_ent}（阈值 >{HIGH_ENTROPY}，"
               f"仅统计 RawSize≥{MIN_ENTROPY_SECTION} 的节）"),
        Signal("S5_import_truncated", W_IMPORT_TRUNCATED,
               dlls >= MIN_DLLS_FOR_RATIO and ratio < TRUNCATED_RATIO,
               f"导入 DD#1 RVA=0x{pe.directories[1][0]:X}：{funcs} 函数 / {dlls} DLL"
               f"（函数/DLL={ratio}，判据 DLL≥{MIN_DLLS_FOR_RATIO} 且比值<{TRUNCATED_RATIO}）"),
        Signal("S6_import_empty", W_IMPORT_EMPTY, funcs == 0,
               f"导入函数数={funcs}（此条仅作参考，不能单独定案：静态链接产物也可能为空）"),
    ]

    score = sum(s.weight for s in signals if s.hit)
    confidence = _confidence(score)

    if has_upx0 and has_upx1 and max_ent > HIGH_ENTROPY:
        shell_guess = "UPX（节名成对 + 高熵 + 导入截断）" if (
            dlls >= MIN_DLLS_FOR_RATIO and ratio < TRUNCATED_RATIO
        ) else "UPX（节名成对 + 高熵）"
    elif score >= 5:
        shell_guess = "未知加壳/打包（启发式，需 unpack 或动态复核）"
    elif score >= 2:
        shell_guess = "节结构可疑，不足以定性"
    else:
        shell_guess = "未发现加壳迹象"

    if has_upx0 and has_upx1:
        verdict = "upx"
    elif score >= 5:
        verdict = "packed?"
    elif score >= 2:
        verdict = "odd"
    else:
        verdict = "normal"

    return TriageResult(
        file=path,
        size=len(pe.data),
        sha256=pe.sha256,
        format=pe.pe_format,
        arch=pe.arch,
        entry_rva=f"0x{pe.entry_rva:X}",
        entry_section=pe.entry_section,
        sections=len(pe.sections),
        section_names=names,
        imports=funcs,
        dlls=dlls,
        funcs_per_dll=ratio,
        max_entropy=max_ent,
        max_entropy_section=top.name if top else "-",
        verdict=verdict,
        shell_guess=shell_guess,
        confidence=confidence,
        score=score,
        signals=signals,
    )


def _expand(paths: list[str]) -> list[str]:
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


def run(paths: list[str]) -> dict[str, Any]:
    """对若干文件跑 triage，返回可直接落盘的结构（JSON 友好）。"""
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for path in _expand(paths):
        try:
            results.append(analyze_file(path).as_dict())
        except (PEError, OSError) as e:
            errors.append({"file": path, "error": f"{type(e).__name__}: {e}"})
    return {"analyzer": NAME, "results": results, "errors": errors}
