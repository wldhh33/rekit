# -*- coding: utf-8 -*-
"""M4b 壳判定层：只回答「UPX / 非 UPX」，不重写 triage 的 S1–S6。

- S1–S6 的权重与阈值直接引用 `triage` 常量，本模块不改它们；
- S7–S10 是新增信号，全部 positive，必须带可复算的文件偏移；
- 判定规则固定在本文件顶部，冻结后由 `eval/freeze_m4b_signals.py` 计算 canonical SHA256。

口径（2026-11-11 范围缩减）：结论只覆盖 UPX 5.0.0 产物；S7–S10 对非 UPX 壳的泛化**未测**。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..core.pe import PE
from . import triage

SIGNALS_VERSION = "m4b-signals-v1"

# 新增信号权重（S1–S6 用 triage 常量）
W_PACKER_SECTION = 3
W_ENTRY_OUTSIDE = 4
W_OVERLAY = 1
W_SECTION_COUNT = 1

OVERLAY_MIN = 0x200
SECTION_COUNT_MAX = 12

# 只做“这是已知壳的节名”提示，不据此断言族；UPX 由 S1/S2 负责
PACKER_SECTION_PREFIXES = (
    ".mpress", ".aspack", ".adata", ".pec", ".petite", ".fsg",
    "kkrunchy", ".nsp", ".boom", ".themida", ".vmp0", ".vmp1", ".enigma",
)


@dataclass
class PackerSignal:
    id: str
    weight: int
    hit: bool
    evidence: dict[str, Any]
    family: str | None = None
    evidence_kind: str = "positive"
    scored: bool = True
    source: str = "packer"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ev(field_name: str, offset_kind: str, offset: int | None, value: str) -> dict[str, Any]:
    return {
        "field": field_name,
        "offset_kind": offset_kind,
        "offset": f"0x{offset:X}" if offset is not None else None,
        "value": value,
    }


def _data_dir_offset(pe: PE) -> int:
    """optional header 里 data directory[0] 的文件偏移。"""
    e_lfanew = pe.r.u32(0x3C)
    opt = e_lfanew + 24
    return opt + (112 if pe.is_64 else 96)


def analyze(pe: PE, t: triage.TriageResult) -> dict[str, Any]:
    names = [s.name for s in pe.sections]
    upper = [n.upper() for n in names]
    has_upx0 = any(n.startswith("UPX0") for n in upper)
    has_upx1 = any(n.startswith("UPX1") for n in upper)
    upx_names = [n for n in names if n.upper().startswith("UPX")]
    zero_raw_exec = [s for s in pe.sections
                     if s.virtual_size > 0 and s.size_of_raw_data == 0 and s.is_executable]

    dd_off = _data_dir_offset(pe)
    import_rva = pe.directories[1][0] if len(pe.directories) > 1 else 0

    sig: list[PackerSignal] = []

    sig.append(PackerSignal(
        "S1_upx_section_pair", triage.W_UPX_PAIR, has_upx0 and has_upx1,
        _ev("section_table.Name", "file", pe.section_table_offset,
            f"节名 {names}（UPX0={'有' if has_upx0 else '无'}，UPX1={'有' if has_upx1 else '无'}）"),
        family="upx"))

    sig.append(PackerSignal(
        "S2_upx_section_any", triage.W_UPX_ANY, bool(upx_names) and not (has_upx0 and has_upx1),
        _ev("section_table.Name", "file", pe.section_table_offset,
            f"UPX 类节名 {upx_names or '无'}（成对时由 S1 计分）"),
        family="upx"))

    sig.append(PackerSignal(
        "S3_zero_raw_exec_section", triage.W_ZERO_RAW_EXEC, bool(zero_raw_exec),
        _ev("section_table.VirtualSize/SizeOfRawData", "file",
            zero_raw_exec[0].header_offset if zero_raw_exec else pe.section_table_offset,
            "；".join(f"{s.name} VirtualSize=0x{s.virtual_size:X} RawSize=0 可执行"
                     for s in zero_raw_exec) or "无此类节")))

    top_sec = None
    for s in pe.sections:
        if s.name == t.max_entropy_section:
            top_sec = s
            break
    sig.append(PackerSignal(
        "S4_high_entropy_section", triage.W_HIGH_ENTROPY,
        t.max_entropy > triage.HIGH_ENTROPY and top_sec is not None
        and top_sec.size_of_raw_data >= triage.MIN_ENTROPY_SECTION,
        _ev("section.RawData", "file", top_sec.header_offset if top_sec else pe.section_table_offset,
            f"{t.max_entropy_section}={t.max_entropy}（阈值 >{triage.HIGH_ENTROPY}）")))

    sig.append(PackerSignal(
        "S5_import_truncated", triage.W_IMPORT_TRUNCATED,
        t.dlls >= triage.MIN_DLLS_FOR_RATIO and t.funcs_per_dll < triage.TRUNCATED_RATIO,
        _ev("optional_header.DataDirectory[1]", "file", dd_off + 8,
            f"导入 {t.imports} 函数 / {t.dlls} DLL（函数/DLL={t.funcs_per_dll}）")))

    sig.append(PackerSignal(
        "S6_import_empty", triage.W_IMPORT_EMPTY, t.imports == 0,
        _ev("optional_header.DataDirectory[1]", "file", dd_off + 8,
            f"导入函数数={t.imports}，Import RVA=0x{import_rva:X}")))

    pack_names = [n for n in names if any(n.lower().startswith(p) for p in PACKER_SECTION_PREFIXES)]
    sig.append(PackerSignal(
        "S7_packer_section_name", W_PACKER_SECTION, bool(pack_names),
        _ev("section_table.Name", "file", pe.section_table_offset,
            f"已知壳节名 {pack_names or '无'}（非 UPX 壳的泛化未测）"),
        family="unknown"))

    inside = []
    for s in pe.sections:
        span = max(s.virtual_size, s.size_of_raw_data)
        inside.append(s.virtual_address <= pe.entry_rva < s.virtual_address + span)
    entry_outside = bool(pe.sections) and not any(inside)
    sig.append(PackerSignal(
        "S8_entry_outside_sections", W_ENTRY_OUTSIDE, entry_outside,
        _ev("optional_header.AddressOfEntryPoint", "rva", pe.entry_rva,
            f"EP RVA=0x{pe.entry_rva:X} 不落在任何节范围（节数={len(pe.sections)}）")))

    raw_end = max((s.pointer_to_raw_data + s.size_of_raw_data for s in pe.sections), default=0)
    cert_off, cert_size = pe.directories[4] if len(pe.directories) > 4 else (0, 0)
    cert_end = cert_off + cert_size if cert_off and cert_size else 0
    overlay_start = max(raw_end, cert_end)
    overlay_len = max(0, len(pe.data) - overlay_start)
    sig.append(PackerSignal(
        "S9_overlay_present", W_OVERLAY, overlay_len > OVERLAY_MIN,
        _ev("file.size-overlay_start", "file", overlay_start,
            f"overlay={overlay_len} 字节（已扣除证书目录 {cert_size}）")))

    sig.append(PackerSignal(
        "S10_section_count_anomaly", W_SECTION_COUNT, len(pe.sections) > SECTION_COUNT_MAX,
        _ev("file_header.NumberOfSections", "file", pe.section_table_offset - 2,
            f"节数={len(pe.sections)}（阈值 >{SECTION_COUNT_MAX}）")))

    hits = [s for s in sig if s.hit]
    score = sum(s.weight for s in sig if s.hit)
    hit_ids = {s.id for s in sig if s.hit}

    if "S1_upx_section_pair" in hit_ids or "S2_upx_section_any" in hit_ids:
        family, verdict, conf = "upx", "packed", 0.97
        upx_hits = [s for s in hits if s.id in ("S1_upx_section_pair", "S2_upx_section_any")]
        basis = "UPX 节名证据：" + "；".join(
            f"{s.id}={s.evidence['value']}" for s in upx_hits)
    elif "S7_packer_section_name" in hit_ids:
        family, verdict, conf = "unknown", "packed", 0.85
        basis = "已知壳节名（S7；非 UPX 壳泛化未测）"
    elif "S8_entry_outside_sections" in hit_ids and "S3_zero_raw_exec_section" in hit_ids:
        family, verdict, conf = "unknown", "packed", 0.80
        basis = "入口在节外 + 零 Raw 可执行节（S8+S3；非 UPX 壳泛化未测）"
    else:
        family, verdict, conf = None, "clean", 0.90
        basis = "无壳结构证据"

    return {
        "signals_version": SIGNALS_VERSION,
        "family": family,
        "verdict": verdict,
        "score": score,
        "confidence": conf,
        "basis": basis,
        "signals": [s.as_dict() for s in hits],
        "signals_all": [s.as_dict() for s in sig],
    }
