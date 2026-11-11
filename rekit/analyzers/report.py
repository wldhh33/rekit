# -*- coding: utf-8 -*-
"""单个样本的自动化报告（Markdown + JSON），24 个字段逐个标注来源。

长期约束（M5 起，后续里程碑同样适用）：
    - 24 个字段中 22 个由脚本自动推导、2 个是人写的判断（结论 / 建议）。
      「结论」「建议」**不计入**自动生成字段数，报告头部必须一眼看出区分。
    - 规则部分由 `core.rules` 的**rekit 规则引擎**求值；它不是 YARA 兼容实现，
      `.yar` 文件一律标注「未经 YARA 校验」。
    - 报告不写本机绝对路径、不写运行时间，保证换机器重跑逐字节一致。
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from . import identify
from ..core import data as data_core
from ..core import dotnet, funcs, rules
from ..core.pe import PE, PEError
from ..core.toolchain import GO_VERSION_RE

NAME = "report"
DESCRIPTION = "单样本自动化报告：结构/语义/家族特化/证据，24 字段带来源标记"

DIRECTORY_NAMES = (
    "导出", "导入", "资源", "异常(.pdata)", "安全", "重定位", "调试", "架构",
    "全局指针", "TLS", "加载配置", "绑定导入", "IAT", "延迟导入", "CLR",
)

# (字段 id, 分组, 标题, 来源)；顺序即报告顺序，共 24 项。
FIELD_SPECS = (
    ("sha256", "身份", "SHA-256", "auto"),
    ("size", "身份", "文件大小", "auto"),
    ("format_bits", "身份", "格式 / 位数", "auto"),
    ("machine", "身份", "机器类型", "auto"),
    ("timestamp", "身份", "PE 时间戳", "auto"),

    ("section_count", "结构", "节数量", "auto"),
    ("sections", "结构", "节表（名/VA/VS/RAW/熵）", "auto"),
    ("entry", "结构", "入口 RVA / 所在节", "auto"),
    ("data_directories", "结构", "非零数据目录", "auto"),
    ("overlay", "结构", "overlay 大小", "auto"),

    ("imports_dlls", "语义", "导入 DLL 数", "auto"),
    ("imports_funcs", "语义", "导入函数数", "auto"),
    ("exports", "语义", "导出数", "auto"),
    ("strings_count", "语义", "字符串总数", "auto"),
    ("strings_top", "语义", "字符串 Top-N（带偏移）", "auto"),
    ("toolchain", "语义", "工具链族 + 置信度", "auto"),
    ("packer", "语义", "UPX / 非 UPX 判定", "auto"),

    ("family_version", "家族特化", "家族与版本", "auto"),
    ("family_inventory_1", "家族特化", "家族清单 1", "auto"),
    ("family_inventory_2", "家族特化", "家族清单 2", "auto"),

    ("signals", "证据", "结论的信号 id + 偏移", "auto"),
    ("rule_hits", "证据", "规则命中（id / 证据偏移）", "auto"),

    ("conclusion", "人工", "结论（≤5 行）", "human"),
    ("recommendation", "人工", "建议（≤5 行）", "human"),
)

TOP_STRINGS = 20
TOP_NAMES = 20


def _ts(value: int) -> str:
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return f"0x{value:08X}（无法转换）"


def _overlay_size(pe: PE) -> int:
    end = 0
    for s in pe.sections:
        if s.size_of_raw_data:
            end = max(end, s.pointer_to_raw_data + s.size_of_raw_data)
    return max(0, len(pe.data) - end)


def _yara_status(rules_path: str | None) -> dict[str, str]:
    """读取与规则同目录的校验记录；没有记录就写“未校验”，不臆测。"""
    return rules.load_validation(rules_path)


def _signal_lines(signals: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    lines, evidence = [], []
    for sig in signals:
        ev = sig.get("evidence") or {}
        offset = ev.get("offset") if isinstance(ev, dict) else None
        value = ev.get("value", "") if isinstance(ev, dict) else ""
        lines.append(f"{sig.get('id', '?')} @ {offset or '-'}  {value}")
        evidence.append({"id": sig.get("id"), "offset": offset, "value": value})
    return ("\n".join(lines) if lines else "（本样本没有命中的信号）"), evidence


def _rule_field(rule_result: dict[str, Any] | None) -> tuple[str, list[dict[str, Any]]]:
    if not rule_result:
        return "未加载规则", []
    hits = [r for r in rule_result["results"] if r["matched"]]
    if not hits:
        return (f"无命中（已评估 {len(rule_result['results'])} 条；"
                f"引擎={rule_result['engine']}）"), []
    lines, evidence = [], []
    for hit in hits:
        offs = [e.get("offset") for e in hit["evidence"] if e.get("offset")]
        off = f"0x{min(offs):X}" if offs else "-"
        lines.append(f"{hit['id']} @ {off}  {hit['description']}")
        evidence.append({"id": hit["id"], "offset": off,
                         "description": hit["description"]})
    return "\n".join(lines), evidence


def _dotnet_fields(info: dotnet.DotnetInfo | None,
                   error: str | None) -> tuple[list[str], list[str], list[str],
                                                list[dict[str, Any]]]:
    if error:
        return ([f"解析失败：{error}"], ["-"], ["-"],
                [{"source": "dotnet", "offset": None, "note": error}])
    if info is None:
        return (["不适用（无 CLR 元数据）"], ["-"], ["-"], [])
    types = info.type_defs
    methods = [n for n, _rva in info.method_defs]
    ev = [{"source": "dotnet", "offset": f"0x{info.metadata_offset:X}",
           "note": "BSJB 元数据根"}]
    version = (f"CLI {info.version_string}；Assembly={info.assembly_name or '-'}；"
               f"流={', '.join(sorted(info.streams))}")
    inv1 = (f"TypeDef {info.type_def_count} 个："
            + "、".join(types[:TOP_NAMES])
            + (f" …（共 {len(types)}）" if len(types) > TOP_NAMES else ""))
    inv2 = (f"MethodDef {info.method_def_count} 个："
            + "、".join(methods[:TOP_NAMES])
            + (f" …（共 {len(methods)}）" if len(methods) > TOP_NAMES else ""))
    return ([version], [inv1], [inv2], ev)


def _go_fields(pe: PE) -> tuple[list[str], list[str], list[str],
                                list[dict[str, Any]]]:
    m = GO_VERSION_RE.search(pe.data)
    version = m.group().decode("ascii", "replace") if m else "未找到版本串"

    tab = funcs.pclntab_from_data(pe)
    if tab is None:
        return ([f"Go 版本：{version}"],
                ["`.gopclntab` 未找到，函数名不可恢复"],
                ["`main.main` 定位不可用"], [])
    names = tab.names
    ev = [{"source": "pclntab", "offset": f"0x{tab.va:X}" if tab.va else None,
           "note": f"magic=0x{tab.magic:08X}，起点 {len(tab.starts)} 个"}]
    top = [f"0x{pc:X} {names[pc]}" for pc in tab.starts if pc in names][:TOP_NAMES]
    inv1 = (f"函数名 {len(names)}/{len(tab.starts)}（{tab.name_status}）："
            + "；".join(top))
    main_pc = next((pc for pc, n in names.items() if n == "main.main"), None)
    if main_pc is None:
        inv2 = "`main.main` 未在函数名表中出现"
    else:
        span = next(((s, e) for s, e in tab.spans if s == main_pc), None)
        inv2 = (f"`main.main` @ 0x{main_pc:X}"
                + (f"（区间 0x{span[0]:X}-0x{span[1]:X}）" if span else ""))
    return ([f"Go 版本：{version}"], [inv1], [inv2], ev)


def _native_fields(pe: PE) -> tuple[list[str], list[str], list[str],
                                    list[dict[str, Any]]]:
    spans = funcs.pdata_spans(pe)
    if not spans:
        return (["原生（无 CLR / Go 元数据）"], [".pdata 为空或不存在"],
                ["函数区间不可用"], [])
    sizes = sorted(e - s for s, e in spans)
    total = sum(sizes)
    median = sizes[len(sizes) // 2]
    preview = "；".join(f"0x{s:X}-0x{e:X}" for s, e in spans[:TOP_NAMES])
    rva = pe.directories[3][0] if len(pe.directories) > 3 else 0
    ev = [{"source": "pdata", "offset": f"0x{rva:X}" if rva else None,
           "note": f"异常目录，{len(spans)} 项"}]
    return (["原生（无 CLR / Go 元数据）"],
            [f".pdata 函数数：{len(spans)}"],
            [f"函数区间（前 {min(len(spans), TOP_NAMES)} 个）：{preview}"
             f"；总字节 {total:,}，中位 {median:,}"], ev)


def analyze_file(path: str, sample_id: str, family: str = "auto",
                 rules_path: str | None = None,
                 allow_large: bool = False) -> dict[str, Any]:
    if family not in ("auto", "dotnet", "go", "native"):
        raise ValueError(f"未知家族：{family}")

    ident = identify.analyze_file(path, allow_large=allow_large)
    rules_payload = rules.load_rules(rules_path) if rules_path else None

    with PE(path, allow_large=allow_large) as pe:
        dotnet_info, dotnet_error = None, None
        try:
            dotnet_info = dotnet.parse(pe)
        except (PEError, dotnet.DotnetError) as e:
            dotnet_error = f"{type(e).__name__}: {e}"

        if family == "auto":
            if dotnet_info is not None:
                family = "dotnet"
            elif b"\xff Go buildinf:" in pe.data or any(
                    s.name == ".gopclntab" for s in pe.sections):
                family = "go"
            else:
                family = "native"

        section_lines = [
            f"{s.index} {s.name} VA=0x{pe.image_base + s.virtual_address:X} "
            f"VS=0x{s.virtual_size:X} RAW=0x{s.size_of_raw_data:X} "
            f"熵={s.entropy:.3f}" for s in pe.sections
        ]
        dirs = [f"#{i} {DIRECTORY_NAMES[i] if i < len(DIRECTORY_NAMES) else '?'} "
                f"RVA=0x{rva:X} Size={size}"
                for i, (rva, size) in enumerate(pe.directories) if rva or size]
        imports = pe.imports()
        dlls = sorted({i.dll for i in imports})
        exports = pe.exports()
        strings = data_core.scan_c_strings(pe, min_len=6)
        top_strings = sorted(strings["items"],
                             key=lambda x: (-x["length"], x["address"]))[:TOP_STRINGS]
        file_size = len(pe.data)
        overlay = _overlay_size(pe)
        pe_format, arch, timestamp = pe.pe_format, pe.arch, pe.timestamp

        rule_result = rules.run(pe, rules_payload) if rules_payload else None

        if family == "dotnet":
            fam = _dotnet_fields(dotnet_info, dotnet_error)
        elif family == "go":
            fam = _go_fields(pe)
        else:
            fam = _native_fields(pe)

    signal_value, signal_ev = _signal_lines(ident["signals"])
    # 家族字段自己带的证据（BSJB / pclntab / .pdata）也并进“信号 id + 偏移”，
    # 避免 .NET 这种没有冻结信号命中的样本出现“结论无出处”。
    extra = [f"{e['source']} @ {e.get('offset') or '-'}  {e.get('note', '')}"
             for e in fam[3]]
    if extra:
        if signal_value.startswith("（"):
            signal_value = "无冻结信号命中；报告自证证据：\n" + "\n".join(extra)
        else:
            signal_value += "\n" + "\n".join(extra)
        signal_ev.extend(fam[3])
    rule_value, rule_ev = _rule_field(rule_result)

    packer = ident["packer"]
    packer_value = ("UPX（packed）" if packer["verdict"] == "packed"
                    else "非 UPX（clean）")
    packer_value += (f"；M4b 判据 score={packer['score']}，"
                     f"signals={packer['signals_version']}")

    strings_lines = [
        f"0x{item['address']:X} len={item['length']} {item['text'][:80]}"
        for item in top_strings
    ] or ["（无非可执行节字符串）"]

    values: dict[str, tuple[str, list[dict[str, Any]]]] = {
        "sha256": (ident["sha256"], [{"source": "文件", "offset": "0x0",
                                      "note": "sha256"}]),
        "size": (f"{file_size:,} 字节", []),
        "format_bits": (f"{pe_format} / "
                        f"{'64' if ident['bitness'] == 'x64' else '32'} 位", []),
        "machine": (f"{ident['bitness']}（{arch}）", []),
        "timestamp": (_ts(timestamp), []),
        "section_count": (str(len(section_lines)), []),
        "sections": ("\n".join(section_lines), []),
        "entry": (f"RVA=0x{pe.entry_rva:X}，节={pe.entry_section}", []),
        "data_directories": ("\n".join(dirs) if dirs else "无", []),
        "overlay": (f"{overlay:,} 字节（{file_size:,} - 末节末尾）", []),
        "imports_dlls": (f"{len(dlls)} 个：{', '.join(dlls[:8])}"
                         + (" …" if len(dlls) > 8 else ""), []),
        "imports_funcs": (str(len(imports)), []),
        "exports": (str(len(exports)), []),
        "strings_count": (f"{strings['count']}"
                          + ("（截断）" if strings["truncated"] else ""), []),
        "strings_top": ("\n".join(strings_lines), []),
        "toolchain": (f"{ident['family']}（置信度 {ident['confidence']}）\n"
                      f"依据：{ident['basis']}", []),
        "packer": (packer_value, []),
        "family_version": ("\n".join(fam[0]), fam[3]),
        "family_inventory_1": ("\n".join(fam[1]), fam[3]),
        "family_inventory_2": ("\n".join(fam[2]), fam[3]),
        "signals": (signal_value, signal_ev),
        "rule_hits": (rule_value, rule_ev),
        "conclusion": ("", []),
        "recommendation": ("", []),
    }

    fields = [{
        "id": fid, "group": group, "label": label, "source": source,
        "value": values[fid][0], "evidence": values[fid][1],
    } for fid, group, label, source in FIELD_SPECS]

    auto = sum(1 for f in fields if f["source"] == "auto")
    human = sum(1 for f in fields if f["source"] == "human")
    assert auto + human == 24, (auto, human)

    return {
        "tool": "rekit",
        "sample": {"id": sample_id, "sha256": ident["sha256"]},
        "family_group": family,
        "field_stats": {"total": 24, "auto": auto, "human": human,
                        "auto_ratio": round(auto / 24, 4)},
        "fields": fields,
        "rules": {
            "path": os.path.basename(rules_path) if rules_path else None,
            "engine": rules.ENGINE_NAME,
            "engine_note": rules.ENGINE_NOTE,
            "yara_compatible": False,
            "yara_validation": _yara_status(rules_path),
            "results": rule_result["results"] if rule_result else [],
            "hit_ids": rule_result["hit_ids"] if rule_result else [],
        },
        "identify": {
            "family": ident["family"], "confidence": ident["confidence"],
            "verdict": ident["verdict"], "packer": packer,
            "signals_version": packer["signals_version"],
        },
        "schema_version": 1,
    }


def _cell(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", "<br>")


def render_markdown(payload: dict[str, Any], version: str) -> str:
    stats = payload["field_stats"]
    rules_info = payload["rules"]
    yara = rules_info["yara_validation"]
    out = [
        f"# rekit 自动化报告 · {payload['sample']['id']}",
        "",
        f"- 样本 sha256：`{payload['sample']['sha256']}`",
        f"- 家族分组：{payload['family_group']}",
        f"- **字段来源**：{stats['total']} 个字段 = **{stats['auto']} 个自动推导**"
        f"（脚本生成）+ **{stats['human']} 个人工判断**（结论、建议）；"
        f"自动生成率 {stats['auto_ratio'] * 100:.1f}%",
        f"- 规则引擎：{rules_info['engine']}（{rules_info['engine_note']}）；"
        f"YARA 校验：**{yara['status']}**（{yara['detail']}）",
        "- 本报告不含本机绝对路径与运行时间；同一命令重跑结果逐字节一致。",
        "",
        "## 字段表",
        "",
        "| # | 分组 | 字段 | 来源 | 值 |",
        "|---|---|---|---|---|",
    ]
    for i, f in enumerate(payload["fields"], 1):
        source = "自动推导" if f["source"] == "auto" else "**人工判断**"
        value = _cell(f["value"])
        if f["source"] == "human" and not f["value"]:
            value = "（待人工填写，不计入自动字段）"
        out.append(f"| {i} | {f['group']} | {f['label']} | {source} | {value} |")

    out += [
        "",
        "## 规则命中",
        "",
        f"- 规则文件：`{rules_info['path'] or '-'}`",
        f"- 引擎：{rules_info['engine']}（非 YARA 兼容）",
        f"- 命中：{', '.join(rules_info['hit_ids']) or '无'}",
        "",
        "## 人工判断（不计入自动生成字段）",
        "",
        "### 结论",
        "",
        "（待人工填写，≤5 行）",
        "",
        "### 建议",
        "",
        "（待人工填写，≤5 行）",
        "",
        f"> 由 rekit {version} 生成；规则为 rekit 规则引擎求值结果；"
        f"`.yar` {_yara_footer(yara['status'])}。",
        "",
    ]
    return "\n".join(out)


def _yara_footer(status: str) -> str:
    if status == "通过":
        return "已用真 YARA 编译并求值校验（语义不等价，部分条件未翻译）"
    if status == "不通过":
        return "未通过 YARA 校验（该文件不可用）"
    return "未经 YARA 校验"
