# -*- coding: utf-8 -*-
"""rekit 规则引擎 —— 条件布尔求值 + 证据偏移，**不是 YARA 实现**。

长期约束（M5 起，后续里程碑同样适用）：
    1. 本模块自制的规则引擎不得声称与 YARA 兼容。文档与输出一律叫「rekit 规则引擎」；
       从同一份 JSON 规则生成的 `.yar` 文本必须标注「未经 YARA 校验」。若环境里装了
       `yara-python`，只把它当**校验器**用，校验不通过就如实写不通过，绝不用本引擎的
       通过结果替代。
    2. 规则只做检索/报告辅助，不参与工具链族判定，也不改 `signals-v1` / `m4b-signals-v1`。

规则文件格式（JSON，零依赖）：

    {
      "engine": "rekit",
      "rules": [
        {"id": "go_binary", "description": "...",
         "any": [[{"fact": "go_buildinfo", "op": "eq", "value": true}]]}
      ]
    }

`any` 是「或」；内层数组是「与」。求值结果只回答“命中/未命中”，不引入新评分。
"""

from __future__ import annotations

import importlib.util
import json
import os
from dataclasses import dataclass, field
from typing import Any

from .pe import PE, PEError

ENGINE_NAME = "rekit 规则引擎"
ENGINE_NOTE = "自制规则引擎，不是 YARA 兼容实现"

# 规则可引用的事实及其含义（写进报告，避免“黑箱命中”）。
FACTS: dict[str, str] = {
    "section_names": "节名列表",
    "dotnet_clr_rva": "CLR 运行时目录 #14 的 RVA（0 表示没有）",
    "dotnet_clr_size": "CLR 运行时目录 #14 的 Size",
    "dotnet_bsjb": "CLR 元数据根签名是否为 BSJB",
    "dotnet_bsjb_offset": "BSJB 的文件偏移",
    "go_pclntab_section": "是否存在 .gopclntab 节",
    "go_buildinfo": "是否含 Go buildinfo 魔数 `\\xff Go buildinf:`",
    "go_buildinfo_offset": "buildinfo 魔数的文件偏移",
    "upx_pair": "是否同时存在 UPX0/UPX1 节",
    "entry_in_upx1": "入口 RVA 是否落在 UPX1 节内",
    "max_section_entropy": "所有节中的最高熵",
    "max_entropy_section": "最高熵所在的节名",
    "max_entropy_raw": "最高熵节的原始大小",
}

OPS = {"eq", "ne", "gt", "ge", "lt", "le", "in"}

# 能被 YARA（4.x）如实表达的事实。其余事实保持“未表达”，不硬凑。
YARA_FACT = {
    "go_pclntab_section":
        'for any i in (0..pe.number_of_sections - 1) : '
        '(pe.sections[i].name == ".gopclntab")',
    "go_buildinfo": "$go_buildinfo",
    "upx_pair":
        'for any i in (0..pe.number_of_sections - 1) : '
        '(pe.sections[i].name == "UPX0") and '
        'for any j in (0..pe.number_of_sections - 1) : '
        '(pe.sections[j].name == "UPX1")',
}
YARA_STRINGS = {
    "$go_buildinfo": "{ FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }",
}


class RulesError(ValueError):
    """规则文件结构不合法，或引用了未登记的事实/操作符。"""


@dataclass
class RuleHit:
    rule_id: str
    description: str
    matched: bool
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "description": self.description,
            "matched": self.matched,
            "evidence": self.evidence,
        }


def yara_available() -> bool:
    return importlib.util.find_spec("yara") is not None


def load_validation(rules_path: str | None) -> dict[str, str]:
    """读取规则同目录的 `m5_validation.json`；没有记录就写“未校验”，不臆测。"""
    if not rules_path:
        return {"status": "未校验", "detail": "未指定规则文件"}
    path = os.path.join(os.path.dirname(os.path.abspath(rules_path)),
                        "m5_validation.json")
    if not os.path.exists(path):
        return {"status": "未校验", "detail": "没有校验记录文件 m5_validation.json"}
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            payload = json.load(f)
        return {"status": str(payload.get("status", "未校验")),
                "detail": str(payload.get("detail", ""))}
    except (OSError, ValueError) as e:
        return {"status": "未校验", "detail": f"校验记录不可读：{type(e).__name__}"}


def load_rules(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8-sig") as f:
        payload = json.load(f)
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RulesError("规则文件缺少非空 `rules` 数组")
    seen: set[str] = set()
    for rule in rules:
        rid = rule.get("id")
        if not isinstance(rid, str) or not rid:
            raise RulesError("规则缺少 `id`")
        if rid in seen:
            raise RulesError(f"规则 id 重复：{rid}")
        seen.add(rid)
        alternatives = rule.get("any")
        if not isinstance(alternatives, list) or not alternatives:
            raise RulesError(f"{rid}: `any` 必须是非空数组")
        for alternative in alternatives:
            if not isinstance(alternative, list) or not alternative:
                raise RulesError(f"{rid}: 每个 `any` 分支必须是非空条件数组")
            for cond in alternative:
                if not isinstance(cond, dict):
                    raise RulesError(f"{rid}: 条件必须是对象")
                if cond.get("fact") not in FACTS:
                    raise RulesError(f"{rid}: 未登记的事实 {cond.get('fact')!r}")
                if cond.get("op") not in OPS:
                    raise RulesError(f"{rid}: 未支持的操作符 {cond.get('op')!r}")
    return payload


def _fact(pe: PE, name: str) -> tuple[Any, dict[str, Any]]:
    """返回 (值, 证据)。证据里的 offset 是文件偏移；没有就写 None。"""
    sections = pe.sections
    if name == "section_names":
        return [s.name for s in sections], {"offset": None, "note": "节表顺序"}
    if name == "dotnet_clr_rva":
        rva, _size = (pe.directories[14] if len(pe.directories) > 14 else (0, 0))
        return rva, {"offset": None, "note": "数据目录 #14 的 RVA 字段"}
    if name == "dotnet_clr_size":
        _rva, size = (pe.directories[14] if len(pe.directories) > 14 else (0, 0))
        return size, {"offset": None, "note": "数据目录 #14 的 Size 字段"}
    if name in ("dotnet_bsjb", "dotnet_bsjb_offset"):
        off = None
        rva, size = (pe.directories[14] if len(pe.directories) > 14 else (0, 0))
        if rva and size >= 16:
            try:
                cor = pe.rva_to_foa(rva)
                meta_rva = pe.r.u32(cor + 8) if cor is not None else 0
                mfoa = pe.rva_to_foa(meta_rva) if meta_rva else None
                if mfoa is not None and pe.data[mfoa:mfoa + 4] == b"BSJB":
                    off = mfoa
            except PEError:
                off = None
        if name == "dotnet_bsjb":
            return off is not None, {"offset": off, "note": "元数据根签名 BSJB"}
        return off, {"offset": off, "note": "BSJB 文件偏移"}
    if name in ("go_pclntab_section",):
        sec = next((s for s in sections if s.name == ".gopclntab"), None)
        return sec is not None, {
            "offset": sec.header_offset if sec else None,
            "note": ".gopclntab 节头" if sec else "无 .gopclntab 节",
        }
    if name in ("go_buildinfo", "go_buildinfo_offset"):
        off = pe.data.find(b"\xff Go buildinf:")
        if off < 0:
            off = None
        if name == "go_buildinfo":
            return off is not None, {"offset": off, "note": "Go buildinfo 魔数"}
        return off, {"offset": off, "note": "Go buildinfo 魔数偏移"}
    if name == "upx_pair":
        pair = {s.name for s in sections}
        hit = "UPX0" in pair and "UPX1" in pair
        sec = next((s for s in sections if s.name == "UPX0"), None)
        return hit, {
            "offset": sec.header_offset if sec else None,
            "note": "UPX0+UPX1 节名成对" if hit else "节名不成对",
        }
    if name == "entry_in_upx1":
        sec = next((s for s in sections if s.name == "UPX1"), None)
        if sec is None:
            return False, {"offset": None, "note": "无 UPX1 节"}
        start = sec.virtual_address
        end = start + max(sec.virtual_size, sec.size_of_raw_data)
        hit = start <= pe.entry_rva < end
        return hit, {
            "offset": sec.header_offset,
            "note": f"入口 RVA=0x{pe.entry_rva:X}，UPX1=[0x{start:X},0x{end:X})",
        }
    if name in ("max_section_entropy", "max_entropy_section", "max_entropy_raw"):
        secs = [s for s in sections if s.size_of_raw_data]
        best = max(secs, key=lambda s: s.entropy, default=None)
        if best is None:
            return (0.0 if name == "max_section_entropy" else
                    ("" if name == "max_entropy_section" else 0)), {
                        "offset": None, "note": "没有可扫描的节"}
        if name == "max_section_entropy":
            return round(best.entropy, 3), {"offset": best.header_offset,
                                           "note": f"{best.name} 熵"}
        if name == "max_entropy_section":
            return best.name, {"offset": best.header_offset, "note": "最高熵节"}
        return best.size_of_raw_data, {"offset": best.header_offset,
                                       "note": f"{best.name} 原始大小"}
    raise RulesError(f"事实 {name!r} 没有取值实现")


def build_facts(pe: PE, needed: set[str] | None = None
                ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    values: dict[str, Any] = {}
    evidence: dict[str, dict[str, Any]] = {}
    for name in sorted(needed or FACTS):
        values[name], evidence[name] = _fact(pe, name)
    return values, evidence


def _compare(op: str, actual: Any, expected: Any) -> bool:
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "in":
        return actual in expected
    if actual is None:
        return False
    try:
        if op == "gt":
            return actual > expected
        if op == "ge":
            return actual >= expected
        if op == "lt":
            return actual < expected
        if op == "le":
            return actual <= expected
    except TypeError:
        return False
    raise RulesError(f"未支持的操作符 {op!r}")


def evaluate(rules: dict[str, Any], values: dict[str, Any],
             evidence: dict[str, dict[str, Any]]) -> list[RuleHit]:
    results: list[RuleHit] = []
    for rule in rules["rules"]:
        matched = False
        hit_evidence: list[dict[str, Any]] = []
        for alternative in rule["any"]:
            checks = [(_compare(c["op"], values.get(c["fact"]), c["value"]), c)
                      for c in alternative]
            if all(ok for ok, _ in checks):
                matched = True
                for _ok, c in checks:
                    ev = evidence.get(c["fact"], {})
                    hit_evidence.append({
                        "fact": c["fact"],
                        "value": values.get(c["fact"]),
                        "offset": ev.get("offset"),
                        "note": ev.get("note", ""),
                    })
                break
        results.append(RuleHit(rule["id"], rule.get("description", ""), matched,
                               hit_evidence))
    return results


def run(pe: PE, rules: dict[str, Any]) -> dict[str, Any]:
    needed = {c["fact"] for rule in rules["rules"]
              for alt in rule["any"] for c in alt}
    values, evidence = build_facts(pe, needed)
    hits = evaluate(rules, values, evidence)
    return {
        "engine": ENGINE_NAME,
        "engine_note": ENGINE_NOTE,
        "yara_compatible": False,
        # 只是“环境里装没装 yara-python”，不代表本批规则已校验；校验结果单独记录。
        "yara_installed": yara_available(),
        "facts": values,
        "results": [h.as_dict() for h in hits],
        "hit_ids": [h.rule_id for h in hits if h.matched],
    }


def render_yara(rules: dict[str, Any],
                validation: dict[str, Any] | None = None) -> str:
    """由同一份 JSON 规则生成 `.yar` 文本。

    `validation` 只接受“真 YARA 跑过”的记录（由 eval 脚本写入 `m5_validation.json`）。
    没有记录就一律写「未经 YARA 校验」；即使校验通过，也必须同时写明
    **语义不等价**（部分条件 YARA 表达不了），不得暗示两套引擎等价。
    """
    status = (validation or {}).get("status", "未校验")
    if status == "通过":
        header = (f"// YARA 校验：通过（{(validation or {}).get('detail', '')}）；"
                  "注意：与 rekit 规则引擎**语义不等价**，只翻译了 YARA 能表达的条件。")
    elif status == "不通过":
        header = (f"// YARA 校验：不通过 —— {(validation or {}).get('detail', '')}。"
                  "本文件不可用。")
    else:
        header = "// 未经 YARA 校验：本文件没有被任何 YARA 实现加载或校验过。"
    lines = [
        "// 由 rekit 规则引擎从同一份 JSON 规则生成。",
        header,
        "// rekit 规则引擎不是 YARA 兼容实现，本文件不构成兼容性保证。",
        "// 未翻译的规则/分支见下方注释；请勿把本文件当作已验证规则使用。",
        "",
        'import "pe"',
        "",
    ]
    skipped: list[str] = []
    for rule in rules["rules"]:
        alternatives: list[str] = []
        omitted: list[str] = []
        for idx, alternative in enumerate(rule["any"], 1):
            parts: list[str] = []
            ok = True
            for cond in alternative:
                fact = cond["fact"]
                expr = YARA_FACT.get(fact)
                if expr is None or cond["op"] != "eq" or cond["value"] is not True:
                    ok = False
                    omitted.append(f"分支 {idx}: {fact} {cond['op']} "
                                   f"{cond['value']!r}（YARA 无法表达）")
                    break
                parts.append(expr)
            if ok:
                alternatives.append("(" + " and ".join(parts) + ")")
        if not alternatives:
            skipped.append(f"规则 {rule['id']} 全部未翻译")
            continue
        if omitted:
            lines.append(f"// {rule['id']} 部分翻译：" + "；".join(omitted))
        used = sorted({s for expr in alternatives for s in YARA_STRINGS
                       if s in expr})
        lines += [
            f"rule rekit_m5_{rule['id']} {{",
            "  meta:",
            f'    rule_id = "{rule["id"]}"',
            f'    description = "{rule.get("description", "")}"',
            '    generated_by = "rekit"',
            f'    yara_validated = {"true" if status == "通过" else "false"}',
        ]
        if used:
            lines.append("  strings:")
            lines += [f"    {name} = {YARA_STRINGS[name]}" for name in used]
        lines += [
            "  condition:",
            "    " + " or\n    ".join(alternatives),
            "}",
            "",
        ]
    if skipped:
        lines.insert(5, "// 未生成：" + "；".join(skipped))
    return "\n".join(lines).rstrip() + "\n"
