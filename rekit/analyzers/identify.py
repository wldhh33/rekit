# -*- coding: utf-8 -*-
"""`rekit identify`：工具链族 + 壳判定的**融合层**。

只做三件事：把各检测器的信号归并、按证据强度选出 `family`、把得分映射成 `confidence`。
检测本身在 `triage` / `core.toolchain` / `funcs` / `unpack`，这里不重写。

输出契约（M4 设计 §2.1）：
    file / sha256 / kind / family / bitness / scope / confidence / verdict /
    signals[] / conflicts[] / schema_version
每条**命中**信号都必须带偏移、偏移类型与 `evidence_kind`（positive | absence）；
`unknown` 是合法结论，不硬猜。absence 类信号不得单独构成族判定。
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from ..contract import error_entry, no_files_entry
from ..core.files import expand_paths
from ..core.pe import PE, PEError
from ..core import toolchain
from . import packer, triage

NAME = "identify"
DESCRIPTION = "工具链族与壳的融合判定（family + confidence + signals 偏移 + conflicts）"
SCHEMA_VERSION = 2

CONF_MIN, CONF_MAX = 0.50, 0.99
DECIDED = 0.80
OFF_RE = re.compile(r"0x([0-9A-Fa-f]{2,})")


def _score(prof: toolchain.ToolchainProfile) -> dict[str, int]:
    s = {f: 0 for f in toolchain.FAMILIES}
    for x in prof.hit:
        if x.family:
            s[x.family] += x.weight
    return s


def _absence_only(family: str, prof: toolchain.ToolchainProfile) -> bool:
    """该族的全部命中信号是否都属于 absence（缺失型）。

    缺失型证据只能削弱置信度，不能单独构成族判定：例如“无 `.rsrc`”只在
    MinGW 默认链接配方下指向 clang，加 manifest 或换 clang-cl 就翻转。
    """
    kinds = [s.evidence_kind for s in prof.hit if s.family == family]
    return bool(kinds) and all(k == "absence" for k in kinds)


def _decide(prof: toolchain.ToolchainProfile) -> tuple[str, str, list[dict[str, Any]], str]:
    """返回 (family, 依据说明, 冲突列表, 证据档位)。规则是硬编码的，阈值不进语料调参。"""
    hit = {s.id for s in prof.hit}
    score = _score(prof)
    conflicts: list[dict[str, Any]] = []

    # 硬证据优先（M4 设计 §5.2）：go/rust 的版本串与节表 > mingw 结构 > msvc 结构
    if score["go_x64"] >= 5:
        family, why, tier = "go_x64", "Go build ID / .gopclntab / go1.x 版本串", "hard"
    elif score["rust_x64"] >= 5:
        family, why, tier = "rust_x64", "rustc 版本串 / panic 串", "hard"
    elif prof.mingw_hint:
        if "T9_clang_version" in hit:
            family, why, tier = "clang_x64", "clang version 串", "hard"
        elif "T10_mingw_default_rsrc" in hit:
            family, why, tier = "gcc_x64", "mingw 串 + .rsrc（MinGW-gcc 驱动默认 manifest 特征）", "structural"
        else:
            # 只有“无 .rsrc”这类 absence 证据：clang 与 gcc 在 strip 后不可区分
            # （设计 §5.3 实验：8 源 × 2 工具链，唯一取值范围不相交的特征就是 .rsrc）。
            family, why, tier = (
                "unknown",
                "仅有 mingw 串；无 .rsrc 是缺失型证据，MinGW-clang 与 gcc strip 后不可区分，不硬判",
                "none",
            )
    elif score["msvc_x64"] >= 4:
        family, why, tier = "msvc_x64", "Rich 头 / 大写节名 / VC 运行时导入", "hard"
    elif score["msvc_x64"] > 0:
        family, why, tier = "msvc_x64", "仅弱信号（VC 运行时导入）", "weak"
    else:
        family, why, tier = "unknown", "无可用工具链指纹", "none"

    # 硬规则：absence 类信号只能压低置信度，不能单独形成族判定
    if family in toolchain.FAMILIES and _absence_only(family, prof):
        ids = [s.id for s in prof.hit if s.family == family]
        family, why, tier = (
            "unknown",
            f"仅缺失型证据（absence：{', '.join(ids)}），不构成族判定",
            "none",
        )

    # 冲突：两个族同时出现 ≥5 分的硬证据（例如 rustc 产物同时带 Rich 头不构成冲突，因为 Rich 只有 4 分）
    strong = [f for f, v in score.items() if v >= 5]
    if len(strong) >= 2:
        involved = [s.id for s in prof.hit if s.family in strong and s.weight >= 3]
        conflicts.append({"between": strong, "signals": involved,
                          "note": "两个族同时达到硬证据分；按优先级取 %s" % family})
    return family, why, conflicts, tier


def _confidence(family: str, prof: toolchain.ToolchainProfile,
                conflicts: list[dict[str, Any]], tier: str) -> float:
    """证据档位 → 置信度。分档表由开发期（训练/校准侧）自检给出，不计达标判定：

    | 档位 | 含义 | 置信度 |
    |---|---|---|
    | hard | 版本串 / 节表 / Rich 头等直接指纹 | 0.97 |
    | structural | 靠 `.rsrc` 有无这类结构推断（依赖 MinGW 驱动默认行为） | 0.93 |
    | weak | 只有单条弱信号 | 0.60 |
    | none / unknown | 无结论 | 0.30 |

    为什么 structural 给 0.93 而不是 0.90：开发期三档在训练/校准侧都判对（仅证明拟合），
    若压到 0.90 以下，ECE 会被人为抬高到 0.10 以上——那不是"保守"，是把校准做错。
    真实泛化能力由测试侧与外部留出集检验，不靠在这里压低数字来假装稳健。
    注意置信度只表示"本次判定在本工具链分布内的可靠度"，不表示信号具有通用性；
    `clang_x64` 的 structural 档只对 MinGW-clang 构建成立（见设计 §5.1 已知风险）。
    每出现一处 `conflicts` 扣 0.05。
    """
    if family == "unknown" or tier == "none":
        return 0.30
    tier_conf = {"hard": 0.97, "structural": 0.93, "weak": 0.60}
    conf = tier_conf[tier] - 0.05 * len(conflicts)
    return round(max(0.05, min(conf, CONF_MAX)), 3)


def analyze_file(path: str, allow_large: bool = False) -> dict[str, Any]:
    t = triage.analyze_file(path, allow_large=allow_large)
    with PE(path, allow_large=allow_large) as pe:
        prof = toolchain.detect(pe)
        sha = hashlib.sha256(pe.data).hexdigest()
        pk = packer.analyze(pe, t)

    family, why, conflicts, tier = _decide(prof)
    # 位数是独立字段：x64 进入 M4a 计分范围；x86 允许给族（改名为 *_x86），
    # 但标 scope=out_of_m4a，不参与 M4a 的五族达标（范围约束，不是放宽阈值）。
    bitness = {0x8664: "x64", 0x014C: "x86"}.get(pe.machine, pe.arch.lower())
    scope = "in_m4a" if bitness == "x64" else "out_of_m4a"
    if family in toolchain.FAMILIES:
        if bitness == "x86":
            family = family.replace("_x64", "_x86")
        elif bitness != "x64":
            family, why, tier = (
                "unknown",
                f"机器类型 {pe.arch} 不在 5 族覆盖范围；工具链信号命中但不硬判",
                "none",
            )
    conf = _confidence(family, prof, conflicts, tier)
    # 壳判定只追加：顶层 verdict 取旧 triage 结论与 M4b packer 结论的并集；
    # 旧字段名与语义不变，工具链 family/confidence/basis 保持原样。
    verdict = "packed" if (pk["verdict"] == "packed" or t.verdict in ("upx", "packed?")) else "clean"
    kind = "packer" if pk["verdict"] == "packed" else "toolchain"

    signals = [s.as_dict() for s in prof.hit]
    # triage 的壳信号一并入册（identify 是统一入口，证据不能只来自工具链层）
    for s in t.signals:
        if not s.hit:
            continue
        m = OFF_RE.search(s.evidence)
        off = int(m.group(1), 16) if m else None
        kind_ev = "file" if (m and ("FO" in s.evidence or "FOA" in s.evidence)) else "text_ref"
        signals.append({
            "id": s.id, "hit": True, "weight": s.weight, "source": "triage",
            "scored": off is not None,
            "evidence": {"field": "triage.evidence", "offset_kind": kind_ev,
                         "offset": f"0x{off:X}" if off is not None else None,
                         "value": s.evidence},
        })
    # M4b：S1–S10 的全量命中证据（带文件偏移/RVA），供 records.jsonl 逐条复算
    signals.extend(pk["signals"])

    return {
        "file": path,
        "sha256": sha,
        "kind": kind,
        "family": family,
        "bitness": bitness,
        "scope": scope,
        "confidence": conf,
        "verdict": verdict,
        "decided": conf >= DECIDED,
        "basis": why,
        "signals": signals,
        "conflicts": conflicts,
        "packer": {"family": pk["family"], "verdict": pk["verdict"], "score": pk["score"],
                   "confidence": pk["confidence"], "basis": pk["basis"],
                   "signals_version": pk["signals_version"],
                   "signals_all": pk["signals_all"]},
        "triage": {"verdict": t.verdict, "score": t.score,
                   "max_entropy": t.max_entropy, "sections": t.sections,
                   "section_names": t.section_names},
        "schema_version": SCHEMA_VERSION,
    }


def run(paths: list[str], allow_large: bool = False) -> dict[str, Any]:
    results, errors = [], []
    files = expand_paths(paths)
    if not files:
        return {"analyzer": NAME, "results": [], "errors": [no_files_entry(paths)]}
    for path in files:
        try:
            results.append(analyze_file(path, allow_large=allow_large))
        except (PEError, OSError) as e:
            errors.append(error_entry(path, e))
    return {"analyzer": NAME, "results": results, "errors": errors}
