# -*- coding: utf-8 -*-
"""`rekit identify`：工具链族 + 壳判定的**融合层**。

只做三件事：把各检测器的信号归并、按证据强度选出 `family`、把得分映射成 `confidence`。
检测本身在 `triage` / `core.toolchain` / `funcs` / `unpack`，这里不重写。

`family` 的语义见 `docs/family.md`：**族 = 最终链接步骤的提供方**
（`msvc` / `gcc` / `go` / `dotnet`），不是编译器前端。`rustc` / `clang` / `go` 只进
`compiler_frontend`；`.rsrc` 有无只作观测，不参与判定。

输出契约（schema 3）：
    file / sha256 / kind / family / compiler_frontend / crt_provider / target_triple /
    bitness / scope / confidence / verdict / signals[] / conflicts[] / schema_version
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
SCHEMA_VERSION = 3

CONF_MIN, CONF_MAX = 0.50, 0.99
DECIDED = 0.80
OFF_RE = re.compile(r"0x([0-9A-Fa-f]{2,})")
# 只在二进制里出现明确的 target triple 时填写；推不出来就 null，不猜。
TRIPLE_RE = re.compile(
    rb"(?:x86_64|i686|aarch64|arm64)[-_](?:pc-windows-(?:msvc|gnu|gnullvm)|w64-mingw32)")


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


GNU_SECTION_MARKERS = (".buildid", ".note")


def _brief(signals: list[toolchain.ToolchainSignal]) -> str:
    """依据只由**实际命中**的信号拼成：id + 偏移 + 实测值。未命中项不出现。"""
    ordered = sorted(signals, key=lambda s: (-s.weight, s.id))
    parts = []
    for s in ordered:
        where = f"@0x{s.offset:X} " if s.offset is not None else ""
        parts.append(f"{s.id} {where}{s.value}")
    return "；".join(parts)


def _is_crt_dll(name: str) -> bool:
    d = name.lower()
    return (d.startswith(toolchain.UCRT_IMPORT_PREFIXES)
            or d.split(".")[0] in toolchain.MSVC_CRT_DLLS
            or d == "msvcrt.dll")


def _mingw_lld_shape(prof: toolchain.ToolchainProfile, data: Any) -> bool:
    """T16 的反向约束：linker 14.x 也可能是 MinGW/LLD 产物，不能单信号硬判 msvc。

    形态证据必须同时成立（全部是 independent 的观测，不看文件名/哈希）：
    - 无 Rich 头、无大写/下划线节名；
    - 节名全小写且含 GNU 链接器标记（`.buildid` / `.note`）；
    - CRT 导入只有 `api-ms-win-crt-*`（无 msvcrt / ucrtbase / VCRUNTIME）；
    - 二进制内嵌 MinGW 目标三元组。
    """
    if data is None:
        return False
    hit = {s.id for s in prof.hit}
    if "T12_msvc_rich_header" in hit or "T13_msvc_upper_section" in hit:
        return False
    names = [n for n in prof.section_names if n]
    if not names or any(ch.isupper() for n in names for ch in n):
        return False
    if not any(n in GNU_SECTION_MARKERS for n in names):
        return False
    crt = [d for d in prof.imports if _is_crt_dll(d)]
    if not crt or not all(d.lower().startswith("api-ms-win-crt") for d in crt):
        return False
    triple = _target_triple(data)
    return bool(triple and "mingw" in triple)


def _mingw_shape_basis(prof: toolchain.ToolchainProfile, data: Any) -> str:
    t16 = next(s for s in prof.hit if s.id == "T16_msvc_linker_version")
    secs = ", ".join(prof.section_names)
    crt = ", ".join(d for d in prof.imports if _is_crt_dll(d))
    triple = _target_triple(data) or "未命中"
    return (f"{t16.id} {t16.value} 是唯一 msvc 命中；但呈 MinGW/LLD 形态："
            f"无 Rich 头、全小写 GNU 节名（{secs}）、CRT 仅 {crt}、三元组 {triple}；"
            f"单信号不足以硬判 msvc")


def _decide(prof: toolchain.ToolchainProfile,
            data: Any = None) -> tuple[str, str, list[dict[str, Any]], str]:
    """返回 (family, 依据说明, 冲突列表, 证据档位)。规则是硬编码的，阈值不进语料调参。

    判定阶梯按**族 = 链接器提供方**排（`docs/family.md` §1）：

    1. `dotnet`：CLR 目录 #14（不是原生链接产物）；
    2. `gcc`：GNU ld 的 linker version 2.x，或 `GCC: (GNU)` 串——**链接器证据优先于
       Go 前端证据**，因为 cgo 外部链接的最终 PE 是 MinGW `ld` 写的；
    3. `go`：Go build ID / `.gopclntab` / `go1.x`；
    4. `msvc`：Rich 头 / MSVC linker version 6–14 / 大写节名 / VC CRT 导入；
    5. 只有弱 msvc 信号 → `msvc`（weak）；否则 `unknown`。

    `msvc` 档有反向约束：linker 14.x 若同时呈 MinGW/LLD 形态（无 Rich、全小写 GNU
    节名、CRT 仅 UCRT API set、内嵌 mingw 三元组），T16 单信号不得硬判 msvc，转
    `unknown`（`_mingw_lld_shape`）。

    `go` 与 `gcc` 同时达到 5 分时**必须**留下冲突记录：这正是 gitea（cgo + MinGW）
    反事实暴露的问题——只改分支顺序会把冲突吞掉。

    `why` 一律由实际命中信号拼接（`_brief`），不写固定文案。
    """
    score = _score(prof)
    conflicts: list[dict[str, Any]] = []

    if score["dotnet"] >= 5:
        family, why, tier = (
            "dotnet", _brief([s for s in prof.hit if s.family == "dotnet"]), "hard")
    elif score["gcc"] >= 5:
        family, why, tier = (
            "gcc", _brief([s for s in prof.hit if s.family == "gcc"]), "hard")
    elif score["go"] >= 5:
        family, why, tier = (
            "go", _brief([s for s in prof.hit if s.family == "go"]), "hard")
    elif score["msvc"] >= 4:
        msvc_hits = [s for s in prof.hit if s.family == "msvc"]
        only_t16 = [s.id for s in msvc_hits] == ["T16_msvc_linker_version"]
        if _mingw_lld_shape(prof, data) and only_t16:
            family, why, tier = "unknown", _mingw_shape_basis(prof, data), "none"
        else:
            family, why, tier = "msvc", _brief(msvc_hits), "hard"
    elif score["msvc"] > 0:
        family, why, tier = (
            "msvc", _brief([s for s in prof.hit if s.family == "msvc"]), "weak")
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

    # 冲突：两个族同时出现 ≥5 分的硬证据。go × gcc 是最重要的一类：
    # Go 前端证据（build ID、pclntab）与 MinGW 链接器证据同时成立，按族定义取 gcc，
    # 但必须把两者都写出来，不能“按顺序吞掉”。
    strong = sorted((f for f, v in score.items() if v >= 5), key=lambda f: -score[f])
    if len(strong) >= 2:
        involved = [s.id for s in prof.hit if s.family in strong and s.weight >= 3]
        if "go" in strong and "gcc" in strong:
            note = ("Go 前端/内部链接证据与 GNU ld 链接器证据同时成立；"
                    "按族=链接器提供方取 gcc（cgo 外部链接），go 只计入 compiler_frontend")
        else:
            note = f"两个族同时达到硬证据分；按族=链接器提供方取 {family}"
        conflicts.append({"between": strong, "signals": involved, "note": note})
    return family, why, conflicts, tier


def _frontend(prof: toolchain.ToolchainProfile, data: Any,
              family: str) -> tuple[str, str | None]:
    """编译器前端与可核验的 target triple。前端不参与 family 判定。"""
    hit = {s.id for s in prof.hit}
    if "T5_rustc_version" in hit:
        frontend = "rustc"
    elif "T9_clang_version" in hit:
        frontend = "clang"
    elif "T1_go_build_id" in hit or "T3_go_pclntab_or_symtab" in hit:
        frontend = "go"
    elif "T8_mingw_gcc_comment" in hit:
        frontend = "gcc"
    elif "T12_msvc_rich_header" in hit and family == "msvc":
        frontend = "msvc-cl"
    else:
        frontend = "unknown"
    return frontend, _target_triple(data)


def _target_triple(data: Any) -> str | None:
    """只在二进制里出现明确 triple 时返回；否则 None（不按族猜）。"""
    m = TRIPLE_RE.search(data)
    return m.group().decode("ascii", "replace") if m else None


def _crt_provider(prof: toolchain.ToolchainProfile, family: str) -> str:
    """CRT 提供方：只描述“链了哪套运行时”，不改变族归属。"""
    dlls = [d.lower() for d in prof.imports]
    if family in ("go", "dotnet"):
        return "none"
    if any(d.startswith(toolchain.UCRT_IMPORT_PREFIXES) for d in dlls):
        return "ucrt"
    if any(d.split(".")[0] in toolchain.MSVC_CRT_DLLS for d in dlls):
        return "ucrt"  # VCRUNTIME140 / MSVCP140 基于 UCRT
    if "msvcrt.dll" in dlls:
        return "msvcrt"
    return "static" if dlls else "none"


def _confidence(family: str, prof: toolchain.ToolchainProfile,
                conflicts: list[dict[str, Any]], tier: str) -> float:
    """证据档位 → 置信度。分档表由开发期（训练/校准侧）自检给出，不计达标判定：

    | 档位 | 含义 | 置信度 |
    |---|---|---|
    | hard | 链接器版本 / Rich 头 / Go build ID / CLR 目录等直接指纹 | 0.97 |
    | weak | 只有单条弱信号 | 0.60 |
    | none / unknown | 无结论 | 0.30 |

    `structural` 是 0.6.x 的档位（靠 `.rsrc` 有无推断），0.7 起不再产生；保留映射只为
    让旧调用不炸，不代表还承认 `.rsrc` 是身份证据。每出现一处 `conflicts` 扣 0.05。
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
        family, why, conflicts, tier = _decide(prof, pe.data)
        # 位数是独立字段：x64 进入 M4a 计分范围，其余标 scope=out_of_m4a。
        # 0.7 起 family 不再按位数改名（没有 *_x64 / *_x86 这套后缀）。
        bitness = {0x8664: "x64", 0x014C: "x86"}.get(pe.machine, pe.arch.lower())
        scope = "in_m4a" if bitness == "x64" else "out_of_m4a"
        frontend, triple = _frontend(prof, pe.data, family)
        crt = _crt_provider(prof, family)
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
        "compiler_frontend": frontend,
        "crt_provider": crt,
        "target_triple": triple,
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
