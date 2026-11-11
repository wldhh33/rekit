# -*- coding: utf-8 -*-
"""工具链族的**信号检测器**：只输出带偏移的信号，不下结论。

`identify` 负责融合与置信度映射；这里不写死"这是哪个族"。

为什么需要单独一层：`funcs.detect_toolchain` 把 clang 并入 gcc（PE 上都走 mingw-w64 运行时），
而 M4a 要求 gcc_x64 / clang_x64 分开。分开的依据不是单一硬指纹，而是多条信号的组合：

| 族 | 硬信号 | 结构/统计信号 |
|---|---|---|
| go_x64 | `Go build ID`、`go1.x` 版本串 | `.gopclntab` / `.symtab`、只导入 kernel32 |
| rust_x64 | `rustc 1.x`、`panicked at` | `api-ms-win-core-synch`（std 线程）|
| msvc_x64 | Rich 头 | 大写节名（`_RDATA`）、`VCRUNTIME140` 导入 |
| gcc_x64 | `GCC: (Rev..)` / `GCC: (GNU)` 串（漏 `GCC: (MinGW-W64`，见设计 §5.1 风险 4）| 存在 `.rsrc`（驱动默认链 manifest；非编译器身份）|
| clang_x64 | `clang version` 串（仅未 strip）| 无：strip 后与 gcc 不可区分，「无 `.rsrc`」是 absence，不能单独定族（设计 §5.4）|

注意 `.rsrc` 只反映"这套 MinGW 驱动会不会默认链接 manifest"，不是编译器身份：
实测同一份源码用 MinGW-clang 编译，显式加一个 manifest 资源后就会从 `clang_x64` 翻成
`gcc_x64`；改用 clang-cl（MSVC 目标/link.exe）则完全不带 mingw 串，被判成 `msvc_x64`。
因此 strip 后的 `clang_x64` 结论**只对 MinGW-clang 构建有效**，不是通用 clang 识别；
报告与已知风险必须写明失效条件（clang-cl、lld、官方 LLVM 工具链、带 manifest 的构建）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .pe import PE

FAMILIES = ("msvc_x64", "gcc_x64", "clang_x64", "go_x64", "rust_x64")

GO_VERSION_RE = re.compile(rb"go1\.\d{1,2}(?:\.\d{1,2})?")
MINGW_COMMENT_RE = re.compile(rb"GCC: \(Rev|GCC: \(GNU\)")

MSVC_CRT_DLLS = ("vcruntime140", "msvcp140", "vcruntime140_1", "ucrtbase")


@dataclass
class ToolchainSignal:
    id: str
    family: str | None      # 该信号指向的候选族；None 表示只作"mingw"这类中间标记
    weight: int
    hit: bool
    field: str
    offset: int | None
    offset_kind: str        # file / section_header / import_descriptor / e_lfanew
    value: str
    # positive = 找到了什么（节、串、导入）；absence = 只证明"没找到什么"。
    # absence 类只能削弱置信度，不能单独构成族判定（见 identify._decide）。
    evidence_kind: str = "positive"

    def as_dict(self, include_miss: bool = False) -> dict[str, Any]:
        if not self.hit and not include_miss:
            return {"id": self.id, "hit": False}
        d: dict[str, Any] = {
            "id": self.id,
            "hit": self.hit,
            "weight": self.weight,
            "family": self.family,
            "evidence_kind": self.evidence_kind,
            "evidence": {
                "field": self.field,
                "offset_kind": self.offset_kind,
                "offset": f"0x{self.offset:X}" if self.offset is not None else None,
                "value": self.value,
            },
        }
        return d


@dataclass
class ToolchainProfile:
    signals: list[ToolchainSignal] = field(default_factory=list)
    mingw_hint: bool = False
    has_rsrc: bool = False
    section_names: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)

    @property
    def hit(self) -> list[ToolchainSignal]:
        return [s for s in self.signals if s.hit]


def _find(data: Any, pat: bytes, start: int = 0) -> int | None:
    pos = data.find(pat, start)
    return pos if isinstance(pos, int) and pos >= 0 else None


def _first_hit(data: Any, patterns: list[bytes]) -> tuple[int, bytes] | None:
    best: tuple[int, bytes] | None = None
    for p in patterns:
        pos = _find(data, p)
        if pos is not None and (best is None or pos < best[0]):
            best = (pos, p)
    return best


def _rich_offset(pe: PE) -> int | None:
    """Rich 头位于 DOS stub 内：`...DanS...Rich<key>`，只在 e_lfanew 之前找。"""
    pos = _find(pe.data, b"Rich", 0x40)
    if pos is None or pos >= pe.e_lfanew:
        return None
    return pos


def detect(pe: PE) -> ToolchainProfile:
    data = pe.data
    names = [s.name for s in pe.sections]
    dlls = sorted({i.dll.lower() for i in pe.imports()})
    prof = ToolchainProfile(section_names=names, imports=dlls)
    sig = prof.signals

    # ---- Go
    go_build = _find(data, b"Go build ID")
    go_ver = None
    m = GO_VERSION_RE.search(data)
    if m:
        go_ver = m.start()
    sig.append(ToolchainSignal(
        "T1_go_build_id", "go_x64", 6, go_build is not None,
        "blob", go_build, "file", "Go build ID" if go_build is not None else "缺失"))
    sig.append(ToolchainSignal(
        "T2_go_version_string", "go_x64", 4, go_ver is not None,
        "blob", go_ver, "file", m.group().decode() if m else "缺失"))
    go_sec = next((s for s in pe.sections if s.name in (".gopclntab", ".symtab")), None)
    sig.append(ToolchainSignal(
        "T3_go_pclntab_or_symtab", "go_x64", 5, go_sec is not None,
        "section.name", go_sec.header_offset if go_sec else None, "section_header",
        go_sec.name if go_sec else "无 .gopclntab/.symtab"))
    only_kernel32 = bool(dlls) and all(
        d.startswith("kernel32") or d.startswith("api-ms-win") or d.startswith("ntdll") for d in dlls)
    sig.append(ToolchainSignal(
        "T4_go_import_profile", "go_x64", 2,
        only_kernel32 and go_sec is not None,
        "import.descriptor", pe.directories[1][0] if len(pe.directories) > 1 else None,
        "import_descriptor", f"{len(dlls)} DLL, 全部为系统 API"))

    # ---- Rust
    rustc_pos, rustc_pat = (_first_hit(data, [b"rustc 1.", b"/rustc/", b"rustc-"]) or (None, b""))
    sig.append(ToolchainSignal(
        "T5_rustc_version", "rust_x64", 6, rustc_pos is not None,
        "blob", rustc_pos, "file", rustc_pat.decode("ascii", "replace") if rustc_pos is not None else "缺失"))
    panic_pos, panic_pat = (_first_hit(data, [b"panicked at", b"library/std/src"]) or (None, b""))
    sig.append(ToolchainSignal(
        "T6_rust_panic_strings", "rust_x64", 4, panic_pos is not None,
        "blob", panic_pos, "file", panic_pat.decode("ascii", "replace") if panic_pos is not None else "缺失"))
    synch = next((i for i in pe.imports() if i.dll.lower().startswith("api-ms-win-core-synch")), None)
    sig.append(ToolchainSignal(
        "T7_rust_core_synch_import", "rust_x64", 1, synch is not None,
        "import.dll", synch.descriptor_offset if synch else None, "import_descriptor",
        synch.dll if synch else "无 api-ms-win-core-synch"))

    # ---- mingw 公共（gcc / clang 都走这套 CRT）
    mingw_pos, mingw_pat = (_first_hit(data, [b"GCC: (Rev", b"GCC: (GNU)"]) or (None, b""))
    prof.mingw_hint = mingw_pos is not None
    sig.append(ToolchainSignal(
        "T8_mingw_gcc_comment", None, 3, mingw_pos is not None,
        "blob", mingw_pos, "file", mingw_pat.decode("ascii", "replace") if mingw_pos is not None else "缺失"))
    clang_pos = _find(data, b"clang version")
    sig.append(ToolchainSignal(
        "T9_clang_version", "clang_x64", 5, clang_pos is not None,
        "blob", clang_pos, "file", "clang version" if clang_pos is not None else "缺失（strip 后通常没有）"))
    rsrc = next((s for s in pe.sections if s.name == ".rsrc"), None)
    prof.has_rsrc = rsrc is not None
    sig.append(ToolchainSignal(
        "T10_mingw_default_rsrc", "gcc_x64", 4, rsrc is not None and prof.mingw_hint,
        "section.name", rsrc.header_offset if rsrc else None, "section_header",
        ".rsrc（驱动默认链 manifest；非编译器身份）" if rsrc is not None else "无 .rsrc"))
    sig.append(ToolchainSignal(
        "T11_mingw_no_rsrc", "clang_x64", 2, (not prof.has_rsrc) and prof.mingw_hint,
        "section.name", pe.section_table_offset, "section_header",
        "节名列表无 .rsrc（驱动未链默认 manifest；不等于 clang 编译）",
        evidence_kind="absence"))

    # ---- MSVC
    rich = _rich_offset(pe)
    sig.append(ToolchainSignal(
        "T12_msvc_rich_header", "msvc_x64", 4, rich is not None,
        "dos_stub.Rich", rich, "file", "Rich 头存在" if rich is not None else "缺失（rustc 用 link.exe 时也会出现）"))
    upper = next((s for s in pe.sections if s.name.startswith((".TEXT", ".RDATA", ".DATA"))
                  or s.name.startswith("_")), None)
    sig.append(ToolchainSignal(
        "T13_msvc_upper_section", "msvc_x64", 3, upper is not None,
        "section.name", upper.header_offset if upper else None, "section_header",
        upper.name if upper else "无大写/下划线节名"))
    crt = next((i for i in pe.imports() if i.dll.lower().split(".")[0] in MSVC_CRT_DLLS), None)
    sig.append(ToolchainSignal(
        "T14_msvc_crt_import", "msvc_x64", 1, crt is not None,
        "import.dll", crt.descriptor_offset if crt else None, "import_descriptor",
        crt.dll if crt else "无 VC/UCRT 导入"))
    return prof


def analyze(path: str, allow_large: bool = False) -> ToolchainProfile:
    with PE(path, allow_large=allow_large) as pe:
        return detect(pe)

