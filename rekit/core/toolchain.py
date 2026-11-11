# -*- coding: utf-8 -*-
"""工具链族的**信号检测器**：只输出带偏移的信号，不下结论。

`identify` 负责融合与置信度映射；这里不写死"这是哪个族"。

族的定义见 `docs/family.md`：**`family` = 最终链接步骤的提供方**
（`msvc` / `gcc` / `go` / `dotnet`）。因此本模块把信号分成两类：

- `target="family"`：指向链接器提供方（Rich 头、可选头 linker version、GNU `ld` 版本、
  CLR 目录、`GCC: (GNU)` 这类由链接器写入/由链接配方决定的痕迹）；
- `target="frontend"`：只指向编译器前端（`rustc`、`clang`、`go`），不参与 `family` 判定。

| family | 硬信号 | 结构/统计信号 |
|---|---|---|
| `msvc` | Rich 头、`MajorLinkerVersion` 14.x（link.exe / lld-link）| 大写节名（`_RDATA`）、`VCRUNTIME140` 导入 |
| `gcc` | `GCC: (Rev..)` / `GCC: (GNU)` 串、`MajorLinkerVersion` 2.x（GNU ld）| 无（`.rsrc` 不是身份） |
| `go` | Go build ID、`go1.x`、`.gopclntab` | 只导入系统 API |
| `dotnet` | CLR 目录（数据目录 #14）、`mscoree.dll` 导入 | 无 |

`.rsrc` 只反映"这套 MinGW 驱动会不会默认链 manifest"，不是编译器身份，也不是链接器身份
（`docs/family.md` §1.1）：因此 T10/T11 只作观测，`family=None`，不参与计分。
同理，"没有 Rich 头"不是 gcc 的证据——`lld-link` 就不写 Rich。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .pe import PE

FAMILIES = ("msvc", "gcc", "go", "dotnet")

GO_VERSION_RE = re.compile(rb"go1\.\d{1,2}(?:\.\d{1,2})?")
MINGW_COMMENT_RE = re.compile(rb"GCC: \(Rev|GCC: \(GNU\)")

MSVC_CRT_DLLS = ("vcruntime140", "msvcp140", "vcruntime140_1", "ucrtbase")
UCRT_IMPORT_PREFIXES = ("api-ms-win-crt", "ucrtbase")
MINGW_CRT_DLLS = ("msvcrt.dll", "libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll")



@dataclass
class ToolchainSignal:
    id: str
    family: str | None      # 该信号指向的候选族；None 表示只作观测（如 .rsrc 有无）
    weight: int
    hit: bool
    field: str
    offset: int | None
    offset_kind: str        # file / section_header / import_descriptor / e_lfanew / opt_header
    value: str
    # positive = 找到了什么（节、串、导入）；absence = 只证明"没找到什么"。
    # absence 类只能削弱置信度，不能单独构成族判定（见 identify._decide）。
    evidence_kind: str = "positive"
    # family = 指向链接器提供方；frontend = 只指向编译器前端（rustc/clang/go）
    target: str = "family"

    def as_dict(self, include_miss: bool = False) -> dict[str, Any]:
        if not self.hit and not include_miss:
            return {"id": self.id, "hit": False}
        d: dict[str, Any] = {
            "id": self.id,
            "hit": self.hit,
            "weight": self.weight,
            "family": self.family,
            "target": self.target,
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
    linker_version: tuple[int, int] = (0, 0)
    has_clr_dir: bool = False

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

    # ---- Go（前端 + 内部链接器）
    go_build = _find(data, b"Go build ID")
    go_ver = None
    m = GO_VERSION_RE.search(data)
    if m:
        go_ver = m.start()
    sig.append(ToolchainSignal(
        "T1_go_build_id", "go", 6, go_build is not None,
        "blob", go_build, "file", "Go build ID" if go_build is not None else "缺失"))
    sig.append(ToolchainSignal(
        "T2_go_version_string", "go", 4, go_ver is not None,
        "blob", go_ver, "file", m.group().decode() if m else "缺失"))
    go_sec = next((s for s in pe.sections if s.name in (".gopclntab", ".symtab")), None)
    sig.append(ToolchainSignal(
        "T3_go_pclntab_or_symtab", "go", 5, go_sec is not None,
        "section.name", go_sec.header_offset if go_sec else None, "section_header",
        go_sec.name if go_sec else "无 .gopclntab/.symtab"))
    only_kernel32 = bool(dlls) and all(
        d.startswith("kernel32") or d.startswith("api-ms-win") or d.startswith("ntdll") for d in dlls)
    sig.append(ToolchainSignal(
        "T4_go_import_profile", "go", 2,
        only_kernel32 and go_sec is not None,
        "import.descriptor", pe.directories[1][0] if len(pe.directories) > 1 else None,
        "import_descriptor", f"{len(dlls)} DLL, 全部为系统 API"))

    # ---- Rust：前端证据，不参与 family 判定（docs/family.md §1）
    rustc_pos, rustc_pat = (_first_hit(data, [b"rustc 1.", b"/rustc/", b"rustc-"]) or (None, b""))
    sig.append(ToolchainSignal(
        "T5_rustc_version", None, 6, rustc_pos is not None,
        "blob", rustc_pos, "file", rustc_pat.decode("ascii", "replace") if rustc_pos is not None else "缺失",
        target="frontend"))
    panic_pos, panic_pat = (_first_hit(data, [b"panicked at", b"library/std/src"]) or (None, b""))
    sig.append(ToolchainSignal(
        "T6_rust_panic_strings", None, 4, panic_pos is not None,
        "blob", panic_pos, "file", panic_pat.decode("ascii", "replace") if panic_pos is not None else "缺失",
        target="frontend"))
    synch = next((i for i in pe.imports() if i.dll.lower().startswith("api-ms-win-core-synch")), None)
    sig.append(ToolchainSignal(
        "T7_rust_core_synch_import", None, 1, synch is not None,
        "import.dll", synch.descriptor_offset if synch else None, "import_descriptor",
        synch.dll if synch else "无 api-ms-win-core-synch", target="frontend"))

    # ---- MinGW / GCC：T8 有族归属（gcc），可与 go 证据形成可见冲突（F1）
    mingw_pos, mingw_pat = (_first_hit(data, [b"GCC: (Rev", b"GCC: (GNU)"]) or (None, b""))
    prof.mingw_hint = mingw_pos is not None
    sig.append(ToolchainSignal(
        "T8_mingw_gcc_comment", "gcc", 3, mingw_pos is not None,
        "blob", mingw_pos, "file", mingw_pat.decode("ascii", "replace") if mingw_pos is not None else "缺失"))
    clang_pos = _find(data, b"clang version")
    sig.append(ToolchainSignal(
        "T9_clang_version", None, 5, clang_pos is not None,
        "blob", clang_pos, "file", "clang version" if clang_pos is not None else "缺失（strip 后通常没有）",
        target="frontend"))
    rsrc = next((s for s in pe.sections if s.name == ".rsrc"), None)
    prof.has_rsrc = rsrc is not None
    sig.append(ToolchainSignal(
        "T10_mingw_default_rsrc", None, 4, rsrc is not None and prof.mingw_hint,
        "section.name", rsrc.header_offset if rsrc else None, "section_header",
        ".rsrc（驱动默认链 manifest；非编译器/链接器身份）" if rsrc is not None else "无 .rsrc"))
    sig.append(ToolchainSignal(
        "T11_mingw_no_rsrc", None, 2, (not prof.has_rsrc) and prof.mingw_hint,
        "section.name", pe.section_table_offset, "section_header",
        "节名列表无 .rsrc（驱动未链默认 manifest；不等于 clang 编译）",
        evidence_kind="absence"))

    # ---- MSVC
    rich = _rich_offset(pe)
    sig.append(ToolchainSignal(
        "T12_msvc_rich_header", "msvc", 4, rich is not None,
        "dos_stub.Rich", rich, "file", "Rich 头存在" if rich is not None else "缺失（rustc 用 link.exe 时也会出现）"))
    upper = next((s for s in pe.sections if s.name.startswith((".TEXT", ".RDATA", ".DATA"))
                  or s.name.startswith("_")), None)
    sig.append(ToolchainSignal(
        "T13_msvc_upper_section", "msvc", 3, upper is not None,
        "section.name", upper.header_offset if upper else None, "section_header",
        upper.name if upper else "无大写/下划线节名"))
    crt = next((i for i in pe.imports() if i.dll.lower().split(".")[0] in MSVC_CRT_DLLS), None)
    sig.append(ToolchainSignal(
        "T14_msvc_crt_import", "msvc", 1, crt is not None,
        "import.dll", crt.descriptor_offset if crt else None, "import_descriptor",
        crt.dll if crt else "无 VC/UCRT 导入"))

    # ---- 链接器版本（F3：Rust msvcrt 样例缺 .rsrc/.comment 时靠它定族）
    # GNU ld 写 2.x；link.exe / lld-link 写 14.x；Go 内部链接器写 3.0；
    # Roslyn 产出的托管程序集写 48.0（走 CLR 目录判定，不进本信号）。
    major, minor = pe.optional_major_linker, pe.optional_minor_linker
    prof.linker_version = (major, minor)
    lv_off = pe.optional_header_offset + 2 if hasattr(pe, "optional_header_offset") else None
    sig.append(ToolchainSignal(
        "T15_gnu_ld_linker_version", "gcc", 5, major == 2,
        "opt_header.MajorLinkerVersion", lv_off, "opt_header",
        f"{major}.{minor}" + ("（GNU ld 的写法）" if major == 2 else "（非 GNU ld）")))
    sig.append(ToolchainSignal(
        "T16_msvc_linker_version", "msvc", 4, 6 <= major <= 14,
        "opt_header.MajorLinkerVersion", lv_off, "opt_header",
        f"{major}.{minor}" + ("（link.exe / lld-link 的写法）" if 6 <= major <= 14 else "（非 MSVC 链接器）")))

    # ---- 托管：CLR 目录 + mscoree
    clr_rva = pe.directories[14][0] if len(pe.directories) > 14 else 0
    prof.has_clr_dir = bool(clr_rva)
    mscoree = next((i for i in pe.imports() if i.dll.lower().startswith("mscoree")), None)
    sig.append(ToolchainSignal(
        "T17_clr_directory", "dotnet", 5, bool(clr_rva),
        "directory[14]", clr_rva or None, "rva", f"CLR 目录 RVA=0x{clr_rva:X}" if clr_rva else "无 CLR 目录"))
    sig.append(ToolchainSignal(
        "T18_mscoree_import", "dotnet", 2, mscoree is not None,
        "import.dll", mscoree.descriptor_offset if mscoree else None, "import_descriptor",
        mscoree.dll if mscoree else "无 mscoree 导入"))
    return prof


def analyze(path: str, allow_large: bool = False) -> ToolchainProfile:
    with PE(path, allow_large=allow_large) as pe:
        return detect(pe)

