# -*- coding: utf-8 -*-
"""rekit.core.pe —— 纯标准库 PE/PE32+ 解析器（v0.1 内嵌精简版）。

只做"拿到原始结构"这一件事，不下结论；所有结论在 analyzers/ 里，并带上这里的文件偏移，
保证每条判断都能回指到字节。

来源：由 工具库/pe/pe_info.py（学习项目里的手写解析器，已与 pefile 100% 交叉校验）
裁剪迁入，保留同样的字段语义与边界检查。完整字段（延迟导入、资源树、.pdata 等）
按路线图在 v0.2 迁入。
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from typing import Any

PE_EXTS = (".exe", ".dll", ".sys", ".cpl", ".ocx", ".scr", ".efi")

MACHINES = {
    0x014C: "i386",
    0x8664: "AMD64",
    0xAA64: "ARM64",
    0x01C4: "ARMv7",
    0x0200: "IA64",
}

SUBSYSTEMS = {
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    13: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

DIR_NAMES = [
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
    "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
    "IAT", "DELAY_IMPORT", "CLR_RUNTIME", "RESERVED",
]

MEM_EXECUTE = 0x20000000
MEM_READ = 0x40000000
MEM_WRITE = 0x80000000

# 加载器映射分类：RVA 在文件里有没有对应字节
MAP_HEADERS = "headers"        # 头部区，1:1 映射
MAP_FILE = "file"              # 文件有字节，loader 原样映射
MAP_ZERO = "zero_fill"         # 内存有、文件无（VirtualSize > RawSize，或 VirtualSize=0 时的 .bss 尾部）
MAP_SLACK = "file_slack"       # 文件有、内存无（RawSize > VirtualSize，填充/末尾对齐）
MAP_PAD = "align_pad"          # 节末尾到 SectionAlignment 边界，loader 补零
MAP_GAP = "gap"                # 落在 SizeOfImage 内但不属于任何节
MAP_BEYOND = "beyond_image"    # >= SizeOfImage


def align_up(value: int, alignment: int) -> int:
    if not alignment:
        return value
    return (value + alignment - 1) // alignment * alignment


def effective_vsize(section: "Section") -> int:
    """PE 规范：VirtualSize=0 时 loader 用 SizeOfRawData 作为内存长度。"""
    return section.virtual_size or section.size_of_raw_data


class PEError(Exception):
    """解析时的边界/格式错误。"""


class Reader:
    """带边界检查的字节读取器，偏移一律指文件偏移（FOA）。"""

    def __init__(self, data: bytes):
        self.data = data

    def _unpack(self, fmt: str, off: int, size: int) -> int:
        if off < 0 or off + size > len(self.data):
            raise PEError(f"读取越界：FOA=0x{off:X} size={size} 文件大小=0x{len(self.data):X}")
        return struct.unpack_from(fmt, self.data, off)[0]

    def u8(self, off: int) -> int:
        return self._unpack("<B", off, 1)

    def u16(self, off: int) -> int:
        return self._unpack("<H", off, 2)

    def u32(self, off: int) -> int:
        return self._unpack("<I", off, 4)

    def u64(self, off: int) -> int:
        return self._unpack("<Q", off, 8)

    def bytes(self, off: int, size: int) -> bytes:
        if off < 0 or off + size > len(self.data):
            raise PEError(f"读取越界：FOA=0x{off:X} size={size}")
        return self.data[off:off + size]

    def cstr(self, off: int, limit: int = 512) -> str:
        if off < 0 or off >= len(self.data):
            raise PEError(f"字符串偏移越界：0x{off:X}")
        end = self.data.find(b"\x00", off, min(off + limit, len(self.data)))
        if end < 0:
            end = min(off + limit, len(self.data))
        return self.data[off:end].decode("ascii", errors="replace")


def entropy(data: bytes) -> float:
    """香农熵（比特/字节）。加壳/压缩数据的典型值 > 7.5。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / total
            e -= p * math.log2(p)
    return e


@dataclass
class Section:
    index: int
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int
    header_offset: int
    raw: bytes = b""

    @property
    def entropy(self) -> float:
        return entropy(self.raw)

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & MEM_EXECUTE)

    @property
    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "virtual_address": self.virtual_address,
            "virtual_size": self.virtual_size,
            "size_of_raw_data": self.size_of_raw_data,
            "pointer_to_raw_data": self.pointer_to_raw_data,
            "characteristics": f"0x{self.characteristics:08X}",
            "executable": self.is_executable,
            "entropy": round(self.entropy, 3),
            "header_offset": f"0x{self.header_offset:X}",
        }


@dataclass
class Import:
    dll: str
    name: str | None
    ordinal: int | None
    iat_rva: int
    descriptor_offset: int


@dataclass
class Export:
    name: str | None
    ordinal: int
    rva: int


class PE:
    """一个 PE 文件的结构视图。构造即完整解析（失败抛 PEError）。"""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.r = Reader(self.data)
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.sections: list[Section] = []
        self.directories: list[tuple[int, int]] = []
        self._parse()

    # ---------- 头 ----------
    def _parse(self) -> None:
        if len(self.data) < 0x40 or self.r.u16(0) != 0x5A4D:
            raise PEError("不是 MZ 文件")
        self.e_lfanew = self.r.u32(0x3C)
        if self.r.u32(self.e_lfanew) != 0x00004550:
            raise PEError(f"e_lfanew=0x{self.e_lfanew:X} 处不是 'PE\\0\\0'")

        fh = self.e_lfanew + 4
        self.machine = self.r.u16(fh)
        self.number_of_sections = self.r.u16(fh + 2)
        self.timestamp = self.r.u32(fh + 4)
        self.size_of_optional_header = self.r.u16(fh + 16)
        self.file_characteristics = self.r.u16(fh + 18)

        opt = fh + 20
        self.magic = self.r.u16(opt)
        if self.magic == 0x10B:
            self.is_64, self.pe_format = False, "PE32"
            self.image_base = self.r.u32(opt + 28)
            self.number_of_rva_and_sizes = self.r.u32(opt + 92)
            dd_off = opt + 96
        elif self.magic == 0x20B:
            self.is_64, self.pe_format = True, "PE32+"
            self.image_base = self.r.u64(opt + 24)
            self.number_of_rva_and_sizes = self.r.u32(opt + 108)
            dd_off = opt + 112
        else:
            raise PEError(f"未知 OptionalHeader Magic=0x{self.magic:X}")

        self.entry_rva = self.r.u32(opt + 16)
        self.section_alignment = self.r.u32(opt + 32)
        self.file_alignment = self.r.u32(opt + 36)
        self.size_of_image = self.r.u32(opt + 56)
        self.size_of_headers = self.r.u32(opt + 60)
        self.subsystem = self.r.u16(opt + 68)
        self.dll_characteristics = self.r.u16(opt + 70)
        self.dd_offset = dd_off

        for i in range(min(self.number_of_rva_and_sizes, 16)):
            self.directories.append((self.r.u32(dd_off + i * 8), self.r.u32(dd_off + i * 8 + 4)))

        sec_off = opt + self.size_of_optional_header
        self.section_table_offset = sec_off
        for i in range(self.number_of_sections):
            base = sec_off + i * 40
            name = self.r.bytes(base, 8).rstrip(b"\x00").decode("ascii", errors="replace")
            raw_size = self.r.u32(base + 16)
            raw_ptr = self.r.u32(base + 20)
            raw = self.data[raw_ptr:raw_ptr + raw_size] if raw_size and raw_ptr < len(self.data) else b""
            self.sections.append(
                Section(
                    index=i,
                    name=name,
                    virtual_size=self.r.u32(base + 8),
                    virtual_address=self.r.u32(base + 12),
                    size_of_raw_data=raw_size,
                    pointer_to_raw_data=raw_ptr,
                    characteristics=self.r.u32(base + 36),
                    header_offset=base,
                    raw=raw,
                )
            )

    # ---------- 地址换算 ----------
    def section_of_rva(self, rva: int) -> Section | None:
        for s in self.sections:
            span = max(s.virtual_size, s.size_of_raw_data)
            if s.virtual_address <= rva < s.virtual_address + span:
                return s
        return None

    def rva_to_foa(self, rva: int) -> int | None:
        if rva < self.size_of_headers:
            return rva
        s = self.section_of_rva(rva)
        if not s or not s.size_of_raw_data:
            return None
        delta = rva - s.virtual_address
        if delta >= s.size_of_raw_data:
            return None
        return s.pointer_to_raw_data + delta

    # ---------- 加载器映射（D4） ----------
    def section_map(self) -> list[dict[str, Any]]:
        """每个节的「RVA 区间 ↔ FOA 区间」对照，附带文件多出/内存补零。

        与 `rva_to_foa` 的区别：这里描述 loader 的映射结果，不判断单点是否可读。
        - 内存区间按 VirtualSize（为 0 时用 RawSize）向上取到 SectionAlignment；
        - 文件区间是 RawPtr..RawPtr+RawSize；
        - `file_slack` = 文件里有、但超出 VirtualSize 不会被映射的字节；
        - `zero_fill` = 内存里有、文件里没有的字节（BSS/解压区）。
        """
        rows: list[dict[str, Any]] = []
        for s in self.sections:
            vs = effective_vsize(s)
            mem_end = align_up(s.virtual_address + vs, self.section_alignment)
            rows.append({
                "index": s.index,
                "name": s.name,
                "rva_start": s.virtual_address,
                "rva_end": s.virtual_address + vs,
                "mem_end": mem_end,
                "foa_start": s.pointer_to_raw_data,
                "foa_end": s.pointer_to_raw_data + s.size_of_raw_data,
                "virtual_size": s.virtual_size,
                "raw_size": s.size_of_raw_data,
                "file_backed": min(vs, s.size_of_raw_data),
                "file_slack": max(0, s.size_of_raw_data - vs),
                "zero_fill": max(0, vs - s.size_of_raw_data),
                "align_pad": mem_end - (s.virtual_address + vs),
                "executable": s.is_executable,
                "readable": bool(s.characteristics & MEM_READ),
                "writable": bool(s.characteristics & MEM_WRITE),
            })
        return rows

    def map_rva(self, rva: int) -> dict[str, Any]:
        """判断某个 RVA 在文件/内存里的归属，返回 kind + 证据说明。

        kind 取值见模块常量 MAP_*；`foa` 仅当 kind=file/headers 时非 None。
        """
        if rva < 0:
            return {"rva": rva, "kind": "invalid", "section": None, "foa": None,
                    "detail": "非法 RVA（负数）"}
        if rva < self.size_of_headers:
            return {"rva": rva, "kind": MAP_HEADERS, "section": None, "foa": rva,
                    "detail": f"RVA 0x{rva:X} < SizeOfHeaders=0x{self.size_of_headers:X}，头部按 1:1 映射"}
        if rva >= self.size_of_image:
            return {"rva": rva, "kind": MAP_BEYOND, "section": None, "foa": None,
                    "detail": f"RVA 0x{rva:X} >= SizeOfImage=0x{self.size_of_image:X}，loader 不会映射"}

        for s in self.sections:
            vs = effective_vsize(s)
            start = s.virtual_address
            end = align_up(start + vs, self.section_alignment)
            if not (start <= rva < end):
                continue
            off = rva - start
            backed = min(vs, s.size_of_raw_data)
            if off < backed:
                foa = s.pointer_to_raw_data + off
                return {"rva": rva, "kind": MAP_FILE, "section": s.name, "foa": foa,
                        "detail": f"节 {s.name} 内偏移 0x{off:X} < 文件长度 0x{backed:X}，"
                                  f"FOA=0x{foa:X}"}
            if off < vs:
                return {"rva": rva, "kind": MAP_ZERO, "section": s.name, "foa": None,
                        "detail": f"节 {s.name} 内偏移 0x{off:X} 在 "
                                  f"[RawSize=0x{s.size_of_raw_data:X}, VirtualSize=0x{vs:X})，"
                                  f"内存补零、文件里没有"}
            if off < s.size_of_raw_data:
                foa = s.pointer_to_raw_data + off
                return {"rva": rva, "kind": MAP_SLACK, "section": s.name, "foa": None,
                        "detail": f"节 {s.name} 内偏移 0x{off:X} >= VirtualSize=0x{vs:X}，"
                                  f"文件字节在 FOA=0x{foa:X} 但不被映射"}
            return {"rva": rva, "kind": MAP_PAD, "section": s.name, "foa": None,
                    "detail": f"节 {s.name} 末尾对齐填充 0x{off:X}（VirtualSize=0x{vs:X}，"
                              f"SectionAlignment=0x{self.section_alignment:X}），loader 补零"}

        return {"rva": rva, "kind": MAP_GAP, "section": None, "foa": None,
                "detail": f"RVA 0x{rva:X} 在 SizeOfImage 内但不属于任何节"}

    def loader_notes(self) -> list[str]:
        """加载器视角的不一致项：文件有/内存无、截断、未对齐、重叠、入口不在代码节。"""
        notes: list[str] = []
        size = len(self.data)
        for s in self.sections:
            vs = effective_vsize(s)
            if s.pointer_to_raw_data + s.size_of_raw_data > size and s.size_of_raw_data:
                notes.append(
                    f"节 {s.name} 原始数据越界：FOA 0x{s.pointer_to_raw_data:X}+0x{s.size_of_raw_data:X} "
                    f"> 文件 0x{size:X}（文件被截断，loader 会补零）")
            if s.size_of_raw_data > vs:
                notes.append(
                    f"节 {s.name} 文件多出 0x{s.size_of_raw_data - vs:X} 字节（RawSize > VirtualSize），"
                    f"这些字节不会被映射")
            if vs > s.size_of_raw_data:
                notes.append(
                    f"节 {s.name} 内存补零 0x{vs - s.size_of_raw_data:X} 字节（VirtualSize > RawSize）")
            if self.section_alignment and s.virtual_address % self.section_alignment:
                notes.append(
                    f"节 {s.name} VA 0x{s.virtual_address:X} 未按 SectionAlignment=0x{self.section_alignment:X} "
                    f"对齐，loader 会向下取整")
            if s.pointer_to_raw_data and self.file_alignment and \
                    s.pointer_to_raw_data % self.file_alignment:
                notes.append(
                    f"节 {s.name} RawPtr 0x{s.pointer_to_raw_data:X} 未按 "
                    f"FileAlignment=0x{self.file_alignment:X} 对齐")
        spans = sorted((s.virtual_address, effective_vsize(s), s.name) for s in self.sections)
        for (a_start, a_size, a_name), (b_start, _b_size, b_name) in zip(spans, spans[1:]):
            if a_start + a_size > b_start:
                notes.append(f"节 {a_name} 与 {b_name} 的 RVA 区间重叠")
        last_end = max((s.virtual_address + effective_vsize(s) for s in self.sections), default=0)
        if self.size_of_image < last_end:
            notes.append(
                f"SizeOfImage=0x{self.size_of_image:X} 小于末节结束 0x{last_end:X}，镜像会被截断")
        if self.entry_rva:
            s = self.section_of_rva(self.entry_rva)
            if s is not None and not s.is_executable:
                notes.append(f"入口 RVA 0x{self.entry_rva:X} 落在不可执行节 {s.name}")
        return notes

    def format_map(self, probes: list[int] | None = None) -> dict[str, Any]:
        """map 命令的完整载荷：节表对照 + loader 提示 + RVA 探针。"""
        return {
            "file": self.path,
            "format": self.pe_format,
            "arch": self.arch,
            "image_base": f"0x{self.image_base:X}",
            "size_of_image": f"0x{self.size_of_image:X}",
            "size_of_headers": f"0x{self.size_of_headers:X}",
            "section_alignment": f"0x{self.section_alignment:X}",
            "file_alignment": f"0x{self.file_alignment:X}",
            "sections": [
                {**row,
                 "rva": f"0x{row['rva_start']:X}-0x{row['rva_end']:X}",
                 "foa": f"0x{row['foa_start']:X}-0x{row['foa_end']:X}"}
                for row in self.section_map()
            ],
            "notes": self.loader_notes(),
            "probes": [self.map_rva(r) for r in (probes or [])],
        }

    # ---------- 导入 / 导出 ----------
    def imports(self) -> list[Import]:
        if len(self.directories) < 2:
            return []
        rva, size = self.directories[1]
        if not rva:
            return []
        out: list[Import] = []
        desc_foa = self.rva_to_foa(rva)
        if desc_foa is None:
            return []
        thunk_size = 8 if self.is_64 else 4
        ord_flag = 1 << (63 if self.is_64 else 31)
        for i in range(4096):
            off = desc_foa + i * 20
            oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", self.data, off) \
                if off + 20 <= len(self.data) else (0, 0, 0, 0, 0)
            if not (oft or name_rva or ft):
                break
            name_foa = self.rva_to_foa(name_rva)
            dll = self.r.cstr(name_foa) if name_foa is not None else f"<rva:0x{name_rva:X}>"
            thunk_rva = oft or ft
            thunk_foa = self.rva_to_foa(thunk_rva)
            if thunk_foa is None:
                continue
            for j in range(65536):
                t_off = thunk_foa + j * thunk_size
                if t_off + thunk_size > len(self.data):
                    break
                val = struct.unpack_from("<Q" if self.is_64 else "<I", self.data, t_off)[0]
                if val == 0:
                    break
                if val & ord_flag:
                    out.append(Import(dll=dll, name=None, ordinal=val & 0xFFFF,
                                      iat_rva=ft + j * thunk_size, descriptor_offset=off))
                else:
                    hn_foa = self.rva_to_foa(val & 0x7FFFFFFF)
                    fname = self.r.cstr(hn_foa + 2) if hn_foa is not None else None
                    out.append(Import(dll=dll, name=fname, ordinal=None,
                                      iat_rva=ft + j * thunk_size, descriptor_offset=off))
        return out

    def exports(self) -> list[Export]:
        if not self.directories:
            return []
        rva, size = self.directories[0]
        if not rva or not size:
            return []
        foa = self.rva_to_foa(rva)
        if foa is None:
            return []
        try:
            base_ord = self.r.u32(foa + 16)
            n_funcs = self.r.u32(foa + 20)
            n_names = self.r.u32(foa + 24)
            a_funcs = self.rva_to_foa(self.r.u32(foa + 28))
            a_names = self.rva_to_foa(self.r.u32(foa + 32))
            a_ords = self.rva_to_foa(self.r.u32(foa + 36))
        except PEError:
            return []
        if a_funcs is None:
            return []
        out: list[Export] = []
        for i in range(min(n_funcs, 65536)):
            try:
                frva = self.r.u32(a_funcs + i * 4)
            except PEError:
                break
            if not frva:
                continue
            out.append(Export(name=None, ordinal=base_ord + i, rva=frva))
        if a_names and a_ords:
            for i in range(min(n_names, 65536)):
                try:
                    nrva = self.r.u32(a_names + i * 4)
                    ord_idx = self.r.u16(a_ords + i * 2)
                    nfoa = self.rva_to_foa(nrva)
                    name = self.r.cstr(nfoa) if nfoa is not None else None
                except PEError:
                    break
                if 0 <= ord_idx < len(out):
                    out[ord_idx].name = name
        return out

    # ---------- 摘要 ----------
    @property
    def arch(self) -> str:
        return MACHINES.get(self.machine, f"0x{self.machine:04X}")

    @property
    def entry_section(self) -> str:
        s = self.section_of_rva(self.entry_rva)
        return s.name if s else "?"

    def summary(self) -> dict[str, Any]:
        imports = self.imports()
        return {
            "file": self.path,
            "size": len(self.data),
            "sha256": self.sha256,
            "format": self.pe_format,
            "arch": self.arch,
            "subsystem": SUBSYSTEMS.get(self.subsystem, str(self.subsystem)),
            "image_base": f"0x{self.image_base:X}",
            "entry_rva": f"0x{self.entry_rva:X}",
            "entry_section": self.entry_section,
            "size_of_image": f"0x{self.size_of_image:X}",
            "sections": [s.as_dict for s in self.sections],
            "imports": len(imports),
            "dlls": len({i.dll for i in imports}),
            "exports": len(self.exports()),
            "max_entropy": round(max((s.entropy for s in self.sections), default=0.0), 3),
        }
