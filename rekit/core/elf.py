# -*- coding: utf-8 -*-
"""ELF 解析器（最小可用集）。

只提供 `funcs` 需要的字段：节表、可执行节、入口、`.dynsym` 导出、地址↔文件偏移。
与 `core.pe.PE` 保持同一套属性名（`image_base` / `entry_rva` / `sections` /
`rva_to_foa` / `exports`），这样 `core.funcs` 的发现逻辑不区分格式。

权威函数表不在这里：PE 是 `.pdata`，ELF64 是 `.eh_frame` / `.gopclntab`，
见 `core.funcs.authority_table`。
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

ELF_MAGIC = b"\x7fELF"

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

SHT_NOBITS = 8
SHT_DYNSYM = 11
SHT_SYMTAB = 2

STT_FUNC = 2
STT_GNU_IFUNC = 10

# e_machine → 可读名；只列本仓库会遇到的（x86 两代 + ARM 两代）
MACHINES = {
    0x03: "i386",
    0x28: "ARM",
    0x3E: "x86_64",
    0xB7: "aarch64",
    0xF3: "riscv",
}

ET_EXEC, ET_DYN = 2, 3


class ElfError(Exception):
    """ELF 结构错误（与 PEError 对等）。"""


@dataclass
class ElfSection:
    index: int
    name: str
    sh_type: int
    flags: int
    virtual_address: int
    offset: int
    size: int
    raw: bytes
    link: int = 0
    entsize: int = 0

    @property
    def is_executable(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)

    @property
    def is_alloc(self) -> bool:
        return bool(self.flags & SHF_ALLOC)

    @property
    def virtual_size(self) -> int:
        return self.size

    @property
    def size_of_raw_data(self) -> int:
        return len(self.raw)

    @property
    def pointer_to_raw_data(self) -> int:
        return self.offset


@dataclass
class ElfSymbol:
    name: str
    rva: int


class Elf:
    """一个 ELF 文件的结构视图；构造即完整解析（失败抛 `ElfError`）。"""

    is_pe = False
    format = "ELF"

    def __init__(self, path: str):
        self.path = str(path)
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            self.data = f.read()
        if len(self.data) < 64 or self.data[:4] != ELF_MAGIC:
            raise ElfError("不是 ELF 文件")
        ei_class, ei_data = self.data[4], self.data[5]
        if ei_class not in (1, 2):
            raise ElfError(f"未知 EI_CLASS={ei_class}")
        if ei_data != 1:
            raise ElfError("只支持小端 ELF")
        self.bits = 64 if ei_class == 2 else 32
        self.arch = f"ELF{self.bits}"
        self.image_base = 0
        self.size_of_headers = 0
        self.directories: list[tuple[int, int]] = [(0, 0)] * 16
        self.file_size = size

        if self.bits == 64:
            (self.etype, self.machine, _, self.entry_rva, _, shoff, _, _, _, _,
             shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", self.data, 16)
        else:
            (self.etype, self.machine, _, self.entry_rva, _, shoff, _, _, _, _,
             shentsize, shnum, shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", self.data, 16)
        self.machine_name = MACHINES.get(self.machine, f"0x{self.machine:04X}")
        if not shoff or not shentsize or not shnum:
            raise ElfError("没有节表（静态条带或非标准 ELF）")

        self._shdrs: list[tuple[int, int, int, int, int, int, int]] = []
        for i in range(shnum):
            off = shoff + i * shentsize
            if off + shentsize > len(self.data):
                break
            if self.bits == 64:
                nameoff, typ, flags, addr, offset, size, link, _info, _align, entsize = \
                    struct.unpack_from("<IIQQQQIIQQ", self.data, off)
            else:
                nameoff, typ, flags, addr, offset, size, link, _info, _align, entsize = \
                    struct.unpack_from("<IIIIIIIIII", self.data, off)
            self._shdrs.append((nameoff, typ, flags, addr, offset, size, link, entsize))

        names = b""
        if 0 < shstrndx < len(self._shdrs):
            _, _, _, _, noff, nsize, _, _ = self._shdrs[shstrndx]
            names = self.data[noff:noff + nsize]

        self.sections: list[ElfSection] = []
        for i, (nameoff, typ, flags, addr, offset, sec_size, link, entsize) in enumerate(
                self._shdrs):
            cut = names.find(b"\0", nameoff) if names else -1
            name = names[nameoff:cut].decode("utf-8", "replace") if cut >= 0 else ""
            raw = b"" if typ == SHT_NOBITS else self.data[offset:offset + sec_size]
            self.sections.append(ElfSection(
                i, name, typ, flags, addr, offset, sec_size, raw, link, entsize))

    # ---------- 与 PE 对齐的接口 ----------
    def section_of_rva(self, rva: int) -> ElfSection | None:
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.size, len(s.raw)):
                return s
        return None

    def section_by_name(self, name: str) -> ElfSection | None:
        return next((s for s in self.sections if s.name == name), None)

    def rva_to_foa(self, rva: int) -> int | None:
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.size, len(s.raw)):
                return s.offset + (rva - s.virtual_address)
        return None

    def iter_exec_sections(self) -> Iterator[ElfSection]:
        return (s for s in self.sections if s.is_executable and s.size_of_raw_data)

    def exports(self) -> list[ElfSymbol]:
        """`.dynsym` 的全局函数符号；只用于播种，不当作权威边界。"""
        out: list[ElfSymbol] = []
        dynsym = self.section_by_name(".dynsym")
        if dynsym is None or dynsym.sh_type != SHT_DYNSYM:
            return out
        dynstr = self.section_by_name(".dynstr") or (
            self.sections[dynsym.link] if dynsym.link < len(self.sections) else None)
        entsize = dynsym.entsize or (24 if self.bits == 64 else 16)
        for pos in range(dynsym.offset,
                         dynsym.offset + dynsym.size - entsize + 1, entsize):
            if self.bits == 64:
                st_name, st_info, _, st_shndx, st_value, _ = \
                    struct.unpack_from("<IBBHQQ", self.data, pos)
            else:
                st_name, st_value, _, st_info, _, st_shndx = \
                    struct.unpack_from("<IIIBBH", self.data, pos)
            if st_shndx == 0 or st_value == 0:
                continue
            if (st_info & 0xF) not in (STT_FUNC, STT_GNU_IFUNC):
                continue
            name = ""
            if dynstr is not None and st_name < len(dynstr.raw):
                cut = dynstr.raw.find(b"\0", st_name)
                name = dynstr.raw[st_name:cut if cut >= 0 else None].decode(
                    "utf-8", "replace")
            out.append(ElfSymbol(name, st_value))
        return out


def open_image(path: str | os.PathLike, allow_large: bool = False) -> Any:
    """按魔数分流：MZ → PE，\\x7fELF → ELF；其它直接拒绝，不猜。"""
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head[:2] == b"MZ":
        from .pe import PE
        return PE(str(path), allow_large=allow_large)
    if head == ELF_MAGIC:
        return Elf(str(path))
    raise ValueError(f"既不是 PE 也不是 ELF：{Path(path).name}")
