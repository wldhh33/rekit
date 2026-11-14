# -*- coding: utf-8 -*-
"""rekit.core.dotnet_il —— 只读 .NET IL / 堆 / 资源事实提取。

范围：
    PE 数据目录 #14 → COR20 头 → 元数据根 `BSJB` → `#~`/`#-` 表流 →
    `#Strings` / `#US` / `#Blob` 堆 → MethodDef 方法体 → IL 字节 →
    异常处理（EH）子句 → ManifestResource 清单 → 自定义属性（TargetFramework 等）。

不做的事：
    不反编译、不还原控制流、不判工具链家族、不参与 `identify` 的
    `family` / `verdict` / `confidence`，也不改 `signals-v1` / `m4b-signals-v1`。

结论口径：
    本模块只输出**结构事实**与**调用点计数**。`capability_hits` 是静态调用点
    聚合，用于取证索引，不是行为判断；真正的“这个程序做什么”仍由人写。
"""

from __future__ import annotations

import math
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from .dotnet import (
    T_ASSEMBLY, T_ASSEMBLYREF, T_CUSTOMATTRIBUTE, T_IMPLMAP,
    T_MANIFESTRESOURCE, T_MEMBERREF, T_METHODDEF, T_METHODSPEC, T_MODULEREF,
    T_NESTEDCLASS, T_TYPEDEF, T_TYPEREF, T_TYPESPEC,
    TABLES, DotnetError, _index_size, _row_size,
)
from .pe import PE

CLR_DIRECTORY_INDEX = 14
BSJB = b"BSJB"

# 单字节 IL 操作码的操作数字节数；未列出的按 0 处理。
OPERANDS: dict[int, int] = {
    0x0E: 1, 0x0F: 1, 0x10: 1, 0x11: 1, 0x12: 1, 0x13: 1,
    0x1F: 1, 0x20: 4, 0x21: 8, 0x22: 4, 0x23: 8,
    0x27: 4, 0x28: 4, 0x29: 4,
    0x2B: 1, 0x2C: 1, 0x2D: 1, 0x2E: 1, 0x2F: 1, 0x30: 1, 0x31: 1,
    0x32: 1, 0x33: 1, 0x34: 1, 0x35: 1, 0x36: 1, 0x37: 1,
    0x38: 4, 0x39: 4, 0x3A: 4, 0x3B: 4, 0x3C: 4, 0x3D: 4, 0x3E: 4,
    0x3F: 4, 0x40: 4, 0x41: 4, 0x42: 4, 0x43: 4, 0x44: 4,
    0x6F: 4, 0x70: 4, 0x71: 4, 0x72: 4, 0x73: 4, 0x74: 4, 0x75: 4,
    0x79: 4, 0x7B: 4, 0x7C: 4, 0x7D: 4, 0x7E: 4, 0x7F: 4, 0x80: 4, 0x81: 4,
    0x8C: 4, 0x8D: 4, 0x8F: 4, 0xA3: 4, 0xA4: 4, 0xA5: 4,
    0xC2: 4, 0xC6: 4, 0xD0: 4, 0xDD: 4, 0xDE: 1,
}
OPERANDS_FE: dict[int, int] = {
    0x06: 4, 0x07: 4, 0x09: 2, 0x0A: 2, 0x0B: 2, 0x0C: 2, 0x0D: 2, 0x0E: 2,
    0x12: 1, 0x15: 4, 0x16: 4, 0x19: 1, 0x1C: 4,
}
CALL_OPS = {0x28, 0x6F, 0x73}
NO_OPERAND = frozenset({
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
    0x1E, 0x24, 0x25, 0x26, 0x2A, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
    0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x76, 0x7A,
    0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8E, 0x90,
    0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C,
    0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
    0xB9, 0xBA, 0xC3, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9,
    0xDA, 0xDB, 0xDC, 0xDF, 0xE0,
})

STRING_ATTRS = {
    "System.Runtime.Versioning.TargetFrameworkAttribute",
    "System.Reflection.AssemblyTitleAttribute",
    "System.Reflection.AssemblyDescriptionAttribute",
    "System.Reflection.AssemblyCompanyAttribute",
    "System.Reflection.AssemblyProductAttribute",
    "System.Reflection.AssemblyCopyrightAttribute",
    "System.Reflection.AssemblyInformationalVersionAttribute",
    "System.Reflection.AssemblyFileVersionAttribute",
    "System.Reflection.AssemblyVersionAttribute",
    "System.Runtime.CompilerServices.InternalsVisibleToAttribute",
    "System.Resources.NeutralResourcesLanguageAttribute",
}
OBFUSCATION_ATTRS = (
    "System.Reflection.ObfuscationAttribute",
    "System.Reflection.ObfuscateAssemblyAttribute",
    "System.Runtime.CompilerServices.SuppressIldasmAttribute",
)

# 仅用于取证索引的静态调用点分类，不构成行为判断。
CAPABILITY_RULES: dict[str, tuple[str, ...]] = {
    "进程/命令执行": ("Process::Start", "ProcessStartInfo", "ShellExecute", "CreateProcess", "WinExec"),
    "网络访问": ("HttpClient", "WebClient", "WebRequest", "Socket", "Dns::", "TcpClient", "UdpClient", "SmtpClient"),
    "文件读写": ("System.IO.File::", "FileStream", "StreamWriter", "StreamReader", "Directory::", "FileInfo", "DirectoryInfo"),
    "注册表": ("Microsoft.Win32.Registry::", "Microsoft.Win32.RegistryKey", "RegistryHive"),
    "加密/哈希": ("System.Security.Cryptography", "SHA256", "Aes", "RSA", "MD5"),
    "调试器检测": ("Debugger::get_IsAttached", "IsDebuggerPresent", "CheckRemoteDebuggerPresent"),
    "进程注入": ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess", "NtUnmapViewOfSection"),
    "环境/主机信息": ("Environment::get_MachineName", "Environment::get_UserName", "Environment::GetEnvironmentVariable", "Environment::get_ProcessPath"),
    "本地 IPC": ("NamedPipeServerStream", "NamedPipeClientStream", "System.Threading.Mutex",
                 "OpenFileMapping", "CreateFileMapping"),
    "自动更新": ("updates.xml", "releases/tag", "UpdateService", "AppUpdateService"),
}


def _u8(d: Any, o: int) -> int:
    if o < 0 or o + 1 > len(d):
        raise DotnetError(f"读取越界：FOA=0x{o:X} size=1")
    return d[o]


def _u16(d: Any, o: int) -> int:
    if o < 0 or o + 2 > len(d):
        raise DotnetError(f"读取越界：FOA=0x{o:X} size=2")
    return struct.unpack_from("<H", d, o)[0]


def _u32(d: Any, o: int) -> int:
    if o < 0 or o + 4 > len(d):
        raise DotnetError(f"读取越界：FOA=0x{o:X} size=4")
    return struct.unpack_from("<I", d, o)[0]


def _u64(d: Any, o: int) -> int:
    if o < 0 or o + 8 > len(d):
        raise DotnetError(f"读取越界：FOA=0x{o:X} size=8")
    return struct.unpack_from("<Q", d, o)[0]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((v / n) * math.log2(v / n) for v in counts.values()), 3)


def compressed_uint(data: Any, off: int) -> tuple[int, int]:
    """ECMA-335 II.23.2 压缩无符号整数；返回 (值, 占用字节)。"""
    b = _u8(data, off)
    if b & 0x80 == 0:
        return b, 1
    if b & 0xC0 == 0x80:
        return ((b & 0x3F) << 8) | _u8(data, off + 1), 2
    if b & 0xE0 == 0xC0:
        return (((b & 0x1F) << 24) | (_u8(data, off + 1) << 16)
                | (_u8(data, off + 2) << 8) | _u8(data, off + 3)), 4
    raise DotnetError(f"非法压缩整数 0x{b:02X} @0x{off:X}")


def ser_string(blob: bytes, off: int = 0) -> tuple[str, int]:
    n, used = compressed_uint(blob, off)
    start = off + used
    if start + n > len(blob):
        raise DotnetError(f"SerString 越过 blob 末尾：@0x{off:X} len={n}")
    return blob[start:start + n].decode("utf-8", "replace"), start + n


class MetadataView:
    """CLI 元数据的只读视图：堆、表、类型/方法/成员引用解析。"""

    def __init__(self, pe: PE):
        self.pe = pe
        self.data = pe.data
        rva, size = pe.directories[CLR_DIRECTORY_INDEX]
        if size < 16:
            raise DotnetError(f"CLR 目录 Size={size}，小于 COR20 头最小长度")
        cor_foa = pe.rva_to_foa(rva)
        if cor_foa is None:
            raise DotnetError(f"CLR 目录 RVA=0x{rva:X} 无法映射到文件偏移")
        self.cor_foa = cor_foa
        d = self.data
        self.cor = {
            "cb": _u32(d, cor_foa),
            "metadata_rva": _u32(d, cor_foa + 8),
            "metadata_size": _u32(d, cor_foa + 12),
            "flags": _u32(d, cor_foa + 16),
            "entry_token": _u32(d, cor_foa + 20),
            "resources_rva": _u32(d, cor_foa + 24),
            "resources_size": _u32(d, cor_foa + 28),
            "strongname_rva": _u32(d, cor_foa + 32),
            "strongname_size": _u32(d, cor_foa + 36),
        }
        self.meta_foa = pe.rva_to_foa(self.cor["metadata_rva"])
        if self.meta_foa is None:
            raise DotnetError(f"元数据 RVA=0x{self.cor['metadata_rva']:X} 无法映射")
        if d[self.meta_foa:self.meta_foa + 4] != BSJB:
            raise DotnetError("元数据根不是 BSJB")
        ver_len = _u32(d, self.meta_foa + 12)
        if ver_len > 512:
            raise DotnetError(f"版本字符串长度异常：{ver_len}")
        self.version = bytes(d[self.meta_foa + 16:self.meta_foa + 16 + ver_len]) \
            .split(b"\x00", 1)[0].decode("ascii", "replace")
        self.metadata_flags = _u16(d, self.meta_foa + 16 + ver_len)
        n_streams = _u16(d, self.meta_foa + 18 + ver_len)

        self.streams: dict[str, tuple[int, int]] = {}
        pos = self.meta_foa + 20 + ver_len
        for _ in range(n_streams):
            off, length = _u32(d, pos), _u32(d, pos + 4)
            end = d.find(b"\x00", pos + 8, min(pos + 72, len(d)))
            if end < 0:
                raise DotnetError("流名未以 NUL 结尾")
            name = bytes(d[pos + 8:end]).decode("ascii", "replace")
            self.streams[name] = (self.meta_foa + off, length)
            pos = pos + 8 + ((end - (pos + 8) + 1 + 3) // 4) * 4

        self.tables_name = "#~" if "#~" in self.streams else "#-"
        toff, tsize = self.streams.get(self.tables_name, (0, 0))
        if not toff:
            raise DotnetError("没有 #~ / #- 表流")
        if tsize < 24 or toff + tsize > len(d):
            raise DotnetError(f"{self.tables_name} 流长度异常：{tsize}")
        self.heap_sizes = _u8(d, toff + 6)
        if self.heap_sizes & ~0x07:
            raise DotnetError(f"HeapSizes=0x{self.heap_sizes:X} 含保留位")
        valid = _u64(d, toff + 8)
        self.rows: dict[int, int] = {}
        p = toff + 24
        for t in range(64):
            if valid & (1 << t):
                self.rows[t] = _u32(d, p)
                p += 4
        self.table_base = p
        self.offsets: dict[int, int] = {}
        cur = 0
        for t in sorted(x for x in range(64) if self.rows.get(x)):
            self.offsets[t] = cur
            cur += _row_size(t, self.heap_sizes, self.rows) * self.rows[t]
        if self.table_base + cur > len(d):
            raise DotnetError("元数据表越过文件末尾")
        self.strings = self._heap("#Strings")
        self.us = self._heap("#US")
        self.blob = self._heap("#Blob")

    def _heap(self, name: str) -> bytes:
        off, size = self.streams.get(name, (0, 0))
        return bytes(self.data[off:off + size]) if size else b""

    def row_offset(self, table: int, row: int) -> int:
        if table not in self.offsets or row >= self.rows.get(table, 0):
            raise DotnetError(f"表 0x{table:02X} 行 {row} 不存在")
        return self.table_base + self.offsets[table] + row * _row_size(
            table, self.heap_sizes, self.rows)

    def cell(self, table: int, row: int, col: int) -> int:
        ro = self.row_offset(table, row)
        for i in range(col):
            ro += _index_size(TABLES[table][i], self.heap_sizes, self.rows)
        size = _index_size(TABLES[table][col], self.heap_sizes, self.rows)
        return _u32(self.data, ro) if size == 4 else _u16(self.data, ro)

    def string(self, idx: int) -> str:
        if not idx or idx >= len(self.strings):
            return ""
        end = self.strings.find(b"\x00", idx, min(idx + 4096, len(self.strings)))
        return self.strings[idx:end if end >= 0 else len(self.strings)] \
            .decode("utf-8", "replace")

    def blob_at(self, idx: int) -> bytes:
        if not idx or idx >= len(self.blob):
            return b""
        n, used = compressed_uint(self.blob, idx)
        return self.blob[idx + used:idx + used + n]

    def type_name(self, row: int) -> str:
        ns = self.string(self.cell(T_TYPEDEF, row, 2))
        name = self.string(self.cell(T_TYPEDEF, row, 1))
        return f"{ns}.{name}" if ns else name

    def typeref_name(self, row: int) -> str:
        ns = self.string(self.cell(T_TYPEREF, row, 2))
        name = self.string(self.cell(T_TYPEREF, row, 1))
        return f"{ns}.{name}" if ns else name

    def nested_map(self) -> dict[int, int]:
        out: dict[int, int] = {}
        for i in range(self.rows.get(T_NESTEDCLASS, 0)):
            out[self.cell(T_NESTEDCLASS, i, 0) - 1] = self.cell(T_NESTEDCLASS, i, 1) - 1
        return out

    def type_full_name(self, row: int, nested: dict[int, int] | None = None) -> str:
        nested = nested if nested is not None else self.nested_map()
        if row in nested:
            return (f"{self.type_full_name(nested[row], nested)}/"
                    f"{self.string(self.cell(T_TYPEDEF, row, 1))}")
        return self.type_name(row)

    def method_row_map(self) -> dict[int, str]:
        """MethodDef 行号(0 起) → 所属类型全名。TypeDef.MethodList 是 1 起。"""
        owner: dict[int, str] = {}
        total = self.rows.get(T_METHODDEF, 0)
        starts = sorted((self.cell(T_TYPEDEF, i, 5), i)
                        for i in range(self.rows.get(T_TYPEDEF, 0)))
        for n, (start, ti) in enumerate(starts):
            end = starts[n + 1][0] if n + 1 < len(starts) else total + 1
            for m in range(start, end):
                owner[m - 1] = self.type_name(ti)
        return owner

    def method_name(self, row: int) -> str:
        return self.string(self.cell(T_METHODDEF, row, 3))

    def method_full(self, row: int, owner: dict[int, str] | None = None) -> str:
        owner = owner or self.method_row_map()
        return f"{owner.get(row, '?')}::{self.method_name(row)}"

    def memberref_full(self, row: int) -> str:
        parent = self.cell(T_MEMBERREF, row, 0)
        tag, prow = parent & 7, parent >> 3
        if tag == 0:
            base = self.type_name(prow - 1)
        elif tag == 1:
            base = self.typeref_name(prow - 1)
        elif tag == 2:
            base = f"ModuleRef:{self.string(self.cell(T_MODULEREF, prow - 1, 0))}"
        elif tag == 3:
            base = f"MethodDef#{prow}"
        else:
            base = f"TypeSpec#{prow}"
        return f"{base}::{self.string(self.cell(T_MEMBERREF, row, 1))}"

    def token_name(self, token: int, owner: dict[int, str]) -> str:
        table, row = token >> 24, token & 0xFFFFFF
        if table == 0x06:
            return self.method_full(row - 1, owner)
        if table == 0x0A:
            return self.memberref_full(row - 1)
        if table == 0x2B:
            coded = self.cell(T_METHODSPEC, row - 1, 0)
            tag, mrow = coded & 1, coded >> 1
            return (self.method_full(mrow - 1, owner) if tag == 0
                    else self.memberref_full(mrow - 1)) + "<>"
        if table == 0x01:
            return self.typeref_name(row - 1)
        if table == 0x02:
            return self.type_name(row - 1)
        if table == 0x1B:
            return f"TypeSpec#{row}"
        return f"Table#{table:X}#{row}"

    def us_string(self, idx: int) -> str | None:
        """#US 偏移 → 字符串；长度含末尾终止字节（ECMA-335 II.24.2.4）。"""
        if idx <= 0 or idx >= len(self.us):
            return None
        try:
            n, used = compressed_uint(self.us, idx)
        except DotnetError:
            return None
        start = idx + used
        if n == 0 or start + n > len(self.us):
            return None
        raw = self.us[start:start + n]
        if raw.endswith(b"\x00"):
            raw = raw[:-1]
        return raw.decode("utf-16le", "replace")


@dataclass
class MethodBody:
    row: int
    name: str
    rva: int
    kind: str
    code_size: int = 0
    max_stack: int = 0
    local_sig: int = 0
    flags: int = 0
    eh_clauses: int = 0
    eh_invalid: list[str] = field(default_factory=list)
    il_start: int = 0


def decode_method_body(md: Any, row: int) -> MethodBody:
    """解析一个 MethodDef 的方法体头与 EH 段（ECMA-335 II.25.4）。"""
    rva = md.cell(T_METHODDEF, row, 0)
    name = md.method_name(row)
    if not rva:
        return MethodBody(row=row + 1, name=name, rva=0, kind="no_body")
    foa = md.pe.rva_to_foa(rva)
    if foa is None:
        return MethodBody(row=row + 1, name=name, rva=rva, kind="rva_unmapped")
    d = md.data
    b = _u8(d, foa)
    if b & 3 == 2:                       # tiny
        code_size, header, maxstack, local, flags = b >> 2, 1, 8, 0, 0
    elif b & 3 == 3:                     # fat
        flags_size = _u16(d, foa)
        flags, header = flags_size & 0x0FFF, (flags_size >> 12) * 4
        if header < 12:
            return MethodBody(row=row + 1, name=name, rva=rva, kind="bad_header")
        maxstack = _u16(d, foa + 2)
        code_size = _u32(d, foa + 4)
        local = _u32(d, foa + 8)
    else:
        return MethodBody(row=row + 1, name=name, rva=rva, kind="bad_header")

    start = foa + header
    end = start + code_size
    if end > len(d):
        return MethodBody(row=row + 1, name=name, rva=rva, kind="code_oob")
    body = MethodBody(row=row + 1, name=name, rva=rva,
                      kind="tiny" if header == 1 else "fat",
                      code_size=code_size, max_stack=maxstack,
                      local_sig=local, flags=flags, il_start=start)
    if flags & 0x08:
        p = (end + 3) & ~3
        if p + 4 > len(d):
            body.eh_invalid.append("EH 段头越界")
            return body
        kind = _u8(d, p)
        data_size = _u8(d, p + 1) | (_u8(d, p + 2) << 8) | (_u8(d, p + 3) << 16)
        # ECMA-335 II.25.4.6：DataSize 含 4 字节段头；0x40 才是 fat 子句。
        clause = 24 if kind & 0x40 else 12
        body_size = data_size - 4
        if p + data_size > len(d):
            body.eh_invalid.append("EH 段越过文件末尾")
        elif body_size < 0 or body_size % clause:
            body.eh_invalid.append(
                f"EH 数据 {data_size}（去头 {body_size}）不是 {clause} 的整数倍")
        else:
            body.eh_clauses = body_size // clause
            for i in range(body.eh_clauses):
                c = p + 4 + i * clause
                try:
                    if clause == 12:
                        # 小子句：Flags(2) TryOffset(2) TryLength(1)
                        #         HandlerOffset(2) HandlerLength(1) ClassToken(4)
                        tf, tl = _u16(d, c + 2), _u8(d, c + 4)
                        hf, hl = _u16(d, c + 5), _u8(d, c + 7)
                    else:
                        # 夫子句：Flags(4) TryOffset(4) TryLength(4)
                        #         HandlerOffset(4) HandlerLength(4) ClassToken(4)
                        tf, tl = _u32(d, c + 4), _u32(d, c + 8)
                        hf, hl = _u32(d, c + 12), _u32(d, c + 16)
                    for label, a, b2 in (("try", tf, tl), ("handler", hf, hl)):
                        if a + b2 > code_size:
                            body.eh_invalid.append(f"{label}[{i}] {a}+{b2}>{code_size}")
                except DotnetError:
                    body.eh_invalid.append(f"EH 子句 {i} 越界")
    return body


def scan_il(md: MetadataView, owner: dict[int, str]) -> dict[str, Any]:
    """逐方法走 IL 字节；只统计结构与调用点，不生成控制流。"""
    stats: dict[str, Any] = {
        "methods_total": md.rows.get(T_METHODDEF, 0),
        "with_body": 0, "no_body": 0, "il_bytes": 0, "max_code": 0,
        "eh_methods": 0, "eh_clauses": 0,
        "invalid": [], "unknown_opcode": [],
        "ldstr": 0, "calls": 0, "ldftn": 0,
        "callees": Counter(),
        "capability_hits": defaultdict(lambda: {"hits": 0, "samples": []}),
        "methods": [],
    }
    for row in range(md.rows.get(T_METHODDEF, 0)):
        body = decode_method_body(md, row)
        if body.kind == "no_body":
            stats["no_body"] += 1
            continue
        if body.kind in ("bad_header", "code_oob", "rva_unmapped"):
            stats["invalid"].append({"row": body.row, "name": body.name,
                                     "rva": f"0x{body.rva:X}", "kind": body.kind})
            continue
        stats["with_body"] += 1
        stats["il_bytes"] += body.code_size
        stats["max_code"] = max(stats["max_code"], body.code_size)
        if body.eh_clauses:
            stats["eh_methods"] += 1
            stats["eh_clauses"] += body.eh_clauses
        if body.eh_invalid:
            stats["invalid"].append({"row": body.row, "name": body.name,
                                     "eh": body.eh_invalid})
        code = md.data[body.il_start:body.il_start + body.code_size]
        pos, calls, strings = 0, 0, 0
        while pos < len(code):
            op = code[pos]
            if op == 0xFE:
                if pos + 1 >= len(code):
                    stats["unknown_opcode"].append({"row": body.row, "op": "FE(truncated)"})
                    break
                op2 = code[pos + 1]
                if op2 in (0x06, 0x07) and pos + 6 <= len(code):
                    tok = _u32(code, pos + 2)
                    stats["callees"][md.token_name(tok, owner)] += 1
                    stats["ldftn"] += 1
                pos += 2 + OPERANDS_FE.get(op2, 0)
                continue
            if op == 0x45:               # switch
                if pos + 5 > len(code):
                    stats["unknown_opcode"].append({"row": body.row, "op": "switch(truncated)"})
                    break
                pos += 5 + 4 * _u32(code, pos + 1)
                continue
            if op not in OPERANDS and op not in NO_OPERAND:
                stats["unknown_opcode"].append({"row": body.row, "op": f"0x{op:02X}", "at": pos})
                break
            operand = OPERANDS.get(op, 0)
            if op == 0x72:               # ldstr
                tok = _u32(code, pos + 1)
                if tok >> 24 == 0x70 and md.us_string(tok & 0xFFFFFF) is not None:
                    stats["ldstr"] += 1
                    strings += 1
            elif op in CALL_OPS:
                tok = _u32(code, pos + 1)
                stats["callees"][md.token_name(tok, owner)] += 1
                calls += 1
            pos += 1 + operand
        stats["calls"] += calls
        if pos != len(code):
            stats["invalid"].append({"row": body.row, "name": body.name,
                                     "reason": f"IL 解析停在 {pos}/{len(code)}"})
        stats["methods"].append({"row": body.row, "name": body.name,
                                 "code_size": body.code_size,
                                 "eh": body.eh_clauses, "calls": calls,
                                 "ldstr": strings, "il_start": f"0x{body.il_start:X}"})

    for callee, n in stats["callees"].items():
        for cap, needles in CAPABILITY_RULES.items():
            if any(x in callee for x in needles):
                stats["capability_hits"][cap]["hits"] += n
                if len(stats["capability_hits"][cap]["samples"]) < 8:
                    stats["capability_hits"][cap]["samples"].append(callee)
    stats["capability_hits"] = {k: dict(v) for k, v in stats["capability_hits"].items()}
    stats["callees"] = [{"name": k, "count": v} for k, v in stats["callees"].most_common(60)]
    stats["methods"] = sorted(stats["methods"], key=lambda x: x["code_size"],
                              reverse=True)[:50]
    return stats


def read_attributes(md: MetadataView, owner: dict[int, str]) -> dict[str, list[str]]:
    """读取字符串型自定义属性与混淆相关属性（保留原始 blob）。"""
    attrs: dict[str, list[str]] = defaultdict(list)
    for i in range(md.rows.get(T_CUSTOMATTRIBUTE, 0)):
        typ = md.cell(T_CUSTOMATTRIBUTE, i, 1)
        tag, row = typ & 7, typ >> 3
        if tag == 2:
            tname = owner.get(row - 1, "?")
        elif tag == 3:
            parent = md.cell(T_MEMBERREF, row - 1, 0)
            ptag, prow = parent & 7, parent >> 3
            if ptag == 0:
                tname = md.type_name(prow - 1)
            elif ptag == 1:
                tname = md.typeref_name(prow - 1)
            else:
                tname = f"MemberRefParent#{prow}"
        else:
            continue
        blob = md.blob_at(md.cell(T_CUSTOMATTRIBUTE, i, 2))
        if tname in STRING_ATTRS or tname == "System.Reflection.AssemblyMetadataAttribute":
            try:
                if tname == "System.Reflection.AssemblyMetadataAttribute":
                    k, p = ser_string(blob, 2)
                    v, _ = ser_string(blob, p)
                    attrs[tname].append(f"{k}={v}")
                elif len(blob) >= 2 and blob[:2] == b"\x01\x00":
                    val, _ = ser_string(blob, 2)
                    attrs[tname].append(val)
            except DotnetError:
                attrs[tname].append(f"<blob 解析失败 {blob[:24].hex()}>")
        elif tname in OBFUSCATION_ATTRS:
            attrs[tname].append(blob.hex())
    return attrs


@dataclass
class DotnetIlInfo:
    assembly_name: str | None = None
    assembly_version: str | None = None
    target_framework: str | None = None
    metadata_version: str = ""
    entry_point_token: int = 0
    type_count: int = 0
    method_count: int = 0
    non_ascii_types: list[str] = field(default_factory=list)
    duplicate_types: list[str] = field(default_factory=list)
    us_count: int = 0
    us_invalid: list[str] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    il: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, list[str]] = field(default_factory=dict)
    obfuscation_signals: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "assembly": self.assembly_name,
            "assembly_version": self.assembly_version,
            "target_framework": self.target_framework,
            "metadata_version": self.metadata_version,
            "entry_point_token": f"0x{self.entry_point_token:X}",
            "types": {"count": self.type_count,
                      "non_ascii": self.non_ascii_types[:50],
                      "duplicates": self.duplicate_types[:50]},
            "methods": {"count": self.method_count,
                        "with_body": self.il.get("with_body", 0),
                        "no_body": self.il.get("no_body", 0),
                        "invalid": len(self.il.get("invalid", []))},
            "il": self.il,
            "strings": {"us_count": self.us_count, "us_invalid": self.us_invalid},
            "resources": self.resources,
            "attributes": {k: v[:20] for k, v in self.attributes.items()},
            "obfuscation_signals": self.obfuscation_signals,
        }


def has_clr(pe: PE) -> bool:
    if len(pe.directories) <= CLR_DIRECTORY_INDEX:
        return False
    rva, size = pe.directories[CLR_DIRECTORY_INDEX]
    return bool(rva and size)


def scan(pe: PE) -> DotnetIlInfo | None:
    """解析一个托管程序集的 IL/堆/资源事实；非 .NET 返回 None，结构损坏抛 DotnetError。"""
    if not has_clr(pe):
        return None
    md = MetadataView(pe)
    owner = md.method_row_map()
    info = DotnetIlInfo(
        metadata_version=md.version,
        entry_point_token=md.cor["entry_token"],
        type_count=md.rows.get(T_TYPEDEF, 0),
        method_count=md.rows.get(T_METHODDEF, 0),
    )

    if md.rows.get(T_ASSEMBLY):
        info.assembly_name = md.string(md.cell(T_ASSEMBLY, 0, 7))
        info.assembly_version = ".".join(
            str(md.cell(T_ASSEMBLY, 0, c)) for c in (1, 2, 3, 4))

    nested = md.nested_map()
    names = [md.type_full_name(i, nested) for i in range(info.type_count)]
    info.non_ascii_types = [n for n in names
                            if any(ch > "\x7e" or ch < "\x20" for ch in n)]
    info.duplicate_types = [n for n, c in Counter(names).items() if c > 1]

    info.attributes = read_attributes(md, owner)
    tf = info.attributes.get("System.Runtime.Versioning.TargetFrameworkAttribute")
    info.target_framework = tf[0] if tf else None

    # #US：顺序走一遍，坏长度即停并记账。
    pos, bad = 1, []
    while pos < len(md.us):
        if md.us[pos] == 0:
            pos += 1
            continue
        try:
            n, used = compressed_uint(md.us, pos)
        except DotnetError as e:
            bad.append(f"off=0x{pos:X} {e}")
            break
        start = pos + used
        if n == 0 or start + n > len(md.us):
            bad.append(f"off=0x{pos:X} len={n}")
            break
        info.us_count += 1
        pos = start + n
    info.us_invalid = bad

    res_rva, res_size = md.cor["resources_rva"], md.cor["resources_size"]
    res_foa = pe.rva_to_foa(res_rva) if res_rva else None
    offsets = sorted((md.cell(T_MANIFESTRESOURCE, i, 0), i)
                     for i in range(md.rows.get(T_MANIFESTRESOURCE, 0)))
    for n, (off, i) in enumerate(offsets):
        name = md.string(md.cell(T_MANIFESTRESOURCE, i, 2))
        impl = md.cell(T_MANIFESTRESOURCE, i, 3)
        end = offsets[n + 1][0] if n + 1 < len(offsets) else res_size
        data = b""
        if impl == 0 and res_foa is not None and 0 <= off <= end <= res_size:
            data = bytes(pe.data[res_foa + off:res_foa + end])
        info.resources.append({
            "name": name, "offset": off, "size": end - off,
            "embedded": impl == 0, "entropy": entropy(data),
            "head_hex": data[:24].hex(),
        })

    info.il = scan_il(md, owner)

    signals = info.obfuscation_signals
    if md.tables_name == "#-":
        signals.append({"id": "uncompressed_tables", "detail": "元数据表流为 #-（ENC/编辑模式）"})
    if info.attributes.get("System.Runtime.CompilerServices.SuppressIldasmAttribute"):
        signals.append({"id": "suppress_ildasm", "detail": "存在 SuppressIldasmAttribute"})
    if (info.attributes.get("System.Reflection.ObfuscationAttribute")
            or info.attributes.get("System.Reflection.ObfuscateAssemblyAttribute")):
        signals.append({"id": "obfuscation_attribute", "detail": "存在混淆相关特性"})
    if info.non_ascii_types:
        signals.append({"id": "non_ascii_identifiers",
                        "detail": f"{len(info.non_ascii_types)} 个类型名含非 ASCII/控制字符"})
    if info.duplicate_types:
        signals.append({"id": "duplicate_type_names",
                        "detail": f"{len(info.duplicate_types)} 个重名类型"})
    if info.il.get("invalid"):
        signals.append({"id": "invalid_method_body",
                        "detail": f"{len(info.il['invalid'])} 个方法体结构异常"})
    if info.il.get("unknown_opcode"):
        signals.append({"id": "unknown_opcode",
                        "detail": f"{len(info.il['unknown_opcode'])} 处未知操作码"})
    return info


def analyze(path: str, allow_large: bool = False) -> DotnetIlInfo | None:
    with PE(path, allow_large=allow_large) as pe:
        return scan(pe)
