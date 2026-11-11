# -*- coding: utf-8 -*-
"""rekit.core.dotnet —— 纯标准库 .NET CLI 元数据解析（只读元数据，不反编译）。

范围（M5）：
    PE 数据目录 #14 (CLR_RUNTIME) → COR20 头 → 元数据根 `BSJB` →
    `#~` 表流 → 表行数与 TypeDef / MethodDef / AssemblyRef 名称。

不做的事：不读 IL 字节码、不还原控制流、不解析泛型签名含义。名字与计数只用于
报告正文；任何“这个程序集做什么”的判断仍由人写。

约束（长期，适用于后续里程碑）：
    本模块只产出结构事实，不参与工具链族判定，也不改 `signals-v1` / `m4b-signals-v1`。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from .pe import PE, PEError

CLR_DIRECTORY_INDEX = 14
BSJB = b"BSJB"

# ---------------------------------------------------------------------------
# 元数据表编号与列定义（ECMA-335 II.22）
# ---------------------------------------------------------------------------

T_MODULE, T_TYPEREF, T_TYPEDEF = 0x00, 0x01, 0x02
T_FIELDPTR, T_FIELD, T_METHODPTR, T_METHODDEF = 0x03, 0x04, 0x05, 0x06
T_PARAMPTR, T_PARAM, T_INTERFACEIMPL = 0x07, 0x08, 0x09
T_MEMBERREF, T_CONSTANT, T_CUSTOMATTRIBUTE = 0x0A, 0x0B, 0x0C
T_FIELDMARSHAL, T_DECLSECURITY, T_CLASSLAYOUT = 0x0D, 0x0E, 0x0F
T_FIELDLAYOUT, T_STANDALONESIG, T_EVENTMAP = 0x10, 0x11, 0x12
T_EVENTPTR, T_EVENT, T_PROPERTYMAP = 0x13, 0x14, 0x15
T_PROPERTYPTR, T_PROPERTY, T_METHODSEMANTICS = 0x16, 0x17, 0x18
T_METHODIMPL, T_MODULEREF, T_TYPESPEC = 0x19, 0x1A, 0x1B
T_IMPLMAP, T_FIELDRVA, T_ENCLOG = 0x1C, 0x1D, 0x1E
T_ENCMAP, T_ASSEMBLY, T_ASSEMBLYPROCESSOR = 0x1F, 0x20, 0x21
T_ASSEMBLYOS, T_ASSEMBLYREF, T_ASSEMBLYREFPROCESSOR = 0x22, 0x23, 0x24
T_ASSEMBLYREFOS, T_FILE, T_EXPORTEDTYPE = 0x25, 0x26, 0x27
T_MANIFESTRESOURCE, T_NESTEDCLASS, T_GENERICPARAM = 0x28, 0x29, 0x2A
T_METHODSPEC, T_GENERICPARAMCONSTRAINT = 0x2B, 0x2C

TABLE_NAMES = {
    T_MODULE: "Module", T_TYPEREF: "TypeRef", T_TYPEDEF: "TypeDef",
    T_FIELDPTR: "FieldPtr", T_FIELD: "Field", T_METHODPTR: "MethodPtr",
    T_METHODDEF: "MethodDef", T_PARAMPTR: "ParamPtr", T_PARAM: "Param",
    T_INTERFACEIMPL: "InterfaceImpl", T_MEMBERREF: "MemberRef",
    T_CONSTANT: "Constant", T_CUSTOMATTRIBUTE: "CustomAttribute",
    T_FIELDMARSHAL: "FieldMarshal", T_DECLSECURITY: "DeclSecurity",
    T_CLASSLAYOUT: "ClassLayout", T_FIELDLAYOUT: "FieldLayout",
    T_STANDALONESIG: "StandAloneSig", T_EVENTMAP: "EventMap", T_EVENTPTR: "EventPtr",
    T_EVENT: "Event", T_PROPERTYMAP: "PropertyMap", T_PROPERTYPTR: "PropertyPtr",
    T_PROPERTY: "Property", T_METHODSEMANTICS: "MethodSemantics",
    T_METHODIMPL: "MethodImpl", T_MODULEREF: "ModuleRef", T_TYPESPEC: "TypeSpec",
    T_IMPLMAP: "ImplMap", T_FIELDRVA: "FieldRVA", T_ENCLOG: "ENCLog",
    T_ENCMAP: "ENCMap", T_ASSEMBLY: "Assembly", T_ASSEMBLYPROCESSOR: "AssemblyProcessor",
    T_ASSEMBLYOS: "AssemblyOS", T_ASSEMBLYREF: "AssemblyRef",
    T_ASSEMBLYREFPROCESSOR: "AssemblyRefProcessor", T_ASSEMBLYREFOS: "AssemblyRefOS",
    T_FILE: "File", T_EXPORTEDTYPE: "ExportedType",
    T_MANIFESTRESOURCE: "ManifestResource", T_NESTEDCLASS: "NestedClass",
    T_GENERICPARAM: "GenericParam", T_METHODSPEC: "MethodSpec",
    T_GENERICPARAMCONSTRAINT: "GenericParamConstraint",
}

# 列类型：u1/u2/u4 = 定长；string/guid/blob = 堆索引；其余为编码索引名。
TABLES: dict[int, tuple[Any, ...]] = {
    T_MODULE: ("u2", "string", "guid", "guid", "guid"),
    T_TYPEREF: ("ResolutionScope", "string", "string"),
    T_TYPEDEF: ("u4", "string", "string", "TypeDefOrRef", "Field", "MethodDef"),
    T_FIELDPTR: ("Field",),
    T_FIELD: ("u2", "string", "blob"),
    T_METHODPTR: ("MethodDef",),
    T_METHODDEF: ("u4", "u2", "u2", "string", "blob", "Param"),
    T_PARAMPTR: ("Param",),
    T_PARAM: ("u2", "u2", "string"),
    T_INTERFACEIMPL: ("TypeDef", "TypeDefOrRef"),
    T_MEMBERREF: ("MemberRefParent", "string", "blob"),
    T_CONSTANT: ("u2", "HasConstant", "blob"),
    T_CUSTOMATTRIBUTE: ("HasCustomAttribute", "CustomAttributeType", "blob"),
    T_FIELDMARSHAL: ("HasFieldMarshal", "blob"),
    T_DECLSECURITY: ("u2", "HasDeclSecurity", "blob"),
    T_CLASSLAYOUT: ("u2", "u4", "TypeDef"),
    T_FIELDLAYOUT: ("u4", "Field"),
    T_STANDALONESIG: ("blob",),
    T_EVENTMAP: ("TypeDef", "Event"),
    T_EVENTPTR: ("Event",),
    T_EVENT: ("u2", "string", "TypeDefOrRef"),
    T_PROPERTYMAP: ("TypeDef", "Property"),
    T_PROPERTYPTR: ("Property",),
    T_PROPERTY: ("u2", "string", "blob"),
    T_METHODSEMANTICS: ("u2", "MethodDef", "HasSemantics"),
    T_METHODIMPL: ("TypeDef", "MethodDefOrRef", "MethodDefOrRef"),
    T_MODULEREF: ("string",),
    T_TYPESPEC: ("blob",),
    T_IMPLMAP: ("u2", "MemberForwarded", "string", "ModuleRef"),
    T_FIELDRVA: ("u4", "Field"),
    T_ENCLOG: ("u4", "u4"),
    T_ENCMAP: ("u4",),
    T_ASSEMBLY: ("u4", "u2", "u2", "u2", "u2", "u4", "blob", "string", "string"),
    T_ASSEMBLYPROCESSOR: ("u4",),
    T_ASSEMBLYOS: ("u4", "u4", "u4"),
    T_ASSEMBLYREF: ("u2", "u2", "u2", "u2", "u4", "blob", "string", "string", "blob"),
    T_ASSEMBLYREFPROCESSOR: ("u4", "AssemblyRef"),
    T_ASSEMBLYREFOS: ("u4", "u4", "u4", "AssemblyRef"),
    T_FILE: ("u4", "string", "blob"),
    T_EXPORTEDTYPE: ("u4", "u4", "string", "string", "Implementation"),
    T_MANIFESTRESOURCE: ("u4", "u4", "string", "Implementation"),
    T_NESTEDCLASS: ("TypeDef", "TypeDef"),
    T_GENERICPARAM: ("u2", "u2", "TypeOrMethodDef", "string"),
    T_METHODSPEC: ("MethodDefOrRef", "blob"),
    T_GENERICPARAMCONSTRAINT: ("GenericParam", "TypeDefOrRef"),
}

# 编码索引：tag 位数 + 可引用的表。
CODED: dict[str, tuple[int, tuple[int, ...]]] = {
    "TypeDefOrRef": (2, (T_TYPEDEF, T_TYPEREF, T_TYPESPEC)),
    "HasConstant": (2, (T_FIELD, T_PARAM, T_PROPERTY)),
    "HasCustomAttribute": (5, (T_METHODDEF, T_FIELD, T_TYPEREF, T_TYPEDEF, T_PARAM,
                               T_INTERFACEIMPL, T_MEMBERREF, T_MODULE, T_DECLSECURITY,
                               T_PROPERTY, T_EVENT, T_STANDALONESIG, T_MODULEREF,
                               T_TYPESPEC, T_ASSEMBLY, T_ASSEMBLYREF, T_FILE,
                               T_EXPORTEDTYPE, T_MANIFESTRESOURCE, T_GENERICPARAM,
                               T_GENERICPARAMCONSTRAINT, T_METHODSPEC)),
    "HasFieldMarshal": (1, (T_FIELD, T_PARAM)),
    "HasDeclSecurity": (2, (T_TYPEDEF, T_METHODDEF, T_ASSEMBLY)),
    "MemberRefParent": (3, (T_TYPEDEF, T_TYPEREF, T_MODULEREF, T_METHODDEF, T_TYPESPEC)),
    "HasSemantics": (1, (T_EVENT, T_PROPERTY)),
    "MethodDefOrRef": (1, (T_METHODDEF, T_MEMBERREF)),
    "MemberForwarded": (1, (T_FIELD, T_METHODDEF)),
    "Implementation": (2, (T_FILE, T_ASSEMBLYREF, T_EXPORTEDTYPE)),
    # ECMA-335：CustomAttributeType 只用 tag 2 (MethodDef) 与 3 (MemberRef)，
    # 但编码宽度仍按 3 位计算。
    "CustomAttributeType": (3, (T_METHODDEF, T_MEMBERREF)),
    "ResolutionScope": (2, (T_MODULE, T_MODULEREF, T_ASSEMBLYREF, T_TYPEREF)),
    "TypeOrMethodDef": (1, (T_TYPEDEF, T_METHODDEF)),
    "TypeDef": (None, (T_TYPEDEF,)),
    "Field": (None, (T_FIELD,)),
    "MethodDef": (None, (T_METHODDEF,)),
    "Param": (None, (T_PARAM,)),
    "Event": (None, (T_EVENT,)),
    "Property": (None, (T_PROPERTY,)),
    "ModuleRef": (None, (T_MODULEREF,)),
    "AssemblyRef": (None, (T_ASSEMBLYREF,)),
    "GenericParam": (None, (T_GENERICPARAM,)),
}


class DotnetError(PEError):
    """元数据结构不完整/越界。调用方应把它当成“不是可解析的 .NET 程序集”。"""


@dataclass
class DotnetInfo:
    metadata_rva: int
    metadata_size: int
    metadata_offset: int
    version_string: str
    flags: int
    entry_point_token: int
    streams: dict[str, tuple[int, int]] = field(default_factory=dict)
    rows: dict[str, int] = field(default_factory=dict)
    type_defs: list[str] = field(default_factory=list)
    method_defs: list[tuple[str, int]] = field(default_factory=list)
    assembly_name: str | None = None
    assembly_refs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def type_def_count(self) -> int:
        return self.rows.get("TypeDef", len(self.type_defs))

    @property
    def method_def_count(self) -> int:
        return self.rows.get("MethodDef", len(self.method_defs))

    def as_dict(self) -> dict[str, Any]:
        return {
            "metadata_rva": f"0x{self.metadata_rva:X}",
            "metadata_size": self.metadata_size,
            "metadata_offset": f"0x{self.metadata_offset:X}",
            "version_string": self.version_string,
            "flags": f"0x{self.flags:X}",
            "entry_point_token": f"0x{self.entry_point_token:X}",
            "streams": sorted(self.streams),
            "rows": dict(sorted(self.rows.items())),
            "type_def_count": self.type_def_count,
            "type_defs": self.type_defs,
            "method_def_count": self.method_def_count,
            "method_defs": [{"name": n, "rva": f"0x{r:X}"}
                            for n, r in self.method_defs],
            "assembly_name": self.assembly_name,
            "assembly_refs": self.assembly_refs,
            "notes": self.notes,
        }


def _u8(data: Any, off: int) -> int:
    if off < 0 or off + 1 > len(data):
        raise DotnetError(f"读取越界：FOA=0x{off:X} size=1")
    return data[off]


def _u16(data: Any, off: int) -> int:
    if off < 0 or off + 2 > len(data):
        raise DotnetError(f"读取越界：FOA=0x{off:X} size=2")
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: Any, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise DotnetError(f"读取越界：FOA=0x{off:X} size=4")
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: Any, off: int) -> int:
    if off < 0 or off + 8 > len(data):
        raise DotnetError(f"读取越界：FOA=0x{off:X} size=8")
    return struct.unpack_from("<Q", data, off)[0]


def _cstring(data: Any, off: int, limit: int = 4096) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, min(off + limit, len(data)))
    if end < 0:
        end = min(off + limit, len(data))
    return bytes(data[off:end]).decode("utf-8", "replace")


def _index_size(column: str, heap_sizes: int, rows: dict[int, int]) -> int:
    """一列的字节宽度：堆索引看 HeapSizes 位，编码索引看最大行数。"""
    if column in ("string", "guid", "blob"):
        bit = {"string": 0, "guid": 1, "blob": 2}[column]
        return 4 if heap_sizes & (1 << bit) else 2
    if column == "u1":
        return 1
    if column == "u2":
        return 2
    if column == "u4":
        return 4
    spec = CODED.get(column)
    if spec is None:
        raise DotnetError(f"未知列类型 {column}")
    tag_bits, tables = spec
    if tag_bits is None:      # 普通表索引
        return 2 if rows.get(tables[0], 0) < (1 << 16) else 4
    limit = 1 << (16 - tag_bits)
    return 2 if max(rows.get(t, 0) for t in tables) < limit else 4


def _row_size(table: int, heap_sizes: int, rows: dict[int, int]) -> int:
    try:
        columns = TABLES[table]
    except KeyError as e:  # pragma: no cover - 只会在遇到未定义表时触发
        raise DotnetError(f"未定义元数据表 0x{table:02X}") from e
    return sum(_index_size(c, heap_sizes, rows) for c in columns)


def _read_index(data: Any, off: int, size: int) -> int:
    return _u32(data, off) if size == 4 else _u16(data, off)


def _table_layout(data: Any, table_base: int, heap_sizes: int,
                  rows: dict[int, int]) -> tuple[dict[int, int], int]:
    """算出每张表的起始偏移（相对 `#~` 表数据起点）。只处理有效位里的表。"""
    offsets: dict[int, int] = {}
    cur = 0
    for table in sorted(t for t in range(64) if rows.get(t)):
        offsets[table] = cur
        cur += _row_size(table, heap_sizes, rows) * rows[table]
    if table_base + cur > len(data):
        raise DotnetError(f"表数据越过流末尾：需要 {cur} 字节，"
                          f"剩余 {len(data) - table_base}")
    return offsets, cur


def _string(strings: Any, index: int) -> str:
    if index == 0:
        return ""
    if index >= len(strings):
        raise DotnetError(f"#Strings 索引越界：0x{index:X}")
    return _cstring(strings, index)


def _parse_tables(data: Any, stream_off: int, stream_size: int,
                  streams: dict[str, tuple[int, int]]) -> dict[str, Any]:
    base = stream_off
    heap_sizes = _u8(data, base + 6)
    valid = _u64(data, base + 8)
    if heap_sizes & ~0x07:
        raise DotnetError(f"HeapSizes=0x{heap_sizes:X} 含保留位")

    row_counts: dict[int, int] = {}
    pos = base + 24
    for table in range(64):
        if valid & (1 << table):
            row_counts[table] = _u32(data, pos)
            pos += 4
    table_base = pos

    offsets, _total = _table_layout(data, table_base, heap_sizes, row_counts)

    strings_off, strings_size = streams.get("#Strings", (0, 0))
    strings = bytes(data[strings_off:strings_off + strings_size]) if strings_size else b""

    def cell(table: int, row: int, column: int) -> int:
        row_off = table_base + offsets[table] + row * _row_size(table, heap_sizes, row_counts)
        size = _index_size(TABLES[table][column], heap_sizes, row_counts)
        for i in range(column):
            row_off += _index_size(TABLES[table][i], heap_sizes, row_counts)
        return _read_index(data, row_off, size)

    result: dict[str, Any] = {
        "rows": {TABLE_NAMES[t]: n for t, n in sorted(row_counts.items())},
        "type_defs": [],
        "method_defs": [],
        "assembly_name": None,
        "assembly_refs": [],
        "notes": [],
    }

    # TypeDef：Flags / TypeName / TypeNamespace / Extends / FieldList / MethodList
    for i in range(row_counts.get(T_TYPEDEF, 0)):
        name = _string(strings, cell(T_TYPEDEF, i, 1))
        ns = _string(strings, cell(T_TYPEDEF, i, 2))
        result["type_defs"].append(f"{ns}.{name}" if ns else name)

    # MethodDef：RVA / ImplFlags / Flags / Name / Signature / ParamList
    for i in range(row_counts.get(T_METHODDEF, 0)):
        rva = cell(T_METHODDEF, i, 0)
        name = _string(strings, cell(T_METHODDEF, i, 3))
        result["method_defs"].append((name, rva))

    # Assembly：HashAlgId / versions / Flags / PublicKey / Name / Culture
    if row_counts.get(T_ASSEMBLY):
        result["assembly_name"] = _string(strings, cell(T_ASSEMBLY, 0, 7))

    # AssemblyRef：versions / Flags / PublicKeyOrToken / Name / Culture / HashValue
    for i in range(row_counts.get(T_ASSEMBLYREF, 0)):
        major = cell(T_ASSEMBLYREF, i, 0)
        minor = cell(T_ASSEMBLYREF, i, 1)
        build = cell(T_ASSEMBLYREF, i, 2)
        rev = cell(T_ASSEMBLYREF, i, 3)
        name = _string(strings, cell(T_ASSEMBLYREF, i, 6))
        result["assembly_refs"].append(f"{name}, Version={major}.{minor}.{build}.{rev}")
    return result


def parse(pe: PE) -> DotnetInfo | None:
    """解析 CLI 元数据；不是 .NET 程序集返回 None，结构损坏抛 `DotnetError`。"""
    if len(pe.directories) <= CLR_DIRECTORY_INDEX:
        return None
    rva, size = pe.directories[CLR_DIRECTORY_INDEX]
    if not rva or not size:
        return None
    cor_foa = pe.rva_to_foa(rva)
    if cor_foa is None:
        raise DotnetError(f"CLR 目录 RVA=0x{rva:X} 无法映射到文件偏移")
    if size < 16:
        raise DotnetError(f"CLR 目录 Size={size}，小于 COR20 头最小长度")

    meta_rva = _u32(pe.data, cor_foa + 8)
    meta_size = _u32(pe.data, cor_foa + 12)
    if not meta_rva:
        raise DotnetError("COR20 头 MetaData RVA=0")
    flags = _u32(pe.data, cor_foa + 16)
    entry = _u32(pe.data, cor_foa + 20)

    meta_foa = pe.rva_to_foa(meta_rva)
    if meta_foa is None:
        raise DotnetError(f"元数据 RVA=0x{meta_rva:X} 无法映射到文件偏移")
    if meta_foa + 20 > len(pe.data):
        raise DotnetError("元数据根越界")
    if pe.data[meta_foa:meta_foa + 4] != BSJB:
        raise DotnetError(f"元数据签名不是 BSJB（实际 {bytes(pe.data[meta_foa:meta_foa + 4])!r}）")

    ver_len = _u32(pe.data, meta_foa + 12)
    if ver_len > 512 or meta_foa + 16 + ver_len + 4 > len(pe.data):
        raise DotnetError(f"版本字符串长度异常：{ver_len}")
    version = bytes(pe.data[meta_foa + 16:meta_foa + 16 + ver_len]) \
        .split(b"\x00", 1)[0].decode("ascii", "replace")
    flags_meta = _u16(pe.data, meta_foa + 16 + ver_len)
    n_streams = _u16(pe.data, meta_foa + 18 + ver_len)

    streams: dict[str, tuple[int, int]] = {}
    pos = meta_foa + 20 + ver_len
    for _ in range(n_streams):
        if pos + 8 > len(pe.data):
            raise DotnetError("流头越界")
        off = _u32(pe.data, pos)
        length = _u32(pe.data, pos + 4)
        name_start = pos + 8
        end = pe.data.find(b"\x00", name_start, min(name_start + 64, len(pe.data)))
        if end < 0:
            raise DotnetError("流名未以 NUL 结尾")
        name = bytes(pe.data[name_start:end]).decode("ascii", "replace")
        streams[name] = (meta_foa + off, length)
        # 流名按 4 字节对齐（包含结尾 NUL）
        pos = name_start + ((end - name_start + 1 + 3) // 4) * 4

    tables_name = "#~" if "#~" in streams else ("#-" if "#-" in streams else None)
    info = DotnetInfo(
        metadata_rva=meta_rva, metadata_size=meta_size,
        metadata_offset=meta_foa, version_string=version, flags=flags,
        entry_point_token=entry, streams=streams,
    )
    if tables_name is None:
        info.notes.append("没有 `#~`/`#-` 表流：只能确认是 .NET，取不到类型清单")
        return info

    stream_off, stream_size = streams[tables_name]
    if stream_size < 24 or stream_off + stream_size > len(pe.data):
        raise DotnetError(f"{tables_name} 流长度异常：{stream_size}")
    parsed = _parse_tables(pe.data, stream_off, stream_size, streams)
    info.rows = parsed["rows"]
    info.type_defs = parsed["type_defs"]
    info.method_defs = parsed["method_defs"]
    info.assembly_name = parsed["assembly_name"]
    info.assembly_refs = parsed["assembly_refs"]
    info.notes = parsed["notes"]
    if tables_name == "#-":
        info.notes.append("使用未压缩表流 `#-`（ENC 编辑模式），行偏移按指针表计算")
    return info


def analyze(path: str, allow_large: bool = False) -> DotnetInfo | None:
    with PE(path, allow_large=allow_large) as pe:
        return parse(pe)
