# -*- coding: utf-8 -*-
"""`.NET` CLI 元数据解析的回归测试。

真实托管程序集用系统自带的 `Accessibility.dll`（Windows + .NET Framework 4.x）。
非 Windows 或该文件不存在时只跳过集成用例，纯结构用例仍会跑。
"""

from __future__ import annotations

import os

import pytest

from rekit.core import dotnet
from rekit.core.dotnet import CODED, TABLES, _index_size, _row_size
from rekit.core.pe import PE

NET_DLL = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Accessibility.dll"
RUST_PE = os.path.join(os.path.dirname(__file__), "..", "..", "实践", "M3",
                       "01-rust-xor-easy", "sample", "rustpj.exe")
RUST_PE = os.path.abspath(RUST_PE)


def test_all_table_columns_are_known():
    """每张表的每一列都必须能算出宽度，避免真实程序集上突然 KeyError。"""
    for table, columns in TABLES.items():
        for column in columns:
            assert column in ("u1", "u2", "u4", "string", "guid", "blob") \
                or column in CODED, f"表 0x{table:02X} 的列 {column} 未定义"


def test_coded_index_width_uses_row_limits():
    rows = {dotnet.T_TYPEDEF: 10, dotnet.T_TYPEREF: 10, dotnet.T_TYPESPEC: 10}
    assert _index_size("TypeDefOrRef", 0, rows) == 2
    # 2 位 tag → 阈值 2^14；超过就必须用 4 字节
    rows[dotnet.T_TYPEREF] = 1 << 14
    assert _index_size("TypeDefOrRef", 0, rows) == 4


def test_heap_index_width_follows_heap_sizes():
    rows: dict[int, int] = {}
    assert _index_size("string", 0, rows) == 2
    assert _index_size("string", 1, rows) == 4
    assert _index_size("guid", 1 << 1, rows) == 4
    assert _index_size("blob", 1 << 2, rows) == 4


def test_typed_row_sizes():
    rows = {dotnet.T_TYPEDEF: 1, dotnet.T_FIELD: 1, dotnet.T_METHODDEF: 1}
    # TypeDef: Flags(4) + Name(2) + Namespace(2) + Extends(2) + Field(2) + Method(2)
    assert _row_size(dotnet.T_TYPEDEF, 0, rows) == 14
    # MethodDef: RVA(4) + ImplFlags(2) + Flags(2) + Name(2) + Signature(2) + Param(2)
    assert _row_size(dotnet.T_METHODDEF, 0, rows) == 14


@pytest.mark.skipif(not os.path.exists(RUST_PE), reason="缺少非 .NET 对照样本")
def test_non_dotnet_pe_returns_none():
    with PE(RUST_PE) as pe:
        assert dotnet.parse(pe) is None


@pytest.mark.skipif(not os.path.exists(NET_DLL), reason="缺少系统 .NET 程序集")
def test_real_managed_assembly_metadata():
    with PE(NET_DLL) as pe:
        info = dotnet.parse(pe)
    assert info is not None
    assert info.version_string.startswith("v4.0.")
    assert info.assembly_name == "Accessibility"
    assert info.type_def_count == len(info.type_defs)
    assert info.type_def_count == info.rows["TypeDef"]
    assert info.method_def_count == info.rows["MethodDef"]
    assert "Accessibility.IAccPropServices" in info.type_defs
    assert any("IAccPropServices" in t for t in info.type_defs)
    assert any(ref.startswith("mscorlib") for ref in info.assembly_refs)
    assert len(info.method_defs) == info.method_def_count
    # 同一份结构跑两遍必须完全一致（报告复现性的前提）
    with PE(NET_DLL) as pe:
        assert dotnet.parse(pe).as_dict() == info.as_dict()


@pytest.mark.skipif(not os.path.exists(NET_DLL), reason="缺少系统 .NET 程序集")
def test_metadata_offset_is_bsjb():
    with PE(NET_DLL) as pe:
        info = dotnet.parse(pe)
        assert bytes(pe.data[info.metadata_offset:info.metadata_offset + 4]) == b"BSJB"
    assert "#~" in info.streams
    assert "#Strings" in info.streams
