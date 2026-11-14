# -*- coding: utf-8 -*-
"""`rekit dotnet` / `rekit.core.dotnet_il` 的回归测试。

覆盖三类输入：
    1. 真实托管程序集（系统 `Accessibility.dll`）：与 `dotnet.parse` 的计数一致；
    2. 合成方法体：tiny / fat 头与小子句、夫子句 EH 的长度口径；
    3. 反例：MethodDef RVA 越界、元数据签名损坏——必须记账或抛 `DotnetError`，
       不能静默产出看似正常的结论。
"""

from __future__ import annotations

import os
import struct

import pytest

from rekit.core import dotnet, dotnet_il
from rekit.core.dotnet import DotnetError
from rekit.core.pe import PE

NET_DLL = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Accessibility.dll"
NET_IL_DLL = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.dll"
RUST_PE = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "实践", "M3", "01-rust-xor-easy",
    "sample", "rustpj.exe"))


def test_compressed_uint_roundtrip():
    assert dotnet_il.compressed_uint(b"\x03", 0) == (3, 1)
    assert dotnet_il.compressed_uint(b"\x80\x2A", 0) == (0x2A, 2)
    assert dotnet_il.compressed_uint(b"\xC0\x00\x01\x00", 0) == (0x100, 4)
    with pytest.raises(DotnetError):
        dotnet_il.compressed_uint(b"\xE0\x00", 0)


class _FakePE:
    def __init__(self, data: bytes):
        self.data = data

    def rva_to_foa(self, rva: int):
        return 0 if rva == 0x1000 else None


class _FakeMd:
    def __init__(self, data: bytes):
        self.data = data
        self.pe = _FakePE(data)

    def cell(self, table, row, col):
        assert table == dotnet.T_METHODDEF and row == 0 and col == 0
        return 0x1000

    def method_name(self, row):
        return "M"


def _fat_body(eh_kind: int, clause: int, clauses: int) -> bytes:
    """构造一个 fat 头方法体：code=[ret]，EH 段按给定子句宽/数量。"""
    data = bytearray(96)
    # Fat 头：flags=0x300B（size=3 dwords，MoreSects=1，低 2 位必须为 3），
    # maxstack=8，code_size=1，local_sig=0
    struct.pack_into("<HHII", data, 0, 0x300B, 8, 1, 0)
    data[12] = 0x2A                       # ret
    p = (12 + 1 + 3) & ~3                 # EH 段 4 字节对齐
    data_size = 4 + clause * clauses
    data[p] = eh_kind                      # 0x01=小, 0x41=fat
    data[p + 1:p + 4] = data_size.to_bytes(3, "little")
    for i in range(clauses):
        c = p + 4 + i * clause
        if clause == 12:
            # Flags(2) TryOffset(2) TryLength(1) HandlerOffset(2) HandlerLength(1) ClassToken(4)
            data[c:c + 12] = struct.pack("<HHBHB", 0, 0, 1, 0, 1) + b"\x00" * 4
        else:
            data[c:c + 24] = struct.pack("<IIIIII", 0, 0, 1, 0, 1, 0)
    return bytes(data)


def test_small_eh_clauses_use_12_bytes_and_include_header():
    body = dotnet_il.decode_method_body(_FakeMd(_fat_body(0x01, 12, 2)), 0)
    assert body.kind == "fat"
    assert body.code_size == 1
    assert body.eh_clauses == 2
    assert body.eh_invalid == []
    assert body.il_start == 12


def test_fat_eh_clauses_use_24_bytes():
    body = dotnet_il.decode_method_body(_FakeMd(_fat_body(0x41, 24, 2)), 0)
    assert body.eh_clauses == 2
    assert body.eh_invalid == []


def test_eh_clause_outside_code_is_recorded():
    data = bytearray(_fat_body(0x01, 12, 1))
    # 把小子的 HandlerOffset 改成 0x20，超出 code_size=1
    p = 16
    data[p + 4 + 5:p + 4 + 7] = struct.pack("<H", 0x20)
    body = dotnet_il.decode_method_body(_FakeMd(bytes(data)), 0)
    assert body.eh_clauses == 1
    assert any("handler" in x for x in body.eh_invalid)


@pytest.mark.skipif(not os.path.exists(RUST_PE), reason="缺少非 .NET 对照样本")
def test_non_dotnet_returns_none():
    with PE(RUST_PE) as pe:
        assert dotnet_il.scan(pe) is None


@pytest.mark.skipif(not os.path.exists(NET_DLL), reason="缺少系统 .NET 程序集")
def test_reference_assembly_has_no_method_bodies():
    """Accessibility.dll 是引用程序集：55 个 MethodDef 的 RVA 全为 0，应计入 no_body。"""
    with PE(NET_DLL) as pe:
        info = dotnet_il.scan(pe)
    assert info is not None
    with PE(NET_DLL) as pe:
        base = dotnet.parse(pe)
    assert info.type_count == base.type_def_count
    assert info.method_count == base.method_def_count
    assert info.assembly_name == base.assembly_name
    assert info.il["with_body"] == 0
    assert info.il["no_body"] == info.method_count
    assert info.il["invalid"] == []


@pytest.mark.skipif(not os.path.exists(NET_IL_DLL), reason="缺少系统 .NET 程序集")
def test_real_assembly_il_is_fully_decoded():
    with PE(NET_IL_DLL) as pe:
        info = dotnet_il.scan(pe)
    assert info is not None
    assert info.il["with_body"] > 1000
    assert info.il["il_bytes"] > 100000
    assert info.il["invalid"] == []
    assert info.il["unknown_opcode"] == []
    assert info.us_count > 0
    assert info.il["calls"] > 0 and info.il["ldstr"] > 0


@pytest.mark.skipif(not os.path.exists(NET_DLL), reason="缺少系统 .NET 程序集")
def test_corrupt_method_rva_is_recorded_not_crashing(tmp_path):
    raw = bytearray(open(NET_DLL, "rb").read())
    with PE(NET_DLL) as pe:
        md = dotnet_il.MetadataView(pe)
        # 第 1 个 MethodDef 的 RVA 单元；改成映射不到的高 RVA
        off = md.row_offset(dotnet.T_METHODDEF, 0)
        struct.pack_into("<I", raw, off, 0x0FFFFFF0)
    bad = tmp_path / "bad_rva.dll"
    bad.write_bytes(raw)
    with PE(str(bad)) as pe:
        info = dotnet_il.scan(pe)
    assert info is not None
    assert any(x["kind"] == "rva_unmapped" for x in info.il["invalid"])
    assert any(s["id"] == "invalid_method_body" for s in info.obfuscation_signals)


@pytest.mark.skipif(not os.path.exists(NET_DLL), reason="缺少系统 .NET 程序集")
def test_corrupt_metadata_signature_raises(tmp_path):
    raw = bytearray(open(NET_DLL, "rb").read())
    with PE(NET_DLL) as pe:
        md = dotnet_il.MetadataView(pe)
        raw[md.meta_foa:md.meta_foa + 4] = b"XXXX"
    bad = tmp_path / "bad_bsjb.dll"
    bad.write_bytes(raw)
    with PE(str(bad)) as pe:
        with pytest.raises(DotnetError):
            dotnet_il.scan(pe)
