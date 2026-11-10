# -*- coding: utf-8 -*-
"""D4：加载器映射回归（节 RVA↔FOA、文件松弛、内存补零、头部/越界）。

固定夹具：hello_rs（未加壳）与 hello_rs.packed（UPX0 纯内存节）。
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from rekit.core.pe import (
    MAP_BEYOND, MAP_FILE, MAP_HEADERS, MAP_PAD, MAP_SLACK, MAP_ZERO,
    PE, PEError, align_up,
)

FIXTURES = Path(__file__).parent / "fixtures"
RAW = FIXTURES / "hello_rs.exe"
PACKED = FIXTURES / "hello_rs.packed.exe"


def _build_slack_pe(path: Path) -> int:
    """造一个单节 PE：VirtualSize=0x200、RawSize=0x400（文件比内存多）。返回节 RVA。"""
    sect_align, file_align = 0x1000, 0x200
    e_lfanew = 0x40
    opt_size = 0xF0
    raw_ptr = 0x200
    raw_size = 0x400
    va = 0x1000
    size_of_image = 0x3000

    data = bytearray(raw_ptr + raw_size)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    struct.pack_into("<I", data, e_lfanew, 0x00004550)
    fh = e_lfanew + 4
    struct.pack_into("<HHIIIHH", data, fh, 0x8664, 1, 0, 0, 0, opt_size, 0x0022)
    opt = fh + 20
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 16, va)          # AddressOfEntryPoint
    struct.pack_into("<I", data, opt + 32, sect_align)
    struct.pack_into("<I", data, opt + 36, file_align)
    struct.pack_into("<I", data, opt + 56, size_of_image)
    struct.pack_into("<I", data, opt + 60, raw_ptr)
    struct.pack_into("<H", data, opt + 68, 3)           # Subsystem = CUI
    struct.pack_into("<I", data, opt + 108, 16)         # NumberOfRvaAndSizes
    sec = opt + opt_size
    data[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<I", data, sec + 8, 0x200)        # VirtualSize
    struct.pack_into("<I", data, sec + 12, va)          # VirtualAddress
    struct.pack_into("<I", data, sec + 16, raw_size)
    struct.pack_into("<I", data, sec + 20, raw_ptr)
    struct.pack_into("<I", data, sec + 36, 0x60000020)  # R+X
    path.write_bytes(bytes(data))
    return va


def test_section_map_matches_raw_header():
    pe = PE(str(RAW))
    rows = pe.section_map()
    assert len(rows) == len(pe.sections) == 5
    for s, row in zip(pe.sections, rows):
        assert row["rva_start"] == s.virtual_address
        assert row["foa_start"] == s.pointer_to_raw_data
        assert row["rva_end"] - row["rva_start"] == (s.virtual_size or s.size_of_raw_data)
        assert row["mem_end"] == align_up(row["rva_end"], pe.section_alignment)
        assert row["zero_fill"] + row["file_backed"] == row["rva_end"] - row["rva_start"]


def test_probe_matches_pefile_offset():
    pefile = pytest.importorskip("pefile")
    ref = pefile.PE(str(RAW), fast_load=True)
    mine = PE(str(RAW))
    for s in mine.sections:
        for rva in (s.virtual_address, s.virtual_address + 0x10):
            got = mine.map_rva(rva)
            assert got["kind"] == MAP_FILE
            assert got["foa"] == ref.get_offset_from_rva(rva)


def test_upx_virtual_only_section_is_zero_fill():
    pe = PE(str(PACKED))
    upx0 = next(r for r in pe.section_map() if r["name"] == "UPX0")
    assert upx0["raw_size"] == 0
    assert upx0["zero_fill"] == 0x15000
    # 解压区：内存有、文件无 —— 这正是「按文件长度 dump 必错」的原因
    probe = pe.map_rva(0x1000)
    assert probe["kind"] == MAP_ZERO and probe["foa"] is None
    assert any("内存补零" in n and "UPX0" in n for n in pe.loader_notes())


def test_headers_and_beyond_image():
    pe = PE(str(RAW))
    assert pe.map_rva(0x10)["kind"] == MAP_HEADERS
    assert pe.map_rva(0x10)["foa"] == 0x10
    beyond = pe.map_rva(int(pe.size_of_image) + 0x1000)
    assert beyond["kind"] == MAP_BEYOND and beyond["foa"] is None


def test_file_slack_synthetic(tmp_path):
    p = tmp_path / "slack.exe"
    va = _build_slack_pe(p)
    pe = PE(str(p))
    row = pe.section_map()[0]
    assert row["file_slack"] == 0x200 and row["zero_fill"] == 0
    assert pe.map_rva(va + 0x100)["kind"] == MAP_FILE          # 文件有、内存有
    slack = pe.map_rva(va + 0x300)                             # 文件有、内存无
    assert slack["kind"] == MAP_SLACK and slack["foa"] is None
    assert pe.map_rva(va + 0x900)["kind"] == MAP_PAD           # 节尾对齐补零
    assert any("文件多出 0x200 字节" in n for n in pe.loader_notes())


def test_map_cli_json(tmp_path):
    from rekit.cli import main

    out = tmp_path / "map.json"
    assert main(["map", str(PACKED), "--rva", "0x1000", "-j", str(out)]) == 0
    assert out.exists()
