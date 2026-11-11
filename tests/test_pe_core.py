# -*- coding: utf-8 -*-
"""core.pe 的结构解析回归：字段值固定，不依赖外部工具。"""

from __future__ import annotations

import math
import mmap
from pathlib import Path

import pytest

from rekit.core.pe import PE, PEFileTooLarge, entropy

FIXTURES = Path(__file__).parent / "fixtures"
RAW = FIXTURES / "hello_rs.exe"
PACKED = FIXTURES / "hello_rs.packed.exe"


def test_entropy_bounds():
    assert entropy(b"") == 0.0
    assert entropy(b"\x00" * 100) == 0.0
    assert 7.9 < entropy(bytes(range(256)) * 4) <= 8.0


def test_entropy_chunked_matches_naive():
    """分块直方图（triage 用的路径）必须与逐字节统计得到同一个熵。"""
    data = bytes(range(256)) * 1000 + b"\x00" * 5000
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    want = -sum((c / total) * math.log2(c / total) for c in counts if c)
    assert entropy(data, chunk_size=4096) == pytest.approx(want, abs=1e-12)
    assert entropy(memoryview(data), chunk_size=7) == pytest.approx(want, abs=1e-12)


def test_raw_headers():
    pe = PE(str(RAW))
    assert pe.pe_format == "PE32+"
    assert pe.arch == "AMD64"
    assert pe.image_base == 0x140000000
    assert len(pe.sections) == 5
    assert pe.entry_section == ".text"
    assert pe.subsystem == 3  # 控制台


def test_raw_imports():
    pe = PE(str(RAW))
    imports = pe.imports()
    assert len(imports) == 85
    assert len({i.dll for i in imports}) == 10
    assert all(i.iat_rva for i in imports)


def test_packed_layout():
    pe = PE(str(PACKED))
    names = [s.name for s in pe.sections]
    assert names == ["UPX0", "UPX1", "UPX2"]
    upx0 = pe.sections[0]
    assert upx0.virtual_size > 0
    assert upx0.size_of_raw_data == 0
    assert upx0.is_executable
    assert pe.entry_section == "UPX1"
    assert pe.sections[1].entropy > 7.8


def test_packed_imports_are_truncated_not_empty():
    """UPX 5 保留导入描述符但截断函数表——这条是判据 S5 的事实基础。"""
    pe = PE(str(PACKED))
    imports = pe.imports()
    assert len(imports) == 13
    assert len({i.dll for i in imports}) == 10
    assert len(imports) / len({i.dll for i in imports}) < 2.0


def test_rva_to_foa_roundtrip():
    pe = PE(str(RAW))
    for s in pe.sections:
        if not s.size_of_raw_data:
            continue
        assert pe.rva_to_foa(s.virtual_address) == s.pointer_to_raw_data


def test_mmap_and_read_paths_agree():
    """强制两种读法，结果必须逐字段一致（sha256 也一致）。"""
    with PE(str(RAW), mmap_threshold=1) as mm:
        assert isinstance(mm.data, mmap.mmap)
        mm_summary = mm.summary()
    with PE(str(RAW), mmap_threshold=1 << 30) as rd:
        assert isinstance(rd.data, bytes)
        rd_summary = rd.summary()
    assert mm_summary == rd_summary
    assert mm_summary["sha256"] == rd_summary["sha256"]


def test_section_raw_is_a_zero_copy_view():
    pe = PE(str(RAW))
    s = pe.sections[1]
    view = s.raw
    assert isinstance(view, memoryview)
    assert view.obj is pe.data
    assert bytes(view) == pe.data[s.pointer_to_raw_data:
                                s.pointer_to_raw_data + s.size_of_raw_data]


def test_oversized_file_is_refused_unless_allowed():
    with pytest.raises(PEFileTooLarge) as exc:
        PE(str(RAW), max_size=1024)
    assert "--allow-large" in str(exc.value)
    PE(str(RAW), max_size=1024, allow_large=True)  # 显式允许后正常解析

