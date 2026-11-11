# -*- coding: utf-8 -*-
"""Go `pclntab` 函数名恢复（M5 第 2 步）。

旧格式用合成 blob 精确校验 `_func.nameoff` 的基准；真实样本用 M3 的 `goCrackMe.exe`。
取不到名字必须显式写“不可恢复”，不允许用地址或占位串冒充。
"""

from __future__ import annotations

import os
import struct

import pytest

from rekit.core.funcs import parse_gopclntab
from rekit.core.pe import PE
from rekit.core.funcs import pclntab_from_data

GO_SAMPLE = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "实践", "M3", "02-gocrackme",
    "sample", "goCrackMe.exe"))


def _old_blob(nameoffs: tuple[int, int], names: bytes) -> bytes:
    """合成一个最小的 Go 1.2–1.15 pclntab（ptrSize=8，2 个函数 + sentinel）。"""
    base = 16 + 3 * 16                 # 头 + (2 函数 + sentinel) * functab 项
    func0, func1, name_base = base, base + 32, base + 64
    out = bytearray()
    out += struct.pack("<IHBB", 0xFFFFFFFB, 0, 1, 8)
    out += struct.pack("<Q", 2)
    out += struct.pack("<QQ", 0x401000, func0)
    out += struct.pack("<QQ", 0x401100, func1)
    out += struct.pack("<QQ", 0x401200, 0)
    for pc, nameoff in ((0x401000, nameoffs[0]), (0x401100, nameoffs[1])):
        out += struct.pack("<QI", pc, nameoff) + b"\x00" * 20
    assert len(out) == name_base
    out += names
    return bytes(out)


def test_old_format_names_are_read():
    blob = _old_blob((128, 138), b"main.main\x00runtime.main\x00")
    tab = parse_gopclntab(blob, 0x401000, 0x401200)
    assert tab is not None
    assert tab.names == {0x401000: "main.main", 0x401100: "runtime.main"}
    assert tab.name_status == "ok"
    assert tab.detail["names"] == 2


def test_old_format_unreadable_names_are_explicitly_marked():
    # nameoff 指向 functab 里的二进制垃圾：解不出可打印名字
    blob = _old_blob((64, 80), b"")
    tab = parse_gopclntab(blob, 0x401000, 0x401200)
    assert tab is not None
    assert tab.names == {}
    assert tab.name_status.startswith("不可恢复")


@pytest.mark.skipif(not os.path.exists(GO_SAMPLE), reason="缺少 M3 Go 样本")
def test_real_go115_sample_recovers_main_main():
    with PE(GO_SAMPLE) as pe:
        tab = pclntab_from_data(pe)
    assert tab is not None
    assert tab.magic == 0xFFFFFFFB          # Go 1.2–1.15 旧格式
    assert tab.name_status == "ok"
    assert len(tab.names) == len(tab.starts)
    assert tab.names[tab.starts[0]] == "go.buildid"
    main_sites = [pc for pc, name in tab.names.items() if name == "main.main"]
    assert len(main_sites) == 1
    assert main_sites[0] in tab.starts
