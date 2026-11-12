# -*- coding: utf-8 -*-
"""`basis` 由实际命中生成 + T16 单信号的反向约束（2026-11-12 修复的机制测试）。

背景：B 池 `curl` 的 linker 14.0 被 T16 单信号硬判成 msvc，而旧 `basis` 是固定文案
「Rich 头 / MSVC 链接器版本 6–14 / 大写节名 / VC CRT 导入」——四条里三条并未命中。
本文件用**合成 PE**锁死两件事，不依赖 B 池（B 池已消费，不能当验证）：

1. `无 Rich + 全小写 GNU 节名 + CRT 仅 UCRT API set + 内嵌 mingw 三元组` 时，
   T16 不得单信号硬判 msvc；
2. `basis` 只能出现实际命中的信号 id，不得出现未命中项。
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from rekit.analyzers import identify

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
E_LFANEW = 0x80
OPT_SIZE = 0xF0
HEADERS_SIZE = 0x400

SECTIONS = [
    # (name, rva, raw_ptr, raw_size, vsize, characteristics)
    (".text", 0x1000, 0x400, 0x200, 0x100, 0x60000020),
    (".rdata", 0x2000, 0x600, 0x200, 0x200, 0x40000040),
    (".buildid", 0x3000, 0x800, 0x200, 0x100, 0x40000040),
    (".note", 0x4000, 0xA00, 0x200, 0x100, 0x40000040),
    (".data", 0x5000, 0xC00, 0x200, 0x100, 0xC0000040),
]


def _section_header(name: str, vsize: int, va: int, raw_size: int,
                    raw_ptr: int, chars: int) -> bytes:
    return (name.encode("ascii").ljust(8, b"\x00")
            + struct.pack("<IIII", vsize, va, raw_size, raw_ptr)
            + struct.pack("<IIIHH", 0, 0, 0, 0, 0)
            + struct.pack("<I", chars))


def _build_pe(*, triple: bool = True, gnu_sections: bool = True) -> bytes:
    """合成一个「linker 14.0 + UCRT API set + MinGW 形态」的最小 PE32+。"""
    data = bytearray(0xE00)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, E_LFANEW)
    data[E_LFANEW:E_LFANEW + 4] = b"PE\x00\x00"

    # COFF header
    fh = E_LFANEW + 4
    struct.pack_into("<HHIIIHH", data, fh, 0x8664, len(SECTIONS), 0, 0, 0,
                     OPT_SIZE, 0x0022)

    # Optional header（PE32+）
    opt = fh + 20
    struct.pack_into("<H", data, opt, 0x20B)
    data[opt + 2] = 14          # MajorLinkerVersion：T16 命中
    data[opt + 3] = 0
    struct.pack_into("<I", data, opt + 4, 0x200)     # SizeOfCode
    struct.pack_into("<I", data, opt + 8, 0x800)     # SizeOfInitializedData
    struct.pack_into("<I", data, opt + 16, 0x1000)   # AddressOfEntryPoint
    struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<I", data, opt + 32, SECTION_ALIGN)
    struct.pack_into("<I", data, opt + 36, FILE_ALIGN)
    struct.pack_into("<I", data, opt + 56, 0x6000)   # SizeOfImage
    struct.pack_into("<I", data, opt + 60, HEADERS_SIZE)
    struct.pack_into("<H", data, opt + 68, 3)        # WINDOWS_CUI
    struct.pack_into("<I", data, opt + 108, 16)      # NumberOfRvaAndSizes
    dd = opt + 112
    struct.pack_into("<II", data, dd + 8, 0x2000, 0x28)   # IMPORT directory

    # Section table
    sec_off = opt + OPT_SIZE
    for i, (name, va, raw_ptr, raw_size, vsize, chars) in enumerate(SECTIONS):
        if not gnu_sections and name in (".buildid", ".note"):
            name = "." + name[1:4] + "x"     # .bui x / .not x：去掉 GNU 标记，仍全小写
        blob = _section_header(name, vsize, va, raw_size, raw_ptr, chars)
        data[sec_off + i * 40:sec_off + (i + 1) * 40] = blob

    # .rdata：导入描述符 + thunk + DLL 名 + 可选三元组
    struct.pack_into("<IIIII", data, 0x600, 0x2050, 0, 0, 0x2080, 0x2060)
    struct.pack_into("<Q", data, 0x650, 0x8000000000000001)   # ordinal 1
    struct.pack_into("<Q", data, 0x660, 0x8000000000000001)
    name = b"api-ms-win-crt-runtime-l1-1-0.dll\x00"
    data[0x680:0x680 + len(name)] = name
    if triple:
        trip = b"x86_64-w64-mingw32\x00"
        data[0x6C0:0x6C0 + len(trip)] = trip

    data[0x400] = 0xC3           # ret
    data[0x800:0x807] = b"buildid"
    data[0xA00:0xA04] = b"note"
    return bytes(data)


def _write(tmp_path: Path, **kwargs) -> str:
    path = tmp_path / "synthetic_mingw_lld.exe"
    path.write_bytes(_build_pe(**kwargs))
    return str(path)


def test_mingw_lld_shape_is_not_hard_msvc(tmp_path: Path) -> None:
    """反向约束：四项 MinGW 形态同时成立时，T16 不能单独把族定到 msvc。"""
    r = identify.analyze_file(_write(tmp_path))
    assert r["family"] == "unknown", r["basis"]
    assert r["confidence"] < 0.8
    assert r["decided"] is False


def test_same_pe_without_triple_is_msvc(tmp_path: Path) -> None:
    """对照组：去掉 mingw 三元组后，同一份 PE 仍按 T16 判 msvc。"""
    r = identify.analyze_file(_write(tmp_path, triple=False))
    assert r["family"] == "msvc"
    assert r["confidence"] >= 0.97


def test_same_pe_without_gnu_section_markers_is_msvc(tmp_path: Path) -> None:
    """对照组：去掉 `.buildid` / `.note` 后，形态证据不完整，不得触发降级。"""
    r = identify.analyze_file(_write(tmp_path, gnu_sections=False))
    assert r["family"] == "msvc"


def test_basis_lists_only_hit_signals(tmp_path: Path) -> None:
    """`basis` 必须由命中信号拼接：降级路径不得出现 T12/T13/T14。"""
    r = identify.analyze_file(_write(tmp_path))
    basis = r["basis"]
    assert "T16_msvc_linker_version" in basis
    assert "x86_64-w64-mingw32" in basis
    for absent in ("T12_msvc_rich_header", "T13_msvc_upper_section", "T14_msvc_crt_import"):
        assert absent not in basis
    assert "Rich 头 / MSVC 链接器版本 6–14" not in basis


def test_basis_never_mentions_unhit_family_signals() -> None:
    """真实 msvc 夹具：basis 里出现的族信号 id 必须都在命中列表里。"""
    path = FIXTURES / "msvc_x64.exe"
    if not path.exists():
        pytest.skip("夹具不在本机")
    r = identify.analyze_file(str(path))
    hit_ids = [s["id"] for s in r["signals"]
               if s["hit"] and s.get("family") == "msvc"]
    assert hit_ids, "msvc 夹具没有 msvc 族命中，夹具可能被替换"
    for sid in hit_ids:
        assert sid in r["basis"], f"{sid} 已命中但未出现在 basis：{r['basis']}"
    assert "Rich 头 / MSVC 链接器版本 6–14" not in r["basis"]
