# -*- coding: utf-8 -*-
"""UPX 解压链的边界语义与两处已确证能力（2026-11-13 深度单元回流）。

1. method=14 是 LZMA，framing 为 **2 字节 UPX 自有 props + 裸 LZMA1**
   （`pb=b0&7, lp=b1>>4, lc=b1&15`，无 5 字节属性头、无 EOS marker）。
   按 LZMA-alone 解释首字节会得 `lc=8`，此前全部失败就在这一步。
   framing 属性越界必须明确报错，不能落到别的解码器上瞎解。
2. filter 0x49 是自同步的：反过滤范围**超出**真实 SizeOfCode 不会损坏 .text
   （只有 `E8/E9` 后一字节等于 cto 的站点会被改），但**截断**会漏站点。
3. 省略反过滤会让 .text 与原件差 8022 字节——这条是既有测试的补充证据。
4. `rebuild_relocs` 从 `orig_crelocs` 恢复原表：与原 `.reloc` **字节表**逐项相等
   （hello_rs 304/304、notepad 366/366，页/偏移/类型/顺序全等，含 ABS 填充项）。
   壳后最小表（12 项 = 11 DIR64 + 1 ABS）只描述壳后镜像，不参与原表恢复。
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

import pytest

from rekit.core import upx
from rekit.core.pe import PE

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]
RAW = FIXTURES / "hello_rs.exe"
PACKED = FIXTURES / "hello_rs.packed.exe"
LZMA_PACKED = FIXTURES / "hello_rs.lzma-packed.exe"

SIZE_OF_CODE = 0x16000
FILTER_CALLS = 2097
FILTER_SKIPPED = 491
U_LEN = 141660
U_ADLER = 0x959BC30F

# notepad 是系统文件，与 7z 同样只在本地跑，不进仓库
LOCAL_NOTEPAD = ROOT.parent / "样本" / "packed" / "notepad_ms.packed.exe"


def _upx1_raw(pe: PE) -> int:
    return next(s for s in pe.sections if s.name == "UPX1").pointer_to_raw_data


def _stream(path: Path):
    """返回 (压缩流, PackHeader, PE)：流起点 = UPX1.rawdataptr - 64 + buf_offset + 32。"""
    data = path.read_bytes()
    pe = PE(str(path))
    ph = upx.parse_pack_header(data, _upx1_raw(pe))
    off = _upx1_raw(pe) - 64 + ph.buf_offset + upx.PH_SIZE
    return data[off:off + ph.c_len], ph, pe


def _image_and_raw():
    """解出镜像 blob 与原件 .text 的（镜像内偏移, 原件字节）对，全部在内存里。"""
    data = PACKED.read_bytes()
    pe, raw = PE(str(PACKED)), PE(str(RAW))
    ph = upx.parse_pack_header(data, _upx1_raw(pe))
    off = _upx1_raw(pe) - 64 + ph.buf_offset + 32
    blob, consumed, _ = upx.nrv2b_le32_decompress(data[off:off + ph.c_len], ph.u_len + 16)
    assert consumed == ph.c_len
    oh, secs, _ = upx.parse_original_header(blob, ph.u_len)
    rvamin = secs[0].vaddr
    image_len = struct.unpack_from("<I", oh, 24 + 56)[0] - rvamin
    text = next(s for s in raw.sections if s.name == ".text")
    lo = text.virtual_address - rvamin
    ref = raw.data[text.pointer_to_raw_data:text.pointer_to_raw_data + text.size_of_raw_data]
    return bytearray(blob[:image_len]), lo, ref, ph.filter_cto


def _mismatch(img: bytes, lo: int, ref: bytes) -> int:
    return sum(a != b for a, b in zip(img[lo:lo + len(ref)], ref))


def _check(result: dict, name: str) -> dict:
    return next(c for c in result["checks"] if c["name"] == name)


def test_lzma_framing_is_two_byte_upx_props():
    """method 14 的流 = 2 字节自有 props + 裸 LZMA1；按 LZMA-alone 解释会得 lc=8。"""
    stream, ph, pe = _stream(LZMA_PACKED)
    assert ph.method == 14
    assert upx.parse_lzma_props(stream) == (3, 0, 2)
    assert stream[0] % 9 == 8, "LZMA-alone 的 property 解释确实会得到非法 lc=8"

    blob, consumed, status = upx.lzma_upx_decompress(stream, ph.u_len)
    assert len(blob) == ph.u_len == U_LEN
    assert status == "u_len", "裸 LZMA1 没有 EOS marker，只能按输出长度截停"
    assert consumed == ph.c_len
    assert zlib.adler32(blob) & 0xFFFFFFFF == ph.u_adler == U_ADLER


def test_lzma_invalid_props_are_rejected_with_evidence():
    """properties 越界/非法必须报错，不能落到 NRV2B 解码器或静默解垃圾。"""
    stream, ph, _ = _stream(LZMA_PACKED)

    broken = bytearray(stream)
    broken[1] = 8                               # lp=0, lc=8 → lc+lp>4
    with pytest.raises(upx.UnpackError, match=r"lc\+lp<=4"):
        upx.lzma_upx_decompress(bytes(broken), ph.u_len)

    broken = bytearray(stream)
    broken[0] = 5                               # pb=5，超出 UPX 允许的 pb<5
    with pytest.raises(upx.UnpackError, match="越界"):
        upx.lzma_upx_decompress(bytes(broken), ph.u_len)


def test_lzma_and_nrv2b_unpack_to_identical_file(tmp_path):
    """同一原件的 LZMA / NRV2B 两种打包必须还原成同一份文件（最硬的交叉验证）。"""
    out_lzma = tmp_path / "hello_rs.lzma.unpacked.exe"
    r_lzma = upx.unpack(LZMA_PACKED, out_lzma)
    assert r_lzma["ok"], [c for c in r_lzma["checks"] if not c["ok"]]
    assert r_lzma["upx"]["method_name"] == "LZMA"
    assert r_lzma["upx"]["lzma_props"] == {"lc": 3, "lp": 0, "pb": 2}
    assert r_lzma["diff"]["text_mismatch"] == 0
    assert (r_lzma["unfilter"]["calls"], r_lzma["unfilter"]["skipped"]) == (
        FILTER_CALLS, FILTER_SKIPPED)

    out_nrv = tmp_path / "hello_rs.nrv.unpacked.exe"
    r_nrv = upx.unpack(PACKED, out_nrv)
    assert r_nrv["ok"], [c for c in r_nrv["checks"] if not c["ok"]]
    assert out_lzma.read_bytes() == out_nrv.read_bytes()


def test_rebuilt_reloc_table_matches_original():
    """原表恢复必须与原 `.reloc` 字节表逐项相等，包括块对齐的 ABS 填充项。"""
    r = upx.unpack(PACKED, None, verify_only=True)
    check = _check(r, "重定位表对照")
    assert check["ok"], check["detail"]
    assert check["detail"].startswith("304/304")
    assert "含 5 条 ABS 填充" in check["detail"]

    raw_table = upx.read_reloc_table(PE(str(RAW)))
    assert len(raw_table) == 304
    assert sum(rtype == 0 for _rva, rtype in raw_table) == 5


def test_packed_stub_reloc_table_is_minimal_but_legal():
    """壳后最小表 12 项（11 DIR64 + 1 ABS）只描述壳后镜像，且目标地址都合法。"""
    pe = PE(str(PACKED))
    table = upx.read_reloc_table(pe)
    assert len(table) == 12
    dir64 = [rva for rva, rtype in table if rtype == 10]
    assert len(dir64) == 11 and sum(rtype == 0 for _rva, rtype in table) == 1

    base = struct.unpack_from("<Q", pe.data, pe.e_lfanew + 24 + 24)[0]
    size_of_image = struct.unpack_from("<I", pe.data, pe.e_lfanew + 24 + 56)[0]
    for rva in dir64:
        foa = pe.rva_to_foa(rva)
        assert foa is not None
        target = struct.unpack_from("<Q", pe.data, foa)[0]
        assert base <= target < base + size_of_image, f"0x{rva:X} 的目标 0x{target:X} 不在镜像内"


@pytest.mark.skipif(not LOCAL_NOTEPAD.exists(), reason="notepad 是系统文件，默认不进仓库")
def test_local_notepad_reloc_table_matches():
    r = upx.unpack(LOCAL_NOTEPAD, None, verify_only=True)
    check = _check(r, "重定位表对照")
    assert check["ok"], check["detail"]
    assert check["detail"].startswith("366/366")
    assert "含 2 条 ABS 填充" in check["detail"]


def test_filter_range_must_cover_but_may_exceed():
    """范围只要**覆盖**全部真实站点就够：多给 0x1000 仍逐字节一致，截一半就漏。"""
    img, lo, ref, cto = _image_and_raw()

    exact = bytearray(img)
    calls, skipped = upx.unfilter_ctok32_e8e9(exact, 0, SIZE_OF_CODE, cto)
    assert (calls, skipped) == (FILTER_CALLS, FILTER_SKIPPED)
    assert _mismatch(exact, lo, ref) == 0

    over = bytearray(img)
    over_calls, over_skipped = upx.unfilter_ctok32_e8e9(over, 0, SIZE_OF_CODE + 0x1000, cto)
    assert over_calls == FILTER_CALLS and over_skipped == FILTER_SKIPPED + 2
    assert _mismatch(over, lo, ref) == 0, "超出范围的站点不该被改（自同步）"

    short = bytearray(img)
    short_calls, _ = upx.unfilter_ctok32_e8e9(short, 0, SIZE_OF_CODE // 2, cto)
    assert short_calls < FILTER_CALLS
    assert _mismatch(short, lo, ref) > 0, "截断范围必须被逐字节对照抓住"


def test_omitting_filter_leaves_8022_bytes_wrong():
    """不做反过滤的差值定值：8022 字节（不是拍脑袋的“差一点”）。"""
    img, lo, ref, _ = _image_and_raw()
    assert _mismatch(img, lo, ref) == 8022
