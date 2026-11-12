# -*- coding: utf-8 -*-
"""UPX 解压链的边界语义（2026-11-13 深度单元回流）。

三条今天实测出来的口径，之前没有测试钉住：

1. method=14 是 LZMA，rekit 不解；必须**明确报错**，不能落到 NRV2B 解码器上瞎解。
2. filter 0x49 是自同步的：反过滤范围**超出**真实 SizeOfCode 不会损坏 .text
   （只有 `E8/E9` 后一字节等于 cto 的站点会被改），但**截断**会漏站点。
3. 反过来，省略反过滤会让 .text 与原件差 8022 字节——这条是既有测试的补充证据。
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from rekit.core import upx
from rekit.core.pe import PE

FIXTURES = Path(__file__).parent / "fixtures"
RAW = FIXTURES / "hello_rs.exe"
PACKED = FIXTURES / "hello_rs.packed.exe"

SIZE_OF_CODE = 0x16000
FILTER_CALLS = 2097
FILTER_SKIPPED = 491


def _upx1_raw(pe: PE) -> int:
    return next(s for s in pe.sections if s.name == "UPX1").pointer_to_raw_data


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


def test_lzma_method_is_rejected_explicitly(tmp_path):
    """method=14（LZMA）必须报“未实现”，不能被 NRV2B 解码器当成垃圾流解下去。"""
    data = bytearray(PACKED.read_bytes())
    ph = upx.parse_pack_header(bytes(data), _upx1_raw(PE(str(PACKED))))
    data[ph.file_offset + 6] = 14                       # method 2 -> 14
    header = data[ph.file_offset:ph.file_offset + 32]
    data[ph.file_offset + 31] = sum(header[4:31]) % 251  # 重算 PackHeader 校验字节
    mutated = tmp_path / "hello_rs.lzma.exe"
    mutated.write_bytes(bytes(data))

    assert upx.parse_pack_header(bytes(data), _upx1_raw(PE(str(mutated)))).checksum_ok
    with pytest.raises(upx.UnpackError, match="LZMA"):
        upx.unpack(mutated, None, verify_only=True)


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
