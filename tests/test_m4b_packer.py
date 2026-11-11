# -*- coding: utf-8 -*-
"""M4b 壳判定层（`packer` + `identify` 融合）的契约测试。

只用训练侧语料（M4b `m01–m03`），不读测试侧；口径是「UPX / 非 UPX 判定」，
不承诺其它壳族的族识别。
"""

from __future__ import annotations

import os

import pytest

from rekit.analyzers import identify, packer

UPX_EXE = r"d:\逆向学习\实践\M4b\corpus\build\train\upx\m01_pe_hdr\m01_pe_hdr_x64_l1.exe"
UPX_DLL = r"d:\逆向学习\实践\M4b\corpus\build\train\upx_dll\m01_pe_hdr\m01_pe_hdr_x64_l1.dll"
CLEAN_EXE = r"d:\逆向学习\实践\M4b\corpus\build\base\m02_ini_state\m02_ini_state_x64.exe"


def _need(path: str) -> None:
    if not os.path.exists(path):
        pytest.skip("M4b 训练侧语料不在本机")


def test_packer_signal_table_is_frozen() -> None:
    assert packer.SIGNALS_VERSION == "m4b-signals-v1"
    assert (packer.W_PACKER_SECTION, packer.W_ENTRY_OUTSIDE,
            packer.W_OVERLAY, packer.W_SECTION_COUNT) == (3, 4, 1, 1)
    # S1–S6 必须直接引用 triage 常量（不在 M4b 里另抄一份权重）
    from rekit.analyzers import triage
    assert triage.W_UPX_PAIR == 4 and triage.W_UPX_ANY == 2


@pytest.mark.parametrize("path", [UPX_EXE, UPX_DLL])
def test_upx_is_packed_with_evidence(path: str) -> None:
    _need(path)
    r = identify.analyze_file(path)
    assert r["schema_version"] == 3
    assert r["kind"] == "packer"
    assert r["verdict"] == "packed"
    pk = r["packer"]
    assert pk["family"] == "upx" and pk["verdict"] == "packed"
    assert pk["confidence"] == 0.97
    assert pk["signals_version"] == "m4b-signals-v1"
    assert len(pk["signals_all"]) == 10

    hits = [s for s in pk["signals_all"] if s["hit"]]
    assert any(s["id"] == "S1_upx_section_pair" for s in hits)
    for s in hits:
        ev = s["evidence"]
        assert ev["field"] and ev["offset_kind"] and ev["offset"], s["id"]


def test_clean_build_is_not_packed() -> None:
    _need(CLEAN_EXE)
    r = identify.analyze_file(CLEAN_EXE)
    assert r["kind"] == "toolchain" and r["verdict"] == "clean"
    pk = r["packer"]
    assert pk["family"] is None and pk["verdict"] == "clean"
    assert pk["score"] == 0 and pk["confidence"] == 0.90
    # 工具链字段按 0.7 语义（族=链接器提供方）：MSVC 链接的干净样本是 msvc
    assert r["family"] == "msvc"


def test_only_upx_family_is_claimed() -> None:
    """非 UPX 壳即使命中 S7，也只能给 family=unknown（泛化未测）。"""
    assert packer.PACKER_SECTION_PREFIXES, "S7 节名表不得为空"
    assert set(packer.PACKER_SECTION_PREFIXES) >= {".mpress", ".aspack"}
