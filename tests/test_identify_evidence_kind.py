# -*- coding: utf-8 -*-
"""证据类型（positive / absence）与位数范围的契约测试。

锁死三条：
1. 每条工具链信号必须声明 `evidence_kind`；`T11_mingw_no_rsrc` 是 absence。
2. **absence 类信号不得单独构成族判定**——只有“无 .rsrc”命中时，不得输出
   任何 ≥0.8 的族（这正是 M3-07 把 GCC 15.2.0 判成 clang 0.93 的失败模式）。
3. 位数是独立字段：x86 允许给族但 `scope=out_of_m4a`，不进 M4a 五族达标。

样本缺失时 skip，不让 CI 因语料不在本机失败。
"""

from __future__ import annotations

import os

import pytest

from rekit.analyzers import identify
from rekit.core import toolchain

TRAIN = r"d:\逆向学习\实践\M4\corpus\build\train"
M3 = r"d:\逆向学习\实践\M3"


def _sig(sid: str, family: str, weight: int, kind: str, off: int = 0x188) -> toolchain.ToolchainSignal:
    return toolchain.ToolchainSignal(
        sid, family, weight, True, "section.name", off, "section_header", "test", kind)


def test_every_signal_declares_evidence_kind() -> None:
    path = rf"{TRAIN}\gcc_x64\p01_arith_loop_o2s.exe"
    if not os.path.exists(path):
        pytest.skip("训练侧语料不在本机")
    prof = toolchain.analyze(path)
    assert prof.signals
    for s in prof.signals:
        assert s.evidence_kind in ("positive", "absence"), s.id
    kinds = {s.id: s.evidence_kind for s in prof.signals}
    assert kinds["T11_mingw_no_rsrc"] == "absence"
    assert kinds["T10_mingw_default_rsrc"] == "positive"


def test_absence_only_profile_cannot_decide_family() -> None:
    """只有 absence 信号命中时，判定必须是 unknown，且置信度远低于 0.8。"""
    prof = toolchain.ToolchainProfile(
        signals=[_sig("T11_mingw_no_rsrc", "clang_x64", 2, "absence")],
        mingw_hint=True, has_rsrc=False)
    assert identify._absence_only("clang_x64", prof) is True

    family, why, conflicts, tier = identify._decide(prof)
    conf = identify._confidence(family, prof, conflicts, tier)
    assert family == "unknown", f"absence 单独命中不得给出族判定，实际 {family}"
    assert conf < 0.8
    assert "缺失型证据" in why or "不可区分" in why

    # 反向：同样的 mingw 前提，只要有一条 positive 的 clang version 串，就可以判
    prof2 = toolchain.ToolchainProfile(
        signals=[_sig("T11_mingw_no_rsrc", "clang_x64", 2, "absence"),
                 _sig("T9_clang_version", "clang_x64", 5, "positive")],
        mingw_hint=True, has_rsrc=False)
    family2, _, _, _ = identify._decide(prof2)
    assert family2 == "clang_x64"


def test_m3_07_regression_gcc_not_high_confidence_clang() -> None:
    """M3-07 是 GCC 15.2.0（`.comment` 证实），曾因“无 .rsrc”被判 clang 0.93。"""
    path = rf"{M3}\07-sbox\sample\sbox_lab.exe"
    if not os.path.exists(path):
        pytest.skip("M3-07 样本不在本机")
    r = identify.analyze_file(path)
    assert not (r["family"] == "clang_x64" and r["confidence"] >= 0.8), \
        f"缺失型证据不得支撑高置信 clang：{r['family']} {r['confidence']}"
    assert r["family"] == "unknown"
    assert r["confidence"] < 0.8


def test_stripped_clang_unknown_unstripped_clang_identified() -> None:
    """strip 后 MinGW-clang 与 gcc 不可区分 → unknown；未 strip 有 clang version 串才判。"""
    stripped = rf"{TRAIN}\clang_x64\p01_arith_loop_o2s.exe"
    unstripped = rf"{TRAIN}\clang_x64\p01_arith_loop_o0g.exe"
    if not (os.path.exists(stripped) and os.path.exists(unstripped)):
        pytest.skip("训练侧语料不在本机")
    assert identify.analyze_file(stripped)["family"] == "unknown"
    plain = identify.analyze_file(unstripped)
    assert plain["family"] == "clang_x64"


def test_x86_family_is_out_of_m4a_scope() -> None:
    """M3-09/10 是 MSVC x86：允许给族，但必须标 out_of_m4a，且不冒充 x64。"""
    path = rf"{M3}\09-flareon2016-i-am-happy\sample\challenge1.exe"
    if not os.path.exists(path):
        pytest.skip("M3-09 样本不在本机")
    r = identify.analyze_file(path)
    assert r["bitness"] == "x86"
    assert r["scope"] == "out_of_m4a"
    assert r["family"] == "msvc_x86"
    assert r["family"] not in toolchain.FAMILIES
