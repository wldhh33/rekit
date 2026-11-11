# -*- coding: utf-8 -*-
"""证据类型（positive / absence）与位数范围的契约测试（0.7 / schema 3）。

锁死四条：
1. 每条工具链信号必须声明 `evidence_kind`；`T11_mingw_no_rsrc` 是 absence。
2. **absence 类信号不得单独构成族判定**——即使它带族标签且分数够，也只能给 unknown。
3. `.rsrc` 有无只作观测（`family=None`），不是编译器/链接器身份（`docs/family.md` §1.1）。
4. 位数是独立字段：x86 允许给族，但 `scope=out_of_m4a`，不进 M4a 达标。

样本缺失时 skip，不让 CI 因语料不在本机失败。
"""

from __future__ import annotations

import os

import pytest

from rekit.analyzers import identify
from rekit.core import toolchain

TRAIN = r"d:\逆向学习\实践\M4\corpus\build\train"
M3 = r"d:\逆向学习\实践\M3"


def _sig(sid: str, family: str | None, weight: int, kind: str,
         off: int = 0x188, target: str = "family") -> toolchain.ToolchainSignal:
    return toolchain.ToolchainSignal(
        sid, family, weight, True, "section.name", off, "section_header", "test",
        kind, target)


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


def test_rsrc_signals_are_observation_only() -> None:
    """`.rsrc` 有无不参与计分：即使命中，family 也必须是 None。"""
    path = rf"{TRAIN}\gcc_x64\p01_arith_loop_o2s.exe"
    if not os.path.exists(path):
        pytest.skip("训练侧语料不在本机")
    prof = toolchain.analyze(path)
    fam = {s.id: s.family for s in prof.signals}
    assert fam["T10_mingw_default_rsrc"] is None
    assert fam["T11_mingw_no_rsrc"] is None


def test_absence_only_profile_cannot_decide_family() -> None:
    """只有 absence 信号命中时，判定必须是 unknown，且置信度远低于 0.8。"""
    prof = toolchain.ToolchainProfile(
        signals=[_sig("T11_mingw_no_rsrc", "gcc", 6, "absence")],
        mingw_hint=True, has_rsrc=False)
    assert identify._absence_only("gcc", prof) is True

    family, why, conflicts, tier = identify._decide(prof)
    conf = identify._confidence(family, prof, conflicts, tier)
    assert family == "unknown", f"absence 单独命中不得给出族判定，实际 {family}"
    assert conf < 0.8
    assert "缺失型证据" in why

    # 反向：同样的缺失证据，只要再有一条 positive 的 gcc 证据，就可以判 gcc
    prof2 = toolchain.ToolchainProfile(
        signals=[_sig("T11_mingw_no_rsrc", "gcc", 6, "absence"),
                 _sig("T8_mingw_gcc_comment", "gcc", 3, "positive")],
        mingw_hint=True, has_rsrc=False)
    family2, _, _, _ = identify._decide(prof2)
    assert family2 == "gcc"


def test_m3_07_regression_gcc_not_high_confidence_clang() -> None:
    """M3-07 是 GCC 15.2.0（`.comment` 证实），0.6.x 曾因“无 .rsrc”被判 clang 0.93。"""
    path = rf"{M3}\07-sbox\sample\sbox_lab.exe"
    if not os.path.exists(path):
        pytest.skip("M3-07 样本不在本机")
    r = identify.analyze_file(path)
    assert r["family"] == "gcc"
    assert r["compiler_frontend"] == "gcc"
    assert r["confidence"] >= 0.8


def test_stripped_clang_family_is_gcc_unstripped_frontend_is_clang() -> None:
    """族看链接器：strip 后 clang 仍归 gcc；未 strip 才能把前端判成 clang。"""
    stripped = rf"{TRAIN}\clang_x64\p01_arith_loop_o2s.exe"
    unstripped = rf"{TRAIN}\clang_x64\p01_arith_loop_o0g.exe"
    if not (os.path.exists(stripped) and os.path.exists(unstripped)):
        pytest.skip("训练侧语料不在本机")
    assert identify.analyze_file(stripped)["family"] == "gcc"
    plain = identify.analyze_file(unstripped)
    assert plain["family"] == "gcc"
    assert plain["compiler_frontend"] == "clang"


def test_go_gcc_conflict_is_visible_and_linker_wins() -> None:
    """cgo + MinGW（gitea 类）：go 与 gcc 同时硬命中 → 冲突可见，family 取 gcc。"""
    prof = toolchain.ToolchainProfile(signals=[
        _sig("T1_go_build_id", "go", 6, "positive"),
        _sig("T3_go_pclntab_or_symtab", "go", 5, "positive"),
        _sig("T2_go_version_string", "go", 4, "positive"),
        _sig("T15_gnu_ld_linker_version", "gcc", 5, "positive"),
        _sig("T8_mingw_gcc_comment", "gcc", 3, "positive"),
    ])
    family, _, conflicts, _ = identify._decide(prof)
    assert family == "gcc"
    assert conflicts, "go × gcc 同时硬命中必须留下冲突记录"
    assert set(conflicts[0]["between"]) == {"go", "gcc"}
    assert "gcc" in conflicts[0]["note"]


def test_x86_family_is_out_of_m4a_scope() -> None:
    """M3-09 是 MSVC x86：族按链接器给 msvc，但必须标 out_of_m4a。"""
    path = rf"{M3}\09-flareon2016-i-am-happy\sample\challenge1.exe"
    if not os.path.exists(path):
        pytest.skip("M3-09 样本不在本机")
    r = identify.analyze_file(path)
    assert r["bitness"] == "x86"
    assert r["scope"] == "out_of_m4a"
    assert r["family"] == "msvc"
    assert r["family"] in toolchain.FAMILIES
