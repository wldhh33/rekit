# -*- coding: utf-8 -*-
"""`rekit xref` 的口径回归：指令流来自 funcs、确定/疑似分列、目标类型。"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("capstone")

from rekit.core.xref import _insn_refs, analyze_xref

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "gcc_o2.exe"
STRING = "hello from C, sum=%d leaf=%d"
LEAF = 0x1400034B0


class _NoSections:
    sections = []


def _refs(code_hex: str, va: int, target: int, bits: int = 64):
    """直接喂一条指令给 `_insn_refs`，不依赖镜像。"""
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    md.detail = True
    insn = next(md.disasm(bytes.fromhex(code_hex), va))
    return _insn_refs(_NoSections(), {va: insn}, lambda _v: None, target,
                      target_is_address=True)


def _analyze(spec: dict):
    return analyze_xref(str(SAMPLE), [spec])


def test_xref_string_finds_certain_rip_lea():
    payload = _analyze({"kind": "string", "value": STRING})
    target = payload["targets"][0]
    assert target["counts"]["resolved"] == 1
    assert target["counts"]["certain"] == 1
    assert target["counts"]["suspected"] == 0
    refs = target["blocks"][0]["refs"]
    assert [(r["ref_type"], r["confidence"], r["mnemonic"]) for r in refs] == [
        ("rip-lea", "certain", "lea")]
    # 引用必须能归到函数体，这是"谁引用了它"的最小可用性
    assert refs[0]["function"] == LEAF


def test_xref_va_separates_certain_from_suspected():
    payload = _analyze({"kind": "va", "value": LEAF})
    block = payload["targets"][0]["blocks"][0]
    certain = [r for r in block["refs"] if r["confidence"] == "certain"]
    suspected = [r for r in block["refs"] if r["confidence"] == "suspected"]
    assert [r["ref_type"] for r in certain] == ["rel32"]
    assert certain[0]["mnemonic"] == "call"
    # 数据节 4 字节槽位是"疑似"，不能混进确定集
    assert [r["ref_type"] for r in suspected] == ["data-pointer-4"]
    assert all(r["function"] is None for r in suspected)
    assert block["counts"]["certain"] == len(certain)
    assert block["counts"]["suspected"] == len(suspected)


def test_xref_missing_literal_is_not_an_error():
    payload = _analyze({"kind": "string", "value": "__no_such_string_zzz__"})
    target = payload["targets"][0]
    assert target["resolved"] == []
    assert target["counts"]["certain"] == 0
    assert target["counts"]["suspected"] == 0


def test_xref_stream_is_funcs_recursive_descent():
    payload = _analyze({"kind": "va", "value": LEAF})
    stream = payload["instruction_stream"]
    assert stream["source"] == "funcs 递归下降"
    assert stream["functions"] > 0
    assert stream["instructions"] > 0


@pytest.mark.parametrize("code_hex,target,bits", [
    ("64 48 8b 04 25 00 00 00 00", 0x00, 64),   # fs:[0]    TLS / 32 位 SEH
    ("64 48 8b 04 25 28 00 00 00", 0x28, 64),   # fs:[0x28] Linux canary
    ("65 48 8b 04 25 10 00 00 00", 0x10, 64),   # gs:[0x10] TEB StackLimit
    ("65 48 8b 04 25 30 00 00 00", 0x30, 64),   # gs:[0x30] TEB
    ("65 48 8b 04 25 60 00 00 00", 0x60, 64),   # gs:[0x60] PEB
    ("64 8b 05 00 00 00 00", 0x00, 32),         # 32 位 fs:[0] SEH 链
])
def test_segment_prefixed_disp_is_not_an_image_address(code_hex, target, bits):
    """`fs:` / `gs:` 的 disp 是线程局部/系统结构偏移，不是镜像内地址。"""
    va = 0x1000 if bits == 64 else 0x401000
    assert _refs(code_hex, va, target, bits) == []


def test_segment_prefix_does_not_suppress_rip_relative():
    """带段前缀的 RIP 相对仍按 RIP 规则判定（段前缀不影响正常路径）。"""
    # fs:[rip + 0x10] @0x1000 -> 0x1000 + 8（含段前缀）+ 0x10 = 0x1018
    refs = _refs("64 48 8b 05 10 00 00 00", 0x1000, 0x1018, 64)
    assert [(r.ref_type, r.confidence) for r in refs] == [
        ("rip-mov", "certain")]


def test_register_indirect_branch_is_not_a_direct_reference():
    """`jmp rdx` 的 `op.imm` 会回落到寄存器枚举值 RDX=0x28。"""
    assert _refs("ff e2", 0x1000, 0x28, 64) == []
