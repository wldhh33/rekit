# -*- coding: utf-8 -*-
"""`rekit xref` 的口径回归：指令流来自 funcs、确定/疑似分列、目标类型。"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

pytest.importorskip("capstone")

from rekit.core import xref as xmod
from rekit.core.funcs import discover, open_image
from rekit.core.xref import (
    _data_refs, _data_refs_batch, _insn_refs, _insn_refs_batch, _reloc_refs,
    _reloc_refs_batch, analyze_xref,
)

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "gcc_o2.exe"
STRING = "hello from C, sum=%d leaf=%d"
LEAF = 0x1400034B0
GLAB = Path(__file__).resolve().parents[2] / "实践" / "2026-11-13-real-target-glab" \
    / "unpacked_canonical" / "v41-go-glab-1129_upx.unpacked.exe"


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


# --- 批量索引与逐目标判定的等价性（纯实现优化，结果必须逐条相同） -----------

def _fixture_stream():
    img = open_image(str(SAMPLE))
    insns: dict[int, object] = {}
    funcs, *_ = discover(img, pointers=True, detail=True, insn_out=insns)
    return img, insns, xmod._owner_lookup(funcs), funcs


def test_batch_insn_refs_match_per_target():
    img, insns, owner, funcs = _fixture_stream()
    targets: dict[int, tuple[bool, ...]] = {
        start: (True,) for start in sorted(funcs)[:12]}
    targets[0x28] = (False,)          # 小常量：走 imm8/imm16 全窗口
    targets[LEAF] = (True, False)     # 同一数值既是地址又是常量
    batch = _insn_refs_batch(img, insns, owner, targets)
    for target, modes in targets.items():
        for is_addr in modes:
            assert [r.as_dict() for r in batch[(target, is_addr)]] == [
                r.as_dict() for r in _insn_refs(
                    img, insns, owner, target, target_is_address=is_addr)]


def test_batch_data_and_reloc_refs_match_per_target():
    img, _insns, _owner, funcs = _fixture_stream()
    targets = set(sorted(funcs)[:6]) | {LEAF}
    data_batch = _data_refs_batch(img, targets)
    reloc_batch = _reloc_refs_batch(img, targets)
    for target in targets:
        assert [r.as_dict() for r in data_batch[target]] == [
            r.as_dict() for r in _data_refs(img, target, target_is_address=True)]
        assert [r.as_dict() for r in reloc_batch[target]] == [
            r.as_dict() for r in _reloc_refs(img, target)]


def test_multi_target_specs_do_not_cross_contaminate():
    two = analyze_xref(str(SAMPLE), [{"kind": "va", "value": LEAF},
                                     {"kind": "const", "value": 0x28}])
    one = _analyze({"kind": "va", "value": LEAF})
    assert two["targets"][0]["blocks"] == one["targets"][0]["blocks"]
    assert two["targets"][1]["input"] == {"kind": "const", "value": 0x28}


GO_SAMPLE = (Path(__file__).resolve().parents[2] / "实践" / "M3"
             / "02-gocrackme" / "sample" / "goCrackMe.exe")


@pytest.mark.skipif(not GO_SAMPLE.exists(), reason="缺少 M3 Go 样本")
def test_batch_matches_per_target_on_real_go_binary():
    """真实 Go 二进制（RIP 相对密集）上也要逐条一致，含 0、小常量与地址目标。"""
    img = open_image(str(GO_SAMPLE))
    insns: dict[int, object] = {}
    funcs, *_ = discover(img, pointers=True, detail=True, insn_out=insns)
    owner = xmod._owner_lookup(funcs)
    targets: dict[int, tuple[bool, ...]] = {
        start: (True,) for start in sorted(funcs)[:20]}
    targets[0] = (False,)
    targets[0x28] = (False,)
    targets[0xFFFFFFFF] = (True,)
    batch = _insn_refs_batch(img, insns, owner, targets)
    for target, modes in targets.items():
        for is_addr in modes:
            assert [r.as_dict() for r in batch[(target, is_addr)]] == [
                r.as_dict() for r in _insn_refs(
                    img, insns, owner, target, target_is_address=is_addr)]


@pytest.mark.skipif(not GLAB.exists(), reason="glab 脱壳样本不在本机")
@pytest.mark.skipif(os.environ.get("REKIT_SKIP_PERF") == "1",
                    reason="REKIT_SKIP_PERF=1")
def test_large_go_file_multi_target_under_5min():
    """52 MB 真实目标：字面量多命中也要在 5 分钟内完成（原实现 >5 min 被中止）。"""
    t0 = time.perf_counter()
    payload = analyze_xref(str(GLAB),
                           [{"kind": "string", "value": "https://gitlab.com/"}])
    elapsed = time.perf_counter() - t0
    target = payload["targets"][0]
    assert target["counts"]["resolved"] >= 1
    assert target["counts"]["certain"] >= 1
    assert elapsed < 300, f"xref 用时 {elapsed:.1f}s，超过 5 分钟口径"
