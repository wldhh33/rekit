# -*- coding: utf-8 -*-
"""锁死“只有测试侧能出判定”的口径（2026-11-22 用户决定）。

训练/校准侧是写信号、定权重用的那批样本，在上面的 100% 只证明拟合；
判定（达标/证据不足/未达标）只能来自与开发过程隔离的测试侧。
"""

from __future__ import annotations

import importlib.util
import os

import pytest

EVAL = r"d:\逆向学习\实践\M4\eval\eval_identify.py"
VERDICTS = ("达标", "证据不足", "未达标")


def _load():
    if not os.path.exists(EVAL):
        pytest.skip("M4 评估脚本不在本机")
    spec = importlib.util.spec_from_file_location("m4_eval_identify", EVAL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _rows(n: int = 20) -> list[dict]:
    return [{"truth": "msvc_x64", "pred": "msvc_x64", "confidence": 0.97} for _ in range(n)]


def test_dev_sides_never_emit_verdict() -> None:
    mod = _load()
    for side in ("train", "calib"):
        st = mod.per_family(_rows(), side)
        assert st["_verdict_applicable"] is False
        for fam in mod.FAMILIES:
            assert st[fam]["verdict"] == mod.SELF_CHECK_LABEL
            assert st[fam]["verdict"] not in VERDICTS


def test_test_side_emits_verdict() -> None:
    mod = _load()
    st = mod.per_family(_rows(20), "test")
    assert st["_verdict_applicable"] is True
    assert st["msvc_x64"]["verdict"] == "达标"   # 20/20 → 点估计 100%、CI 下界 83.9%


def test_require_verdict_asserts_on_dev_side() -> None:
    mod = _load()
    with pytest.raises(AssertionError):
        mod.per_family(_rows(), "train", require_verdict=True)
    with pytest.raises(AssertionError):
        mod.per_family(_rows(), "calib", require_verdict=True)
    # 测试侧必须放行，否则断言会把正常评估也拦掉
    mod.per_family(_rows(), "test", require_verdict=True)
