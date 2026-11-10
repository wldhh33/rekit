# -*- coding: utf-8 -*-
"""System32 真实语料回归基准（防权重/阈值被悄悄改动）。

基准数据 tests/baseline/sys32_140.json 来自 2026-11-10 的真实跑批：
140 个 System32 PE，全部判定 normal，0 失败，其中 11 个因「导入为空」得 1 分。

一次命令复现文档里的全部数字：
    python -m pytest tests/test_baseline.py -q

任何权重、阈值或判定分支的改动都会让这里的断言失败 —— 这是故意的。
"""

from __future__ import annotations

import json
from pathlib import Path

from rekit.analyzers import triage
from rekit.analyzers.triage import Signal

BASELINE = Path(__file__).parent / "baseline" / "sys32_140.json"
DOC = Path(__file__).parents[1] / "docs" / "triage-batch.md"

WEIGHTS = {
    "S1_upx_section_pair": triage.W_UPX_PAIR,
    "S2_upx_section_any": triage.W_UPX_ANY,
    "S3_zero_raw_exec_section": triage.W_ZERO_RAW_EXEC,
    "S4_high_entropy_section": triage.W_HIGH_ENTROPY,
    "S5_import_truncated": triage.W_IMPORT_TRUNCATED,
    "S6_import_empty": triage.W_IMPORT_EMPTY,
}


def _load() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def _signals(entry: dict, overrides: dict[str, int] | None = None) -> list[Signal]:
    weights = dict(WEIGHTS)
    weights.update(overrides or {})
    return [Signal(sid, w, sid in entry["hits"], "") for sid, w in weights.items()]


def test_baseline_fixture_is_complete():
    data = _load()
    assert len(data["files"]) == 140
    assert data["errors"] == 0
    assert len({f["file"] for f in data["files"]}) == 140


def test_baseline_scores_are_reproducible_with_current_weights():
    """当前权重必须能复算出基准里的每一个分数与判定。"""
    for entry in _load()["files"]:
        signals = _signals(entry)
        assert triage.score_of(signals) == entry["score"], entry["file"]
        assert triage.verdict_of(entry["score"], signals) == entry["verdict"], entry["file"]


def test_system32_has_zero_false_positives():
    files = _load()["files"]
    assert all(f["verdict"] == "normal" for f in files)
    assert max(f["score"] for f in files) == 1
    one_point = [f for f in files if f["score"] == 1]
    assert len(one_point) == 11
    # 这 11 个全部只命中「导入为空」，且都是资源型 DLL / API Set 描述符
    assert all(f["hits"] == ["S6_import_empty"] for f in one_point)


def test_s6_weight_five_would_cause_7_9_percent_false_positives():
    """S6 权重从 1 提到 5，这 11 个正常文件会变成 packed?，即 7.9% 假阳性。"""
    files = _load()["files"]
    flipped = [
        f for f in files
        if triage.verdict_of(triage.score_of(_signals(f, {"S6_import_empty": 5})),
                             _signals(f, {"S6_import_empty": 5})) != "normal"
    ]
    assert len(flipped) == 11
    assert all(f["hits"] == ["S6_import_empty"] for f in flipped)
    assert round(len(flipped) / len(files) * 100, 1) == 7.9


def test_docs_quote_the_same_numbers_and_command():
    text = DOC.read_text(encoding="utf-8")
    assert "140" in text and "7.9%" in text and "11" in text
    assert "test_baseline.py" in text
