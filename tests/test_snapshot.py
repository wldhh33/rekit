# -*- coding: utf-8 -*-
"""快照回归：基线于 2026-11-11 / 0.6.0 冻结，之后按“递归子集”校验。

只增不改的含义：
- 基线里出现过的键必须仍然存在且值相等（删字段/改值 → 红）；
- 新增键（例如本轮加的顶层 schema_version、错误码 code/message）不算破坏。
"""

from __future__ import annotations

import json
import re

import pytest

from snapshot_util import (
    BASELINE, SIDECAR, assert_subset, build_cases, canonical_bytes,
    file_sha256, mask_environment, normalize, run_case, sample_paths,
)


@pytest.fixture(scope="module")
def baseline() -> dict:
    assert BASELINE.is_file(), f"缺少冻结基线：{BASELINE}"
    return json.loads(BASELINE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def actual(baseline: dict, tmp_path_factory) -> dict[str, dict]:
    tmpdir = tmp_path_factory.mktemp("snapshot")
    paths = sample_paths(tmpdir / "samples")
    out = tmpdir / "out"
    result = {}
    for case in build_cases(out):
        result[case["case_id"]] = normalize(run_case(case, paths, out), paths, tmpdir)
    return result


def test_baseline_hash_matches_sidecar(baseline: dict) -> None:
    recorded = SIDECAR.read_text(encoding="utf-8").split()[0]
    assert file_sha256(canonical_bytes(baseline)) == recorded


def test_baseline_meta_is_self_describing(baseline: dict) -> None:
    meta = baseline["meta"]
    assert meta["date"] == "2026-11-11"
    assert meta["version"] == "0.7.0"
    assert meta["sample_count"] == 20
    assert meta["case_count"] == len(baseline["cases"])
    assert meta["frozen_before"].startswith("B MVP 开工前")


def test_baseline_has_no_timestamps_or_absolute_paths(baseline: dict) -> None:
    text = json.dumps(baseline["cases"], ensure_ascii=False)
    assert "generated_at" not in text
    assert not re.search(r'"seconds":\s*\d', text), "耗时未归一化"
    assert "C:\\\\" not in text and "d:\\\\" not in text, "基线含本机绝对路径"


def test_baseline_covers_all_eight_commands(baseline: dict) -> None:
    assert {c["command"] for c in baseline["cases"]} == {
        "triage", "unpack", "map", "funcs", "data", "xref", "identify", "report",
    }


def test_snapshot_cases_unchanged(baseline: dict, actual: dict[str, dict]) -> None:
    failures = []
    for expected in baseline["cases"]:
        got = actual[expected["case_id"]]
        try:
            assert got["exit_code"] == expected["exit_code"], (
                f"退出码 {expected['exit_code']} -> {got['exit_code']}")
            assert_subset(mask_environment(expected["json"]),
                          mask_environment(got["json"]), expected["case_id"])
        except AssertionError as exc:
            failures.append(str(exc))
    assert not failures, "快照差异：\n" + "\n".join(failures)


# --- 负向测试：证明“删旧字段”确实会让快照机制变红 -------------------------

def test_comparator_rejects_deleted_field() -> None:
    expected = {"results": [{"file": "a.exe", "sha256": "00"}]}
    with pytest.raises(AssertionError, match="旧字段被删除"):
        assert_subset(expected, {"results": [{"file": "a.exe"}]})


def test_comparator_rejects_changed_value() -> None:
    with pytest.raises(AssertionError):
        assert_subset({"verdict": "normal"}, {"verdict": "upx"}, "$")


def test_comparator_rejects_shorter_list() -> None:
    with pytest.raises(AssertionError, match="数组长度"):
        assert_subset({"items": [1, 2]}, {"items": [1]})


def test_comparator_allows_added_field() -> None:
    # 本轮新增 schema_version / code / message 属于“只增”，必须放行
    assert_subset({"a": 1}, {"a": 1, "schema_version": 1})
