# -*- coding: utf-8 -*-
"""M2 达标门：四族冷启动可达子集召回 ≥ 50%、严格误报 ≤ 2%。

基线数字与样本 SHA256 / 获得方式冻结在 `tests/baseline/m2_families.json`，
阈值来自 `计划/长期目标.md` 的 M2 判定口径（四族逐族同时满足，不得互补）。

两条断言，缺一不可：

1. **门槛**：`reachable.recall >= 0.5` 且 `fp_text / starts <= 2%`；
2. **不悄悄回退**：实测值与冻结值相差 <= 1pp。只看门槛的话，Clang 从 85.6%
   掉到 60% 仍会"通过"，但那已经不是同一个 M2 了。

`go_win.exe` 是 1.6 MB，按仓库规则不随仓库分发；本地缺失时该族 **skip**（不按通过计），
它的 SHA256 与构建方式仍记录在 fixture 里，换机器可用同一份 `hello_go.go` 重建后核对。
缺样本走参数级 skip 标记（收集期不 skip，否则 pytest 9 会判 collection error）；
另有一条只依赖仓库内夹具的用例 `test_m2_gate_runs_on_in_repo_fixtures`，
保证 CI 上至少有一条 M2 门逻辑真的在跑 —— 但它不覆盖 go_win，**CI 绿不等于四族门已执行**。

**Go linux 50.3% 是刀锋边缘**（分母 1091，缺失的 543 个里 529 个是"镜像内无任何引用"）。
如果某次改动让它掉到 50% 以下，正确处理是如实记"未达标"并把缺口写出来，
不是调阈值、换分母或改可达定义。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("capstone")

from rekit.core.funcs import analyze_image

REPO = Path(__file__).resolve().parents[1]      # rekit/
WORKSPACE = REPO.parent                          # d:\逆向学习
BASELINE = Path(__file__).parent / "baseline" / "m2_families.json"

DOC = json.loads(BASELINE.read_text(encoding="utf-8"))
GATE = DOC["gate"]
DRIFT = 0.01          # 与冻结值允许的最大偏差（1pp）
A_RECALL_MIN = 0.95


def _sample(fam: dict) -> Path:
    return (REPO if fam["sample_in_repo"] else WORKSPACE) / fam["sample"]


def _case(fam: dict):
    path = _sample(fam)
    if not path.exists():
        # 收集期不能调 pytest.skip（会让整个模块变成 collection error），
        # 改成给该参数打 skip 标记：缺样本时如实记为 skipped，而不是报错。
        return pytest.param(
            fam, path, id=fam["id"],
            marks=pytest.mark.skip(
                reason=f"依赖仓库外样本：{fam['sample']}（{fam['size']} B）；"
                       f"SHA256 {fam['sha256']}，重建方式：{fam['acquired']}"))
    return pytest.param(fam, path, id=fam["id"])


CASES = [_case(f) for f in DOC["families"]]


def _assert_gate(fam: dict, path: Path) -> None:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == fam["sha256"], (
        f"{fam['family']} 样本 SHA256 与基线不符（样本被替换或重建版本不同）："
        f"{digest} != {fam['sha256']}")
    r = analyze_image(str(path), cold=True)
    cs = r["metrics"]["cold_start"]
    reach = cs["reachable"]
    starts = r["authority"]["starts"]
    assert starts == fam["starts"], "权威起点数变了，先确认样本没被替换"

    strict_fp = cs["fp_text"] / starts
    # 门槛（长期目标.md M2 判定口径，数值不得在这里被放宽）
    assert reach["recall"] >= GATE["reachable_recall_min"], (
        f"{fam['family']} 可达子集召回 {reach['recall']*100:.2f}% < 50%："
        f"如实记未达标，不要调阈值或换分母")
    assert strict_fp <= GATE["strict_fp_max"], (
        f"{fam['family']} 严格误报 {strict_fp*100:.2f}% > 2%")

    # 与冻结基线比对（防"仍过线但明显回退"）
    assert abs(reach["recall"] - fam["cold"]["reachable_recall"]) <= DRIFT, (
        f"{fam['family']} 可达子集召回漂移：实测 {reach['recall']*100:.2f}%，"
        f"冻结 {fam['cold']['reachable_recall']*100:.2f}%")
    assert abs(cs["recall"] - fam["cold"]["recall"]) <= DRIFT, (
        f"{fam['family']} 冷启动全量召回漂移：实测 {cs['recall']*100:.2f}%，"
        f"冻结 {fam['cold']['recall']*100:.2f}%")
    assert abs(strict_fp - fam["cold"]["strict_fp"]) <= DRIFT


@pytest.mark.parametrize("fam,path", CASES)
def test_m2_cold_start_gate(fam, path):
    """B 层：冷启动可达子集召回 ≥50%、严格误报 ≤2%，且与冻结值一致。"""
    _assert_gate(fam, path)


IN_REPO_CASES = [_case(f) for f in DOC["families"] if f["sample_in_repo"]]


@pytest.mark.parametrize("fam,path", IN_REPO_CASES)
def test_m2_gate_runs_on_in_repo_fixtures(fam, path):
    """CI 上真正执行的 M2 门：只用随仓库分发的夹具（clang / go linux / rust musl）。

    `go_win_amd64` 依赖仓库外样本，CI 上该族为 skipped；本用例保证 CI 至少有一条
    M2 门逻辑在真跑，但它不覆盖 go_win。**CI 绿不等于四族门已执行。**
    """
    _assert_gate(fam, path)


@pytest.mark.parametrize("fam,path", CASES)
def test_m2_a_layer_not_regressed(fam, path):
    """A 层：权威表播种后召回 ≥95%、严格误报 ≤2%（分母 = 权威起点数）。"""
    r = analyze_image(str(path), pointers=True)
    a = r["metrics"]["seeded"]
    starts = r["authority"]["starts"]
    assert a["recall"] >= A_RECALL_MIN
    assert a["fp_text"] / starts <= GATE["strict_fp_max"]
    assert abs(a["recall"] - fam["a_layer"]["recall"]) <= DRIFT
    assert abs(a["fp_text"] / starts - fam["a_layer"]["fp_text"] / starts) <= DRIFT


def test_m2_baseline_covers_four_families():
    """四族一个都不能少：少一族就等于把判定口径偷换成"三族"或"两族"。"""
    ids = {f["id"] for f in DOC["families"]}
    assert ids == {"clang_x64_elf", "go_linux_amd64", "go_win_amd64", "rust_musl_elf"}
    for f in DOC["families"]:
        assert len(f["sha256"]) == 64
        assert f["acquired"]
