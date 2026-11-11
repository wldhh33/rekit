# -*- coding: utf-8 -*-
"""rekit 规则引擎（M5）：求值、同源 `.yar` 生成、口径约束。

这些用例只验证“条件布尔求值 + 证据偏移”和标注文字，不验证与 YARA 等价。
"""

from __future__ import annotations

import json
import os

import pytest

from rekit.core import rules
from rekit.core.pe import PE

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "m5.json")
RULES_PATH = os.path.abspath(RULES_PATH)
GO_PE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..",
                                     "实践", "M3", "02-gocrackme", "sample",
                                     "goCrackMe.exe"))
RUST_PE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..",
                                       "实践", "M3", "01-rust-xor-easy", "sample",
                                       "rustpj.exe"))


def test_rule_file_is_well_formed():
    payload = rules.load_rules(RULES_PATH)
    ids = [r["id"] for r in payload["rules"]]
    assert len(ids) == len(set(ids))
    assert set(ids) == {"dotnet_assembly", "go_binary", "upx_packed",
                        "high_entropy_section"}


def test_unknown_fact_is_rejected(tmp_path):
    bad = {"rules": [{"id": "x", "any": [[{"fact": "nope", "op": "eq",
                                           "value": True}]]}]}
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(rules.RulesError):
        rules.load_rules(str(path))


@pytest.mark.skipif(not os.path.exists(GO_PE), reason="缺少 Go 样本")
def test_go_sample_hits_go_binary_with_offset():
    payload = rules.load_rules(RULES_PATH)
    with PE(GO_PE) as pe:
        result = rules.run(pe, payload)
    assert result["hit_ids"] == ["go_binary"]
    hit = next(r for r in result["results"] if r["matched"])
    assert any(e["offset"] for e in hit["evidence"])
    assert result["engine"] == rules.ENGINE_NAME
    assert result["yara_compatible"] is False


@pytest.mark.skipif(not os.path.exists(RUST_PE), reason="缺少原生样本")
def test_native_sample_hits_nothing():
    payload = rules.load_rules(RULES_PATH)
    with PE(RUST_PE) as pe:
        result = rules.run(pe, payload)
    assert result["hit_ids"] == []
    assert all(r["matched"] is False for r in result["results"])


def test_yara_rendering_never_claims_compatibility():
    payload = rules.load_rules(RULES_PATH)
    text = rules.render_yara(payload, None)
    assert "不是 YARA 兼容实现" in text
    assert "未经 YARA 校验" in text
    assert "yara_validated = false" in text
    # 只翻译得出来的规则才生成；.NET/熵规则必须显式列为“未生成”
    assert "rekit_m5_go_binary" in text
    assert "rekit_m5_upx_packed" in text
    assert "规则 dotnet_assembly 全部未翻译" in text
    assert "规则 high_entropy_section 全部未翻译" in text


def test_yara_rendering_records_passed_validation_without_equivalence():
    payload = rules.load_rules(RULES_PATH)
    text = rules.render_yara(payload, {"status": "通过", "detail": "测试记录"})
    assert "YARA 校验：通过" in text
    assert "语义不等价" in text
    assert "yara_validated = true" in text
