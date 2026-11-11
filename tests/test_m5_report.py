# -*- coding: utf-8 -*-
"""`rekit report` 的字段口径（M5）：24 字段 = 22 自动 + 2 人工。"""

from __future__ import annotations

import os

import pytest

from rekit.analyzers import report

RUST_PE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..",
                                       "实践", "M3", "01-rust-xor-easy", "sample",
                                       "rustpj.exe"))
RULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..",
                                          "rules", "m5.json"))


@pytest.mark.skipif(not os.path.exists(RUST_PE), reason="缺少原生样本")
def test_report_field_contract():
    payload = report.analyze_file(RUST_PE, "native-rust-xor", family="native",
                                  rules_path=RULES_PATH)
    fields = payload["fields"]
    assert len(fields) == 24
    assert [f["id"] for f in fields if f["source"] == "human"] == \
        ["conclusion", "recommendation"]
    assert payload["field_stats"] == {"total": 24, "auto": 22, "human": 2,
                                      "auto_ratio": 0.9167}
    # 自动字段不能为空；人工字段必须留空
    assert all(str(f["value"]).strip() for f in fields if f["source"] == "auto")
    assert all(not f["value"] for f in fields if f["source"] == "human")
    assert payload["sample"]["sha256"]
    assert payload["sample"]["id"] == "native-rust-xor"
    assert payload["identify"]["packer"]["signals_version"]
    blob = str(payload)
    assert RUST_PE not in blob
    assert os.path.dirname(RUST_PE) not in blob


@pytest.mark.skipif(not os.path.exists(RUST_PE), reason="缺少原生样本")
def test_markdown_states_field_split_and_rule_engine():
    payload = report.analyze_file(RUST_PE, "native-rust-xor", family="native",
                                  rules_path=RULES_PATH)
    text = report.render_markdown(payload, "0.6.0")
    assert "22 个自动推导" in text
    assert "2 个人工判断" in text
    assert "rekit 规则引擎" in text
    assert "非 YARA 兼容" in text
    # 不允许出现“壳族识别达标”这类被禁止的口径
    assert "壳族识别达标" not in text
