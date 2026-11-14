# -*- coding: utf-8 -*-
"""`rekit report` 的字段口径（M5）：24 字段 = 22 自动 + 2 人工。"""

from __future__ import annotations

import os
import struct

import pytest

from rekit.analyzers import report

RUST_PE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..",
                                       "实践", "M3", "01-rust-xor-easy", "sample",
                                       "rustpj.exe"))
RULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..",
                                          "rules", "m5.json"))
# glab v1.129.0 的 UPX 脱壳件：Go 1.27.3，pclntab 在 .rdata，没有 .gopclntab 节。
GLAB_UNPACKED = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "实践", "2026-11-13-real-target-glab",
    "unpacked_canonical", "v41-go-glab-1129_upx.unpacked.exe"))


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


@pytest.mark.skipif(not os.path.exists(GLAB_UNPACKED), reason="缺少 glab 脱壳样本")
def test_auto_detects_pclntab_embedded_in_rdata():
    """auto 必须识别“pclntab 在 .rdata、无 .gopclntab 节”的 Go 样本。

    夹具是真实目标 glab v1.129.0 的 UPX 脱壳件（Go 1.27.3）。
    """
    payload = report.analyze_file(GLAB_UNPACKED, "glab", family="auto")
    assert payload["family_group"] == "go"
    fields = {f["id"]: f["value"] for f in payload["fields"]}
    assert ".gopclntab" not in fields["sections"]
    assert ".rdata" in fields["sections"]
    assert "43295/" in fields["family_inventory_1"]
    assert "main.main" in fields["family_inventory_2"]


def _write_minimal_pe(path: str) -> None:
    """无导入、无 Rich 头、链接器版本 0 的最小 PE32+：identify 只能给 unknown。"""
    e_lfanew, opt_size = 0x40, 0xF0
    dos = bytearray(0x40)
    struct.pack_into("<H", dos, 0, 0x5A4D)
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    body = bytearray(b"PE\0\0")
    body += struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, opt_size, 0x22)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)
    struct.pack_into("<I", opt, 56, 0x2000)
    struct.pack_into("<I", opt, 60, 0x200)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<I", opt, 108, 16)
    body += opt
    body += struct.pack("<8sIIIIIIHHI", b".text", 0x10, 0x1000, 0x200, 0x200,
                        0, 0, 0, 0, 0x60000020)
    blob = bytes(dos) + bytes(body)
    blob += b"\0" * (0x200 - len(blob)) + b"\xC3" + b"\0" * 0x1FF
    with open(path, "wb") as fh:
        fh.write(blob)


def test_auto_reports_unknown_instead_of_native(tmp_path):
    """没有 CLR/Go 元数据、identify 也判 unknown 时，auto 必须报“无法判定”。"""
    path = str(tmp_path / "minimal.exe")
    _write_minimal_pe(path)
    payload = report.analyze_file(path, "minimal", family="auto")
    assert payload["family_group"] == "unknown"
    fields = {f["id"]: f["value"] for f in payload["fields"]}
    assert fields["family_version"].startswith("无法判定")
    assert "原生" not in fields["family_version"]
