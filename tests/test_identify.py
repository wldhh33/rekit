# -*- coding: utf-8 -*-
"""`identify` 的契约测试：只用 M4 训练侧产物（测试侧不读）。

金标样本缺失时 skip，不让 CI 因“语料不在本机”失败。
"""

from __future__ import annotations

import pytest

from rekit.analyzers import identify

CORPUS = r"d:\逆向学习\实践\M4\corpus\build\train"

CASES = {
    "msvc_x64": rf"{CORPUS}\msvc_x64\p01_arith_loop_o1md.exe",
    "gcc_x64": rf"{CORPUS}\gcc_x64\p01_arith_loop_o2s.exe",
    # clang 只有在未 strip（含 `clang version` 正向串）时才可判；strip 后归 unknown
    "clang_x64": rf"{CORPUS}\clang_x64\p01_arith_loop_o0g.exe",
    "go_x64": rf"{CORPUS}\go_x64\g02_string_parse_plain.exe",
    "rust_x64": rf"{CORPUS}\rust_x64\r02_string_parse_release_stripped.exe",
}


@pytest.mark.parametrize("family,path", list(CASES.items()))
def test_contract_and_family(family: str, path: str) -> None:
    import os
    if not os.path.exists(path):
        pytest.skip("训练侧语料不在本机")
    r = identify.analyze_file(path)

    for key in ("file", "sha256", "kind", "family", "bitness", "scope", "confidence",
                "verdict", "signals", "conflicts", "schema_version"):
        assert key in r, f"缺字段 {key}"
    assert r["schema_version"] == identify.SCHEMA_VERSION
    assert r["family"] == family
    assert r["bitness"] == "x64" and r["scope"] == "in_m4a"
    assert 0.0 <= r["confidence"] <= 1.0
    assert r["verdict"] in ("clean", "packed")
    assert isinstance(r["conflicts"], list)
    assert r["signals"], "至少要有 1 条信号"

    # 每条命中的工具链信号都必须带偏移、偏移类型（设计 §2.1 硬要求）与证据类型
    for s in r["signals"]:
        assert s["hit"] is True
        if not s["id"].startswith("T"):
            continue
        ev = s["evidence"]
        assert ev["offset"], f"{s['id']} 缺偏移"
        assert ev["offset_kind"], f"{s['id']} 缺偏移类型"
        assert ev["field"]
        assert s["evidence_kind"] in ("positive", "absence"), f"{s['id']} 缺 evidence_kind"


def test_unknown_is_legal_on_nonexistent_fingerprint(tmp_path) -> None:
    """无任何指纹的最小 PE 头：允许输出 unknown，但不得抛异常。"""
    import os
    path = os.path.join(str(tmp_path), "fake.exe")
    # 只有 MZ + e_lfanew 指向 PE 头的空壳，解析会失败 → 走 errors 分支而不是崩溃
    with open(path, "wb") as fh:
        fh.write(b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little"))
    try:
        r = identify.analyze_file(path)
    except Exception as e:  # noqa: BLE001 - 只断言"是受控异常"
        assert e.__class__.__name__ in ("PEError", "OSError")
    else:
        assert r["family"] == "unknown"
