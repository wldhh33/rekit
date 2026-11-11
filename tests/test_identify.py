# -*- coding: utf-8 -*-
"""`identify` 的契约测试：只用 M4 训练侧产物（测试侧不读）。

0.7 起 `family` 是**链接器提供方**（`docs/family.md`），不是编译器前端：
- `rust_x64` 训练样本用 `link.exe` 链接 → `family=msvc`、`compiler_frontend=rustc`；
- `clang_x64` 训练样本走 MinGW GNU `ld` → `family=gcc`、`compiler_frontend=clang`；
- strip 后的 clang 样本仍归 `gcc`（族看链接器），前端信息丢失只是附加字段的变化。

金标样本缺失时 skip，不让 CI 因“语料不在本机”失败。
"""

from __future__ import annotations

import os

import pytest

from rekit.analyzers import identify

CORPUS = r"d:\逆向学习\实践\M4\corpus\build\train"

# (样本, 期望 family, 期望 compiler_frontend)
CASES = {
    "msvc_x64": (rf"{CORPUS}\msvc_x64\p01_arith_loop_o1md.exe", "msvc", "msvc-cl"),
    "gcc_x64": (rf"{CORPUS}\gcc_x64\p01_arith_loop_o2s.exe", "gcc", "gcc"),
    # clang 只有在未 strip（含 `clang version` 正向串）时才可判前端；族始终是 gcc
    "clang_x64": (rf"{CORPUS}\clang_x64\p01_arith_loop_o0g.exe", "gcc", "clang"),
    "go_x64": (rf"{CORPUS}\go_x64\g02_string_parse_plain.exe", "go", "go"),
    "rust_x64": (rf"{CORPUS}\rust_x64\r02_string_parse_release_stripped.exe", "msvc", "rustc"),
}


@pytest.mark.parametrize("case", list(CASES))
def test_contract_and_family(case: str) -> None:
    path, want_family, want_frontend = CASES[case]
    if not os.path.exists(path):
        pytest.skip("训练侧语料不在本机")
    r = identify.analyze_file(path)

    for key in ("file", "sha256", "kind", "family", "compiler_frontend", "crt_provider",
                "target_triple", "bitness", "scope", "confidence", "verdict",
                "signals", "conflicts", "schema_version"):
        assert key in r, f"缺字段 {key}"
    assert r["schema_version"] == identify.SCHEMA_VERSION == 3
    assert r["family"] == want_family
    assert r["compiler_frontend"] == want_frontend
    assert r["family"] in toolchain_families()
    assert r["crt_provider"] in ("msvcrt", "ucrt", "static", "none", "unknown")
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


def toolchain_families() -> tuple[str, ...]:
    from rekit.core import toolchain

    return toolchain.FAMILIES


def test_unknown_is_legal_on_nonexistent_fingerprint(tmp_path) -> None:
    """无任何指纹的最小 PE 头：允许输出 unknown，但不得抛异常。"""
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
