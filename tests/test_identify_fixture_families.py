# -*- coding: utf-8 -*-
"""0.7 自建夹具：族 = 链接器提供方（`docs/family.md`）。

覆盖五类，全部由本仓库源码在本机构建（构建配方见 `tests/fixtures/README.md` §0.7）：

| 夹具 | 构建 | family | compiler_frontend | crt_provider | .rsrc |
|---|---|---|---|---|---|
| `rust_msvc.exe` | rustc msvc target | msvc | rustc | ucrt | 无 |
| `rust_gnu.exe` | rustc gnu target + MinGW gcc | gcc | rustc | msvcrt | 有 |
| `cgo_mingw.exe` | go cgo + MinGW gcc | gcc | go | msvcrt | 有 |
| `go_win.exe` | go build 纯 Go | go | go | none | 无 |
| `msvcrt_no_rsrc.exe` | GNU ld 直接链接（去掉 default-manifest.o） | gcc | gcc | msvcrt | 无 |

重点不是“每个样本碰巧判对”，而是：
- `rust` / `clang` 不再是族；前端进 `compiler_frontend`；
- cgo（go 前端 + GNU ld）必须同时留下 go×gcc 冲突，且族取 gcc；
- `.rsrc` 有/无都不改变族（rust_gnu 有、msvcrt_no_rsrc 无，都是 gcc）；
- 纯 Go 的 linker version 是 3.0，不与 GNU ld 的 2.x / MSVC 的 14.x 混淆。
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from rekit.analyzers import identify
from rekit.core import toolchain
from rekit.core.pe import PE

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "round7"

# 文件名 → (family, compiler_frontend, crt_provider, 是否有 .rsrc, linker major)
CASES = {
    "rust_msvc.exe": ("msvc", "rustc", "ucrt", False, 14),
    "rust_gnu.exe": ("gcc", "rustc", "msvcrt", True, 2),
    "cgo_mingw.exe": ("gcc", "go", "msvcrt", True, 2),
    "go_win.exe": ("go", "go", "none", False, 3),
    "msvcrt_no_rsrc.exe": ("gcc", "gcc", "msvcrt", False, 2),
}


@pytest.mark.parametrize("name", list(CASES))
def test_fixture_family_is_linker_provider(name: str) -> None:
    path = FIXTURES / name
    if not path.exists():
        pytest.skip(f"夹具不在本机：{path}")
    want_family, want_frontend, want_crt, want_rsrc, want_linker_major = CASES[name]

    r = identify.analyze_file(str(path))
    assert r["schema_version"] == 3
    assert r["family"] == want_family
    assert r["family"] in toolchain.FAMILIES
    assert r["compiler_frontend"] == want_frontend
    assert r["crt_provider"] == want_crt
    assert r["bitness"] == "x64" and r["scope"] == "in_m4a"

    with PE(str(path)) as pe:
        sections = [s.name for s in pe.sections]
        linker = (pe.optional_major_linker, pe.optional_minor_linker)
    assert (".rsrc" in sections) is want_rsrc, f"{name} 的 .rsrc 观测与构建不符"
    assert linker[0] == want_linker_major, f"{name} 的 linker version 变了：{linker}"


def test_cgo_conflict_visible_and_go_pure_has_none() -> None:
    cgo = FIXTURES / "cgo_mingw.exe"
    pure = FIXTURES / "go_win.exe"
    if not (cgo.exists() and pure.exists()):
        pytest.skip("夹具不在本机")

    cgo_r = identify.analyze_file(str(cgo))
    assert cgo_r["family"] == "gcc"
    assert cgo_r["conflicts"], "cgo 的 go×gcc 冲突必须可见"
    between = set(cgo_r["conflicts"][0]["between"])
    assert between == {"go", "gcc"}
    assert "gcc" in cgo_r["conflicts"][0]["note"]

    pure_r = identify.analyze_file(str(pure))
    assert pure_r["family"] == "go"
    assert pure_r["conflicts"] == []


def test_rsrc_presence_does_not_change_family() -> None:
    """同一 gcc 族、同源 C 代码，有无 .rsrc 都必须是 gcc。"""
    with_rsrc = FIXTURES / "rust_gnu.exe"
    without = FIXTURES / "msvcrt_no_rsrc.exe"
    if not (with_rsrc.exists() and without.exists()):
        pytest.skip("夹具不在本机")
    a = identify.analyze_file(str(with_rsrc))
    b = identify.analyze_file(str(without))
    assert a["family"] == b["family"] == "gcc"
    assert a["crt_provider"] == b["crt_provider"] == "msvcrt"
    assert os.path.exists(with_rsrc) and os.path.exists(without)
