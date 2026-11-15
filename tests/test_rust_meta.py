# -*- coding: utf-8 -*-
"""`rekit rust` / `rekit.core.rust_meta` 的回归测试。

覆盖：
    1. 纯函数的分类口径（混合分隔符、只认 40 位提交、非 `.rs` 串不算路径）；
    2. 真实 Rust 产物夹具（`实践/M3/01-rust-xor-easy/sample/rustpj.exe`）：
       提交哈希、strip 状态、`.pdata` 条目、`&str` 常量对；
    3. 反例：非 Rust PE 不产出语言证据；无 `.pdata` 时明确拒绝归到函数；
    4. CLI 的 JSON 契约。
"""

from __future__ import annotations

import json
import os

import pytest

from rekit.core import funcs, rust_meta
from rekit.core.pe import PE

RUST_PE = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "实践", "M3", "01-rust-xor-easy",
    "sample", "rustpj.exe"))
NOTPAD = r"C:\Windows\System32\notepad.exe"
COMMIT = "58cf8f9c35b355199727627d07ae34a4e2846d67"


def _strings(*items: str) -> list[tuple[int, bytes]]:
    return [(0x1000 + i * 0x100, s.encode("latin-1")) for i, s in enumerate(items)]


def test_classify_mixed_separators_and_buckets():
    facts = rust_meta._classify(_strings(
        f"/rustc/{COMMIT}\\library\\core\\src\\fmt\\mod.rs",  # 提交号后是反斜杠（eza 形态）
        r"C:\Users\runneradmin\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f"
        r"\serde-1.0.219\src\lib.rs",
        r"C:\Users\leet1337\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin",
        r"src\cli.rs",
    ))
    assert facts["rustc_commits"] == [COMMIT]
    assert facts["crates"] == [{"crate": "serde-1.0.219", "strings": 1}]
    assert facts["rustup_toolchains"] == ["stable-x86_64-pc-windows-msvc"]
    assert facts["build_users"] == [r"C:\Users\runneradmin", r"C:\Users\leet1337"]
    # std / crate / app 三个桶按来源分开，不合并
    assert facts["path_strings"] == {
        "total": 3, "embedded": 0, "std": 1, "crate": 1, "app": 1}


def test_classify_keeps_build_metadata_version():
    facts = rust_meta._classify(_strings(
        r"/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libgit2-sys-0.18.5+1.9.4/lib.rs",
    ))
    assert facts["crates"] == [{"crate": "libgit2-sys-0.18.5+1.9.4", "strings": 1}]


def test_utf16le_crate_path_is_recognized():
    # deno 的 libz-sys 路径只以 UTF-16LE 存在；宽字符串要走单独的正则再解码
    raw = r"C:\Users\runneradmin\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f" \
          r"\libz-sys-1.1.20\src\lib.rs"
    wide = raw.encode("utf-16-le")
    m = rust_meta._PRINTABLE_W.search(wide)
    assert m is not None
    text = m.group(0).decode("utf-16-le").encode("latin-1", "replace").decode("latin-1")
    assert rust_meta._classify([(0x1000, text.encode("latin-1"))])["crates"] == [
        {"crate": "libz-sys-1.1.20", "strings": 1}]


def test_classify_isolates_tail_merged_paths():
    # 链接器尾部合并：可打印串前段是别的字面量，不能当源码路径计数
    facts = rust_meta._classify(_strings(
        "*.Failed to read from stdinsrc/main.rs",
        r"src\main.rs",
    ))
    assert facts["path_strings"]["embedded"] == 1
    assert facts["path_strings"]["app"] == 1
    assert facts["path_strings"]["total"] == 2


def test_classify_rejects_short_commit_and_non_rs():
    facts = rust_meta._classify(_strings(
        "/rustc/58cf8f9c/library\\std\\src\\sync\\once.rs",  # 提交不足 40 位
        r"C:\Users\x\.cargo\registry\src\idx\serde-1.0.0\src\lib.toml",  # 不是 .rs
        "panicked at src/main.rs:1:1",  # 消息里带 .rs 但不是独立路径串
    ))
    assert facts["rustc_commits"] == []
    # crate 目录本身即依赖证据（不要求文件是 .rs）
    assert facts["crates"] == [{"crate": "serde-1.0.0", "strings": 1}]
    # 短提交仍是一条 `.rs` 路径，但没有可用的 rustc 提交
    assert facts["path_strings"] == {
        "total": 1, "embedded": 0, "std": 1, "crate": 0, "app": 0}
    assert facts["panic_markers"] == {"panicked at": 1}


@pytest.fixture(scope="module")
def rust_img():
    if not os.path.exists(RUST_PE):
        pytest.skip(f"缺少 Rust 夹具：{RUST_PE}")
    with PE(RUST_PE) as pe:
        yield pe


def test_real_rust_facts(rust_img):
    facts = rust_meta.scan(rust_img)
    ev = facts["language_evidence"]
    assert ev["rustc_commit"] == COMMIT          # 只认 rustc 发行的 std 源码根
    assert facts["path_strings"]["std"] > 0
    assert facts["structure"]["name_status"] == "none"
    assert facts["structure"]["pdata_entries"] > 50
    assert facts["structure"]["fptable"] is None or isinstance(
        facts["structure"]["fptable"]["all_zero"], bool)


def test_real_str_pairs(rust_img):
    strings = rust_meta.ascii_strings(rust_img)
    pairs = rust_meta.str_pair_index(rust_img, strings)
    assert pairs, "真实 Rust 产物应至少有一个 &str 常量对"
    by_va = {va: s for va, s in strings}
    for str_va in pairs.values():
        assert by_va[str_va].endswith(b".rs")


def test_no_pdata_refuses_attribution(rust_img, monkeypatch):
    monkeypatch.setattr(funcs, "pdata_spans", lambda _pe: [])
    got = rust_meta.map_refs(rust_img, {0x1000: "x"})
    assert got["reason"].startswith("无 .pdata")
    assert got["refs"] == 0


def test_non_rust_pe_has_no_language_evidence():
    if not os.path.exists(NOTPAD):
        pytest.skip("缺少系统 notepad.exe")
    with PE(NOTPAD) as pe:
        facts = rust_meta.scan(pe)
    assert facts["language_evidence"]["rustc_commit"] is None
    assert facts["crates"] == []
    assert facts["path_strings"]["total"] == 0
    assert facts["structure"]["name_status"] == "none"


def test_cli_json_contract(rust_img, tmp_path):
    from rekit import cli

    out = tmp_path / "rust.json"
    rc = cli.main(["rust", RUST_PE, "-j", str(out)])
    assert rc == 0
    blob = json.loads(out.read_text(encoding="utf-8"))
    assert blob["errors"] == []
    row = blob["results"][0]
    assert row["language_evidence"]["rustc_commit"] == COMMIT
    assert row["structure"]["pdata_entries"] > 0
    assert "str_pairs" in row
