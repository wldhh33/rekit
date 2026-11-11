# -*- coding: utf-8 -*-
"""`rekit data` 的回归测试：字符串、指针数组、结构体字段偏移。

ground truth 全部来自 `tests/fixtures/` 的自编译样本：
* `hello_c.c` 里的 `binop table[2] = {fx_add, fx_mul}` → 代码指针表；
* `struct_probe.rs` 的 `#[repr(C)]` 布局 → 偏移 0/4/8/0x10；
* Go 样本的 `hello from Go` 字面量 → 无终止符下的恢复能力。
"""

from pathlib import Path

import pytest

from rekit.analyzers.data import run as run_data
from rekit.core.data import (analyze_image_data, infer_struct_fields,
                             scan_c_strings, scan_go_strings,
                             scan_pointer_arrays)
from rekit.core.elf import open_image
from rekit.core.funcs import authority_table
from rekit.core.pe import PE

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> str:
    path = FIXTURES / name
    if not path.exists():
        pytest.skip(f"缺少 fixture：{name}")
    return str(path)


def test_c_strings_are_found_in_c_binary():
    result = scan_c_strings(open_image(_fixture("gcc_o2.exe")))
    texts = [i["text"] for i in result["items"]]
    assert any("hello from C" in t for t in texts)
    assert all(i["length"] >= 6 for i in result["items"])


def test_go_binary_has_no_terminators_so_c_scan_overruns():
    result = scan_c_strings(open_image(_fixture("go_linux_amd64")))
    longest = max(i["length"] for i in result["items"])
    # Go 的字符串 blob 里没有 NUL，C 串扫描必然把多个字面量并成一条超长串。
    assert longest > 1000


def test_go_strings_recovered_from_call_sites_and_data_headers():
    result = analyze_image_data(_fixture("go_linux_amd64"), arrays=False,
                                structs=False)
    assert result["is_go"] is True
    go = result["go_strings"]
    assert go["supported"] is True
    # 代码站点恢复：调用点的 lea + 相邻参数槽长度
    assert go["sites"] > 0
    assert go["naive_would_overread"] > 0
    # 数据头恢复：hello from Go 是通过全局 string 头传递的，只能从 (ptr,len) 得到
    hello = [i for i in go["items"] if i["text"] == "hello from Go"]
    assert hello, "未能恢复 hello from Go"
    assert hello[0]["evidence"] in ("data-pair", "code+data")


def test_go_strings_are_not_reported_on_non_go_binary():
    result = analyze_image_data(_fixture("gcc_o2.exe"), arrays=False,
                                structs=False)
    assert result["is_go"] is False
    assert result["go_strings"]["count"] == 0


def test_pointer_array_ground_truth_hits_authority_starts():
    path = _fixture("gcc_o2.exe")
    img = open_image(path)
    starts = set(authority_table(img).starts)
    result = scan_pointer_arrays(img, min_run=2, authority_starts=starts)
    code_tables = [a for a in result["arrays"] if a["target_class"] == "code"]
    assert code_tables, "未找到代码指针表"
    # hello_c.c 的 binop table[2] 两项都是真函数入口
    best = max(code_tables, key=lambda a: a.get("authority_start_ratio", 0))
    assert best["count"] == 2
    assert best["authority_start_ratio"] == 1.0
    text = next(s for s in img.sections if s.is_executable)
    base = 0 if not isinstance(img, PE) else img.image_base
    for target in best["first_targets"]:
        assert base + text.virtual_address <= target < base + text.virtual_address + len(text.raw)


def test_pointer_array_skips_relocation_sections():
    img = open_image(_fixture("hello_elf"))
    result = scan_pointer_arrays(img, min_run=2)
    assert result["arrays"], "hello_elf 应当有可报的数据表"
    for a in result["arrays"]:
        low = a["section"].lower()
        assert "got" not in low and "plt" not in low, f"重定位槽被误报：{a['section']}"


def test_struct_probe_layout_matches_repr_c():
    path = _fixture("struct_probe.exe")
    img = open_image(path)
    expected = {(0, 1), (4, 4), (8, 8), (16, 8)}
    exports = {e.name: img.image_base + e.rva for e in img.exports()}
    result = infer_struct_fields(img)
    by_start = {f["start"]: f for f in result["functions"]}
    for name in ("probe_read", "probe_write"):
        assert name in exports, f"{name} 未导出，fixture 构建参数可能丢了 /EXPORT"
        fn = by_start.get(exports[name])
        assert fn is not None, f"{name} 没有被结构体统计覆盖"
        got = {(f["offset"], f["width"]) for f in fn["fields"]}
        assert expected <= got, f"{name} 字段偏移不符：{sorted(got)}"


def test_data_analyzer_output_contract():
    payload = run_data([_fixture("gcc_o2.exe")], structs=False, arrays=True)
    assert payload["errors"] == []
    r = payload["results"][0]
    for key in ("file", "format", "bits", "is_go", "sections", "c_strings",
                "go_strings", "string_pairs", "pointer_arrays"):
        assert key in r
    assert r["format"] == "PE"
    assert r["bits"] == 64
    assert isinstance(r["sections"], list)
