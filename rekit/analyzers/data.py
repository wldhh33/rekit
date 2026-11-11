# -*- coding: utf-8 -*-
"""data 分析器 —— 节里到底有什么数据。

回答 D10 的问题：这个二进制有哪些字符串、哪些指针数组是真实的数据表、
哪些函数的入参被当结构体用。字符串分三路取证：

* `c`：NUL/非可打印终止，对 C/C++/Rust 有效；
* `go-code`：调用点的 `lea` + 相邻参数槽长度，**不依赖终止符**；
* `go-data`：数据节里的 `(ptr,len)` 头（Go 的 string/slice 头形状）。

Go 二进制上三路互补：`go-data` 能覆盖全局字符串表，`go-code` 覆盖直接传参，
C 串扫描则会因为无终止符把整个 blob 读成一条超长串——`c_longest` 就是证据。
"""

from __future__ import annotations

from typing import Any

from ..contract import error_entry, no_files_entry
from ..core.data import DataUnavailable, analyze_image_data
from ..core.elf import ElfError
from ..core.files import expand_paths
from ..core.pe import PEError

NAME = "data"
DESCRIPTION = "数据识别：C/Go 字符串、指针数组、结构体字段偏移"
VERSION = "0.1.0"

CSV_FIELDS = ["file", "kind", "address", "length", "section", "encoding", "text"]


def run(paths: list[str], *, min_c_len: int = 6, min_go_len: int = 4,
        utf16: bool = False, arrays: bool = True, structs: bool = True,
        max_items: int = 20000, min_run: int = 4,
        allow_large: bool = False) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    files = expand_paths(paths)
    if not files:
        return {"analyzer": NAME, "results": [], "errors": [no_files_entry(paths)]}
    for path in files:
        try:
            r = analyze_image_data(
                path, min_c_len=min_c_len, min_go_len=min_go_len,
                utf16=utf16, arrays=arrays, structs=structs,
                max_items=max_items, min_run=min_run, allow_large=allow_large)
            if "c_strings" in r:
                r["c_strings"]["longest"] = max(
                    (i["length"] for i in r["c_strings"]["items"]), default=0)
            results.append(r)
        except (PEError, ElfError, DataUnavailable, OSError, ValueError) as e:
            errors.append(error_entry(path, e))
    return {"analyzer": NAME, "results": results, "errors": errors}


def csv_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    f = result["file"]
    for item in result["c_strings"]["items"]:
        rows.append({"file": f, "kind": "c", "address": f"0x{item['address']:X}",
                     "length": item["length"], "section": item["section"],
                     "encoding": item["encoding"], "text": item["text"]})
    for item in result.get("go_strings", {}).get("items", []):
        rows.append({"file": f, "kind": "go",
                     "address": f"0x{item['address']:X}",
                     "length": item["length"], "section": item["section"],
                     "encoding": item.get("evidence", ""), "text": item["text"]})
    return rows
