# -*- coding: utf-8 -*-
"""UPX 加壳不改写 PE 可选头 linker version（LV-001 普查结论的回归锁定）。

背景：T15/T16 从可选头 +2/+3 读 Major/MinorLinkerVersion（`docs/family.md` §1.1）。
2026-11-12 普查（`工具库/pe/linker_ver_scan.py`，证据 `实践/2026-11-12-linkerver-survey/`）：

- UPX 5.0.0 `--best` 三对外部样本（7z / hello_rs / notepad_ms）加壳前后字段逐值不变；
- System32 顶层 4202 个 PE 中 2.x 出现 0 次；自建 M4 语料 340 文件三值（14.29/2.47/3.0）
  与三族零重叠。

本测试用仓库内 UPX 对（`tests/fixtures/hello_rs.exe` / `hello_rs.packed.exe`）钉死该性质，
防止未来壳处理 / 头重建代码无意改写该字段（同型教训：`SizeOfCode` 偏移取错导致
反过滤覆盖错误，见 CHANGELOG 2026-11-12）。
"""

from __future__ import annotations

from pathlib import Path

from rekit.core.pe import PE

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _header(path: Path) -> tuple[tuple[int, int], list[str]]:
    with PE(str(path)) as pe:
        linker = (pe.optional_major_linker, pe.optional_minor_linker)
        sections = [s.name for s in pe.sections]
    return linker, sections


def test_upx_packing_preserves_linker_version() -> None:
    plain, plain_sections = _header(FIXTURES / "hello_rs.exe")
    packed, packed_sections = _header(FIXTURES / "hello_rs.packed.exe")

    assert plain == (14, 29), f"基准夹具 linker version 变了: {plain}"
    assert any(n.startswith("UPX") for n in packed_sections), (
        "hello_rs.packed.exe 不含 UPX 节，夹具可能被替换为未加壳副本，测试失去意义"
    )
    assert packed == plain, (
        "UPX 壳改写了 linker version 字段；T15/T16 对加壳样本的读数将被污染，"
        "需在壳处理代码中核对可选头拷贝逻辑"
    )
