# -*- coding: utf-8 -*-
"""M1 B4 —— 跨类别 500 个文件的解析结果基线（零差异回归）。

背景：M1 用 `工具库/pe/verify_with_pefile.py` 对 2,783 个系统文件跑了 72,358 次逐字段
交叉校验，结果全是 0 差异。但那是"某天某次跑出来的数字"，不是能反复执行的断言。
这里把那批结果按类别等距抽样 500 个，把 rekit 解析出的每个字段固化成 fixture：

    python tests/test_m1_baseline.py     # 重新生成 tests/baseline/m1_500.json（需本机有语料）
    python -m pytest tests/test_m1_baseline.py -q

语料是 Windows 系统文件，换一台机器可能没有；缺失的文件按 skip 计，全部缺失则整个用例
skip（并提示怎么准备语料），不会假装通过。
"""

from __future__ import annotations

import hashlib
import json
import os
import statistics
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rekit.core.pe import PE, PEError  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "baseline" / "m1_500.json"
CORPUS_DIR = ROOT.parent / "实践" / "2026-11-11-m1"

# 每个类别从哪个 CSV 抽、抽多少。总数 500，按 M1 语料的类别占比等距取。
# 最后一项 True 表示只取 CSV 里该 class 的行；huge.csv 整份就是大文件语料，
# 其中部分文件因为分类规则被标成 native，所以按来源整体抽。
QUOTAS = [
    ("sys32_1500.csv", "native", 200, True),
    ("mui_500.csv", "resource_only", 100, True),
    ("drivers.csv", "driver", 100, True),
    ("dotnet.csv", "dotnet", 90, True),
    ("huge.csv", "huge", 5, False),
    ("corrupt.csv", "corrupt", 5, False),
]

# 每个文件固定检查这些字段（26 项；imports/exports 用摘要 + 计数，避免 fixture 膨胀）
FIELDS = (
    "format", "arch", "machine", "timestamp", "characteristics", "entry_rva",
    "image_base", "section_alignment", "file_alignment", "size_of_image",
    "size_of_headers", "subsystem", "dll_characteristics", "sections_count",
    "directories", "section_names", "section_vsize", "section_va",
    "section_rawsize", "section_rawptr", "section_chars", "imports_count",
    "imports_dlls", "imports_digest", "exports_count", "exports_digest",
)


def _digest(items: list[str]) -> str:
    return hashlib.sha256("\n".join(items).encode("utf-8")).hexdigest()[:16]


def m1_fields(pe: PE) -> dict:
    """把一个 PE 的结构视图压成可比较的字段字典（不涉及 pefile）。"""
    imports = pe.imports()
    exports = pe.exports()
    imp_names = sorted(f"{i.dll}!{i.name if i.name else '#' + str(i.ordinal)}" for i in imports)
    exp_names = sorted(f"{e.name if e.name else ''}#{e.ordinal}@0x{e.rva:X}" for e in exports)
    return {
        "format": pe.pe_format,
        "arch": pe.arch,
        "machine": pe.machine,
        "timestamp": pe.timestamp,
        "characteristics": pe.file_characteristics,
        "entry_rva": pe.entry_rva,
        "image_base": pe.image_base,
        "section_alignment": pe.section_alignment,
        "file_alignment": pe.file_alignment,
        "size_of_image": pe.size_of_image,
        "size_of_headers": pe.size_of_headers,
        "subsystem": pe.subsystem,
        "dll_characteristics": pe.dll_characteristics,
        "sections_count": pe.number_of_sections,
        "directories": [list(d) for d in pe.directories],
        "section_names": [s.name for s in pe.sections],
        "section_vsize": [s.virtual_size for s in pe.sections],
        "section_va": [s.virtual_address for s in pe.sections],
        "section_rawsize": [s.size_of_raw_data for s in pe.sections],
        "section_rawptr": [s.pointer_to_raw_data for s in pe.sections],
        "section_chars": [s.characteristics for s in pe.sections],
        "imports_count": len(imports),
        "imports_dlls": sorted({i.dll for i in imports}),
        "imports_digest": _digest(imp_names),
        "exports_count": len(exports),
        "exports_digest": _digest(exp_names),
    }


def _read_csv(name: str) -> list[dict]:
    import csv

    path = CORPUS_DIR / name
    if not path.is_file():
        return []
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def _sample(rows: list[dict], k: int) -> list[dict]:
    """按文件名排序后等距抽样，保留大小分布（不挑样本）。"""
    rows = sorted(rows, key=lambda r: r["file"])
    if len(rows) <= k:
        return rows
    step = (len(rows) - 1) / (k - 1)
    return [rows[round(i * step)] for i in range(k)]


def build() -> dict:
    files: list[dict] = []
    for csv_name, cls, quota, filter_class in QUOTAS:
        rows = _read_csv(csv_name)
        if filter_class:
            rows = [r for r in rows if r.get("class") == cls]
        picked = _sample(rows, quota)
        if len(picked) < quota:
            raise SystemExit(f"{csv_name} 只抽到 {len(picked)}/{quota} 个 {cls}")
        for row in picked:
            path = row["file"]
            if not os.path.isabs(path):  # corrupt 语料在 CSV 里是相对 workspace 的路径
                path = str(ROOT.parent / path)
            rec: dict = {"file": path, "class": cls, "size": int(row["size"])}
            try:
                with PE(path) as pe:
                    rec["fields"] = m1_fields(pe)
                    rec["file_sha256"] = pe.sha256
            except (PEError, OSError) as e:
                rec["error"] = f"{type(e).__name__}: {e}"
            files.append(rec)

    sizes = [r["size"] for r in files]
    meta = {
        "note": "M1 跨类别 500 文件的 rekit 字段快照；生成时与 pefile 的 72,358 次校验为 0 差异",
        "date": "2026-11-11",
        "corpus": "实践/2026-11-11-m1/*.csv（System32 1500 / .mui 500 / drivers 471 / "
                  ".NET 307 / huge 5 / corrupt 12）",
        "sampling": "按文件名排序后每类等距抽样，未按大小或结果挑选",
        "quotas": {cls: quota for _, cls, quota, _ in QUOTAS},
        "files": len(files),
        "fields_per_file": len(FIELDS),
        "field_checks": len(files) * len(FIELDS),
        "size_mib": {"min": round(min(sizes) / 2**20, 2),
                     "median": round(statistics.median(sizes) / 2**20, 2),
                     "max": round(max(sizes) / 2**20, 2)},
    }
    payload = {"meta": meta, "fields": list(FIELDS), "entries": files}
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[写入] {FIXTURE}（{len(files)} 个文件，{meta['field_checks']} 次检查）")
    return payload


@pytest.fixture(scope="module")
def baseline() -> dict:
    if not FIXTURE.is_file():
        pytest.skip(f"缺少基线 fixture：{FIXTURE}")
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_fixture_covers_all_classes(baseline: dict) -> None:
    meta = baseline["meta"]
    classes = [rec["class"] for rec in baseline["entries"]]
    for _, cls, quota, _ in QUOTAS:
        assert classes.count(cls) == quota, cls
    assert meta["files"] == 500
    assert meta["field_checks"] == 500 * len(FIELDS)


def test_zero_diff_against_baseline(baseline: dict) -> None:
    """重新解析 500 个文件，逐字段比对 fixture；缺失文件跳过并计数。

    注意：**基线可能被系统更新污染**。`C:\\Windows\\System32` 下的文件会被 Windows
    更新原地替换（例如 `MRT.exe` 升版后 timestamp/entry_rva/size_of_image 全变），
    这属于环境漂移，不是解析器漂移。遇到单条不一致时，先看文件 `LastWriteTime`
    与 `FileVersion` 是否变过；确认是更新后只刷新该条记录，不要重建整个基线
    （其余记录全等才是"解析器没漂移"的证据）。
    """
    missing: list[str] = []
    diffs: list[str] = []
    for rec in baseline["entries"]:
        path = rec["file"]
        if not os.path.isfile(path):
            missing.append(path)
            continue
        if "error" in rec:
            with pytest.raises((PEError, OSError)):
                with PE(path) as pe:
                    m1_fields(pe)
            continue
        try:
            with PE(path) as pe:
                got = m1_fields(pe)
        except (PEError, OSError) as e:  # 基线里是 OK 的文件现在报错
            diffs.append(f"{path}: 现在报错 {type(e).__name__}: {e}")
            continue
        bad = [k for k in base_fields(baseline) if got[k] != rec["fields"][k]]
        if bad:
            detail = ", ".join(f"{k}: {rec['fields'][k]!r} -> {got[k]!r}" for k in bad[:3])
            diffs.append(f"{path}: {detail}")

    checked = len(baseline["entries"]) - len(missing)
    if checked == 0:
        pytest.skip("本机没有这批 Windows 系统文件；在装齐语料的机器上运行才有意义")
    assert not diffs, f"{len(diffs)}/{checked} 个文件与基线不一致：\n" + "\n".join(diffs[:10])
    if missing:
        print(f"[skip] {len(missing)} 个文件本机不存在，已跳过")


def base_fields(baseline: dict) -> tuple[str, ...]:
    return tuple(baseline["fields"])


if __name__ == "__main__":
    build()
