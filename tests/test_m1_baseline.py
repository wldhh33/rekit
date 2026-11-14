# -*- coding: utf-8 -*-
"""M1 B4 —— 跨类别 500 个文件的解析结果基线（零差异回归）。

语料已从活的 `C:\\Windows\\System32` 改为**固定只读副本**（2026-11-14 决定）：
Windows 更新会原地替换系统文件，2026-11-11 的基线在 3 天后已有 166/500 条漂移，
无法区分「解析器回归」与「系统更新」。现在基线只解析
``<workspace>/语料/m1-2026-11-11/files`` 下的副本，并用清单 SHA256 证明是同一批文件。

    python tests/make_m1_corpus.py     # 首次或需要重建语料时（会复制 500 个文件）
    python tests/test_m1_baseline.py   # 重新生成 tests/baseline/m1_500.json
    python -m pytest tests/test_m1_baseline.py -q

语料目录不提交；入库的只有 ``tests/baseline/m1_corpus_manifest.json``。换机器时
把语料放到同位置，或用 ``REKIT_M1_CORPUS`` 指向副本。缺失时按 skip 计，不假装通过。
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import statistics
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import m1_corpus as mc  # noqa: E402
from rekit.core.pe import PE, PEError  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "baseline" / "m1_500.json"

# 每个类别固定检查这些字段（26 项；imports/exports 用摘要 + 计数，避免 fixture 膨胀）
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


def build() -> dict:
    manifest = mc.load_manifest(in_repo=True)
    if manifest is None:
        raise SystemExit(
            f"缺少语料清单 {mc.REPO_MANIFEST}；先运行 python tests/make_m1_corpus.py")
    files: list[dict] = []
    for item in manifest["entries"]:
        path = mc.FILES_ROOT / item["rel"]
        rec: dict = {
            "rel": item["rel"],
            "source": item["source"],
            "source_sha256": item["sha256"],
            "class": item["class"],
            "size": item["size"],
        }
        try:
            with PE(str(path)) as pe:
                rec["fields"] = m1_fields(pe)
                rec["file_sha256"] = pe.sha256
        except (PEError, OSError) as e:
            rec["error"] = f"{type(e).__name__}: {e}"
        files.append(rec)

    sizes = [r["size"] for r in files]
    src = manifest["meta"]
    meta = {
        "note": "M1 跨类别 500 文件的 rekit 字段快照；解析对象为固定只读语料副本",
        "date": src["created_at"][:10],
        "corpus": "语料/m1-2026-11-11/files（固定只读副本；来源见 m1_corpus_manifest.json）",
        "corpus_id": src["corpus_id"],
        "corpus_created_at": src["created_at"],
        "corpus_source": src["source_csv_dir"],
        "corpus_platform": src.get("platform", ""),
        "baseline_created_at": "",
        "sampling": "按文件名排序后每类等距抽样，未按大小或结果挑选",
        "quotas": src["quotas"],
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
    for cls, quota in meta["quotas"].items():
        assert classes.count(cls) == quota, cls
    assert meta["files"] == 500
    assert meta["field_checks"] == 500 * len(FIELDS)
    assert len(meta["corpus_id"]) == 64


def test_corpus_is_fixed_read_only_and_hash_matches(baseline: dict) -> None:
    """语料必须是只读副本，且逐文件 SHA256 与清单一致——证明测的是同一批文件。"""
    missing = [r["rel"] for r in baseline["entries"]
               if not (mc.FILES_ROOT / r["rel"]).is_file()]
    if missing:
        pytest.skip(f"语料缺失 {len(missing)} 个（{mc.FILES_ROOT}），先运行 make_m1_corpus.py")
    writable, bad_hash = [], []
    for rec in baseline["entries"]:
        path = mc.FILES_ROOT / rec["rel"]
        if path.stat().st_mode & stat.S_IWRITE:
            writable.append(rec["rel"])
        if mc.sha256_file(path) != rec["source_sha256"]:
            bad_hash.append(rec["rel"])
    assert not writable, f"{len(writable)} 个语料副本可写：{writable[:5]}"
    assert not bad_hash, f"{len(bad_hash)} 个语料副本哈希变化：{bad_hash[:5]}"
    assert mc.corpus_id(baseline["entries"]) == baseline["meta"]["corpus_id"]


def test_zero_diff_against_baseline(baseline: dict) -> None:
    """重新解析 500 个固定副本，逐字段比对 fixture；缺失文件跳过并计数。"""
    missing: list[str] = []
    diffs: list[str] = []
    for rec in baseline["entries"]:
        path = mc.FILES_ROOT / rec["rel"]
        if not path.is_file():
            missing.append(rec["rel"])
            continue
        if "error" in rec:
            with pytest.raises((PEError, OSError)):
                with PE(str(path)) as pe:
                    m1_fields(pe)
            continue
        try:
            with PE(str(path)) as pe:
                got = m1_fields(pe)
        except (PEError, OSError) as e:  # 基线里是 OK 的文件现在报错
            diffs.append(f"{rec['rel']}: 现在报错 {type(e).__name__}: {e}")
            continue
        bad = [k for k in base_fields(baseline) if got[k] != rec["fields"][k]]
        if bad:
            detail = ", ".join(f"{k}: {rec['fields'][k]!r} -> {got[k]!r}" for k in bad[:3])
            diffs.append(f"{rec['rel']}: {detail}")

    checked = len(baseline["entries"]) - len(missing)
    if checked == 0:
        pytest.skip("本机没有固定语料；先运行 python tests/make_m1_corpus.py")
    assert not diffs, f"{len(diffs)}/{checked} 个文件与基线不一致：\n" + "\n".join(diffs[:10])
    if missing:
        print(f"[skip] {len(missing)} 个文件本机不存在，已跳过")


def base_fields(baseline: dict) -> tuple[str, ...]:
    return tuple(baseline["fields"])


if __name__ == "__main__":
    import time
    payload = build()
    payload["meta"]["baseline_created_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    FIXTURE.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[时间] {payload['meta']['baseline_created_at']}")
