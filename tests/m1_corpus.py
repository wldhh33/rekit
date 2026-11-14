# -*- coding: utf-8 -*-
"""M1 固定语料：选样、清单与语料标识。

背景：M1 原先直接解析 `C:\\Windows\\System32` 下的活文件，Windows 更新会原地替换
它们（2026-11-11 之后 500 个抽样文件中有 166 个字段变化），导致「解析器回归」和
「系统更新」混在一起。这里把抽中的 500 个文件复制成独立只读副本，基线只认副本，
用 `corpus_id` + 每文件 SHA256 证明「以后测的是同一批文件」。

语料默认位置：``<workspace>/语料/m1-2026-11-11``，可用环境变量
``REKIT_M1_CORPUS`` 覆盖。语料本身不入库；入库的只有
``tests/baseline/m1_corpus_manifest.json``（名称、来源、哈希）。
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT.parent / "实践" / "2026-11-11-m1"
CORPUS_ROOT = Path(os.environ.get("REKIT_M1_CORPUS")
                   or ROOT.parent / "语料" / "m1-2026-11-11")
FILES_ROOT = CORPUS_ROOT / "files"
MANIFEST = CORPUS_ROOT / "MANIFEST.json"
REPO_MANIFEST = Path(__file__).resolve().parent / "baseline" / "m1_corpus_manifest.json"

QUOTAS = [
    ("sys32_1500.csv", "native", 200, True),
    ("mui_500.csv", "resource_only", 100, True),
    ("drivers.csv", "driver", 100, True),
    ("dotnet.csv", "dotnet", 90, True),
    ("huge.csv", "huge", 5, False),
    ("corrupt.csv", "corrupt", 5, False),
]


def read_csv(name: str) -> list[dict]:
    path = SOURCE_DIR / name
    if not path.is_file():
        return []
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def sample(rows: list[dict], k: int) -> list[dict]:
    """按文件名排序后等距抽样，保留大小分布（不挑样本）。"""
    rows = sorted(rows, key=lambda r: r["file"])
    if len(rows) <= k:
        return rows
    step = (len(rows) - 1) / (k - 1)
    return [rows[round(i * step)] for i in range(k)]


def _abs_source(raw: str) -> Path:
    p = Path(raw)
    return p if p.is_absolute() else ROOT.parent / p


def select_entries() -> list[dict]:
    """复算 500 个抽样；返回 source/class/size/csv，不读取文件内容。"""
    out: list[dict] = []
    for csv_name, cls, quota, filter_class in QUOTAS:
        rows = read_csv(csv_name)
        if filter_class:
            rows = [r for r in rows if r.get("class") == cls]
        picked = sample(rows, quota)
        if len(picked) < quota:
            raise SystemExit(f"{csv_name} 只抽到 {len(picked)}/{quota} 个 {cls}")
        for row in picked:
            out.append({
                "source": str(_abs_source(row["file"])),
                "class": cls,
                "size": int(row["size"]),
                "csv": csv_name,
            })
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def corpus_id(entries: list[dict]) -> str:
    """对 (rel, sha256) 排序行做 SHA256，得到语料指纹。"""
    lines = "\n".join(
        f"{e['rel']} {e.get('sha256') or e.get('source_sha256')}"
        for e in sorted(entries, key=lambda x: x["rel"]))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def load_manifest(in_repo: bool = False) -> dict | None:
    path = REPO_MANIFEST if in_repo else MANIFEST
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
