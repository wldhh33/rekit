# -*- coding: utf-8 -*-
"""建立 M1 固定只读语料并写入清单。

    python tests/make_m1_corpus.py

产物：
    <workspace>/语料/m1-2026-11-11/files/<class>/<NNN>_<basename>   只读副本
    <workspace>/语料/m1-2026-11-11/MANIFEST.json                    语料清单
    tests/baseline/m1_corpus_manifest.json                          入库清单（同内容）

语料目录默认在仓库外，不提交；清单入库，用来证明测试对象是同一批文件。
已存在的只读文件会先恢复可写再覆盖，重复执行是幂等的。
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import m1_corpus as mc  # noqa: E402


def _writable(path: Path) -> None:
    if path.exists():
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)


def main() -> int:
    entries = mc.select_entries()
    files_dir = mc.FILES_ROOT
    files_dir.mkdir(parents=True, exist_ok=True)
    made: list[dict] = []
    total = 0
    for i, item in enumerate(entries):
        src = Path(item["source"])
        if not src.is_file():
            print(f"[缺失] {src}", file=sys.stderr)
            return 2
        rel = Path(item["class"]) / f"{i:03d}_{src.name}"
        dst = files_dir / rel
        _writable(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        os.chmod(dst, stat.S_IREAD)
        src_hash = mc.sha256_file(src)
        dst_hash = mc.sha256_file(dst)
        if src_hash != dst_hash:
            print(f"[复制校验失败] {src} -> {dst}", file=sys.stderr)
            return 3
        made.append({
            "rel": str(rel).replace("\\", "/"),
            "source": str(src),
            "class": item["class"],
            "csv": item["csv"],
            "size": dst.stat().st_size,
            "sha256": dst_hash,
        })
        total += dst.stat().st_size

    manifest = {
        "meta": {
            "corpus_id": mc.corpus_id(made),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "files": len(made),
            "total_bytes": total,
            "source_csv_dir": str(mc.SOURCE_DIR),
            "quotas": {cls: quota for _, cls, quota, _ in mc.QUOTAS},
            "platform": platform.platform(),
            "note": "M1 500 文件固定只读语料；基线只解析本目录副本，不再读取活的 System32",
        },
        "entries": made,
    }
    text = json.dumps(manifest, ensure_ascii=False, indent=1)
    mc.MANIFEST.write_text(text, encoding="utf-8")
    mc.REPO_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    mc.REPO_MANIFEST.write_text(text, encoding="utf-8")
    print(f"[语料] {mc.CORPUS_ROOT}  文件 {len(made)}  "
          f"{total / 2**20:.1f} MiB  id={manifest['meta']['corpus_id'][:16]}")
    print(f"[清单] {mc.MANIFEST}")
    print(f"[入库] {mc.REPO_MANIFEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
