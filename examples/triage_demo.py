#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""示例：直接在代码里用 triage，不经过 CLI。

用法（仓库根目录）：
    python examples/triage_demo.py
    python examples/triage_demo.py C:\\Windows\\System32\\notepad.exe

和 CLI 的区别：这里 import `rekit.analyzers.triage`，拿到字典自己处理，
适合接到别的流水线里（比如批量扫描后写数据库）。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rekit.analyzers import triage  # noqa: E402


def main(argv: list[str]) -> int:
    targets = argv[1:] or [
        str(Path(__file__).resolve().parents[1] / "tests/fixtures/hello_rs.exe"),
        str(Path(__file__).resolve().parents[1] / "tests/fixtures/hello_rs.packed.exe"),
    ]

    payload = triage.run(targets)

    for r in payload["results"]:
        print(f"{r['file']}")
        print(f"  {r['format']} / {r['arch']}  EP={r['entry_rva']} in {r['entry_section']}")
        print(f"  verdict={r['verdict']}  confidence={r['confidence']}  score={r['score']}")
        for s in r["signals"]:
            mark = "HIT" if s["hit"] else "   "
            print(f"    [{mark}] {s['id']:<28} +{s['weight']}  {s['evidence']}")
        print()

    for e in payload["errors"]:
        print(f"[ERR] {e['file']}: {e['error']}", file=sys.stderr)

    return 0 if not payload["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
