# -*- coding: utf-8 -*-
"""冻结 M6-B 快照基线。只在“改代码之前”跑一次；之后由 tests/test_snapshot.py 校验。

用法（仓库根目录）::

    python tests/make_snapshot.py

产物：
- ``tests/baseline/snapshot_v0.8.0.json`` —— 20 个样本 × 8 个子命令的规范化输出
- ``tests/baseline/snapshot_v0.8.0.json.sha256`` —— 基线文件自身的 SHA256（防篡改）
"""

from __future__ import annotations

import datetime
import json
import platform
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from snapshot_util import (  # noqa: E402
    BASELINE, BASELINE_DIR, SIDECAR, build_cases, canonical_bytes,
    file_sha256, normalize, run_case, sample_paths,
)


def _capstone_version() -> str:
    try:
        import capstone
    except ImportError:
        return "未安装"
    return getattr(capstone, "__version__", "未知")


def main() -> int:
    import rekit

    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rekit-snapshot-") as tmp:
        tmpdir = Path(tmp)
        paths = sample_paths(tmpdir / "samples")
        missing = [sid for sid, p in paths.items() if not p.is_file()]
        if missing:
            print(f"[失败] 缺少样本：{missing}", file=sys.stderr)
            return 1

        cases = build_cases(tmpdir / "out")
        frozen = [normalize(run_case(c, paths, tmpdir / "out"), paths, tmpdir)
                  for c in cases]
        sample_meta = {sid: {"sha256": file_sha256(p.read_bytes()),
                             "bytes": p.stat().st_size}
                       for sid, p in sorted(paths.items())}

    payload = {
        "schema": "rekit-snapshot-baseline-v1",
        "meta": {
            "date": datetime.date.today().isoformat(),
            "version": rekit.__version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "capstone": _capstone_version(),
            "frozen_before": "B MVP 开工前：尚未加入顶层 schema_version 与错误码 code/message",
            "sample_count": len(paths),
            "case_count": len(frozen),
            "normalization": {
                "generated_at": "删除",
                "seconds": "值替换为 <SECONDS>",
                "absolute_paths": "样本路径 -> <SAMPLE:id>，临时目录 -> <TMP>",
                "comparison": "递归子集：旧字段必须存在且相等，新增字段放行",
            },
            "samples": sample_meta,
        },
        "cases": frozen,
    }
    baseline_bytes = canonical_bytes(payload)
    BASELINE.write_text(json.dumps(payload, ensure_ascii=False, indent=2,
                                   sort_keys=True) + "\n", encoding="utf-8")
    digest = file_sha256(baseline_bytes)
    SIDECAR.write_text(f"{digest}  {BASELINE.name}\n", encoding="utf-8")
    print(f"[OK] 基线 {BASELINE.relative_to(BASELINE.parents[2])}")
    print(f"     样本 {len(paths)}，用例 {len(frozen)}，sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
