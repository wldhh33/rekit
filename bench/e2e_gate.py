#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""e2e_gate.py —— 端到端性能门（整进程子命令，M6-B 补测）。

度量对象是用户实际跑的入口：

    python -m rekit triage <file> -o out.json -m out.md
    python -m rekit report <file> --rules rules/m5.json -o out.md -j out.json

每个样本点都是一次完整的子进程调用：解释器启动 + import + 解析 + 写输出。
这与 ``bench/parse_core_gate.py``（进程内只测 ``PE`` 解析内核的微基准，量级
0.2 ms）不是一回事，两者在文档里分开命名、分开冻结基线、分开报数。

冷态 / 热态：
- 热态：预热 ``WARMUP`` 轮后连续 ``HOT_ROUNDS`` 轮，字节码缓存与 OS 文件缓存
  都已是热的，对应用户重复分析同一文件。
- 冷态：先丢弃 1 轮，再取 ``COLD_ROUNDS`` 轮；每轮把 ``PYTHONPYCACHEPREFIX``
  指向一个全新的空目录，强制重新编译 Python 模块（模拟全新安装 / 干净 CI）。
  说明：无特权无法清空 OS 文件缓存，所以这里的「冷」不等于磁盘冷启动，
  基线 meta 里如实写明。

门槛：**热态中位数 ≤ 基线热态中位数 × 1.15**，冷态同理；p90 一并报出与冻结，
但只用中位数做门（用户约定「慢不过 15%」）。

门的分工：**热态是主门**（用户重复分析同一文件的实际路径）；冷态是「人为冷」的
**import 膨胀哨兵**——真实用户首次运行后字节码已落盘，不会再经历每轮重建缓存，
所以冷态灵敏度高但脆，只作上限哨兵。冷态变红先排查环境与缓存路径，不得改冷态定义
来让门变绿。

贴近门限的处理（2026-11-12 约定）：实测中位数与门限相差在 **1% 以内**时，单次红/绿
都不能当结论——必须原样重跑至少两次，把两次实测值一并记录下来再判。两次都超才判退化；
一红一绿记「边界噪声」，既不调门限，也不改冷/热定义。（起因：`triage/hot` 218.3 ms
对门限 218.2 ms，重跑 218.0 / 217.6 ms 均过。）

用法::

    python bench/e2e_gate.py --write-baseline   # 只在基准确立时跑一次
    python bench/e2e_gate.py                    # 校验；失败退出码 1
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SAMPLE = ROOT / "tests" / "fixtures" / "hello_rs.exe"
RULES = ROOT / "rules" / "m5.json"
BASELINE = ROOT / "tests" / "baseline" / "perf_e2e.json"

HOT_ROUNDS = 15
COLD_ROUNDS = 7
WARMUP = 3
MEDIAN_FACTOR = 1.15


def _command(name: str, outdir: Path) -> list[str]:
    """固定的最小端到端命令；输出落到 outdir，避免污染仓库。"""
    if name == "triage":
        return [sys.executable, "-m", "rekit", "triage", str(SAMPLE),
                "-o", str(outdir / "triage.json"),
                "-m", str(outdir / "triage.md")]
    if name == "report":
        return [sys.executable, "-m", "rekit", "report", str(SAMPLE),
                "--rules", str(RULES),
                "-o", str(outdir / "report.md"),
                "-j", str(outdir / "report.json")]
    raise ValueError(f"未知命令: {name}")


def _run_once(command: list[str], env: dict | None = None) -> float:
    start = time.perf_counter()
    proc = subprocess.run(
        command, cwd=str(ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
    )
    elapsed = time.perf_counter() - start
    if proc.returncode != 0:
        raise RuntimeError(
            f"命令失败 rc={proc.returncode}: {' '.join(command[:5])} ...")
    return elapsed


def _percentile(values: list[float], pct: float) -> float:
    """最近秩（nearest-rank）分位数，小样本下比插值更直观。"""
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100.0 * len(ordered)))
    return ordered[rank - 1]


def _summary(samples: list[float]) -> dict:
    return {
        "n": len(samples),
        "median_s": round(statistics.median(samples), 6),
        "p90_s": round(_percentile(samples, 90), 6),
        "min_s": round(min(samples), 6),
        "max_s": round(max(samples), 6),
    }


def measure_hot(name: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="rekit-e2e-hot-") as tmp:
        outdir = Path(tmp)
        command = _command(name, outdir)
        for _ in range(WARMUP):
            _run_once(command)
        samples = [_run_once(command) for _ in range(HOT_ROUNDS)]
    return _summary(samples)


def _cold_run(name: str) -> float:
    cache_root = Path(tempfile.mkdtemp(prefix="rekit-e2e-cold-"))
    outdir = cache_root / "out"
    outdir.mkdir()
    env = os.environ.copy()
    env["PYTHONPYCACHEPREFIX"] = str(cache_root / "pycache")
    try:
        return _run_once(_command(name, outdir), env)
    finally:
        shutil.rmtree(cache_root, ignore_errors=True)


def measure_cold(name: str) -> dict:
    _cold_run(name)  # 丢弃：首次冷编译会把整个标准库都编一遍，属预热噪声
    samples = [_cold_run(name) for _ in range(COLD_ROUNDS)]
    return _summary(samples)


def collect() -> dict:
    from rekit import __version__

    commands = {}
    for name in ("triage", "report"):
        commands[name] = {
            "hot": measure_hot(name),
            "cold": measure_cold(name),
        }
    return {
        "schema": "rekit-e2e-perf-baseline-v1",
        "meta": {
            "date": time.strftime("%Y-%m-%d"),
            "version": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "sample": SAMPLE.relative_to(ROOT).as_posix(),
            "sample_bytes": SAMPLE.stat().st_size,
            "sample_sha256": hashlib.sha256(SAMPLE.read_bytes()).hexdigest(),
            "rules": RULES.relative_to(ROOT).as_posix(),
            "warmup": WARMUP,
            "hot_rounds": HOT_ROUNDS,
            "cold_warmup": 1,
            "cold_rounds": COLD_ROUNDS,
            "cold_definition": "每轮使用全新空的 PYTHONPYCACHEPREFIX，强制重新编译；"
                               "未清空 OS 文件缓存，不等价于磁盘冷启动",
            "commands": {
                "triage": f"python -m rekit triage {SAMPLE.relative_to(ROOT).as_posix()} "
                          "-o triage.json -m triage.md",
                "report": f"python -m rekit report {SAMPLE.relative_to(ROOT).as_posix()} "
                          "--rules rules/m5.json -o report.md -j report.json",
            },
            "note": "机器信息只写在 meta；rekit 生成的 JSON/Markdown 内容不含这些信息。",
        },
        "gates": {"median_factor": MEDIAN_FACTOR, "statistic": "median"},
        "commands": commands,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="rekit 端到端性能门")
    parser.add_argument("--write-baseline", action="store_true",
                        help="写入 tests/baseline/perf_e2e.json（只在本轮基准确立时用）")
    args = parser.parse_args()

    if not SAMPLE.is_file():
        print(f"[失败] 缺少样本：{SAMPLE}", file=sys.stderr)
        return 2

    current = collect()
    for name, item in current["commands"].items():
        hot, cold = item["hot"], item["cold"]
        print(f"{name:<7} 热态 中位数 {hot['median_s'] * 1000:8.1f} ms  "
              f"p90 {hot['p90_s'] * 1000:8.1f} ms  n={hot['n']}    "
              f"冷态 中位数 {cold['median_s'] * 1000:8.1f} ms  "
              f"p90 {cold['p90_s'] * 1000:8.1f} ms  n={cold['n']}")

    if args.write_baseline:
        BASELINE.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
        print(f"[OK] 基线写入 {BASELINE.relative_to(ROOT)}")
        return 0

    if not BASELINE.is_file():
        print(f"[失败] 缺少基线：{BASELINE}", file=sys.stderr)
        return 2
    base = json.loads(BASELINE.read_text(encoding="utf-8"))
    factor = base["gates"]["median_factor"]

    failures = []
    for name in ("triage", "report"):
        for mode in ("hot", "cold"):
            now = current["commands"][name][mode]["median_s"]
            old = base["commands"][name][mode]["median_s"]
            limit = old * factor
            if now > limit:
                failures.append(
                    f"{name}/{mode} 变慢：中位数 {now * 1000:.1f} ms > "
                    f"上限 {limit * 1000:.1f} ms（基线 {old * 1000:.1f} ms × {factor}）")

    if failures:
        for text in failures:
            print(f"[失败] {text}", file=sys.stderr)
        return 1
    print(f"[通过] triage/report 冷热中位数均 ≤ {factor}× 基线")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
