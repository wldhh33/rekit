#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""parse_core_gate.py —— 解析内核微基准门（进程内，非端到端）。

**这不是用户实际跑的路径。** 这里只度量 ``PE`` 解析内核本身：打开 + 节表/数据
目录 + imports + exports，进程内循环 31 轮取中位数，量级约 0.2 ms。它的用途是
把「解析内核有没有变慢 / 内存有没有涨」与解释器启动、CLI 输出等噪声隔离开。
用户实际路径的墙钟时间由 ``bench/e2e_gate.py`` 负责，两者分开冻结、分开报数。

为什么用“校准比”而不是绝对秒数：
- 绝对耗时依赖机器；CI 与本机不可直接比。
- 同时测一段固定的纯 Python 计算作为校准负载，门限比较 ``解析中位数 / 校准中位数``；
  这样换机器时总体快慢会被约掉，只有“解析相对变慢”才会触发。

门限：
- 解析中位数比 ≤ 基线 × 1.15
- 峰值内存（tracemalloc，Python 分配）≤ 基线 × 1.2

用法::

    python bench/parse_core_gate.py --write-baseline   # 只在本轮基准确立时跑一次
    python bench/parse_core_gate.py                    # 校验；失败退出码 1
"""

from __future__ import annotations

import argparse
import gc
import json
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rekit.core.pe import PE  # noqa: E402

SAMPLE = ROOT / "tests" / "fixtures" / "hello_rs.exe"
BASELINE = ROOT / "tests" / "baseline" / "perf_parse_core.json"
ITERATIONS = 31
CALIBRATION_ROUNDS = 5
MEDIAN_FACTOR = 1.15
PEAK_FACTOR = 1.2


def parse_once(path: Path) -> None:
    pe = PE(str(path))
    pe.imports()
    pe.exports()


def calibration_once() -> int:
    total = 0
    for i in range(120_000):
        total = (total + ((i * 2654435761) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return total


def measure_parse(path: Path, iterations: int = ITERATIONS) -> float:
    parse_once(path)  # 预热，不计入
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        parse_once(path)
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def measure_calibration(rounds: int = CALIBRATION_ROUNDS) -> float:
    calibration_once()
    samples = []
    for _ in range(rounds):
        start = time.perf_counter()
        calibration_once()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def measure_peak(path: Path) -> int:
    gc.collect()
    tracemalloc.start()
    parse_once(path)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak


def collect() -> dict:
    from rekit import __version__

    import hashlib

    parse_s = measure_parse(SAMPLE)
    calib_s = measure_calibration()
    peak = measure_peak(SAMPLE)
    return {
        "date": time.strftime("%Y-%m-%d"),
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "sample": str(SAMPLE.relative_to(ROOT)).replace("\\", "/"),
        "sample_bytes": SAMPLE.stat().st_size,
        "sample_sha256": hashlib.sha256(SAMPLE.read_bytes()).hexdigest(),
        "iterations": ITERATIONS,
        "calibration_rounds": CALIBRATION_ROUNDS,
        "parse_median_s": round(parse_s, 9),
        "calibration_median_s": round(calib_s, 9),
        "ratio": round(parse_s / calib_s, 6),
        "peak_bytes": peak,
        "gates": {"median_factor": MEDIAN_FACTOR, "peak_factor": PEAK_FACTOR},
        "note": "进程内解析内核微基准，不是端到端；端到端见 bench/e2e_gate.py。"
                "绝对秒数仅供本机参考；门限比较 ratio（解析/校准），可跨机器。",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="rekit 解析内核微基准门（非端到端）")
    parser.add_argument("--write-baseline", action="store_true",
                        help="写入 tests/baseline/perf_parse_core.json（只在本轮基准确立时用）")
    args = parser.parse_args()

    if not SAMPLE.is_file():
        print(f"[失败] 缺少样本：{SAMPLE}", file=sys.stderr)
        return 2

    current = collect()
    print(f"样本 {current['sample']}  {current['sample_bytes']} 字节")
    print(f"解析中位数 {current['parse_median_s'] * 1000:.3f} ms  "
          f"校准 {current['calibration_median_s'] * 1000:.3f} ms  "
          f"ratio {current['ratio']}")
    print(f"峰值内存 {current['peak_bytes'] / 1024:.1f} KiB")

    if args.write_baseline:
        payload = {"schema": "rekit-perf-parse-core-baseline-v1", **current}
        BASELINE.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
        print(f"[OK] 基线写入 {BASELINE.relative_to(ROOT)}")
        return 0

    if not BASELINE.is_file():
        print(f"[失败] 缺少基线：{BASELINE}", file=sys.stderr)
        return 2
    base = json.loads(BASELINE.read_text(encoding="utf-8"))

    failures = []
    limit_ratio = base["ratio"] * base["gates"]["median_factor"]
    if current["ratio"] > limit_ratio:
        failures.append(
            f"解析变慢：ratio {current['ratio']} > 上限 {limit_ratio:.6f}"
            f"（基线 {base['ratio']} × {base['gates']['median_factor']}）")
    limit_peak = base["peak_bytes"] * base["gates"]["peak_factor"]
    if current["peak_bytes"] > limit_peak:
        failures.append(
            f"峰值内存 {current['peak_bytes']} > 上限 {limit_peak:.0f}"
            f"（基线 {base['peak_bytes']} × {base['gates']['peak_factor']}）")

    if failures:
        for text in failures:
            print(f"[失败] {text}", file=sys.stderr)
        return 1
    print(f"[通过] 中位数 ≤ {base['gates']['median_factor']}×、"
          f"峰值 ≤ {base['gates']['peak_factor']}× 基线")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
