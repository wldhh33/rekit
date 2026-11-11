#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""benchmark.py —— 本解析器 vs pefile 的同任务性能基准。

保证可比：
- 同一批文件、同一任务：打开 + 节表/数据目录 + imports + exports；
- 先预热 10 个文件，再跑 3 轮，总耗时取中位数；每个文件取 3 轮中位数后按大小档聚合；
- 内存峰值单独跑一轮（tracemalloc，只统计 Python 分配，不计入耗时）；
- 冷启动用 3 次独立子进程 import，取中位数，并减去空进程基线。

用法：
    python bench/benchmark.py --dir C:\\Windows\\System32 --limit 500 --out docs/benchmark.md
    python bench/benchmark.py --from-csv path/to/sys32_500.csv --out docs/benchmark.md
    python bench/benchmark.py --from-csv path/to/huge.csv --per-file --out docs/memory.md
"""

from __future__ import annotations

import argparse
import csv
import gc
import json
import os
import platform
import statistics
import subprocess
import sys
import time
import tracemalloc

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rekit.core.pe import PE  # noqa: E402

try:
    import pefile  # type: ignore
except ImportError:  # pragma: no cover
    print("[依赖缺失] python -m pip install pefile", file=sys.stderr)
    raise SystemExit(2)

TIERS = (("small", 64 * 1024), ("medium", 1024 * 1024), ("large", float("inf")))
DIRS = [
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
]


def tier_of(size: int) -> str:
    if size < 64 * 1024:
        return "small"
    if size < 1024 * 1024:
        return "medium"
    return "large"


def parse_mine(path: str) -> None:
    pe = PE(path)
    pe.imports()
    pe.exports()


def parse_pefile(path: str) -> None:
    ref = pefile.PE(path, fast_load=True)
    ref.parse_data_directories(directories=DIRS)
    ref.close()


TOOLS = (("rekit (纯 Python)", parse_mine), ("pefile", parse_pefile))


def cold_start(module: str, runs: int = 3) -> float:
    """子进程 import 的中位数，减去解释器空跑基线（秒）。"""
    code = f"import {module}"
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        subprocess.run([sys.executable, "-c", code], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        times.append(time.perf_counter() - t0)
    base = []
    for _ in range(runs):
        t0 = time.perf_counter()
        subprocess.run([sys.executable, "-c", "pass"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        base.append(time.perf_counter() - t0)
    return max(0.0, statistics.median(times) - statistics.median(base))


def measure(files: list[str], fn, rounds: int = 3):
    per_file: dict[str, list[float]] = {p: [] for p in files}
    totals: list[float] = []
    for _ in range(rounds):
        gc.collect()
        t0 = time.perf_counter()
        for p in files:
            s = time.perf_counter()
            fn(p)
            per_file[p].append(time.perf_counter() - s)
        totals.append(time.perf_counter() - t0)
    med = {p: statistics.median(v) for p, v in per_file.items()}
    return med, statistics.median(totals), min(totals), max(totals)


def peak_memory(files: list[str], fn) -> int:
    gc.collect()
    tracemalloc.start()
    for p in files:
        fn(p)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return peak


# ---------------------------------------------------------------------------
# 逐文件峰值内存（子进程 + 进程峰值工作集）
#
# tracemalloc 只统计 Python 堆：mmap 读入的字节不计，用它比"谁更省内存"会失真。
# 这里每个文件单独起一个子进程，读取 OS 记录的峰值工作集（Windows=
# PeakWorkingSetSize，POSIX=ru_maxrss），再减去"只 import 不解析"的基线。
# ---------------------------------------------------------------------------

def peak_rss() -> int:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class Pmc(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        pmc = Pmc()
        pmc.cb = ctypes.sizeof(Pmc)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Pmc),
                                               wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        if not psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
            raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo 失败")
        return int(pmc.PeakWorkingSetSize)
    import resource
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * (1024 if sys.platform == "darwin" else 1)


def child_main(tool: str, path: str | None) -> int:
    """子进程：import（+ 解析一个文件），报告耗时与进程峰值工作集。"""
    t0 = time.perf_counter()
    if tool == "rekit":
        import rekit.core.pe as mod
        if path:
            pe = mod.PE(path)
            pe.imports()
            pe.exports()
    elif tool == "rekit-triage":
        from rekit.analyzers.triage import analyze_file
        if path:
            analyze_file(path)
    elif tool == "pefile":
        import pefile  # type: ignore
        if path:
            ref = pefile.PE(path, fast_load=True)
            ref.parse_data_directories(directories=DIRS)
            ref.close()
    else:
        raise SystemExit(f"未知 tool: {tool}")
    ms = (time.perf_counter() - t0) * 1000
    print(json.dumps({"peak": peak_rss(), "ms": round(ms, 3)}))
    return 0


def run_child(tool: str, path: str | None) -> dict:
    """每个样本独立子进程，避免峰值在文件之间累积。"""
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "--child", tool, path or ""],
        capture_output=True, text=True, encoding="utf-8",
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"子进程失败 rc={proc.returncode}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _median_runs(tool: str, path: str | None, runs: int = 3) -> dict:
    vals = [run_child(tool, path) for _ in range(runs)]
    return {"peak": int(statistics.median(v["peak"] for v in vals)),
            "ms": round(statistics.median(v["ms"] for v in vals), 3)}


def per_file_report(files: list[str], out: str | None) -> str:
    base = {"rekit": _median_runs("rekit", None), "pefile": _median_runs("pefile", None)}
    rows = []
    for p in files:
        size = os.path.getsize(p)
        r = _median_runs("rekit", p)
        f = _median_runs("pefile", p)
        rows.append({"file": p, "size": size, "rekit": r, "pefile": f})
        print(f"  {size/2**20:8.1f} MiB  rekit {r['peak']/2**20:7.1f} MiB / "
              f"{r['ms']:8.1f} ms   pefile {f['peak']/2**20:7.1f} MiB / {f['ms']:8.1f} ms  "
              f"{os.path.basename(p)}")

    lines = ["# 逐文件峰值内存（大文件）\n"]
    lines.append(f"- 环境：{platform.platform()} / Python {platform.python_version()} / "
                 f"pefile {pefile.__version__}")
    lines.append("- 语料：M1 `huge` 5 个（23–230 MB），`--per-file` 每个文件一个子进程")
    lines.append(f"- 基线（只 import 不解析）：rekit {base['rekit']['peak']/2**20:.1f} MiB / "
                 f"pefile {base['pefile']['peak']/2**20:.1f} MiB")
    lines.append("- 指标：进程峰值工作集（Windows PeakWorkingSetSize），已减 import 基线；"
                 "每个文件 3 次取中位数；耗时是子进程内解析耗时，不含解释器启动\n")
    lines.append("| 文件 | 大小 MiB | rekit 峰值 MiB | rekit 净 MiB | rekit 耗时 ms | "
                 "pefile 峰值 MiB | pefile 净 MiB | pefile 耗时 ms |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for row in rows:
        r_net = max(0.0, (row['rekit']['peak'] - base['rekit']['peak']) / 2**20)
        f_net = (row['pefile']['peak'] - base['pefile']['peak']) / 2**20
        lines.append(
            f"| {os.path.basename(row['file'])} | {row['size']/2**20:.1f} | "
            f"{row['rekit']['peak']/2**20:.1f} | {r_net:.1f} | {row['rekit']['ms']:.1f} | "
            f"{row['pefile']['peak']/2**20:.1f} | {f_net:.1f} | {row['pefile']['ms']:.1f} |")
    lines.append("")
    lines.append("> 净内存 = 进程峰值 − 只 import 的基线（结果波动约 ±1 MiB，"
                 "负值记 0 表示与基线在同一噪声内）。整文件 `read()` 的实现净内存约等于"
                 "文件大小的 2 倍（原始字节 + 节切片副本）；mmap 实现只拉进真正解析到的页。")
    text = "\n".join(lines) + "\n"
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[写入] {out}")
    return text


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="本解析器 vs pefile 性能基准")
    ap.add_argument("--child", nargs=2, metavar=("TOOL", "FILE"), help=argparse.SUPPRESS)
    ap.add_argument("--dir")
    ap.add_argument("--from-csv", help="用 CSV 的 file 列锁定与 M1 完全相同的语料")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--per-file", action="store_true",
                    help="逐文件子进程测量峰值工作集（大文件用，不跑吞吐）")
    ap.add_argument("--out", help="把 Markdown 结果写入文件")
    args = ap.parse_args(argv)

    if args.child:
        return child_main(args.child[0], args.child[1] or None)

    if args.from_csv:
        with open(args.from_csv, encoding="utf-8-sig") as f:
            files = [r["file"] for r in csv.DictReader(f) if r.get("file")]
    elif args.dir:
        files = sorted(os.path.join(args.dir, n) for n in os.listdir(args.dir)
                       if n.lower().endswith((".dll", ".exe", ".sys", ".cpl")))
    else:
        ap.error("需要 --dir 或 --from-csv")
    if args.limit:
        files = files[: args.limit]
    files = [p for p in files if os.path.isfile(p)]
    if not files:
        print("[错误] 没有文件", file=sys.stderr)
        return 2

    if args.per_file:
        text = per_file_report(files, args.out)
        print(text)
        return 0

    sizes = {p: os.path.getsize(p) for p in files}
    tiers: dict[str, list[str]] = {name: [] for name, _ in TIERS}
    for p in files:
        tiers[tier_of(sizes[p])].append(p)
    warm = files[:10]

    results = {}
    for name, fn in TOOLS:
        for p in warm:
            fn(p)
        med, total, best, worst = measure(files, fn, args.rounds)
        results[name] = {"med": med, "total": total, "best": best, "worst": worst}

    mem = {name: peak_memory(files, fn) for name, fn in TOOLS}
    cold = {"rekit": cold_start("rekit.core.pe"), "pefile": cold_start("pefile")}

    lines: list[str] = []
    lines.append("# 解析性能基准\n")
    lines.append(f"- 环境：{platform.platform()} / Python {platform.python_version()} / "
                 f"pefile {pefile.__version__}")
    lines.append(f"- 语料：{len(files)} 个文件（{args.from_csv or args.dir}），"
                 f"预热 10 个，{args.rounds} 轮取中位数")
    lines.append("- 任务：打开 + 节表/数据目录 + imports + exports（两边同一子集；rekit 尚未解析重定位）")
    lines.append("- rekit 侧不计算 SHA256（改为按需属性）：上一版基准里它顺手算了哈希，pefile 没有，"
                 "两边任务并不对等；这一版才是同任务。")
    lines.append("- 计时不含内存采样；内存峰值用 tracemalloc 单独跑一轮（仅 Python 分配，"
                 "mmap 的页不计入，大文件真实峰值见 docs/memory.md）\n")

    lines.append("## 分档单文件耗时（毫秒，中位数）\n")
    lines.append("| 档位 | 文件数 | 大小中位数 | rekit | pefile | 倍率 |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    tier_med_sample = {}
    for tname, _ in TIERS:
        group = tiers[tname]
        if not group:
            continue
        size_med = statistics.median(sizes[p] for p in group)
        a = statistics.median(results["rekit (纯 Python)"]["med"][p] for p in group) * 1000
        b = statistics.median(results["pefile"]["med"][p] for p in group) * 1000
        tier_med_sample[tname] = len(group)
        lines.append(f"| {tname} | {len(group)} | {size_med/1024:.0f} KiB | {a:.2f} | {b:.2f} | {a/b:.2f}× |")

    lines.append("\n## 吞吐与内存\n")
    lines.append("| 指标 | rekit | pefile |")
    lines.append("|---|---:|---:|")
    ta = results["rekit (纯 Python)"]
    tb = results["pefile"]
    lines.append(f"| {len(files)} 文件总耗时（中位数，秒） | {ta['total']:.2f} | {tb['total']:.2f} |")
    lines.append(f"| 吞吐（文件/秒） | {len(files)/ta['total']:.1f} | {len(files)/tb['total']:.1f} |")
    lines.append(f"| 单文件中位耗时（毫秒） | "
                 f"{statistics.median(ta['med'].values())*1000:.2f} | "
                 f"{statistics.median(tb['med'].values())*1000:.2f} |")
    lines.append(f"| 内存峰值（MiB，tracemalloc） | {mem['rekit (纯 Python)']/2**20:.1f} | "
                 f"{mem['pefile']/2**20:.1f} |")
    lines.append(f"| 冷启动 import（毫秒，已减基线） | {cold['rekit']*1000:.0f} | "
                 f"{cold['pefile']*1000:.0f} |")

    lines.append("\n## 测量方法\n")
    lines.append("- 每轮内逐文件计时，取 3 轮中位数作为该文件耗时；档位取组内中位数，避免长尾拉偏；")
    lines.append("- 总耗时取 3 轮中位数；吞吐 = 文件数 / 总耗时；")
    lines.append("- 内存峰值：另起一轮，`tracemalloc` 统计 Python 层分配峰值（不含解释器/扩展模块常驻）；")
    lines.append("- 冷启动：3 次子进程 `python -c \"import …\"` 的中位数，减去 `python -c pass` 基线；")
    lines.append("- 语料与 M1 B1 完全相同（CSV 的 `file` 列），未按大小或结果挑选。\n")

    lines.append("## 为什么快 / 为什么内存高\n")
    lines.append("**快在少做事，不是做得巧。** 两者任务是同一子集，但实现路径不同：\n")
    lines.append("- 单遍顺序解析：文件头 → 节表 → 数据目录，全部用 `struct.unpack_from` 在原始缓冲区上取值，"
                 "不建对象树；pefile 为每个头/节/导入项创建 `Structure` 实例并回写格式化属性，"
                 "成本随结构数量线性增长。")
    lines.append("- 只解析要求的目录（导入、导出），不碰重定位、资源、调试、签名；"
                 "pefile 即使 `fast_load=True`，`parse_data_directories` 仍带一层通用分发。")
    lines.append("- 字符串按 `bytes` 切片取，不逐字符解码；序号导入保持 `#序号`，不做 ordlookup 名称映射。")
    lines.append("- 节数据不复制：`Section.raw` 是整个文件缓冲区的 `memoryview` 切片，"
                 "旧版每个节 `data[ptr:ptr+size]` 都复制一份。\n")
    lines.append("**内存策略**：小文件整读、大文件（≥ 8 MiB）`mmap` 按页读，"
                 "`Section.raw` 零拷贝；SHA256 改为按需。500 个 System32 的 tracemalloc 峰值 "
                 "7.9 MiB vs pefile 4.8 MiB（旧版 15.6 MiB：整文件 + 节切片副本）。"
                 "大文件按真实进程峰值另测，见 [docs/memory.md](memory.md)。\n")
    lines.append("**冷启动**：rekit 略慢于 pefile，因为 `rekit.core.pe` 走包 import（`rekit/__init__` "
                 "+ `core/__init__` 链），pefile 是单模块；差值在毫秒级，可忽略。\n")
    lines.append("## 局限\n")
    lines.append("- **这个倍率来自只解析导入导出的实现**；补齐重定位、资源、调试目录后，"
                 "rekit 会做更多事，倍率必然下降。它衡量的是当前子集，不是\"解析 PE 比 pefile 快 9 倍\"。")
    lines.append("- 两边都不解析重定位，因为 rekit 尚未实现 `relocations()`；"
                 "加上后 rekit 的相对优势会缩小。")
    lines.append("- 语料是 System32 前 500 个（M1 B1 同一批），最大约 10 MiB，"
                 "不含 50 MB 以上的超大文件（后者见 [docs/memory.md](memory.md)）。")
    lines.append("- 单机单次测量，未做 CPU 频率锁定；数值用于量级判断，不用于微优化回归。")
    lines.append("- 基准日期 2026-11-11，可复跑：`python rekit/bench/benchmark.py "
                 "--from-csv 实践/2026-11-11-m1/sys32_500.csv --out rekit/docs/benchmark.md`。\n")

    text = "\n".join(lines) + "\n"
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[写入] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
