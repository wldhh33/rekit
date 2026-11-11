# 大文件内存改造（2026-11-11）

上一版基准里 rekit 的 tracemalloc 峰值 15.6 MiB vs pefile 4.8 MiB。根因不是"Python 慢"，而是
**整个文件读进 bytes，再把每个节切片复制一份**：峰值 ≈ 文件大小 × 2，文件越大越离谱。
本文记录改造前后的真实数字与代价。

## 改了什么

| 改动 | 位置 | 作用 |
|---|---|---|
| ≥ 8 MiB 的文件走 `mmap` 按页读，以下仍整读 | `core/pe.py: PE.__init__` | 大文件只把解析到的页拉进工作集；小文件不付 mmap/缺页开销 |
| `Section.raw` 改为整个缓冲区的 `memoryview` 切片 | `core/pe.py: Section` | 去掉每个节的 bytes 副本 |
| `sha256` 改为按需属性 | `core/pe.py: PE.sha256` | 结构解析不需要哈希；上一版基准里 rekit 顺手算了、pefile 没算，任务并不对等 |
| > 512 MiB 默认拒绝，`--allow-large` / `allow_large=True` 显式放行 | `core/pe.py` + `cli.py` | 不再"默默吃掉几百 MB" |

## 改造前后：M1 huge 语料（23–230 MB）

同一台机器（Windows 11 build 26200 / Python 3.14.0 / pefile 2024.8.26），每个文件独立子进程，
读进程峰值工作集（`PeakWorkingSetSize`，已减 import 基线），改造后每项 3 次取中位数。
任务与基准一致：打开 + 节表/数据目录 + imports + exports。

| 文件 | 大小 MiB | 改造前峰值 MiB | 改造后峰值 MiB | 改造前耗时 ms | 改造后耗时 ms |
|---|---:|---:|---:|---:|---:|
| MRT.exe | 219.6 | 464.0 | 26.8 | 193.1 | 0.7 |
| OneDriveSetup.exe | 85.6 | 197.8 | 27.1 | 76.6 | 1.4 |
| mfxplugin64_hw.dll | 26.7 | 79.9 | 27.1 | 23.9 | 0.5 |
| edgehtml.dll | 24.8 | 76.4 | 27.2 | 23.7 | 1.2 |
| mshtml.dll | 22.9 | 72.6 | 27.1 | 21.5 | 1.5 |

- 230 MB 文件：峰值 **464 MiB → 26.8 MiB**（基线 26.7 MiB，即解析几乎不再额外占内存），耗时 **193 ms → 0.7 ms**。
- 耗时同时下降，是因为旧版每次解析都读完整文件并算 SHA256；新版只读头/节表/导入导出所在的页。
- 改造后 5 个文件的净内存都在 0–0.5 MiB，属于测量噪声量级（±1 MiB）。
- 对照 pefile（同为 mmap）：MRT 27.5 MiB / 6.6 ms；mfxplugin64 56.5 MiB / 16.3 ms。
  rekit 的峰值更低，是因为它不建完整对象模型。

## 小文件有没有变慢

没有。500 个 System32（中位 208 KiB）改造前后：

| 指标 | 改造前 | 改造后 |
|---|---:|---:|
| 500 文件总耗时（中位） | 0.43 s | 0.27–0.28 s（两次测量） |
| 单文件中位耗时 | 0.55 ms | 0.41–0.43 ms |
| tracemalloc 峰值 | 15.6 MiB | 7.9 MiB |

小文件仍走整读路径，8 MiB 阈值按"System32 `large` 档最大约 10 MiB、中位 1.6 MiB"选：
阈值以下 mmap 的建映射成本大于收益，阈值以上收益随文件大小线性增长。
`--per-file` 模式可复测任意语料，若换了语料发现拐点不同，直接改 `DEFAULT_MMAP_THRESHOLD`。

## 代价与仍然存在的内存开销

- **triage 是"必须看每个字节"的任务**：算 SHA256 + 对每个 RawSize ≥ 4096 的节算熵。
  第一版改造只把解析换成 mmap，triage 的峰值**没有下降**（MRT 仍是 246 MiB）——
  原因不是复制，而是**顺序扫过 220 MB 映射页后，这些页都计入进程工作集**
  （`PeakWorkingSetSize` 统计驻留页，mmap 只保证"可回收"，不保证"不驻留"）。
  第二版把 triage 改成一次 `read()` 分块顺序读，同时算 SHA256 和每节直方图：
  每块 1 MiB，页缓存不计工作集，峰值才真正下来。见下节。
- **unpack 仍整读**：脱壳需要整块解压（解压后镜像本身就有几十 MB），不在本次范围内。
- mmap 的页算进程工作集、不算 Python 堆；拿 tracemalloc 比较 mmap 实现会低估对方，本文的
  前后对比用进程峰值工作集，避免这个问题。

## triage：分块顺序读（SHA256 + 每节熵）

旧实现：`PE` 打开文件（mmap）→ `pe.sha256` 扫一遍 → 对每个大节 `Section.raw` 逐字节
`for b in data: counts[b] += 1`，纯 Python 循环。两个问题：mmap 扫完所有页后工作集涨到文件大小；
逐字节循环只有约 40 MiB/s。

新实现（`analyzers/triage.py::_scan_file`）：以 1 MiB 为单位顺序 `read()`，同一块里
累加 SHA256、并按节的文件区间更新 256 桶直方图（`Counter`，C 层计数）。
内存与文件大小解耦，熵的数学定义不变（桶数 / 总字节）。

| MRT.exe（219.6 MiB，单个子进程） | 改造前 | 改造后 |
|---|---:|---:|
| 峰值工作集 | 246.1 MiB | **30.2 MiB** |
| 耗时（3 次中位） | 10.63 s | **4.87 s** |

500 个 System32（主流场景，不能退化）：

| 指标 | 改造前 | 改造后 |
|---|---:|---:|
| 总耗时 | 9.50 s | **5.89 s**（19.0 → 11.8 ms/文件） |
| 峰值工作集 | 32.7 MiB | 34.9 MiB（最大单文件 ~10 MiB，噪声范围） |

小文件反而更快，原因是旧代码对每个大节算了两遍熵（`max(key=entropy)` 之后又取
`top.entropy`），且纯 Python 逐字节循环被 `Counter` 取代。内存的 +2 MiB 来自 500 个
`TriageResult` 列表本身，与熵无关。

### 这个方案的上限

- 熵仍是 O(字节) 且逐字节；纯标准库没有更快的直方图原语，实测约 45 MiB/s
  （旧循环 40 MiB/s）。220 MB 仍需 ~4.9 s，这是"看每个字节"的成本，不是内存问题。
- 只统计 RawSize ≥ 4096 的节（`MIN_ENTROPY_SECTION`），小的 `.reloc`/`.tls` 不计；
  这与判据一致（加壳看的是大节）。

## 复跑命令

```bash
# triage 单文件峰值工作集 + 耗时（子进程，减 import 基线）
python rekit/bench/benchmark.py --child rekit-triage C:\Windows\System32\MRT.exe

# 改造后：逐文件峰值工作集 + 耗时（大文件）
python rekit/bench/benchmark.py --from-csv 实践/2026-11-11-m1/huge.csv --per-file \
  --out 实践/2026-11-11-m1/mem_after.md

# 500 个 System32 的吞吐 / 内存基准
python rekit/bench/benchmark.py --from-csv 实践/2026-11-11-m1/sys32_500.csv \
  --out rekit/docs/benchmark.md
```

改造前的数字留档在 `实践/2026-11-11-m1/mem_before.md`。
