# 解析性能基准

- 环境：Windows-11-10.0.26200-SP0 / Python 3.14.0 / pefile 2024.8.26
- 语料：500 个文件（实践/2026-11-11-m1/sys32_500.csv），预热 10 个，3 轮取中位数
- 任务：打开 + 节表/数据目录 + imports + exports（两边同一子集；rekit 尚未解析重定位）
- rekit 侧不计算 SHA256（改为按需属性）：上一版基准里它顺手算了哈希，pefile 没有，两边任务并不对等；这一版才是同任务。
- 计时不含内存采样；内存峰值用 tracemalloc 单独跑一轮（仅 Python 分配，mmap 的页不计入，大文件真实峰值见 docs/memory.md）

## 分档单文件耗时（毫秒，中位数）

| 档位 | 文件数 | 大小中位数 | rekit | pefile | 倍率 |
|---|---:|---:|---:|---:|---:|
| small | 74 | 44 KiB | 0.24 | 2.96 | 0.08× |
| medium | 371 | 208 KiB | 0.43 | 4.73 | 0.09× |
| large | 55 | 1675 KiB | 1.14 | 7.66 | 0.15× |

## 吞吐与内存

| 指标 | rekit | pefile |
|---|---:|---:|
| 500 文件总耗时（中位数，秒） | 0.28 | 2.57 |
| 吞吐（文件/秒） | 1810.4 | 194.9 |
| 单文件中位耗时（毫秒） | 0.43 | 4.66 |
| 内存峰值（MiB，tracemalloc） | 7.9 | 4.8 |
| 冷启动 import（毫秒，已减基线） | 28 | 20 |

## 测量方法

- 每轮内逐文件计时，取 3 轮中位数作为该文件耗时；档位取组内中位数，避免长尾拉偏；
- 总耗时取 3 轮中位数；吞吐 = 文件数 / 总耗时；
- 内存峰值：另起一轮，`tracemalloc` 统计 Python 层分配峰值（不含解释器/扩展模块常驻）；
- 冷启动：3 次子进程 `python -c "import …"` 的中位数，减去 `python -c pass` 基线；
- 语料与 M1 B1 完全相同（CSV 的 `file` 列），未按大小或结果挑选。

## 为什么快 / 为什么内存高

**快在少做事，不是做得巧。** 两者任务是同一子集，但实现路径不同：

- 单遍顺序解析：文件头 → 节表 → 数据目录，全部用 `struct.unpack_from` 在原始缓冲区上取值，不建对象树；pefile 为每个头/节/导入项创建 `Structure` 实例并回写格式化属性，成本随结构数量线性增长。
- 只解析要求的目录（导入、导出），不碰重定位、资源、调试、签名；pefile 即使 `fast_load=True`，`parse_data_directories` 仍带一层通用分发。
- 字符串按 `bytes` 切片取，不逐字符解码；序号导入保持 `#序号`，不做 ordlookup 名称映射。
- 节数据不复制：`Section.raw` 是整个文件缓冲区的 `memoryview` 切片，旧版每个节 `data[ptr:ptr+size]` 都复制一份。

**内存策略**：小文件整读、大文件（≥ 8 MiB）`mmap` 按页读，`Section.raw` 零拷贝；SHA256 改为按需。500 个 System32 的 tracemalloc 峰值 7.9 MiB vs pefile 4.8 MiB（旧版 15.6 MiB：整文件 + 节切片副本）。大文件按真实进程峰值另测，见 [docs/memory.md](memory.md)。

**冷启动**：rekit 略慢于 pefile，因为 `rekit.core.pe` 走包 import（`rekit/__init__` + `core/__init__` 链），pefile 是单模块；差值在毫秒级，可忽略。

## 局限

- **这个倍率来自只解析导入导出的实现**；补齐重定位、资源、调试目录后，rekit 会做更多事，倍率必然下降。它衡量的是当前子集，不是"解析 PE 比 pefile 快 9 倍"。
- 两边都不解析重定位，因为 rekit 尚未实现 `relocations()`；加上后 rekit 的相对优势会缩小。
- 语料是 System32 前 500 个（M1 B1 同一批），最大约 10 MiB，不含 50 MB 以上的超大文件（后者见 [docs/memory.md](memory.md)）。
- 单机单次测量，未做 CPU 频率锁定；数值用于量级判断，不用于微优化回归。
- 基准日期 2026-11-11，可复跑：`python rekit/bench/benchmark.py --from-csv 实践/2026-11-11-m1/sys32_500.csv --out rekit/docs/benchmark.md`。

