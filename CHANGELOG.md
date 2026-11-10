# 变更日志

## 0.2.0 — 2026-11-11

### 新增 `rekit unpack`

把学习项目里 D2 手工脱壳的能力回流进产品，实现位于 `rekit/core/upx.py`，
`工具库/pe/unpack_upx.py` 改为它的薄 CLI 包装，避免两份代码漂移。

- 识别 UPX PackHeader（version / format / method / level / filter / cto / checksum）
- 解压：NRV2B_LE32（method=2）、NRV2E_LE32（method=8），带 adler 校验与消费字节数
- 反过滤：`u_ctok32_e8e9_bswap_le`，范围 = `BaseOfCode` 起 `SizeOfCode`（可选头 +4）字节
- IAT 重建：名称 / 序号 / 预置原值三类槽位，`inamespos=0` 走原位写回
- 重定位重建：`unoptimizeReloc` 增量解码 + 8 字节 bswap 还原，按 4KB 页重建 `.reloc`
- `.rsrc` 重建：复刻 `PeFile::rebuildResources` —— 从壳区搬回未压缩资源数据（保留原 RVA
  与 4 字节对齐）、重建资源目录树（三层、命名项、名称区）、图标组计数 `icondir_count`
- TLS 检查、DOS stub 复用、`SizeOfHeaders` / `chksum` / DEBUG / IAT / BOUND_IMPORT 修正
- 按原布局写文件，并与原件对照输出 `.text` 差异、整文件差异、IAT 条数
- CLI：`rekit unpack <paths> [-d out_dir] [--verify-only] [-j report.json]`，默认输出到 `./unpacked/`

### 实测（本地样本不进仓库）

| 样本 | 资源项 | 重建前整文件残差 | 重建后 | 与 `upx -d` |
|---|---|---|---|---|
| 7z 24.08 | 2（搬回 2） | 1,712 | 284 | 0 字节 |
| notepad | 31（搬回 16） | 91,796 | 1,455 | 0 字节 |
| hello_rs | 0 | 232 | 232 | 0 字节 |

剩余残差来自 DEBUG/IAT 目录项清零、CodeView 调试记录、导入名区重排与资源目录树布局规范化，
参考实现 `upx -d` 对原件的差异与之一致。

### 测试

- 新增 `tests/test_unpack.py`（8 条）：hello_rs（自有样本）端到端 `.text` 零字节差、
  IAT 85/85、产物运行输出 `hello from rustc, sum=385`；资源目录解析/重建逐字节往返；
  本地 7z 样本资源重建（无样本时自动跳过）；CLI 写文件 / JSON / `--verify-only`；
  非 UPX 输入不崩。
- 新增 `SizeOfCode` 偏移回归（`test_unfilter_range_equals_size_of_code`）与变异验证
  （`test_size_of_code_mutation_is_caught`）：把 codesize 退回可选的 +16（AddressOfEntryPoint）
  后，`.text` 尾部 43 处 `E8/E9` 共 172 字节不再被反过滤，逐字节对照立即报错。
- 删除 triage 测试里"unpack 未实现、返回 0.2.0"的占位断言。
- `python -m pytest -q`：32 passed（含 1 条依赖本地 7z 样本的用例）。

### 新增 `rekit map`（D4）

- `core/pe.py`：`section_map()` / `map_rva()` / `loader_notes()` / `format_map()`，
  按加载器语义区分 `headers` / `file` / `zero_fill` / `file_slack` / `align_pad` / `gap` /
  `beyond_image`；`VirtualSize=0` 时按 PE 规范回退到 `RawSize`。
- CLI：`rekit map <paths> [--rva 0x...] [-j report.json]`，输出节表对照（RVA 区间、
  FOA 区间、内存长度、文件长度、补零、松弛、权限）与加载器提示（越界、未对齐、重叠、
  SizeOfImage 截断、入口不在代码节）。
- 实测：120 个 System32 文件、1,790 个节起点/中点探针，与 pefile `get_offset_from_rva`
  0 差异；120/120 个文件存在 `RawSize > VirtualSize` 的文件松弛，64/120 存在内存补零。
- 新增 `tests/test_map.py`（6 条）：节表与原始头一致、pefile 对照、UPX0 纯内存节、
  头部/越界、合成文件的文件松弛与对齐填充、CLI JSON。
- `python -m pytest -q`：38 passed。

### 性能基准（同语料 vs pefile）

- 新增 `bench/benchmark.py`：锁定 M1 B1 的 500 个 System32 文件，同一任务
  （打开 + 节表/数据目录 + imports + exports）；预热 10 个、3 轮取中位数，
  内存峰值用 `tracemalloc` 单独跑一轮，冷启动用子进程 import 减解释器基线。
- 结果（Windows 11 / Python 3.14 / pefile 2024.8.26）：总耗时 **0.43 s vs 2.50 s**
  （约 6×，1,156 vs 200 文件/秒）；单文件中位数 0.55 ms vs 4.46 ms；
  内存峰值 15.6 MiB vs 4.8 MiB；冷启动 27 ms vs 23 ms。
- 原因与局限写进 [docs/benchmark.md](docs/benchmark.md)：快在单遍顺序解析、不建对象树、
  只解析导入/导出；内存高在整文件读入 + 切片副本；两边都不解析重定位。

### 已知边界

- 32 位 PE、LZMA / CL1B、UPX2 多节壳未覆盖，遇到时明确报"不支持"而不是产出错误文件。
- 资源目录树的**布局**与原件可能有几十到几百字节差异（UPX 打包时已把原目录清零，
  只剩重建版），`upx -d` 亦然；资源数据本身逐字节一致。

## 0.1.0 — 2026-11-10

- 首个版本：`rekit triage`，六条加权信号（UPX 节名成对、零 Raw 可执行节、高熵节、
  导入表截断等），每条带文件偏移证据；JSON / Markdown 双输出。
