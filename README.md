# rekit

模块化的二进制分析流水线 CLI。**编排 + 证据链 + 可复现**，不重复造轮子。

A modular binary-analysis pipeline CLI. **Orchestration + evidence chain + reproducibility**, no reinventing wheels.

> **快**：500 个 System32 文件全量解析（头 / 节 / 导入 / 导出）**0.43 s**，同任务 pefile **2.50 s**
> —— 约 **6×**；单文件中位数 0.55 ms vs 4.46 ms。代价是内存峰值 15.6 MiB vs 4.8 MiB。
> 测量方法、分档数据与原因分析见 [docs/benchmark.md](docs/benchmark.md)。

```
rekit triage <path...>   → PE 概览、异常评分、壳识别   [v0.1 已实现]
rekit unpack <path...>   → 静态脱壳（UPX 优先）        [v0.2 已实现]
rekit map    <path...>   → 节 RVA↔FOA / 加载器映射      [v0.2 已实现]
rekit symbols <path...>  → Ghidra headless 出函数边界  [v0.3 计划]
rekit report             → Markdown + JSON            [随各段输出]
```

设计原则（Design principles）：

- **每条结论都能回指字节**：信号里带文件偏移（FO，file offset），不是"看起来很可疑"。
- **可复现**：同一输入 + 同一命令 + 同一版本 → 同样的结果（除时间戳）。
- **不重复造轮子**：解析用标准库手写（可控、可审计），符号用 Ghidra，脱壳复用已验证探针。
- **依赖极少**：v0.2 运行时零第三方依赖，CLI 只用 `argparse`。

---

## 安装 / Install

需要 Python ≥ 3.10。

```bash
git clone <repo-url> rekit && cd rekit
python -m pip install -e .
```

装有 pytest 时跑测试：

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

> 若 `rekit` 命令不在 PATH（Windows 用户级安装的常见情况），用等价的 `python -m rekit`。

## 用法 / Usage

```bash
# 两个文件：未加壳 vs UPX 加壳
python -m rekit triage tests/fixtures/hello_rs.exe tests/fixtures/hello_rs.packed.exe \
  -o out.json -m out.md

# 目录 / 通配符 / csv 之外的批量输入
python -m rekit triage 样本/packed -o out.json -m out.md
```

真实输出（2026-11-10，rekit 0.1.0）：

```
normal    无   0分  未发现加壳迹象                      tests\fixtures\hello_rs.exe
upx       高  12分  UPX（节名成对 + 高熵 + 导入截断）     tests\fixtures\hello_rs.packed.exe
[JSON] out.json
[MD]   out.md
```

Markdown 报告结构：总览表 → 失败文件 → 逐文件证据（每条信号的权重/命中/偏移）→ 判据说明与边界。

### 脱壳 / Unpack

```bash
# 写出脱壳文件到 ./unpacked/，并把报告存成 JSON
python -m rekit unpack tests/fixtures/hello_rs.packed.exe -d unpacked -j unpack.json

# 只校验、不落盘（适合批量回归）
python -m rekit unpack tests/fixtures/hello_rs.packed.exe --verify-only
```

支持 PE32+ / NRV2B / NRV2E / filter 0x49；不调用 `upx -d`，按 UPX 源码的格式定义重放：
PackHeader → 解压（adler 校验）→ 反过滤（覆盖 `BaseOfCode + SizeOfCode`）→ IAT 重建 →
重定位重建 → `.rsrc` 重建（资源数据搬回 + 目录树重建）→ TLS 检查 → DOS stub + 原节表按原布局写文件。

真实输出（2026-11-11，rekit 0.2.0）：

```
OK   tests\fixtures\hello_rs.packed.exe
  路径   静态还原（UPX 13 / NRV2B_LE32 / filter=0x49）
  解压   141,660 字节（压缩 59,388），adler 一致 0x959BC30F
  IAT    10 个 DLL / 85 个符号；重定位 299 条
  对照   .text 90,112 字节中 0 字节不同；整文件 232 字节不同
  输出   unpacked\hello_rs.unpacked.exe
  [通过] 反过滤：filter=0x49，范围 [0x0, +0x16000) = SizeOfCode，改写 2097 处，跳过 491 处
  [通过] 逐字节对照：.text 90,112 字节中 0 字节不同；整文件 130,560 字节中 232 字节不同
         （DEBUG/IAT 目录项、调试记录与导入名区由 UPX 规范化）
```

那 232 字节残差与 `upx -d` 的行为一致（实测两者输出 **0 字节差**）：UPX 会把 DEBUG/IAT
目录项与 CodeView 调试记录清零，并重新排布导入名区，原始未加壳文件里对应的字节自然对不上。
判定标准因此是 `.text` 逐字节一致 + IAT 条数一致 + 产物可运行，而不是"整文件等于原件"。

资源目录重建后，带资源的样本也与参考实现对齐（2026-11-11 本地实测，样本不进仓库）：

| 样本 | 壳 | 资源项 | 未重建时整文件残差 | 重建后 | 与 `upx -d` 差异 |
|---|---|---|---|---|---|
| 7z 24.08 | NRV2E | 2（搬回 2） | 1,712 | 284 | 0 字节 |
| notepad | NRV2E | 31（搬回 16） | 91,796 | 1,455 | 0 字节 |

剩余残差全部落在"UPX 自己也还原不了"的桶里：DEBUG/IAT 目录项清零、CodeView 调试记录、
导入名区重排，以及资源**目录树**的布局规范化（资源数据本身 0 字节差）。`upx -d` 产物里
这些字节同样对不上原件，说明不是本实现独有的缺口。

已知边界：32 位 PE、LZMA/CL1B、UPX2 多节壳未覆盖；图标组计数（`icondir_count`）已实现，
但遇到"资源被压缩进主镜像"的条目只搬运不重排，行为与 `upx -d` 一致。

### 节映射 / Map

```bash
# 每个节的 RVA 区间 ↔ FOA 区间、内存补零、文件松弛
python -m rekit map tests/fixtures/hello_rs.packed.exe --rva 0x1000 --rva 0x1C589

# 批量 + JSON
python -m rekit map 样本/packed -j map.json
```

回答两个容易混淆的问题：**内存里有、文件里没有**（`VirtualSize > RawSize`，loader 补零），
以及**文件里有、内存里没有**（`RawSize > VirtualSize`，超出部分不会被映射）。`--rva` 逐个
说明某个 RVA 属于 `headers` / `file` / `zero_fill` / `file_slack` / `align_pad` / `gap` /
`beyond_image` 的哪一种，并给出判据。

真实输出（2026-11-11，rekit 0.2.0，UPX 加壳样本）：

```
..\样本\packed\hello_rs.packed.exe  PE32+ AMD64  ImageBase=0x140000000  SectionAlign=0x1000 FileAlign=0x200
   # 节      RVA 区间                FOA 区间                内存   文件     补零   多出  权限
   0 UPX0    0x1000-0x16000         0x400-0x400              86,016      0   86,016      0  R-X
   1 UPX1    0x16000-0x25000        0x400-0xF200            61,440 60,928      512      0  RWX
  探针 RVA 0x1000 -> zero_fill 节=UPX0
       节 UPX0 内偏移 0x0 在 [RawSize=0x0, VirtualSize=0x15000)，内存补零、文件里没有
```

与 pefile 的 `get_offset_from_rva` 对照：120 个 System32 文件、1,790 个节起点/中点探针，0 差异。

### 输出契约 / Output contract

JSON 顶层：

```json
{
  "tool": "rekit", "version": "0.2.0", "generated_at": "…",
  "analyzer": "triage",
  "results": [ { "file": "…", "verdict": "upx", "confidence": "高", "score": 12,
                 "signals": [ { "id": "S1_upx_section_pair", "weight": 4, "hit": true,
                                "evidence": "节表 FO 0x200：节名 ['UPX0','UPX1','UPX2']" } ] } ],
  "errors":  [ { "file": "…", "error": "PEError: …" } ]
}
```

- `verdict` ∈ `normal` / `odd` / `packed?` / `upx`
- `confidence` ∈ `无` / `低` / `中` / `高`（分数 ≥2 / ≥5 / ≥9）
- **`errors` 永远显式列出**，不静默跳过失败文件。

`unpack` 的每条 `results[]`（报告里"用了哪条路径 / 解压字节数 / adler / IAT 条数 / 与原件差异"）：

```json
{
  "packed": "…", "raw": "…", "out": "…",
  "path_used": "静态还原（UPX 13 / NRV2B_LE32 / filter=0x49）",
  "upx":     {"version": 13, "method": 2, "method_name": "NRV2B_LE32", "checksum_ok": true},
  "unpacked_bytes": 141660, "compressed_bytes": 59388, "consumed_bytes": 59388,
  "adler":   {"declared": "0x959BC30F", "actual": "0x959BC30F", "ok": true},
  "unfilter":{"filter": "0x49", "start": 0, "size": 90112, "calls": 2097, "skipped": 491},
  "imports": {"dlls": 10, "names": 85, "ordinals": 0, "raw": 0},
  "relocs":  {"dir64": 299, "other": 0, "bytes": 664},
  "diff":    {"text_size": 90112, "text_mismatch": 0, "file_size": 130560, "file_mismatch": 232},
  "checks":  [{"name": "逐字节对照", "ok": true, "detail": "…"}],
  "ok": true
}
```

`map` 的每条 `results[]`：

```json
{
  "file": "…", "format": "PE32+", "arch": "AMD64",
  "section_alignment": "0x1000", "file_alignment": "0x200", "size_of_image": "0x26000",
  "sections": [{"index": 0, "name": "UPX0", "rva": "0x1000-0x16000", "foa": "0x400-0x400",
                "virtual_size": 86016, "raw_size": 0, "zero_fill": 86016, "file_slack": 0,
                "executable": true, "readable": true, "writable": false}],
  "notes": ["节 UPX0 内存补零 0x15000 字节（VirtualSize > RawSize）"],
  "probes": [{"rva": 4096, "kind": "zero_fill", "section": "UPX0", "foa": null,
              "detail": "节 UPX0 内偏移 0x0 在 [RawSize=0x0, VirtualSize=0x15000)，内存补零、文件里没有"}]
}
```

---

## 为什么需要它 / Why

逆向学习中反复出现的动作是「拿到一个陌生二进制 → 判断它是什么 → 决定下一步」。这些判断散在脚本、笔记和记忆里，结论无法回查、无法复现、无法回归。

rekit 把这些判断固化成**可测的代码**：今天学到的一条判据，明天就是 `triage` 的一个信号加一条测试；一次手工脱壳，就是 `unpack` 的一个用例。

## 扩展点 / Extension points

`rekit/analyzers/` 下每个模块是一个插件，契约只有三样：

```python
NAME = "triage"                                  # 子命令名
DESCRIPTION = "…"                                # 一句说明
def run(paths: list[str]) -> dict: ...           # 返回 JSON 友好结构
```

在 `rekit/analyzers/__init__.py` 的 `REGISTRY` 注册，再在 `rekit/cli.py` 加子命令即可。
架构、证据链规则与版本路线见 [DESIGN.md](DESIGN.md)；判据阈值与误报边界见 [docs/rules.md](docs/rules.md)。

## English quickstart

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python -m rekit triage tests/fixtures/hello_rs.exe tests/fixtures/hello_rs.packed.exe -o out.json -m out.md
```

```
normal    无   0分  未发现加壳迹象                      tests\fixtures\hello_rs.exe
upx       高  12分  UPX（节名成对 + 高熵 + 导入截断）     tests\fixtures\hello_rs.packed.exe
```

Every verdict is a weighted sum of six signals (`triage.py`), and each signal carries an `evidence` string with a
**file offset** (`FO 0x…`) so you can re-check it in a hex editor. Thresholds, sample table and known bypasses live in
[docs/rules.md](docs/rules.md); the System32 batch run (140 files, 0 errors, ~22 ms/file) is in
[docs/triage-batch.md](docs/triage-batch.md).

Exit codes: `0` success (at least one file analysed/unpacked and every check passed) · `1` nothing processed, a check failed, or output write failed · `2` subcommand not implemented yet.
`errors[]` is always emitted — failed inputs are never silently skipped.

## 许可 / License

MIT，见 [LICENSE](LICENSE)。

测试样本是自编译的 Hello World（Rust），可自由再分发；**仓库不含任何专有系统文件或恶意样本**，见 [tests/fixtures/README.md](tests/fixtures/README.md)。

## 状态 / Status

v0.2.0 —— `triage` + `unpack` + `map`。`unpack` 覆盖 PE32+ 的 UPX（NRV2B / NRV2E / filter 0x49），
`.text` 与原件逐字节一致、IAT / 重定位 / `.rsrc` 重建、按原布局写文件，7z 与 notepad
两个真实样本的产物与 `upx -d` 零字节差；`map` 给出节 RVA↔FOA 对照与加载器视角
（内存补零 / 文件松弛 / 未映射间隙），对 120 个 System32 文件 1,790 个探针与 pefile 零差异。
32 位 PE、LZMA/CL1B 与多节 UPX2 壳仍在路线图上。`symbols` 是占位（退出码 2 并提示计划版本），
不假装成功。

版本变更见 [CHANGELOG.md](CHANGELOG.md)。
