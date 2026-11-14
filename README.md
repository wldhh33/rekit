# rekit

模块化的二进制分析流水线 CLI。**编排 + 证据链 + 可复现**，不重复造轮子。

A modular binary-analysis pipeline CLI. **Orchestration + evidence chain + reproducibility**, no reinventing wheels.

> **快（口径见下）**：500 个 System32 文件解析（头 / 节 / 导入 / 导出）**0.28 s**，
> 同任务 pefile **2.57 s** —— 约 **9×**；单文件中位数 0.43 ms vs 4.66 ms。
> 上一版报的 **6×** 是含「每文件 SHA256」的旧口径，两个数字不可直接比。
> **代价**：内存峰值更高（tracemalloc 7.9 MiB vs 4.8 MiB）、冷启动更慢（28 ms vs 20 ms）。
> 大文件已改 mmap + 分块读：230 MB 文件的结构解析峰值从 464 MiB 降到 26.8 MiB，
> `triage`（含 SHA256 与全节熵）从 246.1 MiB / 10.63 s 降到 30.2 MiB / 4.87 s。
> **这个倍数来自只解析导入导出的实现，功能补齐后倍数会下降。**
> 基准日期 2026-11-11，语料与跑法见 [docs/benchmark.md](docs/benchmark.md)、内存改造见
> [docs/memory.md](docs/memory.md)。

```
rekit triage <path...>   → PE 概览、异常评分、壳识别   [v0.3 已实现]
rekit unpack <path...>   → 静态脱壳（UPX 优先）        [v0.3 已实现]
rekit map    <path...>   → 节 RVA↔FOA / 加载器映射      [v0.3 已实现]
rekit funcs  <path...>   → 函数边界 + 证据来源          [v0.3 已实现]
rekit data   <path...>   → 字符串 / 指针数组 / 结构体   [v0.4 已实现]
rekit xref   <path...>   → 谁引用了这个字符串/地址/函数  [v0.5 已实现]
rekit identify <path...> → 工具链族 + 壳判定 + 证据类型 + 位数范围  [v0.6 扩展 M4a/M4b]
rekit symbols <path...>  → Ghidra headless 出函数边界  [计划]
rekit report <sample>    → 单样本自动化报告（24 字段）+ 规则命中  [v0.6 新增 M5]
```

`rekit data` 的三条硬规则（详见 [docs/data.md](docs/data.md)）：

- **C 串的"扫到不可打印字节为止"在 Go 上必然错**。go.exe 实测最长一条 56,098 字节，
  9,273 条 Go 串里 **84.05%** 会被这样读穿。Go 串只有两条正确入口：调用点的相邻参数槽、
  或 8 字节对齐的 `(ptr,len)` 头，每条结果带 `evidence`。
- **"指向代码"不足以定义函数指针表**。`.got/.plt/IAT` 整节排除；剩下的靠
  `authority_start_ratio`（命中 `.pdata`/`.eh_frame`/`.gopclntab` 起点的比例）判真假——
  同节两组同 stride 的数据实测 0.0 vs 1.0。
- **结构体只报偏移和宽度**（`[+0x18/8B]`），不猜类型；不做跨块值流，那是模拟执行的活。

`rekit xref` 的硬规则（详见 [docs/xref.md](docs/xref.md)）：

- **指令流只来自 `funcs` 的递归下降**，不写第二套线性扫描；召回上限 = 函数发现率。
- 确定集只收 RIP 相对操作数、直接分支 `rel32`、重定位 addend；绝对立即数、
  数据节指针、`.text` 字节扫描一律进疑似集。
- `.text` 内搜索必须声明是**指令边界**还是**字节扫描**；字节扫描命中必须标注
  “可能落在操作数内部”（`docs/rules.md` §0.1）。

```bash
# Go 二进制：字符串走双入口，数组与结构体同时出
python -m rekit data C:\Program Files\Go\bin\go.exe -j go.json --csv go_strings.csv

# 只想看 C 串（不需要 capstone）
python -m rekit data notepad.exe --no-arrays --no-structs
```

设计原则（Design principles）：

- **每条结论都能回指字节**：信号里带文件偏移（FO，file offset），不是"看起来很可疑"。
- **可复现**：同一输入 + 同一命令 + 同一版本 → 同样的结果（除时间戳）。
- **不重复造轮子**：解析用标准库手写（可控、可审计），符号用 Ghidra，脱壳复用已验证探针。
- **依赖极少**：v0.4 的 `triage`/`unpack`/`map` 与 `data` 的纯字符串扫描零第三方依赖；
  `funcs` 与 `data` 的 Go 串/结构体统计需要 capstone（`pip install -e ".[funcs]"`）。

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

`funcs` 需要反汇编后端（capstone），单独装：

```bash
python -m pip install -e ".[dev,funcs]"
```

> 若 `rekit` 命令不在 PATH（Windows 用户级安装的常见情况），用等价的 `python -m rekit`。

> **CI 测试覆盖**：`tests/test_m2_gate.py` 的 `go_win_amd64` 依赖仓库外样本（1.6 MB，未随仓库分发），
> CI 上该族为 skipped；`test_m2_gate_runs_on_in_repo_fixtures` 只用仓库内夹具跑同一条门槛与漂移断言，
> 覆盖 clang / go linux / rust musl 三族。
> **M2 门依赖仓库外样本，CI 上为 skipped，绿不等于门已执行。**
> CI 另以 `REKIT_SKIP_PERF=1` 关闭性能门（共享 runner 噪声）；性能门请在固定机器上跑
> `python -m pytest tests/test_perf_gate.py -q`。

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

支持 PE32+ / NRV2B / NRV2E / LZMA / filter 0x49；不调用 `upx -d`，按 UPX 源码的格式定义重放：
PackHeader → 解压（adler 校验）→ 反过滤（覆盖 `BaseOfCode + SizeOfCode`）→ IAT 重建 →
重定位重建 → `.rsrc` 重建（资源数据搬回 + 目录树重建）→ TLS 检查 → DOS stub + 原节表按原布局写文件。

LZMA（method=14）的流是 **2 字节 UPX 自有 properties + 裸 LZMA1**（`pb=b0&7, lp=b1>>4,
lc=b1&15`），不是 LZMA-alone：没有 5 字节属性头、没有 EOS marker。按 LZMA-alone 解释首字节会得
`lc=8`（非法）。裸流没有结束标记，因此只按 `u_len` + adler 判定，不校验"消费字节数"。

有同源未加壳文件时，`unpack` 还会把重建的 `.reloc` 字节表与原表逐项对照（含块对齐 ABS 填充）：
hello_rs 304/304、notepad 366/366 逐项相等（页、偏移、类型、顺序）。

overlay 不参与压缩，所以产物末尾接的是**打包文件的 overlay**（不是解压流尾部）。
若 overlay 是结构合法的 `WIN_CERTIFICATE`（`dwLength` 8 字节对齐后正好闭合、
`revision=0x0200`、`type=0x0002`），`unpack` 会把 security directory 恢复成
`offset=证书起点 / size=overlay 长度`，并在 JSON 的 `signature` 里分开报告
`bytes_present` / `certificate_valid` / `directory_restored`；结构不合格就保持清零。
rekit **不验签**：脱壳重建了头部，外部验证器预期报 `HashMismatch`（glab 实测签名者
`CN=GitLab Inc.`、状态 HashMismatch），不能据此认为发布链一致。无 overlay 时
`NotSigned` 就是事实，不追加检查项。

真实输出（2026-11-11，rekit 0.3.0）：

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

已知边界：32 位 PE、CL1B、UPX2 多节壳未覆盖；图标组计数（`icondir_count`）已实现，
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

真实输出（2026-11-11，rekit 0.3.0，UPX 加壳样本）：

```
..\样本\packed\hello_rs.packed.exe  PE32+ AMD64  ImageBase=0x140000000  SectionAlign=0x1000 FileAlign=0x200
   # 节      RVA 区间                FOA 区间                内存   文件     补零   多出  权限
   0 UPX0    0x1000-0x16000         0x400-0x400              86,016      0   86,016      0  R-X
   1 UPX1    0x16000-0x25000        0x400-0xF200            61,440 60,928      512      0  RWX
  探针 RVA 0x1000 -> zero_fill 节=UPX0
       节 UPX0 内偏移 0x0 在 [RawSize=0x0, VirtualSize=0x15000)，内存补零、文件里没有
```

与 pefile 的 `get_offset_from_rva` 对照：120 个 System32 文件、1,790 个节起点/中点探针，0 差异。

### 函数边界 / Funcs

```bash
# 权威表 + 递归下降 + 指针表；输出函数表（起点/终点/证据/口径）
python -m rekit funcs tests/fixtures/hello_elf

# 量化 B 层：穷举 + 不把 .eh_frame 当权威表；结构化落盘
python -m rekit funcs 样本/noeh.so --exhaust full --no-eh-frame \
  --json funcs.json --csv funcs.csv

# 孤立桶精度验算：参照表（Ghidra CSV）只量精度、不参与发现
python -m rekit funcs 样本/noeh.so --exhaust full --reference ghidra.csv

# 冷启动：禁用导出/符号/权威表播种，只用代码与数据本身（模拟 strip + PIE 恶意样本）
python -m rekit funcs 样本/stripped_pie --cold-start

# 交叉引用：从字符串找引用者函数（确定集），数据指针/立即数单列为疑似
python -m rekit xref tests/fixtures/gcc_o2.exe --string "hello from C, sum=%d leaf=%d"

# 从函数入口找调用点
python -m rekit xref tests/fixtures/gcc_o2.exe --va 0x1400034B0
```

52 MB 级目标不再按目标重复遍历：先解析全部目标，再只走一遍指令流，用字节级候选预筛
（RIP disp / 立即数 / rel8/rel32）跳过无关指令，命中后仍走原 operand 判定，结果逐条不变。
glab 脱壳件 `--string https://gitlab.com/` 全流程 **87.7 s**（旧实现单目标约 248 s，
且按命中数线性放大）；实现与等价性约束见 [docs/xref.md](docs/xref.md) §8。

PE64 用 `.pdata`、ELF64 用 `.eh_frame`、Go 用 `.gopclntab` 当权威函数表（A 层）；
Go PE 没有同名节，按 pclntab 魔数在数据节里扫（`go_win.exe`：`.pdata` 1588 → `.gopclntab` 1890，
表头 1892 里末尾 2 项是填充，已剔除）。Go 1.2–1.15 的旧头（`0xFFFFFFFB`）另走绝对
PC 解析（`goCrackMe.exe` 实测 1836 函数、冷启动 93.85%）。
**Go 函数名直接进 `funcs` 输出**：JSON 行级 `name`、CSV 末尾 `name` 列、控制台多一列
`函数名`；`authority.names_recovered/name_status` 说明恢复数量与状态，恢复不了就写
`不可恢复: 原因`，不用再绕过 CLI 调 `pclntab_from_data()`。
没有权威表的样本走 B 层（可达 / 含孤立两个口径）。`.eh_frame_hdr` 缺失时自动退回
线性扫描并标注。`.plt` 的误报单列，不混进 `.text` 的召回/误报。

孤立桶（`B-isolated`）在 CLI / JSON / CSV 三处都硬标 **不可交付（内部参考）**：
`isolated_metrics.deliverable` 恒 `false`，CSV `deliverable` 列对 `B-isolated` 行恒 `false`。
非 x86（如 ARM64）只交权威表，B 层跳过并在 `notes` 写明。

`--cold-start` 是贴近真实恶意样本的口径：导出表/符号/权威表都不参与播种，只剩入口、
`.init_array`/TLS 回调、GOT、PIE 相对重定位、字符串/代码取址、数据节函数指针、
间接调用（`call [reg+off]` 的块内有限值流 + 已知重定位槽位）、Go 的 `itab` 方法表，
与 `call` 边不动点。四族基线：Clang strip+PIE 23.8%、Go linux 36.5%、Go PE 62.1%、
Rust musl 42.3%（同二进制反事实口径 17.2% / 48.7% / 49.0% / 81.6%）；可达子集召回
**85.6% / 50.3% / 75.5% / 91.0%**，`.text` 误报 2 / 5 / 5 / 5（严格误报率均 <0.3%），
间接调用解析率 5.3% / 8.6% / 5.6% / 84.8%。
Go 的 `moduledata`/`itab` 播种（`metrics.cold_start.itab`）在 `go_linux_amd64` 与
`go_win.exe` 上分别把冷启动从 20.9%/25.9% 提到 36.4%/42.0%；随后指针槽位的两条修正
（冷启动不再读 `.pdata` 判重、多块函数不再被"首个 jmp 栈平衡"误拒）把两族可达子集
进一步推到 50.3%/75.5%，Clang 45.4% → 85.6%。缺口归因、Go 1.18–1.24 的实测版本范围与
`icall` 的负结论见 [docs/funcs.md](docs/funcs.md) §6.1–§6.4。

真实输出（2026-11-11，rekit 0.3.0，自带 ELF fixture，函数表 2848 行此处截断）：

```
tests\fixtures\hello_elf  ELF64  工具链=gcc(0.97)/gcc_x64  权威表=.eh_frame  2360 项
  起点        终点        大小  证据                        组      口径    节
  0x86600     0x8665F        95  entry                       直接引用  B 可达  .text
  0x86663     0x86699        54  jmp                         直接引用  B 可达  .text
  …
  0x86820     0x86889       105  eh_frame                    权威表    A       .text
  0x868C8     0x868CD         5  eh_frame+call               权威表    A       .text
  …
  [A 层] 起点 2360/2360  召回 100.0%  （.text 口径 2360 项，召回 100.0%）
         严格误报 0（.text 0，.plt 单列 0）；权威表外 488 个入口
  [自证]   不拿权威表播种：召回 81.6%，严格误报 432（.text 432）
  [证据]   权威表 2360；直接引用 488
```

`[自证]` 是反事实口径：不拿权威表播种，只靠入口/导出/递归下降/指针表，
用来证明召回不是"把答案当输入"得来的。

### 工具链识别 / Identify

```bash
python -m rekit identify a.exe b.exe -j identify.json
```

输出 `family` / `compiler_frontend` / `crt_provider` / `target_triple` / `bitness` / `scope` /
`confidence` / `signals[]`（每条命中信号带偏移与 `evidence_kind`）/ `conflicts[]`。硬规则：

- **`family` 指链接器提供方，不指编译器前端**：只取 `msvc` / `gcc` / `go` / `dotnet`，
  完整定义见 [docs/family.md](docs/family.md)。`rustc` / `clang` / `go` 写在
  `compiler_frontend`，不占 `family`；`crt_provider` 只描述链了哪套 CRT。
- **`clang` 的归属写死**：`clang` + MinGW GNU `ld` → `family=gcc`；`clang-cl` /
  `lld-link` → `family=msvc`。判据是最终链接步骤（target triple、`MajorLinkerVersion`、
  导入表），不是 `clang version` 串。`family` 枚举里没有 `clang`。
- **`unknown` 是合法结论，不硬猜**。`evidence_kind` 只有 `positive`（找到了什么：节、串、导入）
  和 `absence`（只证明没找到什么）两种；**absence 类信号只能削弱置信度，不能单独构成族判定**。
  `.rsrc` 有无只作观测（`family=None`）：它反映 MinGW 驱动是否默认链 manifest，既不是编译器
  身份，也不是链接器身份。
- **冲突必须可见**：cgo + MinGW（gitea 类）同时有 Go 前端证据与 GNU `ld` 证据，输出
  `conflicts=[{between:[go,gcc], ...}]`，`family=gcc`（族看最后写 PE 的链接器），
  Go 证据只计入 `compiler_frontend`。不靠调整分支顺序把冲突吞掉。
- **位数是独立字段**：x86 允许给族（如 `msvc`），但标 `scope=out_of_m4a`，不冒充 x64、
  也不进 M4a 的 x64 计分。x86 目前只做结构解析 / `map` / `funcs`（B 层），
  **不做 x86 库函数识别**（无签名库匹配，不标注或剔除已知库函数）。
- **x86 召回怎么读（两个数必须一起看）**：单样本 `notepad_x86` 的冷启动结果是
  **对全表 69.2%（424/613）** 与 **可达闭包内 98.2%（267/272）**。前者才是「能找到多少函数」，
  后者只说明「在 rekit 自己展开出的直接 `call`/`jmp` 闭包里不漏」，**不能当能力结论**。
  参照表是 Ghidra 的函数划分，**x86 没有权威表**，所以只能与同层参照横向自比，
  不与 x64 合并、不求差。换用 Ghidra 引用图算闭包的独立对照为 98.1%（265/270），
  结论同上。详见 `实践/2026-11-12-x86-pe/召回结果.md`、`闭包对照结果.md`。

> **口径断点（0.6.x → 0.7）**：0.6.x 的 `family` 可能输出 `rust_x64` / `clang_x64`，那是编译器前端
> 语义；0.7 起 `family` 只表示链接器提供方（见 [docs/family.md](docs/family.md)），前端迁到
> `compiler_frontend`、`schema_version` 升到 3。两套口径的数字**不可并列**：M4a 的 4 族 80/80、
> clang 10/20、A 轮 3 的 per-class 成绩都记在 0.6.x 口径下，不得与 0.7 的任何评估结果放在
> 同一张表、求差或画趋势。

### 外部落差 / External gap

> 看 `identify` 只该看这一节。自编样本上的高分不等于能力，**外部样本上的数才算数**。

> **0.7.0 的外部验证状态（2026-11-12 收口）**：B 池 v4.1 已按预注册跑完**唯一一次**评估
> （n=32、单池、一次性、不可外推）：macro-F1 **0.9683**、unknown **0/32**、跨族硬错
> **至少 1/32**。硬错率 3.125% 高于 3% 的容错上限（n=32 时允许 0 个），因此 **未达标**。
> 被判错的 `curl` 经二进制取证是检测器缺陷：它**没有 Rich 头**、无 `GCC:` 串、节表为 GNU
> 风格（`.buildid`/`.note`）、CRT 导入只有 `api-ms-win-crt-*`、内嵌 `x86_64-w64-mingw32`，
> 旧判定靠 T16（linker 14.0）单信号硬判 `msvc`，真值不需要复核。
> 另有一处真值标注缺陷 `syncthing`（应 `gcc`、记 `msvc`）：按定义修正后跨族硬错为 **2/32**
> （6.25%）、macro-F1 **0.9364** —— **修正真值只会让结果更差，不会改善**；冻结真值在这条上
> 使结果**偏乐观**，不是偏悲观。
> **外部验证到此收口**：A/B/C 三轮均因供给侧不足未能扩大 n（C 池 82 个资产只产出 25 个项目，
> `cgo=0`、`rust_gnu=0`），**第四轮不再进行**，缺口留档。B 池已消费，回归只能检查另外 31 个
> 是否被带偏，**不能替代验证**。结论只有一种写法：**未达标 + 缺口**，不写成「受样本所限
> 基本达标」。版本号前进了，能力叙述不跟着前进。

| 数据 | 规模 | 成绩 | 说明 |
|---|---:|---|---|
| 自编校准（开发期自检） | 30 | 27/30（计分 4 族 24/24；clang 3/6） | 拟合，不计判定 |
| 自编测试（一次性，`signals-v1`） | 100 | 4 族 **80/80**（CI 83.9–100，达标）；clang 10/20；unknown 10 | 同风格分布内的能力 |
| 外部 M3 十题 | 10 | **5/9**（x64 原生 PE；含 x86 为 7/9） | 真实第三方样本，最冷的水 |
| 外部 B 池 v4.1（一次性） | 32 | macro-F1 **0.9683**；unknown **0/32**；硬错 **≥1/32** | **未达标**；`curl` 属检测器缺陷，`syncthing` 真值按定义修正后应为 **2/32**（0.9364） |
| 外部 System32 500 | 500 | 硬错 1/500；unknown 0.4%；packed FPR 0 | 系统 DLL 上不误报 |
| 外部 `E_sys32` 200（留出） | 200 | 硬错 0/200；unknown 0；packed FPR 0 | FPR 结论稳定 |

**怎么读**：

- 自编 100% 只证明“在自编分布内可分”。测试源码与训练源码出自同一批人、同一风格，
  真正的冷水只有 M3 的 **5/9** 与系统 DLL 上的 **0 误报**。M4b 的 UPX 100%（40/40）同理，
  只说明同分布可分；它**只覆盖 UPX 5.0.0**，不是多壳族能力。
- 对外最有意义的两个数是 **5/9** 和 **0/700**：前者说明真实样本还有判不出的（2 个 unknown、
  1 个 packed、1 个 ELF 不支持），后者（`N_sys32` 500 + `E_sys32` 200）说明“不乱报”是稳的。
  M4b 的 `E_sys32_b` 200 留出切片同样 0 次误报；按该切片计的 Wilson 95% 上界为 **1.88%**
  （n=200，最保守），不能写成“FPR 已证明 ≤0.2%”。
- 测试侧 100 个变体只评估一次，结果归档在 `实践/M4/eval/test_once.json`；未达标时的正确做法是
  新建测试源码包重测，不在同一批数据上改信号后重跑。
- **负样本口径（2026-11-22 定稿）**：测试侧没有负样本，**FPR 只由外部系统 DLL 集给出**
  （`N_sys32` 500 开发期 + 每次只跑一次的 200 个留出切片）。不补建的公开理由：从同一
  System32 池复制进 `corpus/test` 不是独立样本；真正的独立负样本需要第三方二进制与分发许可，
  本机没有。因此表里的 FPR 只能说“System32 分布上的 FPR”，不能外推到任意干净程序；
  精确率的分母也会显式计入外部负样本上的误报。

### 壳判定 / Packer（M4b，UPX / 非 UPX）

`identify` 追加 `kind=packer` 与 `packer` 块（`schema_version=2`），工具链字段一个字未改，
读旧字段的消费者不受影响。口径是「**UPX / 非 UPX 判定**」，不宣称覆盖多壳族的识别能力。

| 数据 | 规模 | 成绩 | 说明 |
|---|---:|---|---|
| 自编开发期（`N_sys32` 500） | 100 + 500 | UPX 100/100；packed 误报 0；证据覆盖率 100% | 拟合，不计判定 |
| 自编测试（一次性，`m4b-signals-v1`） | 40 EXE + 20 DLL | 两个源各 20/20 **源级达标**；DLL 20/20 | 达标只看源级点估计 |
| 外部 `E_sys32_b` 200 | 200 | 观测 0 次误报（n=200），Wilson 95% 上界 1.88% | 仅 System32 分布 |

- **局限（原样保留，不因发布删改）**：只覆盖 **UPX 5.0.0** 的产物；**五族缺族**
  （mpress / aspack / pecompact / fsg / petite，供给侧拿不到可验证来源）；**S7–S10 对
  非 UPX 壳的泛化未测**。补族尝试未做（kkrunchy/Crinkler 会拖累主线）；单族 macro 不构成证据。
- 测试侧只评估一次（`access_log.jsonl` 120 条），之后打包为 `corpus/test_sealed.7z` 并删除明文。
- 完整报告：`实践/M4b/report_m4b.md`。

### 自动化报告 / Report（M5）

```bash
# 一条命令：报告（Markdown/JSON）+ 规则命中 + 同源 .yar
python -m rekit report samples/foo.dll --id foo --rules rules/m5.json \
  -o reports/foo.md -j reports/foo.json --yar rules/m5.yar
```

24 个字段每个都带来源标记：**22 个自动推导 + 2 个人工判断**（「结论」「建议」）。
报告头部先给统计口径，再列字段表，人工字段留空不预填。.NET 走 CLI 元数据
（`#~` 表流的 TypeDef / MethodDef / AssemblyRef，纯标准库、不反编译）；
Go 从 `_func.nameoff` 恢复函数名（1.2–1.15 旧格式与 1.16+/1.18+/1.20+ 分开处理，
失败显式写「不可恢复」）；原生走 `.pdata` 函数区间。

`--family auto` 的判定顺序：CLR 元数据 → `\xff Go buildinf:` / `.gopclntab` →
`pclntab_from_data()` 结构命中（pclntab 嵌在 `.rdata` 也能识别）→ `identify` 的
go 族/前端证据 → `unknown` → `native`。没有 CLR/Go 元数据且 `identify` 也判
`unknown` 时，报告写「无法判定」，**不落到 `native` 猜一个族**（规则见
[docs/rules.md](docs/rules.md) §0.7）。

| 样本（单样本口径） | 自动结果 | 规则命中 |
|---|---|---|
| .NET `Accessibility.dll` | CLI `v4.0.30319`；TypeDef 11；MethodDef 55；引用 `mscorlib` | `dotnet_assembly` |
| Go `goCrackMe.exe` | `go1.15.2`；函数名 **1836/1836**；`main.main` @ `0x4AC140` | `go_binary` |
| 原生 Rust crackme | `.pdata` 函数 **467** | 无 |

- **规则引擎叫「rekit 规则引擎」，不是 YARA 兼容实现**：JSON 条件布尔求值（`any`/`all`
  + `eq/ne/gt/ge/lt/le/in`），事实来自 PE 结构，每条命中带证据偏移；不引入新评分，
  **不参与 `identify` 的族/壳判定**。
- **`.yar` 同源生成、只翻译 YARA 能表达的条件**：`dotnet_assembly`、`high_entropy_section`
  无法表达故未生成；`upx_packed` 只翻译节名成对。头部注释逐条列出未翻译分支。
- **真 YARA 校验（如实记录）**：`yara-python` 4.5.4 安装成功，`.yar` 编译通过、13 样本
  求值完成，记录在 `rules/m5_validation.json`。通过只证明「能被 YARA 编译并求值」，
  **不证明两套引擎语义等价**；.NET 样本上 rekit 命中而 YARA 不命中是明示差异。
  校验未通过时头部写「不通过，本文件不可用」；装不上直接写「未经 YARA 校验」。
- **误报只报观测值**：`N_sys32` 500 上 `go_binary` 0/500、`upx_packed` **0/500**
  （Wilson 95% 上界 **0.76%**）、`high_entropy_section` 0/500、`dotnet_assembly` 2/500
  （真实托管程序集，属真实语义命中）。不写「无误报」。
- **复现**：不写时间戳/绝对路径/用户名，排序稳定；同一命令两次运行与已提交产物逐字节一致。
- **边界**：每个家族只有 1 个真实样本，结论只描述「该样本的自动化报告」，不外推家族能力。
  设计文档见 `计划/M5-真实家族自动化报告设计.md`（§0.0 长期约束）。

### 输出契约 / Output contract

JSON 顶层：

```json
{
  "tool": "rekit", "version": "0.3.0", "generated_at": "…",
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

## 性能基准 / Benchmark

- 日期：2026-11-11；机器：Windows 11 build 26200 / Python 3.14.0 / pefile 2024.8.26。
- 语料：`实践/2026-11-11-m1/sys32_500.csv` 的 500 个 System32 文件，未按大小或结果挑选；
  大文件另用 `huge.csv` 的 5 个 23–230 MB 样本。
- 任务：打开 + 节表/数据目录 + imports + exports；两侧同一子集，rekit 不建对象树、不解析重定位。
- 方法：预热 10 个，3 轮取中位数；内存峰值用 tracemalloc 单跑一轮；冷启动是 3 次子进程 import 的中位数。

| 指标 | rekit | pefile |
|---|---:|---:|
| 500 文件总耗时（中位数） | 0.28 s | 2.57 s |
| 单文件中位耗时 | 0.43 ms | 4.66 ms |
| 吞吐 | 1,810 文件/秒 | 195 文件/秒 |
| tracemalloc 峰值（仅 Python 堆） | 7.9 MiB | 4.8 MiB |
| 冷启动 import | 28 ms | 20 ms |

复跑：

```bash
python rekit/bench/benchmark.py --from-csv 实践/2026-11-11-m1/sys32_500.csv \
  --out rekit/docs/benchmark.md
python rekit/bench/benchmark.py --from-csv 实践/2026-11-11-m1/huge.csv --per-file \
  --out 实践/2026-11-11-m1/mem_after.md
```

**这个倍数只对「只解析导入导出」的子集成立**：加上重定位、资源、调试目录后 rekit 会做更多事，
倍数会下降；它不等于"通用 PE 解析比 pefile 快 9 倍"。

## 什么时候不该用它 / When not to use it

- **需要重定位、资源、签名、调试目录**：v0.3 不解析这些数据目录，用 pefile / LIEF / Ghidra。
- **需要完整对象模型**（每字段可写、可回写、可重打包）：rekit 只提供只读结构视图。
- **单个文件特别大且要全量分析**：结构解析已走 mmap（230 MB 文件峰值 26.8 MiB、0.7 ms），
  `triage` 也已改 1 MiB 分块读（同一文件 30.2 MiB、4.87 s），但仍要整文件算一遍 SHA256 与
  全节熵，I/O 是硬成本。这类文件用 pefile 按需取字段更省事；超过 512 MiB 默认拒绝，
  需显式 `--allow-large`。
- **被当库高频 import / 上万次短解析**：冷启动 28 ms 略慢于 pefile 的 20 ms，
  且每次构造 Section 对象；纯批量字段提取直接用 pefile 更成熟。

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

v0.6.0 —— 在 v0.5 的 `xref`/`identify` 之上补完 **M4a 工具链族**、**M4b 壳判定**与
**M5 自动化报告**（0.6.0 未对外发布过，三批工作合并为同一版本）：
`identify` 输出 4 个计分工具链族（msvc / gcc / go / rust，`clang` 为条件族）+ `kind=packer`
与 `packer` 块（`schema_version=2`），每条命中信号都带 `field/offset_kind/offset`；
`report` 一条命令产出 24 字段报告（22 自动 + 2 人工，自动率 91.7%）+ 规则命中 + 同源 `.yar`。
对外数字：自编测试 4 族 80/80、UPX 40/40（同分布可分，不作为能力证明）；真实第三方
M3 十题 **5/9**；系统 DLL **0/700** 误报，M4b 留出切片 n=200 的 Wilson 95% 上界 **1.88%**。
局限：壳判定**只覆盖 UPX 5.0.0**，五族缺族，S7–S10 对非 UPX 壳未测；M5 每个家族只有
1 个真实样本，报告只描述「该样本」；规则引擎是自研的「rekit 规则引擎」，**不是 YARA
兼容实现**，`.yar` 经真 YARA 4.5.4 编译校验通过但只翻译了可表达条件、**语义不等价**；
规则不参与族/壳判定，`signals-*` 未改动。
`unpack` 覆盖 PE32+ 的 UPX（NRV2B / NRV2E / LZMA / filter 0x49）；32 位 PE、CL1B 与多节 UPX2
壳仍在路线图上。`symbols` 是占位（退出码 2 并提示计划版本），不假装成功。

版本变更见 [CHANGELOG.md](CHANGELOG.md)。
