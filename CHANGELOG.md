# 变更日志

## 0.6.1 — 2026-11-11

修 0.6.0 在 CI（pytest 9.2.0）上的收集期崩溃，并补一条真正在 CI 上执行的 M2 门。

### 修复

- `tests/test_m2_gate.py`：`_case()` 不再在收集期调 `pytest.skip`（pytest 9 判
  `Using pytest.skip outside of a test...`，整个模块变成 collection error），改为参数级
  `pytest.mark.skip`；缺 `go_win.exe` 时该族如实记 skipped，而不是报错。
- 新增 `test_m2_gate_runs_on_in_repo_fixtures`：只用仓库内夹具（clang / go linux /
  rust musl）跑同一条门槛与漂移断言，保证 CI 上 M2 门逻辑真的在执行。

### 说明

- **M2 门依赖仓库外样本，CI 上为 skipped，绿不等于门已执行。** CI 覆盖
  clang / go linux / rust musl 三族，未覆盖 `go_win_amd64`。
- 更正 0.6.0 条目里的测试数：`139 passed` 是旧数字，0.6.0 提交时为 **168 passed**；
  0.6.1 起共 171 个用例（CI 上 go_win 相关的 2 个用例 skipped，其余全跑）。
- 版本号 0.6.0 → 0.6.1；未改任何判定逻辑、阈值或分母。
- 快照基线 `tests/baseline/snapshot_v0.6.0.json` 只把 `version` 字面量 0.6.0 → 0.6.1
  （版本号本身是输出字段），sidecar 同步重算；20×8 用例的其余断言一字未动。

## 0.6.0 — 2026-11-22

本版合并两批工作（0.6.0 从未对外发布，不切两个版本）：`identify` 补完两层判定——
**M4a 工具链族**（4 个计分族 + clang 条件族）与 **M4b 壳判定**（UPX / 非 UPX）；
以及 **M5 自动化报告**——`rekit report` 一条命令产出 24 字段报告、规则命中与同源 `.yar`。
工具链字段一个字未改；壳判定只追加 `kind=packer` 与 `packer` 块，`schema_version` 升到 2，
读旧字段的消费者不受影响。

### 新增

#### M4a 工具链族 / M4b 壳判定

- **M4a 工具链族**：`msvc_x64` / `gcc_x64` / `go_x64` / `rust_x64` 四族计分，
  `clang_x64` 为条件族（strip 后与 MinGW-gcc 不可区分，只在 `clang version` 正向串
  命中时判）。`absence` 类信号不得单独构成族判定；位数是独立字段（x86 标
  `scope=out_of_m4a`）。输出每条命中信号带 `evidence_kind`（positive / absence）。
- **M4b 壳判定**：新增 `rekit/analyzers/packer.py`，信号 S1–S10（S1–S6 直接引用
  triage 常量，不改 triage；S7 壳节名、S8 入口在节外、S9 overlay、S10 节数异常），
  版本 `m4b-signals-v1`，canonical SHA256 `5a5e765b…4f4e`。
  - 判定：S1/S2 → `upx`；S7 或 S8∧S3 → `unknown + packed`；否则 `clean`。
  - 顶层 `verdict` 取 triage 与 packer 的并集；`kind` 在 packed 时为 `packer`。
  - `signals_all` 保留全部 10 条（含未命中），命中信号必须有 `field/offset_kind/offset`。
- 测试：`tests/test_m4b_packer.py`（UPX EXE/DLL、干净样本、信号表冻结、只认 UPX 族）。

#### M5 自动化报告

- `rekit report <sample> [--id] [--family auto|dotnet|go|native] [--rules] [--yar] [-o md] [-j json]`：
  Markdown + JSON + 规则命中 + `.yar` 一次产出；退出码 0 成功 / 1 分析失败 / 2 参数或依赖错误。
- 24 字段报告（`rekit/analyzers/report.py`）：每字段带 `source=auto|human` 与证据；
  **22 自动 + 2 人工**，「结论」「建议」不计入自动统计，报告头部先给口径。
- `rekit/core/dotnet.py`：纯标准库 CLI 元数据解析（PE 数据目录 #14 → COR20 → `BSJB` →
  `#~` 表流 → TypeDef / MethodDef / AssemblyRef）。**只读元数据，不反编译**。
- `rekit/core/funcs.py`：Go 函数名恢复。旧格式（1.2–1.15，magic `0xFFFFFFFB`）按
  `_func.nameoff` 相对 pclntab 读；1.16（`0xFFFFFFFA`）与 1.18+/1.20+（`0xFFFFFFF0`/`F1`）
  按 funcnametab 读。失败写 `name_status=不可恢复`，不编造。
- `rekit/core/rules.py`：**rekit 规则引擎**——JSON 条件布尔求值（`any` 为或、内层 `all` 为与，
  操作符 `eq/ne/gt/ge/lt/le/in`），事实来自 PE 结构，每条命中带证据偏移；不引入新评分，
  **不参与 `identify` 的族/壳判定**。**不是 YARA 兼容实现**。
- `rules/m5.json`：4 条规则 `dotnet_assembly` / `go_binary` / `upx_packed` / `high_entropy_section`。
- `rules/m5.yar`：由同一份 JSON 同源生成，只翻译 YARA 可表达的条件；头部逐条列出未翻译分支。
- 测试：`tests/test_dotnet.py`、`tests/test_m5_go_names.py`、`tests/test_m5_rules.py`、
  `tests/test_m5_report.py`。

### 实测

- **M4a**：自编测试侧 100 变体只评估一次——4 计分族各 20/20（Wilson 83.9–100，达标），
  `clang` 10/20（条件族，未达标），unknown 10；`N_sys32` 500 硬错 1/500、packed FPR 0；
  真实第三方 M3 十题 **5/9**（x64 原生 PE，含 x86 为 7/9）。
- **M4b**：开发期 100/100，`N_sys32` 500 packed 误报 0，证据覆盖率 1398/1398，ECE 0.0883；
  测试侧 60（40 EXE + 20 DLL）唯一一次，`access_log` 120 条，两个源各 20/20 源级达标，
  DLL 20/20；`E_sys32_b` 200：观测 0 次误报，Wilson 95% 上界 **1.88%**；合并 ECE 0.0838。
- **M5**：3 个真实样本各 1 份报告——.NET `Accessibility.dll`（CLI `v4.0.30319`、TypeDef 11、
  MethodDef 55、引用 `mscorlib`）；Go `goCrackMe.exe`（`go1.15.2`、函数名 **1836/1836**、
  `main.main` @ `0x4AC140`）；原生 Rust crackme（`.pdata` 函数 467）。
  字段口径 3 份均 **24 = 22 自动 + 2 人工（91.7%）**。
- **M5 YARA 校验（如实记录）**：`yara-python` **4.5.4 安装成功**，`rules/m5.yar` 编译通过，
  13 个样本求值完成（3 个 M5 + 5 个 UPX 阳性 + 5 个基线阴性），记录在
  `rules/m5_validation.json`。**语义不等价**：`dotnet_assembly` / `high_entropy_section`
  无对应表达未生成，`upx_packed` 只翻译节名成对，`go_binary` 完整翻译。
  校验通过只证明该 `.yar` 能被 YARA 编译并求值，不证明两套引擎等价。
- **M5 误报观测**：`N_sys32` 500 上 `go_binary` 0/500、`upx_packed` **0/500**
  （Wilson 95% 上界 **0.76%**）、`high_entropy_section` 0/500、`dotnet_assembly` 2/500
  （真实托管程序集）。只写「命中 x/500 + 上界」，不写「无误报」。
- **M5 复现**：同一命令两次运行与已提交产物逐字节一致（MD/JSON × 3 样本），
  报告内无时间戳与绝对路径。
- `pytest -q` **168 passed**（0.6.1 更正：原写 139 是旧数字）。
- 系统 DLL 累计 **0/700** 误报（`N_sys32` 500 + `E_sys32` 200；M4b 另 200 留出也是 0）。

### 工程契约与回归校验（M6-B）

- **统一外层**：8 个子命令（`triage` / `unpack` / `map` / `funcs` / `data` / `xref` /
  `identify` / `report`）都带顶层 `schema_version`（`identify` 保持 2，其余为 1），
  唯一来源是 `rekit/contract.py`。
- **稳定错误码**：错误对象在保留旧 `file` / `error` 的前提下**新增** `code` / `message`；
  码表 `E_NO_FILES` / `E_NOT_FOUND` / `E_IO` / `E_TOO_LARGE` / `E_PARSE` / `E_FORMAT` /
  `E_VALUE` / `E_DEPENDENCY` / `E_INTERNAL`。`report` 失败时若给了 `-j` 也写统一错误
  JSON（不含时间戳）。
- **只增不改**：`report` 成功 JSON 补齐 `analyzer` / `version` / `errors`，未删除任何旧字段。
- **快照基线（先冻结，后改字段）**：20 个固定样本（13 夹具 + 7 个确定性派生坏样本）
  × 8 子命令 = **89 个用例**，冻结为 `tests/baseline/snapshot_v0.6.0.json`，
  SHA256 `4b985d39f6c554d3d88e133558071fa224b442f377c3d3e84e20c4adbd067085`。
  比对用递归子集（旧键必须存在且相等，新增键放行），归一化去掉 `generated_at` /
  `seconds` / 绝对路径，`yara_validation` 叶子按环境掩码。
- **负向测试已实测**：真实删除 `triage` 的 `sha256` 后 `tests/test_snapshot.py` 变红
  （`旧字段被删除`），恢复后全绿；另留 4 条自动化反例（删字段 / 改值 / 数组变短必须红，
  新增字段必须放行）。
- **性能门（两条，分开命名）**：
  - 主门 `bench/e2e_gate.py`：整进程 `triage` / `report`，热态 15 轮、冷态 7 轮，
    报中位数与 p90，门限冷热中位数均 ≤ 基线 × 1.15；基线
    `tests/baseline/perf_e2e.json`。
  - 窄口径哨兵 `bench/parse_core_gate.py`：进程内解析内核 + 峰值内存，
    ratio ≤ 1.15×、峰值 ≤ 1.2×；基线 `tests/baseline/perf_parse_core.json`。
    原 `0.187 ms` 门测的是这一层，**不是用户实际路径**，已在文档中明确标注。
- **CI**：仍只有 `ubuntu-latest`；**Windows 行为未覆盖**，未加未验证的 Windows 矩阵。

### 已知限制（原样保留）

- 壳判定**只覆盖 UPX 5.0.0** 的产物；**五族缺族**（mpress / aspack / pecompact / fsg / petite，
  供给侧无法取得可验证来源，不是能力受限）；**S7–S10 对非 UPX 壳的泛化未测**。
- 单族 macro（1.0）不构成证据；不得表述为多壳族识别能力。
- FPR 只在 System32 分布上观测，不能外推到任意干净程序。
- 自编 100% 只说明同分布可分，真实第三方能力看 M3 的 5/9。
- **M5 每个家族只有 1 个真实样本**：报告只描述「该样本的自动化报告」，不外推家族整体能力。
- **M5 规则引擎不是 YARA 兼容实现**；`.yar` 只翻译可表达条件（.NET 元数据、节熵未翻译），
  与 rekit 引擎**语义不等价**，未翻译条件只能在 rekit 引擎里求值。
- M5 规则命中不参与 `identify` 的族/壳判定；`signals-v1` / `m4b-signals-v1` 语义与哈希未变。

## 0.5.0 — 2026-11-20

新增 `rekit xref`：从“列得出字符串”走到“答得出谁引用了它”；补 Go 1.2–1.15 旧
`.gopclntab`；修两处 `funcs` 失步/漏 trace。

### 新增

- `rekit xref`：**交叉引用**，输出契约见 [docs/xref.md](docs/xref.md)。
  - 目标：`--string` / `--va` / `--rva` / `--const`，多个目标可同时给。
  - 引用类型：`rip-lea`/`rip-mov`/`rip-other`、`rel32`、`abs-mem`、`reloc-addend`
    （以上 `certain`）；`imm8/32/64`、`data-pointer-8/4`、`byte-scan`（以上 `suspected`）。
  - **指令流只来自 `funcs` 递归下降**（`discover(..., insn_out=...)`），不写第二套
    线性扫描；召回上限 = 函数发现率，输出里显式注明。
  - 确定/疑似分列，`referencing_functions` 汇总每个引用者函数。
  - CSV：`file,target_kind,target_input,target_va,ref_type,confidence,va,mnemonic,
    text,function,section,detail`。
- Go 1.2–1.15 旧 `.gopclntab`（`0xFFFFFFFB`）：旧头无 `textStart`/偏移字段，
  `functab` 紧跟 `nfunc`，每项 `(entry, funcoff)`、`entry` 为绝对 PC。
  要求条目严格递增且 ≥90% 落在 `.text`，否则按假魔数拒绝。
  实测 `goCrackMe.exe`（Go 1.15.2）：**1836 函数 / 141,918 指令**，
  冷启动 **93.85%** 召回、`fp_text=0`（首次让旧样本的冷启动召回可评估）。
- 规则入文档：`docs/rules.md` §0.1——“任何在 `.text` 内做搜索的结论，必须声明是
  基于指令边界还是字节扫描；字节扫描得到的命中必须显式标注可能落在操作数内部。”

### 修复

- `funcs`：权威区间内的前向 `jmp` 不再截断函数体（M3-01 的 `Correct!` 引用在
  `jmp` 之后，此前 xref 返回 0 条）。
- `funcs`：xref 取流模式下，指针表召回的函数也会真正下降一次，消除“函数表里有
  条目但 0 条指令”的 thunk（whoami 9 条 FN → 0）。
- `xref`：绝对内存引用（`abs-mem`）排除带段前缀的操作数。`fs:[0]`（TLS）曾被当成
  绝对地址 `[0]`，在 `clang_O0` 上产生 77 条假引用；修后为 0。

### 实测

- M3-01 `rustpj.exe`：`Correct!` → `0x140002F20`（`lea rcx,[rip+...]` 在
  `0x1400030D2`），与手写扫描脚本一致。
- Ghidra 引用表独立比对，**归一后**（distinct 指令地址/目标地址，折叠 PARAM 与
  可证明的寄存器传播）：
  - `rustpj.exe` 召回 0.9699 / 精度 1.0000（11 条 FN 是跳转表后块未下降）
  - `goCrackMe.exe` 召回 1.0000 / 精度 0.9270（400 条 FP 全部为真，见下）
  - `whoami.exe` 召回 1.0000 / 精度 1.0000
  - `clang_O0` 召回 0.9904 / 精度 1.0000（6 条 FN 同类）
- `goCrackMe.exe` 400 条 FP 经逐条反汇编审计：**400/400 为真引用**（`rel32` call，
  目标全在 `.text`，18 个被调函数），且 400 条的引用指令全部落在 Ghidra 未覆盖区。
  “精度 0.927”来自 Ghidra 覆盖缺口，非本工具误报；**对外精度记 1.0000**。
- 对外只引用“归一后召回 + 审计后精度”，旧口径（0.9103/0.9798/0.9359/0.5568）
  仅作历史对照；`clang_O0` 旧口径的 77 条误报是上述 `fs:[0]` bug，不属于口径差。
- `pytest -q` **94 passed**。

## 0.4.0 — 2026-11-19

新增 `rekit data`：把"这段字节是什么"从猜测变成有证据的结论。

### 新增

- `rekit data`：**四类数据识别**，输出契约见 [docs/data.md](docs/data.md)。
  - **C 串**：非可执行节内 `[\x20-\x7e\t\r\n]{4,}`，`--min-c-len`（默认 6）、`--utf16` 独立开关
    （默认关——会把 ASCII 段读成两字节噪声）。
  - **Go 串**：双入口。**调用点**要求长度写进**相邻参数槽**（Go amd64 内部 ABI 顺序
    `rax,rbx,rcx,rdi,rsi,r8,r9,r10,r11`，字符串占两槽；栈路径要求 `[rsp+off]`/`[rsp+off+8]`）；
    **数据头**要求 8 字节对齐 `(ptr,len)`，ptr 落在只读节。每条带 `evidence`
    （`reg-pair` / `stack-pair` / `data-pair` / `code+data`）。
  - **指针数组**：非可执行节按 8/4 字节步长扫连续 ≥`--min-run`（默认 4）项，目标全在镜像内；
    **整节排除** `.got/.plt/IAT/.idata/.edata/.reloc/.dynamic/.dynsym`；每组给
    `authority_start_ratio`（目标命中 `.pdata`/`.eh_frame`/`.gopclntab` 起点的比例）
    与 `target_class`（code/data）。
  - **结构体字段**：在权威表函数区间内扫 `[reg+disp]` 的 `mov`，按 `(disp,width)` 签名聚类，
    要求同函数 ≥2 字段、`disp ≤ 0x800`；排除带 index 的数组访问与 `lea`；补 PE 入口/导出起点
    （Rust 导出函数常无 `.pdata`）。
- `detect_go` 改为**三重校验**：`\xff Go buildinf:` 标记 / `.gopclntab` 节名 / 完整 pclntab 头
  （magic + pad + minLC + ptrSize + nfunc 落在 100–5,000,000）。修 notepad.exe 因 4 字节 magic
  随机命中被误判为 Go。
- CLI：`rekit data <paths> [-j out.json] [--csv s.csv] [--min-c-len N] [--min-go-len N] [--utf16]
  [--min-run N] [--max-items N] [--no-arrays] [--no-structs] [--allow-large]`。
  纯字符串扫描不需要 capstone；Go 串与结构体需要（`pip install -e ".[funcs]"`）。

### 实测

- `go.exe`（Go 1.27.3，17.5 MB PE）：Go 串 **9,273** 条（reg 5,429 / stack 71 / code+data 284 /
  data-pair 3,489）；`naive_would_overread` 7,794 = **84.05%**——即"按不可打印字节断开"会读穿
  84% 的条目，最长一条 56,098 字节。指针数组 1,076 组；结构体 737 函数，最大聚类 58 函数共享
  `[+0x18/8B, +0x20/8B]`。
- 同节两组指针数据只有权威表能分开：1,152 项（`pcdata` 侧表）`authority_start_ratio` **0.0**，
  884 项（itab/方法槽）**1.0**。
- `pyyaml_stripped.so` 769 C 串 / 139 数组（`GOT` 排除后）/ 139 函数结构体；
  `notepad.exe` 738 / 11 / 79。
- 与 `rz-bin -zz` 交叉验证（对齐 `(vaddr,len)` 后）：`gcc_o2.exe` 真差异 **0**、
  `struct_probe.exe` **0**、`go_linux_amd64` 15、`go.exe` 2——后者全部是控制字符 `\x07` 导致切分点不同
  （rz-bin 还把 `\n` 当终止符，属口径差）。
- fixture：`struct_probe.exe`（rustc `#[repr(C)]` + `extern "C"` 导出）两函数偏移
  `{0/1, 4/4, 8/8, 16/8}` 全中；`gcc_o2.exe` 的 `binop table[2]` 权威比 **1.0**。
- `pytest -q` **88 passed**。

## 0.3.0 — 2026-11-12

首个把 `map`、`unpack`、`funcs`、大文件内存改造、`triage` 分块熵一起发布的版本（0.2.0 的 tag 从未推送，
其内容并入本版）。

### 新增

- `rekit funcs`：函数边界 + **证据来源**。三套权威表（PE `.pdata`、ELF `.eh_frame`、Go `.gopclntab`）
  按格式自动选择，`.eh_frame_hdr` 缺失时走线性扫描并在输出里标注；工具链判别自动选序言形状库
  （`msvc_x86` / `msvc_x64` / `gcc_x64` / `go_x64` / `generic`）。每条函数带
  `start / end / size / evidence / evidence_group / layer / section`，证据 token 为
  `entry|export|call|jmp`（直接引用）、`pdata|eh_frame|gopclntab`（权威表）、`ptr`（指针表）、
  `exhaust-reachable|exhaust-isolated`（穷举），口径为 A 层 / B 层可达 / B 层含孤立。
  CLI：`rekit funcs <paths> [--json] [--csv] [--no-pointers] [--data-sections] [--exhaust fast|normal|full]
  [--profile] [--no-eh-frame] [--allow-large] [--reference]`，字段契约见 [docs/funcs.md](docs/funcs.md)。
  误报拆 `.text` / `.plt` 两列，`.plt` 单列不计入 A 层阈值。
  孤立桶（`B-isolated`）在 CLI / JSON（`exhaust.isolated_metrics`）/ CSV（`deliverable` 列）
  三处硬标 **"不可交付（内部参考）"**，`deliverable` 恒 `false`；`--reference <ghidra.csv>`
  只用于验算该样本的孤立桶精度（Wilson 95% CI），不参与发现。
  非 x86（ARM64）只交权威表，B 层跳过并在 `notes` 写明；`payload.machine` 给出 `e_machine` 名。
  实测：自有 ELF fixture `hello_elf` `.eh_frame` 2360 项 → A 层召回 100%、`.text` 误报 0、
  反事实（不播种）81.6%；`hello_rs.exe` `.pdata` 333 项 → 100% / 0；
  `hello_linux_stripped` `.gopclntab` 1799 项（表头 1801，末尾 2 项填充已剔除）→ 100% / 0。
  跨族（Rust / Go / GCC / Clang / MSVC / ARM64）逐族数字见 [docs/funcs.md](docs/funcs.md) §5.3 / §6。
- `rekit funcs --cold-start`：**冷启动召回**立成独立指标（`metrics.cold_start`）。禁用导出/符号
  与权威表播种，只用代码与数据本身：入口、`.init_array`/`.fini_array`（PE `.CRT*`/TLS 回调）、
  GOT、ELF `RELATIVE` 重定位 addend、`lea [rip+str]` 字符串交叉引用、`lea [rip+code]` 代码取址、
  指针表、**间接调用目标**、**Go itab 方法表**，再用已确认函数体的 `call` 边做不动点补全（≤4 轮）。
  候选统一过序言形状 + `_after_terminator` 双门（`jmp` 例外：必须在下降阶段自身像函数起点，
  不满足即视为函数内标签，不进不动点），`str`/`addr` 另过全函数体校验，抑制中段假起点级联。
  四族基线（权威表只作分母）：Clang x64 strip+PIE 17.2% → **23.8%**（fp 2）、
  Go linux amd64 strip 48.7% → **36.5%**（fp 5）、Go windows amd64 strip 49.0% → **62.1%**（fp 5）、
  Rust musl strip 81.6% → **42.3%**（fp 5）。相比上一版的 13.7/27.2/42.7，这一轮把 `jmp`
  从不动点里收掉（误报 15/92/274 → 2/5/5），Go 另加 itab 播种（+15.5pp），再叠加指针槽位
  的两条修正（下一条），三项分开记账见 [docs/funcs.md](docs/funcs.md) §6.1 / §6.3 / §6.4。
- 冷启动**指针槽位修正**（`ptr`）：两点都是"指针已经是直接证据，却按合成候选的标准去卡"。
  ① `_pointer_functions` 在冷启动里仍读 `.pdata` 判"是否落在已有函数体"，指针正好指向
  `.pdata` Begin 时被当成 `inside_span` 丢掉（`go_win.exe` 160 个），既是漏检也违反
  "权威表只作分母"的口径；冷启动改为只用当前已产出函数体判重。② `_validate_candidate`
  的"线性走到第一个 `jmp` 处必须栈平衡 + 首指令像序言"会误拒多块函数（Clang -O0、
  Go 的 split 栈头），改为：槽位 + 序言门（形状，或前一字节 `0xCC` 填充）通过时这两项
  只作参考，decode / `int3` / 重叠照旧拒绝。门不用 `_after_terminator`——它含 `0x00`
  （Go 的 jmp 位移尾字节），实测 `go_linux` 44 个误报全从这里来；`0xCC` 边界在三族上是
  130/130、26/26、8/8 真。净效果：Clang 可达子集 45.4% → **85.6%**、
  Go PE 49.6% → **75.5%**、Go linux 50.2% → 50.3%、Rust 90.9% → 91.0%，`.text` 误报
  2/5/5/5（严格误报率 0.28%/0.28%/0.26%/0.21%）。归因表与"只造一条线"的取舍见
  [docs/funcs.md](docs/funcs.md) §6.4。
- 冷启动**间接调用解析**（证据 token `icall`）：把 `call reg` / `call [reg+off]` 的解引用链
  纳入不动点，但只做**基本块内的有限值流**——追 `lea`、`mov reg,[rip+x]`、`mov reg,[reg+off]`
  与入口整数参数；不追跨块、不追别名、不追 PHI/合并，`call` 清空 caller-saved 寄存器，
  解析不出的一律记"未解析"不猜。解析率 Clang 3/57（5.3%）、Go linux 3/35（8.6%）、
  Go windows 3/54（5.6%）、Rust **1879/2217（84.8%）**；Rust 命中目标此前已被 861 条
  `RELATIVE` addend 播种，新增覆盖为 0，`.text` 误报不升。**这个方向的负结论（做了什么、
  边界、为什么零收益、什么条件下才重启）已定稿在 [docs/funcs.md](docs/funcs.md) §6.2，
  不再加码。**
- 冷启动**分母拆分**：`metrics.cold_start.reachable = {total, emitted, recall, unreachable}`，
  分母只算从入口/数据表 root 沿权威区间内已知 `call`/`jmp` 边可达的函数。四族可达子集召回
  **85.6%（166/194）/ 50.3%（549/1091）/ 75.5%（1109/1469）/ 91.0%（938/1031）**，
  不可达项 520 / 708 / 421 / 1329。
- **M2 回归门**（`tests/test_m2_gate.py` + `tests/baseline/m2_families.json`）：四族数字连同
  样本 `SHA256` / 大小 / 获得方式一起冻结，逐族断言可达子集召回 ≥50%、严格误报 ≤2%，
  并要求与冻结值相差 ≤1pp（防"仍过线但明显回退"）；A 层另断言召回 ≥95%、误报 ≤2%；
  另一条用例保证四族一个不少。`go_win.exe` 1.65 MB 不随仓库分发，本地缺失时该族 **skip**
  而**不按通过计**。**Go linux 50.3% 是刀锋边缘**（543 个缺口里 529 个在镜像内无任何引用）：
  跌破 50% 按"未达标"记录，不调阈值、不换分母。9 项用例全绿。
- 冷启动 **Go moduledata / itab 播种**（证据 token `itab`）：从 `.gopclntab` 拿表头 VA，
  在数据节里按"首字段 == `tab.va`"找 `moduledata`，再用 `funcnametab`/`text..etext`/
  `types<etypes` 校验；随后走两种布局——`itablinks []*itab`（Go 1.18–1.24，按 magic 选
  `0x168`/`0x178`）或 `types + itaboffset/itabsize` 的连续 blob（Go 1.27+），取出
  `itab{inter,_type,hash,fun[1]}` 的 `fun[]` 作为方法入口。方法数取自
  `InterfaceType.Methods`（`Type`(0x30) + `PkgPath Name`(0x08) → ptr 0x38 / len 0x40）。
  `metrics.cold_start.itab` 给出 `{supported, moduledata, layout, itabs, methods, rejected, ...}`。
  实测：`go_linux_amd64` 15 个 itab / 68 个方法 → 冷启动 20.9% → **36.4%**、可达子集
  25.7% → **50.2%**、fp 5 → 5；`go_win.exe` 17 / 70 → 25.9% → **42.0%**、28.9% → **49.6%**、
  fp 0 → 0。经典 `itablinks` 分支用 go1.19.13（magic `F0`，偏移 `0x168`）与 go1.22.12
  （`F1`，`0x178`）实测：两版 linux/windows 各一，都是 11/12 个 itab、56/57 个方法。
  反证：把两条偏移互换后仍解析成功——真正起作用的是结构探测 + 扫描回退，版本偏移表
  只是第一猜（如实记在 [docs/funcs.md](docs/funcs.md) §6.3，不吹成"按 magic 分派已验证"）。
- Go pclntab **填充剔除**：functab 末尾的 `CC`/`00` 填充项按内容（长度 <2 或全 `0xCC`/`0x00`）
  丢弃，`header_nfunc` 与 `padding_entries` 写入 `authority.detail`。`go_win.exe`
  1892 → **1890**，`go_linux_amd64` 1801 → **1799**，`go_linux_arm64` 1762 → **1760**。
  `go_win.exe` 的 `.pdata` 1588 项全部落在 pclntab 内，多出的 302 项里 125 项是直接
  `call` 目标、270 项无 `push`/`sub rsp`（中位 32 字节）——PE 链接器只为需要栈展开的函数
  生成 `.pdata`，Go 叶子函数被省略，不是解析器多算。
- Go PE 权威表：没有 `.gopclntab` 节名，改为在非可执行数据节按 pclntab 魔数
  （`0xFFFFFFF1`/`F0`/`FA`）扫描，用表头自洽校验（`nfunc`、`pcln` 偏移、entryoff 单调）
  过滤误命中，命中后优先于 `.pdata`。`go_win.exe` 从 `.pdata` 1588 项提升到
  `.gopclntab` **1890** 项（`found_in=.rdata`；表头 1892，末尾 2 项填充已剔除）。
- Go `go_x64` 形状收紧为 `gosplit` / `calleepush`：Go 1.20+ 函数中段普遍有 `push rbp`，
  `framepush` 会把中段当起点；冷启动误报 814 → 462，召回 63.9% → 27.0%（后者才是可信基线）。
- `rekit map`（D4）：按加载器语义区分 `headers` / `file` / `zero_fill` / `file_slack` /
  `align_pad` / `gap` / `beyond_image`；`VirtualSize=0` 时按 PE 规范回退到 `RawSize`。
  CLI：`rekit map <paths> [--rva 0x...] [-j report.json]`。
  实测：120 个 System32、1,790 个探针与 pefile `get_offset_from_rva` 0 差异。
- `rekit unpack`（D2 回流）：UPX PackHeader 识别、NRV2B/NRV2E 解压、E8/E9 反过滤、
  IAT / 重定位 / `.rsrc` / TLS 重建，`工具库/pe/unpack_upx.py` 改为其薄 CLI 包装。
  CLI：`rekit unpack <paths> [-d out_dir] [--verify-only] [-j report.json]`。
- `bench/benchmark.py --per-file`：逐文件子进程读进程峰值工作集（Windows `PeakWorkingSetSize` /
  POSIX `ru_maxrss`），减 import 基线，3 次取中位数——`tracemalloc` 看不到 mmap 的用量。
- `tests/test_m1_baseline.py` + `tests/baseline/m1_500.json`：500 个文件 × 26 字段 = 13,000 次
  检查固化为回归，缺语料按 skip 而不是假装通过。
- `docs/memory.md`：内存改造的前后数字、阈值理由与代价。

### 改动

- `core/pe.py`：≥ 8 MiB 走 `mmap` 按页读，小文件保持整读；`Section.raw` 改为零拷贝
  `memoryview`；`sha256` 改为按需属性；> 512 MiB 默认抛 `PEFileTooLarge`，
  `triage` / `map` 增加 `--allow-large`。
- `analyzers/triage.py`：SHA256 与每节熵在**一次 1 MiB 顺序读**里同时完成（`_scan_file`），
  熵用 256 桶直方图分块累加。用 mmap 顺序扫页会让峰值等于文件大小，必须 `read()` 分块。

### 修复

- triage 对同一个大节重复计算两遍熵。

### 实测

| 场景 | 改造前 | 改造后 |
|---|---:|---:|
| MRT.exe（219.6 MiB）triage 峰值 / 耗时 | 246.1 MiB / 10.63 s | 30.2 MiB / 4.87 s |
| MRT.exe `triage` 之外的单文件读入峰值 / 耗时 | 464.0 MiB / 193.1 ms | 26.8 MiB / 0.7 ms |
| 500 个 System32 总耗时 | 9.50 s（19.0 ms/文件） | 5.89 s（11.8 ms/文件） |
| 500 个 System32（仅解析，无 triage） | 0.43 s / 15.6 MiB | 0.28 s / 7.9 MiB |

小文件没有变慢；其余四个 23–85 MB 样本峰值都从 72–198 MiB 降到 27 MiB 左右。

基准口径修正：上一版 6× 的跑法里 rekit 顺手算了每个文件的 SHA256，pefile 没有；这版把哈希改为
按需，两侧才是同一任务。新数字 0.28 s vs 2.57 s（约 9×）、0.43 ms vs 4.66 ms，与旧 6× 不可直接比。

### 测试

- `python -m pytest -q`：71 passed。
- 新增 4 条：mmap 与整读两条路径 summary 逐字段一致、`Section.raw` 是零拷贝视图、
  超限文件默认拒绝且 `allow_large` 放行、分块熵与逐字节熵结果一致。
- 新增 3 条：Go `moduledata`/`itab` 播种（`go_linux_amd64` 上 `moduledata=True`、
  `layout=itaboffset/itabsize`、itab ≥10、方法 ≥20、播种数 == `evidence_counts.itab`、
  `fp_text ≤10`，并直接断言 M2 口径 `reachable.recall ≥ 0.5`、严格误报 ≤2%）、
  非 Go 样本 `itab.supported == False`、`_validate_candidate` 的 `trust_slot`
  （Go split 栈头 + 中途 `jmp`：严格校验判 `unbalanced`，指针槽位信任时接受）。
- `tests/test_funcs_core.py` 24 条：PE `.pdata` 端到端（333 项、召回 1.0、误报 0）、
  ELF `.eh_frame` 端到端（>2000 条、hdr 与线性扫描一致、导出覆盖 >70%）、
  `.eh_frame_hdr` 清零后的线性兜底标注、CSV 列契约（含 `deliverable`）、`.gopclntab`
  合成表与未知 magic、孤立桶精度与恒定标签、参照表 base 平移与 thunk/external 过滤、
  跨族判别（GCC PE 不被误判成 MSVC、MSVC x86 落 B 层、ARM64 只交权威表、Go ARM64 走 `.gopclntab`）、
  冷启动（默认 `null`；不开导出/权威表 token；ELF `rel` 播种 >100；PE 中段 `call` 被挡住；
  非 x86 跳过；`reachable.total` 与 `unreachable` 自洽、可达召回高于全量、`indirect.attempts > 100`）、
  Go PE pclntab 数据节扫描与 `min_func` 门槛、pclntab 末尾填充项剔除（`starts=11`、
  `header_nfunc=12`、`padding_entries=1`）。
- `tests/fixtures/` 新增 9 个自有编译样本（`gcc_o0/o2.exe`、`clang_o0/o2`、`clang_arm64_o2`、
  `msvc_x64/x86.exe`、`go_linux_amd64/arm64`），源码与重建脚本在 `fixtures/src/`，单文件 ≤ 1.6 MB。

## 0.2.0 — 2026-11-11（未发布，内容并入 0.3.0）

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
