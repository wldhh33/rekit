# `rekit funcs` 输出契约

函数边界发现：权威表（A 层）+ 递归下降 / 指针表 / 穷举（B 层），每条入口都带证据来源。

```
rekit funcs <路径...> [--json out.json] [--csv out.csv]
            [--no-pointers] [--data-sections .rdata,.data]
            [--exhaust fast|normal|full] [--profile auto|...]
            [--no-eh-frame] [--allow-large] [--reference ghidra.csv]
            [--cold-start]
```

---

## 1. 权威表与口径

| 格式 | 权威表 | 来源 | 适用边界 |
|---|---|---|---|
| PE64 | `.pdata` | 异常目录，每项 `BeginRVA/EndRVA` | 链接器写的权威值 |
| ELF64 | `.eh_frame` | DWARF FDE `[start, start+len)` | 需要异常展开表；被 strip 掉则不可用 |
| ELF64 + Go | `.gopclntab` | Go 1.2–1.15 旧头（`0xFFFFFFFB`）/ Go 1.16+ functab | 优先于 `.eh_frame`；两代布局分别解析 |
| PE32 / ELF32 | 无 | — | A 层不适用，只出 B 层 |

- `.eh_frame_hdr` 存在时用它做二分表交叉校验；缺失时退回线性扫描 FDE，
  `authority.detail.source` 标为 `线性兜底`，其余指标口径不变。
- **A 层**：入口等于权威表起点。
- **B 层可达**：不在权威表，但有直接引用（`entry/export/call/jmp`）或指针表证据。
- **B 层孤立**：只由穷举 `exhaust-isolated` 发现，没有任何引用。

### 误报口径

- `fp`（严格）：入口落在权威区间**内部**（`start < entry < end`），不含起点本身。
- `fp_plt`：`strict fp` 中位于 `.plt` 的条数。`.plt` 的 FDE 单独成列，
  **不进入** `fp_text` / `fp_text_rate`，A 层交付数字只反映 `.text`。
- `recall`：权威表起点的命中率；`recall_text`：排除 `.plt` 后的命中率。
- `outside_authority`：不在权威表里的入口数（B 层 + 权威表漏项）。

### 冷启动口径（`--cold-start`）

真实恶意样本的常态是 strip + PIE、导出表为空、无调试信息。`--cold-start` 在**同一次
分析里追加**一个口径：**禁用导出/符号播种、禁用权威表播种**，只允许使用代码与数据
本身；权威表只作为评估分母（召回），不参与发现。

| 播种源 | token | 说明 |
|---|---|---|
| 入口点 | `entry` | PE `AddressOfEntryPoint` / ELF `e_entry` |
| 初始化表 | `init` | ELF `.init_array`/`.fini_array`/`.preinit_array`；PE `.CRT*`/`.init`/`.tls` + TLS 回调（目录 9） |
| PLT/GOT | `plt` | ELF `.got`/`.got.plt`/`.plt.got` 里指向可执行节的对齐指针 |
| 重定位表 | `rel` | ELF `.rela.dyn`/`.rela.plt` 的 `R_X86_64_RELATIVE(8)` / `R_AARCH64_RELATIVE(1027)` addend（PIE 下 vtable 只存在于这里） |
| 指针表 | `ptr` | 数据节里的函数指针。槽位本身就是直接证据：序言门（形状，或前一字节是 `0xCC` 填充）通过即可，不要求"线性走到第一个 `jmp` 处栈平衡"（多块函数必然不满足）；decode / `int3` / 重叠仍拒绝。冷启动**不读 `.pdata`**，只用当前已产出函数体判重 |
| 代码取址 | `addr` | `lea reg,[rip+disp]` 指向可执行节（`main` 的来源） |
| 字符串引用 | `str` | `lea reg,[rip+str]` 命中字符串后，向前回退到最近的序言 |
| 直接调用 | `call` / `jmp` | 已确认函数体内的直接边；`call` 目标要过序言/边界门，再对全部函数体做不动点补全（≤4 轮） |
| 间接调用 | `icall` | `call reg` / `call [reg+off]` 的目标：本基本块内追 `reg` 的单次定义（`lea`、`mov reg,[rip+x]`、`mov reg,[reg+off]`、入口整数参数），再读重定位槽位或槽位原值 |
| 接口方法表 | `itab` | Go：从 `.gopclntab` 定位 `moduledata`，走 `itablinks[]`（Go 1.18–1.24）或 `types+itaboffset/itabsize` 的连续 blob（Go 1.27+），按 `itab{inter,_type,hash,fun[1]}` 取 `fun[]` 的方法地址。这是运行时自己写的表，不过序言门 |

间接调用解析有**硬边界**：只做**基本块内的有限值流**。值域只有三种——`("code", VA)`、
`("addr", 槽位 VA)`、`未知`；不追跨块、不追别名、不追 PHI/合并。同一个寄存器在块内
被定义两次、或来源是未建模指令（`add`/`xor`/栈加载等）一律置未知；`call` 会把
caller-saved 寄存器（`rax/rcx/rdx/rsi/rdi/r8–r11`）清空。解析不出的槽位计为
**未解析**，不猜；解析出的目标仍要过序言/边界门才播种（证据 token `icall`）。

冷启动误报的抑制比常规口径严：`call` 候选必须满足"序言形状"或"前一条是终止指令/填充"
（`_after_terminator`）之一，否则只记引用、不播种；`jmp` 候选在下降阶段就必须
**自身**像函数起点（`_strong_prologue`），不满足即视为函数内部跳转标签、直接结束本路径，
因此 `jmp` 不进入不动点补全（否则"`ret`/填充之后的分支标签"会被当成新函数入口——
实测 Go 的误报 233 → 5、Rust 631 → 310，代价是召回 −94 / −7）；`str`/`addr` 候选还要
通过全函数体的 `_validate_candidate`（解到 `ret`/`jmp` 且栈平衡），防止切在函数中段后
级联出假 call 边。`ptr` 不走这条：槽位是直接证据，序言门通过后栈平衡只作参考（理由与
实测见 §6.1 / §6.4）。

字段见 `metrics.cold_start`；非 x86 或未开启时为 `null`。

---

## 2. JSON 字段

顶层：

| 字段 | 含义 |
|---|---|
| `file/format/arch/bits/image_base` | 输入与映像基本信息 |
| `machine` | ELF `e_machine` 的可读名（`x86_64` / `aarch64` / …）；判"B 层是否适用"看它 |
| `toolchain` | `{family, bits, confidence, profile, evidence}`；`profile` 是实际使用的形状库 |
| `authority` | `{name, usable, starts, starts_text, reason, detail}` |
| `metrics` | 见下 |
| `functions` | 函数表，按起点升序 |
| `exhaust` | 穷举统计（未开启为 `null`） |
| `notes` | 发现阶段的降级/跳过说明 |
| `seconds` | 用时 |

`metrics.seeded`：拿权威表播种后的结果（解析器与反汇编器互相校验）。

| 字段 | 含义 |
|---|---|
| `emitted/recall` | 命中权威起点数 / 命中率 |
| `recall_text` | 排除 `.plt` 的命中率 |
| `fp/fp_plt/fp_text` | 严格误报总数 / `.plt` 单列 / `.text` 交付 |
| `fp_text_rate` | `fp_text ÷ starts_text` |
| `outside_authority` | 权威表外的入口数 |

`metrics.counterfactual`：**不拿权威表播种**，只靠入口/导出/递归下降/指针表，
用于证明发现能力不是自证。字段同 `seeded` 的子集；权威表不可用、或非 x86（B 层未实现）时为 `null`。

`metrics.cold_start`：**连导出/符号也禁用**的冷启动口径（见 §1）。未开 `--cold-start`
或非 x86 时为 `null`。

| 字段 | 含义 |
|---|---|
| `emitted/recall` | 命中权威起点数 / 命中率（权威表只作分母） |
| `fp/fp_text/fp_text_rate` | 严格误报 / `.text` 口径 / 占比 |
| `functions` | 冷启动产出的函数总数（含 B 层） |
| `reachable` | `{total, emitted, recall, unreachable}`：**可达子集召回**。分母只算从入口/数据表 root 出发、沿权威区间自身的 `call`/`jmp` 边可达的权威函数（边取自权威表，仅用于评估） |
| `indirect` | `{attempts, resolved, seeded, rate}`：间接调用尝试数 / 解析成功数 / 可作起点的目标数 / 成功率。`rate` 在无尝试时为 `null` |
| `itab` | Go 的 `moduledata`/`itab` 播种结果：`{supported, moduledata, layout, itabs, methods, rejected, moduledata_va, itablinks_offset}`；1.27 布局另给 `itab_offset`（blob 起始 VA）与 `itab_size`（字节数），经典布局另给 `itablinks`（表项数）。非 Go 为 `{supported: false, reason}`；Go 但结构探测失败为 `{supported: true, moduledata: false}` |
| `itab_seeded` | 由 `itab` 实际播种、且不在权威表起点里的函数数（=`evidence_counts.itab`） |
| `evidence_counts` | 本次播种实际用到的 token 计数（不含 `export` 与权威表 token） |
| `notes` | 播种概要（不动点轮数、取址/字符串播种数、间接调用解析 x/y） |
| `seconds` | 冷启动这一遍的耗时（常规口径另算） |

`metrics.evidence_counts`：每个证据 token 命中的函数数。
`metrics.evidence_groups`：按中文证据组汇总的函数数。

`exhaust`：穷举统计（未开启为 `null`）。`reachable` / `isolated` 两个口径分列；
`isolated_metrics` 是孤立桶的精度验算，**永远标不可交付**，字段与判定见 §5。

`functions[]` 每项：

| 字段 | 含义 |
|---|---|
| `start/end/size` | 区间 `[start, end)` 与长度（十进制；CSV 里是 `0x` 十六进制） |
| `insns` | 解码到的指令数 |
| `evidence` | 证据 token 数组，按强度排序，可多值 |
| `evidence_group` | 主要证据组（取 `evidence` 里最靠前的一个） |
| `layer` | `A` / `B-reachable` / `B-isolated` |
| `section` | 起点所在节（`.text` / `.plt` / 其他） |

### 证据 token

| token | 组 | 含义 |
|---|---|---|
| `pdata` / `eh_frame` / `gopclntab` | 权威表 | 起点来自权威函数表 |
| `entry` | 直接引用 | PE/ELF 入口点 |
| `export` | 直接引用 | `.pdata` 导出 / `.dynsym` 全局函数 |
| `call` | 直接引用 | 被 `call` 直接调用的目标 |
| `jmp` | 直接引用 | 尾调用 `jmp` 的目标 |
| `icall` | 间接调用 | `call [reg+off]` 经基本块内有限值流 + 已知重定位槽位解析出的目标；仅冷启动 |
| `itab` | 间接调用 | Go `moduledata` 的 `itab.fun[]`（接口方法实现）；仅冷启动 |
| `ptr` | 指针表 | 数据节里的函数指针，过了形状 + 栈平衡验证 |
| `rel` | 重定位表 | ELF `RELATIVE` 重定位 addend（PIE 的 vtable）；仅冷启动 |
| `addr` | 代码取址 | `lea reg,[rip+code]` 的代码地址；仅冷启动 |
| `init` | 数据表 | `.init_array` / PE `.CRT*` / TLS 回调；仅冷启动 |
| `plt` | PLT/GOT | `.got*` 里指向可执行节的指针；仅冷启动 |
| `str` | 字符串引用 | `lea reg,[rip+str]` 回退到序言；仅冷启动 |
| `exhaust-reachable` | 穷举+可达 | 穷举候选，且被直接引用命中 |
| `exhaust-isolated` | 穷举+孤立 | 穷举候选，没有任何引用 |

---

## 3. CSV 字段

列顺序固定：

```
file,format,arch,bits,layer,deliverable,evidence,evidence_group,start,end,size,insns,section
```

- `deliverable`：`B-isolated` 行恒为 `false`，其余为 `true`。这是给下游的硬标记，
  不要靠 `layer` 字符串自行判断（见 §5）。
- `evidence` 用 `+` 连接，例如 `pdata+call`。
- `start/end` 为 `0x` 十六进制；`size/insns` 为十进制。
- 一行一个函数；多个输入文件共用同一张表，靠 `file` 区分。

---

## 4. 形状库与穷举

`--profile auto` 先判工具链（PE：hotpatch/导入指纹；ELF：Go 节、`.comment`、
`endbr64`），再选形状库：

| profile | 形状 |
|---|---|
| `msvc_x64` | framepush / calleepush / stackalloc / homeslot / endbr |
| `msvc_x86` | framepush / calleepush / stackalloc / seh |
| `gcc_x64` | endbr / framepush / calleepush / stackalloc |
| `go_x64` | gosplit / calleepush（入口 16 字节对齐；Go 函数中段普遍有 `push rbp`，不能当起点） |
| `generic` | 并集，置信度 < 0.6 时兜底 |

`--exhaust` 的步长：`fast=4` / `normal=2` / `full=1`。`full` 下多了两道边界检查：

1. `misaligned`：候选落在**已解码指令**内部；
2. `boundary_rejected`：候选前一条指令会顺序流入它（不是填充/`ret`/`jmp`），
   说明候选只是函数中段的基本块。

---

## 5. 孤立桶（`B-isolated`）：不可交付（内部参考）

`--exhaust` 的孤立桶 = 穷举找到、但**没有任何引用证据**的候选。定位是内部参考线索，
不是交付物；下游拿到 `B-isolated` 行必须当"未验证"处理。

### 5.1 三处硬标记

| 位置 | 标记 |
|---|---|
| CLI | `[孤立桶] n=… 精度 …（95% CI …）落在参照函数体内 … → 不可交付（内部参考）` |
| JSON | `exhaust.isolated_metrics.deliverable` 恒 `false`，`label` 恒 `"不可交付（内部参考）"` |
| CSV | `deliverable` 列：`B-isolated` 行恒 `false`，其余 `true` |

### 5.2 `exhaust.isolated_metrics`

| 字段 | 含义 |
|---|---|
| `n` | 孤立桶条数 |
| `inside` | 落在参照函数体**内部**（`start < va < end`）→ 判假 |
| `exact` | 与参照起点完全相同 |
| `not_found` | 参照表查无（Ghidra 漏建不算假，单列） |
| `precision` | `1 − inside / n` |
| `precision_ci` | Wilson 95% 区间 |
| `meets_thresholds` | `precision ≥ 0.97` 且 `n ≥ 100` |
| `deliverable` | **恒 `false`**；达标也只是"可提交用户批准"，不自动交付 |
| `label` | `"不可交付（内部参考）"` |
| `note` | 未给 `--reference` 时写"精度未验证" |
| `reference_file` | 实际使用的参照表路径 |

`--reference` 只用来**验算**，不参与发现。参照表由 Ghidra headless 生成：

```
python -m pyghidra <样本> 工具库/ghidra/gh_count.py <样本>.csv
rekit funcs <样本> --exhaust full --reference <样本>.csv --json out.json
```

`load_reference` 排除 `is_thunk=1` / `is_external=1`；ET_DYN 的 `base` 平移到 0，
其它格式按 `image_base` 平移。

### 5.3 各族实测精度（判假口径：落在参照函数体内）

| 样本族 | 样本 | n | inside | 精度 | Wilson 95% CI | ≥97% 且 n≥100 | 交付 |
|---|---|---:|---:|---:|---|---|---|
| GCC x64（无 eh，等价构造） | `numpy_tests_noeh.so` | 64 | 41 | **35.9%** | 25.3–48.2% | 否 | 不可交付 |
| GCC x64（无 eh，等价构造） | `pyyaml_noeh.so` | 63 | 6 | 90.5% | 80.7–95.6% | 否（n<100） | 不可交付 |
| MSVC x86 | `notepad_x86.exe` | 114 | 2 | 98.2% | 93.8–99.5% | 是 | **仍不交付**（需批准） |
| Go x64 | `hello_linux_stripped` | 563 | 0 | 100% | 99.3–100% | 是 | **仍不交付**（权威表已覆盖） |
| 本轮跨族小样本 | `clang_o0` / `rust_*` / `go_win.exe` | 1–2 | 0 | 100% | — | 否（样本量） | 不可交付 |

### 5.4 为什么不可交付、需要什么才能解决

| 样本族 | 主要假因 | 为什么不可交付 | 需要什么 |
|---|---|---|---|
| GCC x64（无 eh） | `align=1` 错位解码：入口比真函数头晚 1 字节，前一条是悬空 REX 前缀 `41`/`48`，解出的"序言"是巧合 | 35.9% 离 97% 很远；numpy 是"全 RELRO 的 Python C 扩展"，真函数只能从 `PyMethodDef` 这类数据表找到 | 对候选做 **CFG 归属**（挂回所属函数的基本块），或解析 `PyMethodDef` 类数据表。**本轮决定不投入**，保持不可交付 |
| MSVC x86 | 函数中段的 SEH 注册 `push imm; push imm; call` 与序言形状撞车 | 98.2% 但 CI 下界 93.8%，且只有 1–2 个样本支撑 | 更多 x86 PE 样本 + SEH 感知的序言判别 |
| Go x64 | 无假（100%），但 238 条"查无" | 权威表 `.gopclntab` 已覆盖，孤立桶是重复劳动 | 无需解决：A 层已够，孤立桶只作内部参考 |
| 任意族 | 样本量 1–2 条 | 统计上无意义 | 扩样本；不与 A 层混算 |

**结论**：孤立桶在所有族都保持 `deliverable: false`。达标族（MSVC x86 / Go x64）
也只是"可提交批准"，不因精度高自动进入交付口径。

---

## 6. 已知边界

- **非 x86（ARM64 / ARM / RISC-V）**：`_md()` 只构建 capstone x86 两代，形状库是 x86
  指令字节模式，指针/跳转表逻辑也假定 x86。当前行为是**只交权威表**（`.eh_frame` /
  `.gopclntab` 的 A 层），`counterfactual` 置 `null`、`--exhaust` 跳过并在 `notes` 写明。
  实测 `clang_arm64_o2`：A 层召回 100%、`.text` 误报 0，B 层为 0（自证不适用）。
  要补齐需要：ARM64 capstone 解码、ARM64 序言形状（`stp x29,x30` / `sub sp`）、
  `adrp`+`add` / `adrp`+`ldr` 指针表识别。
- **MSVC x86（PE32）**：没有 `.pdata`，A 层不适用，只能出 B 层。
  对 Ghidra 召回 61.7%（29/47）、体内误报 2（小样本，CI 很宽）。
- **Go PE**：没有 `.gopclntab` 节名，`authority_table` 会在非可执行数据节里按魔数
  （`0xFFFFFFF1` / `0xFFFFFFF0` / `0xFFFFFFFA`）扫描，并用表头自洽校验（`nfunc` 合理、
  `pcln` 偏移在节内、entryoff 单调）过滤误命中，命中后优先于 `.pdata`。
  实测 `go_win.exe`：`.pdata` 1588 → `.gopclntab` **1890**（表头 `nfunc=1892`，
  末尾 2 项是填充：一项 1 字节、一项全 `0xCC`，已按内容剔除；`found_in=.rdata`，
  `found_offset=0x112C8`），A 层召回 100%、`.text` 误报 1（指针表尾部别名）。
  `.pdata` 的 1588 项**全部**落在 pclntab 内，pclntab 多出 302 项：其中 125 项是直接
  `call` 目标、270 项没有 `push`/`sub rsp`、中位大小 32 字节——即 PE 只为需要栈展开的
  函数生成 `.pdata`，Go 叶子函数被链接器省略，不是解析器多算。复核脚本见
  `实践/2026-11-17-families/verify_go_pclntab.py`。
  注意：**Go ELF 的 1801 是 `go_linux_amd64` 的表头项数，不是 `go_win.exe` 的**；
  早期把两者相减得到的"多 91 个"是跨二进制误比，不成立。
- **Clang x64 ELF O2**：样本只有 10 条 FDE，A 层 100% 但统计无意义（自证 10%）；
  O0（714 条）才有参考价值。
- **静态链接**：FDE 数量大、`.plt` 少；口径不变，但 A 层数字包含 C 运行时。
- **`-fno-asynchronous-unwind-tables` / `strip --remove-section=.eh_frame`**：
  无权威表，只能出 B 层。本仓库的 `*_noeh.so` 是等价改造样本，不是真实编译产物。
- **Go 1.2–1.15**：旧头只有 `magic/pad/minLC/ptrSize/nfunc`，`functab` 紧跟其后，
  每项 `(entry uintptr, funcoff uintptr)`，`entry` 是**绝对 PC**，没有 `textStart`
  字段。按 `ptrSize` 读 `nfunc`，相邻 `entry` 之差为函数区间；要求条目严格递增且
  ≥90% 落在 `.text` 内，否则视为假魔数（字符串表里也常见 `FB FF FF FF`）。
  实测 `goCrackMe.exe`（Go 1.15.2，PE64）：`nfunc=1836`、A 层 1836 个函数 /
  141,918 条指令、`entries_outside_text=0`；该样本无 `.pdata`，无 `.gopclntab`
  节名（魔数在 `.rdata`，`found_offset=0x4B920`）。冷启动（禁权威表播种）
  1723/1836 = **93.85%** 召回、`fp_text=0`——旧样本的冷启动召回由此首次可评估。
  旧头的 `moduledata` 布局与 1.16+ 不同，**不解析 `itab`**（`itab.supported=false`），
  冷启动召回全部来自指针表（1701 项）。
- **ELF32**：`.eh_frame` 未纳入 A 层（未实测，不冒充）。
- **`.plt`**：FDE 与发现到的 stub 单列，不混进 `.text` 召回/误报。
- **自证召回的播种源**：反事实只从入口/导出/递归下降/指针表播种。strip + PIE 且没有
  `--export-dynamic` 时导出表为空，自证会掉到 8%（`clang_o0`）；同源加
  `--export-dynamic` 后回到 81.6%（Rust `hello_elf`）。低自证先怀疑播种源，再看算法。
- **Go `go_x64` 形状**：Go 1.20+ 函数头是 `CMPQ SP,0x10(R14); JBE; PUSHQ BP; MOVQ SP,BP`，
  `push rbp` 会出现在函数中段第 2–3 条指令。形状库原先把 `framepush` 当起点判据，
  冷启动下每个带帧指针的函数都会切出一个中段假起点并级联假 call 边（`go_linux_amd64`
  误报 814 → 462，代价是召回 63.9% → 27.0%）。**这 27% 才是可信基线**，63.9% 是假起点撑起来的。

### 6.1 冷启动召回基线（`--cold-start`）

四个"最需要能力"的样本族，同一二进制、同一次分析里：`before` = 反事实（不用权威表，
但允许导出符号），`after` = 冷启动（导出/符号也禁用）。权威表只作分母；"可达子集"的
分母只算沿已知边可达的权威函数（口径见 §2）。

| 族 | 权威表 | 权威项 | before（反事实） | 冷启动·上一轮 | **冷启动·现在** | 可达子集召回 | `.text` 误报 | 函数数 | 耗时 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Clang x64 ELF strip+PIE | `.eh_frame` | 714 | 17.2% | 12.9% | **23.8%** | **85.6%**（166/194） | 2 | 284 | 0.84 s |
| Go linux/amd64 strip | `.gopclntab` | 1799 | 48.7% | 36.4% | **36.5%** | 50.3%（549/1091） | 5 | 661 | 4.69 s |
| Go windows/amd64 strip | `.gopclntab` | 1890 | 49.0% | 42.0% | **62.1%** | **75.5%**（1109/1469） | 5 | 1178 | 6.39 s |
| Rust musl ELF strip | `.eh_frame` | 2360 | 81.6% | 42.3% | **42.3%** | **91.0%**（938/1031） | 5 | 1306 | 8.23 s |

这一轮只动了一条线：**指针槽位**（§6.4 的归因表就是这么定的）。之前 `_pointer_functions`
在冷启动里仍读 `.pdata` 做"是否落在已有函数体"的过滤，Go PE 有 160 个真指针目标被当成
`inside_span` 丢掉；同时 `_validate_candidate` 用"线性走到第一个 `jmp` 就要求栈平衡"
校验，多块函数（Clang -O0、Go 的 split 栈头）必然不满足。两处都是"指针已经是直接证据，
却按合成候选的标准去卡"。修法只有一条：指针槽位 + 序言门（形状或前一字节 `0xCC`）通过时，
栈平衡与首指令形状降为参考，其余（decode / stop / overlap）照旧拒绝。

反事实召回也跟着变了（Clang 8.1→17.2%），但它是同一套指针规则的产物，不是独立对照；
"上一轮"列才是同口径的版本对照。

分母拆分：Clang 714 项里 520 项从入口沿已知边**不可达**，可达 194 项里命中 166；
Go linux 1799 项里 708 项不可达，可达 1091 项里命中 549；Go PE 1890 项里 421 项不可达，
可达 1469 项里命中 1109；Rust 2360 项里 1329 项不可达，可达 1031 项里命中 938。
全量召回低不等于找不到——Rust 的 42.3% 有 91.0% 落在可达子集里，欠账主要来自静态链接的 std/core。

间接调用解析（`metrics.cold_start.indirect`）：

| 族 | 解析成功/尝试 | 成功率 | 可作起点 | 新增覆盖 |
|---|---:|---:|---:|---:|
| Clang | 3/57 | 5.3% | 1 | +1（上一轮实测） |
| Go linux | 3/35 | 8.6% | 2 | +3（上一轮实测） |
| Go PE | 3/54 | 5.6% | 2 | +2 |
| Rust | 1879/2217 | **84.8%** | 289 | **0** |

Rust 的 84.8% 说明值流本身是对的：`RELATIVE` 重定位槽位 + 块内 `mov` 链足以把
vtable 间接调用解析出来。但召回没有上升，因为 289 个目标此前已被 `rel` 的 861 条
addend 直接播种——**这一步新增的覆盖为零，它验证的是解析能力而不是覆盖率**。
Clang / Go 的 5–9% 是真实瓶颈：它们的间接调用多是 `mov reg,[mem]` 从全局表分多步
装配（Go 的 `CALL DX` 前常有三四条指令从 `moduledata`/`itab` 取值），单块值流够不着；
按约定这类一律记未解析，不用猜测补。这个方向的正式结论见 §6.2。

播种构成（`metrics.cold_start.evidence_counts`；多 token 可命中同一函数，合计会超出函数数）：

| 族 | 实际用到的 token |
|---|---|
| Clang | `entry 1` / `plt 78` / `ptr 122` / `call 81` / `addr 3` / `str 3` / `jmp 2` / `icall 1` |
| Go linux | `entry 1` / `itab 21` / `jmp 443` / `call 639` / `ptr 32` / `addr 17` / `str 2` / `icall 2` |
| Go PE | `entry 1` / `itab 23` / `jmp 667` / `call 882` / `ptr 299` / `addr 21` / `str 1` / `icall 2` |
| Rust | `entry 1` / `call 408` / `rel 861` / `icall 289` / `jmp 44` / `addr 49` / `str 26` |

每族缺什么：

| 族 | 缺口 | 说明 |
|---|---|---|
| Clang strip+PIE | 静态链接的 libc 不被本程序调用；间接调用解析率只有 5.3% | 可达子集 85.6%，剩 28 项。修前归因里 36/106 属 `.eh_frame`-only（`auth` 类），指针槽位补完就只剩这类 |
| Go linux strip | 可达子集里 97.4% 的缺口**在镜像里没有任何引用**（只有 `.gopclntab` 自己知道） | 冷启动到 50.3% 已接近这条线的上限；再往上必须动"不可达/无引用"证明，而不是加播种源 |
| Go PE strip | `.pdata` 贡献了 60.7% 的缺口，但它是冷启动禁用的权威表 | 指针槽位补上后到 75.5%；剩下的主要也是 `.pdata`-only |
| Rust strip | 靠 861 条 `RELATIVE` 重定位把 vtable 找回（8.1% → 42.3%）；间接解析 84.8% 但目标已被 `rel` 覆盖 | 可达子集 91.0%，剩下的主要是静态链接 std/core 与不可达代码 |

下一步优先级：**"不可达函数"证明**（把全量召回里的欠账和真漏检彻底分开，四个族都受益），
其次是 Go 的 `funcval` 数组（`itab` 已完成）；跨块值流与别名分析明确不做——代价是解析率，
换来的是"解析不出就记未解析"的可复核性（理由见 §6.2）。

**M2 回归门（2026-11-18 冻结）**：上面的数字与四个样本的 `SHA256` / 获得方式存在
`tests/baseline/m2_families.json`，`tests/test_m2_gate.py` 每次跑四族，逐族断言
可达子集召回 **≥50%**、严格误报 **≤2%**，并与冻结值相差 **≤1pp**（`test_m2_cold_start_gate`）；
A 层另断言召回 ≥95%、误报 ≤2%（`test_m2_a_layer_not_regressed`）；另有一条用例保证
四族一个不少（少一族就等于把口径偷换成"三族"）。`go_win.exe` 1.65 MB 不随仓库分发，
本地缺失时该族 **skip**（不按通过计），重建方式见 `build_fixtures.ps1 -GoWindows`。

**Go linux 50.3% 是刀锋边缘**：分母 1091，缺口 543 个里 529 个（97.4%）在镜像内**没有任何
引用**，只加播种源碰不到。若某次改动让它掉到 50% 以下，正确处理是**如实记未达标**并写出
缺口归因，**不是**调阈值、换分母或改可达定义。

### 6.2 负结果与已排除方向：块内间接调用值流（`icall`）

**做了什么。** 冷启动时给 `call reg` / `call [reg+off]` 加一层"基本块内有限值流"：
在同一个基本块里向前找 `reg` 的定义，只认 `lea reg,[rip+x]`、`mov reg,[rip+x]`、
`mov reg,[reg+off]`、入口整数参数这几种；命中已知槽位（`RELATIVE` 重定位）就直接读
重定位值，否则读槽位原值。`call` 会清空 caller-saved 寄存器，遇到未建模指令
（`add`/`xor`/栈加载）就把该寄存器置未知。**不跨块、不追别名、不合并 PHI**。

**边界怎么定的。** 一条硬线：解析不出目标就记"未解析"，不猜、不降级成"扫 `.text`
里所有像函数起点的地址"。所以 `rate` 是严格的成功率，不是估计值。

**数字（三族，`--cold-start`）。**

| 族 | 解析成功/尝试 | 成功率 | 可作起点 | 新增覆盖 |
|---|---:|---:|---:|---:|
| Clang x64 ELF | 3/32 | 9.4% | 1 | +1 |
| Go linux/amd64 | 3/35 | 8.6% | 2 | +3 |
| Rust musl ELF | 1879/2217 | **84.8%** | 289 | **0** |

**为什么零收益。** Rust 的 289 个目标全部已被 `rel` 播种：`RELATIVE` 重定位本身就
把 vtable 里的函数指针写进了枚举范围，值流只是"重新找到同一批地址"。Clang/Go 的目标
数量本来就只有个位数，因为它们的间接调用是"从全局表分多指令装配"（Go 的 `CALL DX`
前常有 3–4 条指令从 `moduledata`/`itab`/`funcval` 取值），单块值流按定义够不着。

**结论：这条线停手，不再加码。** 不放宽到跨块/别名/PHI——那会把一天的工作变成一个月，
而当前证据（三族 2284 次尝试，值流真正新增的起点是 Rust 0 个、Clang 1 个、Go 3 个）
不支持它能带来召回收益。

**什么条件下才值得重启。** 出现新的样本族，其间接调用形态是"单块内取址"而不是
"从全局表分步装配"，例如：
1. 单块内 `lea rax,[rip+table]` + `mov rax,[rax+idx*8]` + `call rax` 的跳转表分发（C++ 虚表已由 `rel` 覆盖，不算）；
2. 编译器把函数地址直接以立即数/`lea` 形式写进块内再 `call`，且该地址不在 `.data` 指针表里；
3. 出现"`rel` 不可用但间接调用占比高"的样本（例如静态链接、无 `.rela.dyn` 的裸 ELF）。

重启时的验收线：该族 `icall` 的"新增覆盖"必须 > 0 且误报不升，否则照样停手。

### 6.3 Go 的 moduledata / itab：换"知识"而不是"算力"

Go 的间接调用不是"值流解不出"，而是"表在哪、长什么样"属于运行时知识。`moduledata`
与 `itab` 是 Go 运行时自己写的公开结构，源码可对照（`runtime/symtab.go`、
`runtime/iface.go`、`internal/abi/iface.go`），不依赖分析深度。

**定位路径。** 先解析 `.gopclntab` 拿到表头 VA（`tab.va`）与 `funcnameOffset`；
在非可执行数据节里按 8 字节步进找"第一个字段等于 `tab.va`"的候选，再用
`funcnametab == tab.va + funcnameOffset`、`text/etext` 落在可执行节、`types < etypes`
三条结构校验确认它是 `moduledata`。**不猜偏移**，只做结构探测。

**两种布局，按 magic + 结构分支。**

| Go 版本 | magic | itab 表位置 | 状态 |
|---|---|---|---|
| 1.18 / 1.19 | `0xFFFFFFF0` | `moduledata+0x168`：`itablinks []*itab`（ptr/len/cap） | **实测**（go1.19.13，linux 与 windows 各一，11/12 个 itab、56/57 个方法） |
| 1.20 – 1.24 | `0xFFFFFFF1` | `moduledata+0x178`：同上 | **实测**（go1.22.12，linux 与 windows 各一，11/12 个 itab、56/57 个方法） |
| 1.27.x | `0xFFFFFFF1` | 无 `itablinks`；`types(+0x128) + itaboffset(+0x140)` 起、长度 `itabsize(+0x148)` 的连续 blob，按 `itab.Size()` 步进 | **实测**（go1.27.3 / go1.27.4 各一） |

1.20+ 与 1.27 的 magic 相同，**不能用 magic 区分**，所以先试经典 `itablinks`（含 `0x100..0x190`
的扫描回退），探测失败再试 1.27 的 blob；两者都失败就报 `moduledata: false`，不播种。

关于"版本分支"：把 `0x168` / `0x178` 两条偏移互换后，1.19 与 1.22 的样本**仍然解析成功**
（同样是 11 个 itab / 56 个方法）。也就是说，真正起作用的是**结构探测 + 扫描回退**，
版本偏移表只是第一猜。反证见 `实践/2026-11-17-families` 的偏移互换实验。这不是缺陷
（不猜、可复核），但不能把"支持 1.18–1.24"说成"按 magic 分派已验证"。

`itab` 结构（`internal/abi/iface.go`，各版本一致）：
`inter *InterfaceType`(0x00)、`_type *Type`(0x08)、`hash uint32`(0x10)、`fun [1]uintptr`(0x18)，
`Size() = 0x20 + (len(inter.Methods) - 1) * 8`。方法数取自
`InterfaceType.Methods`：`Type`(0x30) + `PkgPath Name`(0x08) → 指针 0x38、len 0x40。

**实测（两侧同参，只切 `itab` 播种）。**

| 样本 | 配置 | 冷启动召回 | 可达子集召回 | `.text` 误报 | 函数数 |
|---|---|---:|---:|---:|---:|
| `go_linux_amd64`（1.27.4） | 无 itab | 20.9%（376/1799） | 25.7%（269/1048） | 5 | 381 |
| | **有 itab** | **36.4%（655/1799）** | **50.2%（548/1091）** | **5** | 660 |
| `go_win.exe`（1.27.4，PE） | 无 itab | 25.9%（489/1890） | 28.9%（425/1469） | 0 | 489 |
| | **有 itab** | **42.0%（793/1890）** | **49.6%（729/1469）** | **0** | 793 |

播种规模：`go_linux_amd64` 15 个 itab / 68 个方法 / 21 个新起点；`go_win.exe`
17 个 itab / 70 个方法 / 23 个新起点。**误报一条没涨**——因为 `itab.fun[]` 里的地址
全部是 `.gopclntab` 的起点，播种后不会引入中段入口。

同一张表里"上一轮 27.2%"与"现在 36.4%"不能直接相减：这一轮同时把 `jmp` 从不动点里
收掉了（Go 20.9%、Rust 42.3%、Clang 12.9% 都是收口后的基线）。分开看是：
`jmp` 收口 −6.3pp（召回）/ −87 个误报，`itab` +15.5pp（召回）/ ±0 个误报。

**老版本 Go 样本（不进仓库，只本地量测）**：同一份 `src/hello_go.go`，Go 装在独立目录
（`D:\tools\go1.19`、`D:\tools\go1.22`），`GO111MODULE=off` + `-trimpath -ldflags="-s -w"`。
重建方式见 `tests/fixtures/src/build_fixtures.ps1 -Go119 ... -Go122 ...`。

| 样本 | 大小 | SHA256 | `layout` | itab / 方法 | 冷启动 | 可达子集 | `.text` 误报 |
|---|---:|---|---|---:|---:|---:|---:|
| `go119_linux` | 1,212,416 | `34ffdd79033d2587aa72d98556405f9a0e26465402b052010a9d24760f1ca8e4` | `itablinks` | 11 / 56 | 54.92% | 67.88% | 2 |
| `go119_win.exe` | 1,326,592 | `0d7755b7abc84d291c056833ef84f9558252ee165dd652e41c7bd253bb2e8a4c` | `itablinks` | 12 / 57 | 58.02% | 69.41% | 2 |
| `go122_linux` | 1,233,048 | `86a8529bdef306d1f209941cefa9f24db01bc33baf084e20a5b4138ba4086f62` | `itablinks` | 11 / 56 | 51.00% | 65.04% | 2 |
| `go122_win.exe` | 1,329,664 | `eeddd4b310540302290faf508497b3b96c275e99b0b72a61433b3e493c36483a` | `itablinks` | 12 / 57 | 54.77% | 68.87% | 2 |

这四份样本的作用只有一个：证明经典 `itablinks` 分支在 1.18–1.24 上**可用**，不是"结构探测在
1.27 上的偶然成功"。


### 6.4 未达标族的缺失归因（修前快照）

做法：取"可达子集分母（§2 的 `reachable.total`）减冷启动实际产出"的差集，对每个函数
反查镜像里的引用来源，按**能直接播种的强弱**记一个主类；同时记录它是否过形状门、
指针槽位落在哪个节。脚本 `实践/2026-11-17-families/attribute_gap.py`，结果
`gap_attribution.json`，可重跑。样本就是 §6.1 那四个二进制，无抽样。

| 族 | 可达 | 已找到 | 缺失 | `auth` | `ptr8` | `rel32` | `none` | 其它 |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Clang | 194 | 88 | 106 | 36（34.0%） | **65（61.3%）** | 5（4.7%） | 0 | — |
| Go PE | 1469 | 729 | 740 | **449（60.7%）** | 170（23.0%） | 78（10.5%） | 43（5.8%） | — |
| Go linux | 1091 | 548 | 543 | 3（0.6%） | 1（0.2%） | 1（0.2%） | **529（97.4%）** | `ptr8x` 7 / `lea` 2 |
| Rust | 1031 | 937 | 94 | 78（83.0%） | 0 | 2（2.1%） | 0 | `rel` 9 / `ptr8x` 5 |

分类说明（两类是原清单外补的，否则数字会被误读）：

- `auth`：只被权威表自己的字节引用（`.pdata` / `.gopclntab` / `.eh_frame` 的 FDE）。
  **冷启动定义上不能用它播种**，所以它不算"可补的缺口"，只能算"冷启动的天花板"。
- `none`：全镜像没有任何引用。Go linux 的 543 个缺失里 529 个是这类——它们的唯一
  来源就是 `.gopclntab` 本身，任何"找引用"的方向都补不上。

两处关键读数：

1. **最大可补类是 `ptr8`**（Clang 65 + Go PE 170 = 235），不是 `auth`（权威表，禁用）
   也不是 `none`（无解）。
2. `ptr8` 的 235 个里，真正被"校验规则"挡住的是 75 个（Clang 65 + Go PE 10）；Go PE
   另外 160 个是**冷启动里仍在读 `.pdata`** 导致的误判——指针正好指向 `.pdata` 的
   Begin，于是被 `_ptr_covered` 当成"落在已有函数体里"丢掉。这既是漏检，也违反
   "冷启动只作分母"的口径。

修完这一条线（细节见 §6.1）的净效果：Clang 45.4% → **85.6%**、Go PE 49.6% → **75.5%**、
Go linux 50.2% → 50.3%、Rust 90.9% → 91.0%；`.text` 误报依次 2→2 / 0→5 / 5→5 / 5→5，
严格误报率 0.28% / 0.26% / 0.28% / 0.21%，都在 2% 以内。**Go linux 与 Rust 基本不动，
说明这一条线只对"指针表型"的程序有效**；Go linux 的欠账在 `none`，Rust 的欠账在
静态链接的不可达代码，两者都不该靠继续加播种源解决。

---

## 7. 自带 fixture

| 文件 | 来源 | 用途 |
|---|---|---|
| `hello_rs.exe` | 本项目 Rust / MSVC x64 | PE `.pdata` 333 项 |
| `hello_elf` | 本项目 Rust musl（`src/hello_elf.rs`） | ELF `.eh_frame` 2360 条 + `.eh_frame_hdr` |
| `gcc_o2.exe` / `gcc_o0.exe` | MinGW-w64 GCC 16.2（`src/hello_c.c`） | GCC x64 PE，`.pdata` 59；工具链判别不被误判成 MSVC |
| `clang_o0` / `clang_o2` | zig cc（Clang 后端，`src/hello_c.c`） | Clang x64 ELF，`.eh_frame` 714 / 10 |
| `clang_arm64_o2` | zig cc `-target aarch64-linux-gnu` | 非 x86：A 层可用、B 层显式跳过 |
| `msvc_x64.exe` | VS2019 BuildTools 19.29（`src/hello_c.c`） | MSVC x64 `.pdata` 28 |
| `msvc_x86.exe` | VS2019 BuildTools 19.29 `/x86` | PE32 无 `.pdata`，只能 B 层 |
| `go_linux_amd64` / `go_linux_arm64` | Go 1.27.4（`src/hello_go.go`） | `.gopclntab` 1799 / 1760（表头 1801 / 1762，各剔 2 项填充） |

全部由本项目源码编译，仓库内单个 fixture ≤ 1.6 MB；构建命令见 `tests/fixtures/README.md`。
`go_win.exe`（1.6 MB）只在本地量测、不进仓库（Go 函数表解析已由 Go ELF fixture 覆盖）；
它的 PE 容器扫描路径（数据节魔数 + 表头自洽校验）由 `pclntab_from_data` 的合成用例覆盖。
