# `rekit xref` 输出契约

交叉引用：回答“谁引用了这个字符串 / 地址 / 函数 / 常量”。

```
rekit xref <路径...> (--string S | --va 0x... | --rva 0x... | --const N)...
           [--json out.json] [--csv out.csv]
           [--no-pointers] [--utf16] [--byte-scan] [--allow-large]
```

改这里必须同步改 `rekit/core/xref.py` 与 `tests/test_xref.py`。

---

## 1. 指令流从哪来（最重要的一条）

**所有指令级引用都来自 `funcs` 的递归下降结果**（`discover(..., insn_out=...)`），
xref 不写第二套线性扫描。

- 召回上限 = 函数发现率。没被 `funcs` 发现的函数体里的引用不会出现。
- `instruction_stream` 字段会写明来源、函数数、指令数；CLI 每次都会打印这条注。
- 无权威表且 `funcs` 覆盖很差的样本（如无 `.eh_frame` 的 strip ELF），
  xref 基本不可用——这是设计边界，不是 bug。

可选的 `--byte-scan` 是**唯一**的字节扫描路径，结果全部标 `suspected`，
`detail` 写明“可能命中操作数内部”，并区分命中位置是否落在已解码指令内部。

---

## 2. 目标输入

| 参数 | 解析方式 |
|---|---|
| `--string S` | 在非可执行节按字节找字面量（可选 `--utf16`）；命中多个位置时逐个列 block |
| `--va 0x...` | 直接按 VA；若该 VA 是 `funcs` 函数起点会标 `function_start` |
| `--rva 0x...` | `ImageBase + RVA` |
| `--const N` | 只查**立即数**，不查数据指针/重定位 |

字面量只出现在可执行节时，按字节扫描定位，并标“仅作目标线索”。

---

## 3. 引用类型与置信度

**确定（`certain`）**——可机械判定，不含猜测：

| `ref_type` | 含义 |
|---|---|
| `rip-lea` / `rip-mov` / `rip-other` | RIP 相对内存操作数，按 `insn.address + insn.size + disp` 算目标 |
| `rel32` | 直接相对分支（`call` / `jmp` / `jcc`）的目标 |
| `abs-mem` | 无基址、无变址、**无段前缀**的绝对内存操作数 `[disp]`（`fs:[0]` / `gs:[0]` 不算） |
| `reloc-addend` | ELF `R_*_RELATIVE` addend、PE `DIR64` / `HIGHLOW` 的值等于目标 |

**疑似（`suspected`）**——单列，绝不混进确定集：

| `ref_type` | 含义 |
|---|---|
| `imm8` / `imm32` / `imm64` | 绝对立即数，可能是整数常量而不是地址 |
| `data-pointer-8` / `data-pointer-4` | 数据节里 8/4 字节字等于目标（或 4 字节 RVA 等于 `target-ImageBase`） |
| `byte-scan` | `--byte-scan` 下在可执行节扫到的字（可能落在操作数内部） |

数据指针/重定位引用没有“引用者函数”（`function=null`），因为它们不在指令流里。

---

## 4. JSON 字段

顶层：

| 字段 | 含义 |
|---|---|
| `file` / `format` / `arch` / `machine` / `bits` / `image_base` | 镜像信息 |
| `instruction_stream.source` | 固定 `funcs 递归下降` |
| `instruction_stream.functions` / `.instructions` | 参与引用判定的函数数与指令数 |
| `instruction_stream.notes` | funcs 的召回说明 + 召回上限提示 |
| `targets[]` | 每个输入目标一项 |

`targets[i]`：

| 字段 | 含义 |
|---|---|
| `input` | `{kind, value}` 原样回显 |
| `resolved[]` | 目标位置（`va/section/preview`；字符串含 `encoding`） |
| `blocks[]` | 每个目标地址一块：`refs[]`、`counts{certain,suspected,functions}`、`referencing_functions[]`、`notes[]` |
| `counts` | `resolved` / `certain` / `suspected` 汇总 |

`refs[]` 字段：`target, ref_type, confidence, va, size, mnemonic, text, function,
section, detail`。

---

## 5. CSV 字段

`file,target_kind,target_input,target_va,ref_type,confidence,va,mnemonic,text,function,section,detail`

`function` 为 `-` 表示不在指令流内（数据指针/重定位）。

---

## 6. Ghidra 比对（独立参照）

脚本：`工具库/ghidra/gh_xref.py`（导出 `from,to,type,...,from_func`）+
`实践/M3/_reflow/compare_xref.py`（抽样与归因）+
`实践/M3/_reflow/audit_fp.py`（FP 逐条反汇编审计）。

只比**指令级**确定集（`rip-*` / `rel32` / `abs-mem`），数据指针与重定位不入分子分母。

### 6.1 两套口径

- **旧口径**：分母 = Ghidra 原始引用条目数（同一条指令的 PARAM/传播使用点各算一条）。
- **归一后**：两侧都折叠成 distinct **(指令地址, 目标地址)** 对；Ghidra 的 `PARAM`
  先剔除，能证明是寄存器传播的使用点也剔除（该指令已被我们解码、但操作数里没有
  目标地址）。我们没解码的 Ghidra 引用保留，记为潜在漏报（`unassessed`）。

### 6.2 结果（新旧并列）

| 样本 | 旧口径 召回/精度 | 归一后 召回/精度 | 审计后 精度 | 归一后 分子/分母 |
|---|---|---|---|---|
| M3-01 `rustpj.exe`（Rust/MSVC PE64） | 0.9103 / 1.0000 | **0.9699 / 1.0000** | 1.0000 | 355 / 366 |
| M3-02 `goCrackMe.exe`（Go 1.15 PE64） | 0.9798 / 0.9270 | **1.0000 / 0.9270** | **1.0000** | 5081 / 5081 |
| `whoami.exe`（System32 PE64） | 0.9359 / 1.0000 | **1.0000 / 1.0000** | 1.0000 | 321 / 321 |
| `clang_O0`（ELF64） | 0.5568 / 0.8892（含下述 bug） | **0.9904 / 1.0000** | 1.0000 | 620 / 626 |

折叠量：`rustpj` 剔除 2 条 PARAM + 22 条传播；`goCrackMe` 剔除 105 条传播（无 PARAM）；
`whoami` 剔除 11 + 11；`clang_O0` 剔除 102 条 PARAM + 340 条传播。

**差异来源**：

- 召回上升：旧分母把同一条指令的传播/PARAM 重复计为多条，归一时只保留
  “操作数里真的编码了目标”的那一条。
- 精度不变或上升：`goCrackMe` 的 400 条在归一后仍在（它们是我们的确定引用，
  Ghidra 没有），审计证明全部为真（见 6.3）；`clang_O0` 旧口径的 77 条误报
  **是我们自己的 bug**：`fs:[0]` 这类段前缀操作数被当成绝对内存 `[0]`。
  已在 `_insn_refs` 增加 `segment == 0` 条件修复，归一口径下 0 误报。

### 6.3 `goCrackMe` 400 条 FP 审计

`audit_fp.py` 对 400 条逐条反汇编（不是抽样估计）：

- **400/400 = `real_ref`**；固定取前 40 条样本也是 **40/40**。
- 全部是 `call <目标>`（`rel32`），目标全部落在 `.text`，共 18 个被调函数
  （最多的是 `0x464AE0` 249 条、`0x462E80` 57 条）；引用者地址范围
  `0x406DE0`–`0x4A0775`，都在 Go 冷块里。
- 400 条的引用指令**全部**不在 Ghidra 已建引用的指令集内，也不在 Ghidra 函数区间内
  （`insn_gh_covered=False`，400/400）。
- 结论：这 400 条是 **Ghidra 的覆盖缺口**，不是本工具误报。
  “原 0.927 来自 Ghidra 未覆盖区域，非本工具误报。”

### 6.4 对外声明用哪一列

**只引用“归一后召回 + 审计后精度”**：

| 样本 | 对外召回 | 对外精度 |
|---|---|---|
| `rustpj.exe` | 0.9699 | 1.0000 |
| `goCrackMe.exe` | 1.0000 | 1.0000 |
| `whoami.exe` | 1.0000 | 1.0000 |
| `clang_O0` | 0.9904 | 1.0000 |

“精度对 Ghidra”一列（`goCrackMe` 0.9270）只作中间量，不能对外当缺陷数；
它衡量的是 Ghidra 覆盖，不是本工具正确性。

### 6.5 FN 归因（归一后）

- `rustpj`：11 条 `unassessed`，全部是 Ghidra 有引用、我们没解码的指令——
  同一函数内间接跳转/跳转表后的块（`funcs` 不解析 `jmp reg/[table]`）。
- `clang_O0`：6 条同类。
- `goCrackMe`、`whoami`：0 条。
- 其余旧口径下的 `fn_propagation` / `fn_param` 已在归一化时折叠，不再计入召回。

---

## 7. 已知边界

- 只支持 x86 / x86-64；其它架构直接报错。
- `--const` 只查立即数，不做数据节扫描。
- `--byte-scan` 结果不可用于“确定引用”结论，只用于找线索。
- Go 旧头（`0xFFFFFFFB`）的 `.gopclntab` 只给函数边界，不给字符串信息；
  字符串仍需 `--string` / `data` 恢复。
