# Rust 产物的静态事实与可恢复边界

`rekit rust` 是**只读**的语言证据层：回答「这个 PE 是不是 rustc 产物、用哪个提交编的、
链接了哪些 crate、panic/诊断常量被哪些函数引用」，但**不参与** `identify` 的
`family` / `verdict` / `confidence`，也不改任何冻结口径（M4a / M4b / signals-v1）。

## 为什么单独一层：工具链证据 ≠ 语言证据

Windows 上的 `x86_64-pc-windows-msvc` 目标用 MSVC 链接器：Rich 头、linker version、
CRT 导入集与 C/C++ 产物完全同源。`identify` 对真实 Rust 产物（fd 10.5.2）给出
`msvc`、置信度 0.97——**在「哪个链接器」的意义上没错**，但它不是「程序用什么语言写的」。
语言证据只落在字符串与节布局里。

| 判据 | 强度 | 实测 | 反例 / 边界 |
|---|---|---|---|
| `/rustc/<40 位提交>/library\…` | 强 | 7 个目标 7/7 命中，各 1 个提交 | 只证明 std 来自该提交；自编译产物落成 `.rustup\toolchains\…\lib\rustlib\src\rust\library\…`；提交号后既可能是 `/` 也可能是 `\` |
| `.cargo\registry\src\<index>-<hash>\<crate>-<ver>` | 强 | fd 24 / just 37 / deno 376 个 crate | 只证明该依赖出现在**panic/诊断常量**里；无 panic 的依赖不留路径；版本可带 `+build` 元数据 |
| `panicked at` / ``called `Result::unwrap()` `` | 中 | 每个目标 7–29 处 | 条数 ≠ panic 站点数（常量被多处引用） |
| `C:\Users\<user>\…` | 中 | fd/just/zoxide/dust/hyperfine/deno 均为 `runneradmin`（GitHub Actions 默认用户）；eza 无用户路径 | 只说明构建环境，不说明作者 |
| `.rustc` 节 | 有则强，无则无语义 | 7 个目标**全部没有** | 缺失 ≠ 非 Rust |
| `.fptable` 节 | **不作判据** | fd/just/zoxide/deno 有（256 B **全零**、无重定位、Load Config 不引用），dust/eza/hyperfine 没有；`ucrtbase.dll` 也有 | MSVC 链接器产物，非 Rust 特征 |

## `&str` 常量对：crate 路径真实被谁引用

Rust 的 `&'static str` 在 `.rdata` 里是 `(ptr, len)` 两个 u64。代码里 `lea` 的是
**常量对的地址**，不是字符串地址。只按「`lea` 直指字符串」统计会严重低报：fd 上
函数归属从 103 个涨到 501 个。

`rekit rust --map-crates`：

1. 非可执行节里取 ASCII/UTF-16LE 字符串 → `.rs` 结尾者；
2. 在 `.rdata` 里找 `[ptr][len]` 且 `ptr` 指向该串、`len == 串长` → 常量对地址；
3. `.text` 单遍 capstone 解码，收 `lea r64,[rip+disp32]` 且目标命中「串地址 ∪ 常量对地址」；
4. 用 `.pdata` 函数块把引用指令归到函数起点。

**边界**：只覆盖「常量被直接引用」的站点。fd 8,017 个函数里 501 个（6.2%）能归到
某个 crate，其余是 std/core 的泛型实例化与没有诊断常量的业务代码。
**覆盖率不是召回率**，不能读成「62% 的 Rust 函数可识别」。

## 七个真实目标的实测（2026-11-15，全部未运行）

| 目标 | 大小 | `.pdata` 条目 | crate | rustc 提交 | 名称状态 | crate→函数 |
|---|---|---|---|---|---|---|
| fd 10.5.2 | 4,163,584 | 8,017 | 24 | `58cf8f9c…` | none | 501（6.2%） |
| just | 5,922,304 | 10,296 | 37 | `48a229ce…` | none | 592（5.7%） |
| zoxide | 1,261,568 | 2,799 | 9 | `31fca3ad…` | none | 68（2.4%） |
| dust | 2,877,952 | 5,482 | 23 | `58cf8f9c…` | none | 435（7.9%） |
| eza | 3,245,056 | 4,226 | 32 | `1159e78c…` | none | 210（5.0%） |
| hyperfine | 1,441,792 | 3,052 | 20 | `b940084d…` | none | 118（3.9%） |
| deno 2.9.8 | 98,081,568 | 127,625 | 376 | `59807616…` | export（266） | 9,653（7.6%） |

样本登记：fd / deno 在 `实践/A/manifest.json`（`a-rs-fd` / `a-rs-deno`，sha256 已核）。
just / zoxide / dust / eza / hyperfine 是本机已有的**未登记**样本，本轮只用于解析稳健性
复核，**不作为结论依据**，登记待补。

- 六个目标 **COFF 符号 0、导出 0**，CodeView 只留 PDB 文件名（`fd.pdb` 等），
  没有任何名字可 demangle；函数级身份只有 `.pdata` 的 RVA 区间。
- 因此 `legacy(_ZN…17h<hash>E)` / `v0(_R…)` 规则在这类目标上**不产出结论**，
  写了也是空转；只有拿到 PDB / debuginfo 才谈得上 demangle。
- deno 的 266 个导出全是 C 风格（`aws_lc_*` 等），**0 个修饰名**，不构成 demangle 入口。
- `map_refs` 在没有 `.pdata` 时返回 `reason`，不拿「最近的已知函数」凑答案。

## 外部复核（不是自证）

- **crate 清单 vs rizin `rz-bin -zz`**：7 个目标在归一化 `+build` 元数据后集合一致。
  deno 我们多出 `unicode-general-category-1.1.0`（原始字节里有，rizin 未列出）；
  `libz-sys-1.1.20` 在 deno 里**只有 UTF-16LE 形式**，ASCII 扫描会漏——已补宽字符扫描。
- **crate→函数 vs Ghidra 引用表**（fd）：我们 1,986 条「指令 → 常量」引用中，
  **1,861 条（93.7%）与 Ghidra 同指令同目标**；剩余 125 条所在地址 Ghidra 根本没反汇编
  （「反汇编了但目标不同」= 0 条）。按函数聚合：精确率 **0.8754**、召回率 **0.9696**，
  差异来自 Ghidra 把部分引用记在 `from_func=0`（未归函数）上，不是归错函数。

## 已记录的解析失败模式

| 现象 | 后果 | 处理 |
|---|---|---|
| 提交号后 `/` 与 `\` 混用（fd `/`、eza `\`） | eza 首版取不到提交 | 正则两种都收；测试钉住 |
| 版本带构建元数据（`libgit2-sys-0.18.5+1.9.4`） | 该 crate 整条漏掉 | 版本允许 `[-+]`；测试钉住 |
| 链接器尾部合并（消息 + 路径粘成长串，fd 最长 1,016 B） | 512 字节上限把路径截掉；`...stdinsrc/main.rs` 被当路径 | 上限提到 4,096；非根路径计入 `embedded` 不计数 |
| 宽字符路径（deno 的 `libz-sys-1.1.20`） | ASCII 扫描漏 | 增加 UTF-16LE 扫描 |
| `.rs` 出现在消息串中（`failed at src/x.rs`） | 误当独立路径 | 只认「从根开始」的串 |
| 无 COFF/导出/`.rustc` | 无法 demangle | 明说 `name_status=none`，不造名字 |

## 复现

```powershell
python -m rekit rust <样本|目录> [--map-crates] [-j out.json]
python -m pytest tests/test_rust_meta.py -q          # 10 例
python 工具库/rust/rust_probe.py 实践/A/samples/rust --csv out.csv
python 实践/2026-11-15-rust-real/verify.py            # rizin + Ghidra 复核
```

测试夹具：`实践/M3/01-rust-xor-easy/sample/rustpj.exe`（提交
`58cf8f9c35b355199727627d07ae34a4e2846d67`）；反例：`C:\Windows\System32\notepad.exe`
（无任何 Rust 语言证据，用于钉住「不产出证据」）。
