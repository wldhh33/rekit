# `identify.family` 的语义

> 状态：**已冻结（2026-11-11）**。本文件定义 `rekit identify` 输出里 `family` 字段的含义。
> 在 0.7 落地之前，代码行为与本文不一致的地方按 §4 记为已知偏差；本文定稿后不再新增
> 任何不属于本定义的"族"。

## 0. 这笔定义债是什么

`identify` 从 M4a 起就输出 `family`，但没有任何文档说明它指的是：

1. **编译器前端**（gcc / clang / rustc / go / cl）；
2. **链接器**（GNU ld / MSVC link.exe / Go 内部链接器）；
3. **CRT 提供方**（msvcrt / UCRT / 自带的 Go 运行时）。

三种读法在混装工具链上会给出不同答案。A 轮 3 的 6 个硬错里有 5 个正是这个歧义造成的
（`rustc` 前端串压过 `link.exe` 的证据，见 `实践/A/attribution_v3.md` §2）。字段名与语义
不匹配是产品缺陷，不能用"识别目标不同"来免责。

## 1. 定义（唯一口径）

**`family` = 最终链接步骤的提供方（linker provider），按该链接步骤所服务的 ABI 归档。**

| family | 判定对象 | 典型构建 |
|---|---|---|
| `msvc` | MSVC ABI 的链接器（`link.exe`，或 `lld-link`）+ Windows SDK 导入库 | `cl.exe` → `link.exe`；`rustc --target x86_64-pc-windows-msvc` |
| `gcc` | MinGW-w64 ABI 的链接器（binutils `ld`，或 GNU flavor 的 `lld`）+ MinGW CRT（`msvcrt` 或 UCRT 都算） | `gcc` → `ld`；`rustc --target x86_64-pc-windows-gnu`；`clang` + MinGW `ld` |
| `go` | Go 内部链接器（自带运行时，不链外部 CRT） | `go build` 纯 Go 产物 |
| `dotnet` | 不是原生链接产物（CLR 目录 + `mscoree.dll`），单列 | 托管程序集 |

按这个定义：

- `rustc` + `link.exe` → `msvc`；`rustc` + GNU `ld`（gnu target）→ `gcc`。**`rust` 不是族。**
- `clang` + MinGW `ld` → `gcc`；`clang-cl` / `clang` + `lld-link` → `msvc`。**`clang` 不是族。**
- cgo 且外部链接（最终链接交给 MinGW `gcc`/`ld`）→ `gcc`，不是 `go`。
- 纯 Go（内部链接器）→ `go`。
- 同一个二进制里混有 Rust/C/C++ 对象不影响归属：族看最后是谁把 PE 写出来的。

### 1.1 `clang` 的归属（写死，0.7 迁移时不得改成"特殊族"）

`clang` 是前端，不是族。它归哪一族只看**最终链接步骤**：

| 构建方式 | `family` | `compiler_frontend` | 判定依据（按优先级） |
|---|---|---|---|
| `clang-cl`，或 `clang --target=*-windows-msvc` + `lld-link` / `link.exe` | `msvc` | `clang` | 1) 构建元数据：target 为 `*-windows-msvc`，链接器为 `lld-link`/`link.exe`；2) 可选头 `MajorLinkerVersion` 为 `14.x`；3) 导入 MSVC CRT（`VCRUNTIME140*` / `MSVCP140*` / `ucrtbase`）；4) Rich 头**不作为判据**（`lld-link` 默认不写） |
| `clang --target=*-windows-gnu` + MinGW GNU `ld`（或 GNU flavor 的 `lld`） | `gcc` | `clang` | 1) 构建元数据：target 为 `*-windows-gnu`，链接器为 `ld`；2) 可选头 `MajorLinkerVersion` 为 `2.x`；3) 导入 `msvcrt.dll` 或 `api-ms-win-crt-*`；4) `GCC: (GNU)` / `GCC: (Rev` 串可有可无（strip 后消失） |

硬规则：

- `clang version` 串只决定 `compiler_frontend=clang`，**不参与 `family` 判定**。
- "没有 Rich 头"不是 gcc 的证据（`lld-link` 就不写）；`.rsrc` 只反映 MinGW 驱动是否默认链 manifest，
  既不是编译器身份，也不是链接器身份。
- 构建元数据与 PE 特征冲突时（例如 target 写 msvc、linker version 却是 2.x），`family=unknown`
  并输出冲突，不猜。
- 0.7 的 `family` 枚举里**不得出现 `clang`**；旧代码里的"clang 条件族"在迁移时删除，不是改名保留。

可核验的元数据来源（按可复核性排序）：

1. 发布资产名/构建脚本里的 target triple（`x86_64-pc-windows-msvc` / `-gnu`）与链接器选择；
2. PE 可选头 `MajorLinkerVersion`/`MinorLinkerVersion`（`link.exe` 14.x；GNU `ld` 2.x）；
3. 导入表：MSVC CRT（`VCRUNTIME140*`、`MSVCP140*`、`ucrtbase`）vs MinGW（`msvcrt.dll`、
   `api-ms-win-crt-*`、`libgcc_s_*`、`libstdc++-6`）；
4. 字符串：`clang version`（只定前端）、`GCC: (GNU)`、`/rustc/`、Go build ID。

## 2. 为什么选链接器，而不是前端或 CRT

1. **产物结构是链接器写的。** 节表、导入表、重定位、Rich 头、`.rsrc` manifest 都产生在链接阶段；
   前端留下的是代码与 `.comment` 串（`GCC:`、`rustc`），既能被 strip，也能在一个程序里混装多种
   前端的目标文件，无法唯一确定"这套程序是谁链出来的"。
2. **前端在混装工具链上不是单值。** 同一个 target 可以接 `link.exe` 或 `ld`；按前端归类会让
   一个二进制同时属于两族，`family` 就无法作为单值字段使用。
3. **与预注册一致。** `实践/A/preregistration_v3.md` §1 已写明 `rust` 不是族、按 target triple
   归 `msvc`/`gcc`。本文只是把这条写成可执行的判定规则，不是事后改真值。
4. **可被外部元数据核验。** 构建说明与 CI 配置能给出 target triple 与链接配方；前端指纹只能从
   二进制里反推，无法作为真值来源。
5. **反例检验。** 若选"前端"，A 轮 3 的 6 个硬错会全部变成"判对"（rust→rust、gitea→go），
   等于用定义把失败抹掉；若选"CRT"，则重复 v2 被撤回的理由——同一个 GCC + `ld` 会因
   `msvcrt`/`ucrt` 分裂成两族，与"族按链接器定义"自相矛盾。

## 3. 它如何解释「Rust-msvc 被判 rust」

`core/toolchain.py` 的检测器给出的 `T5_rustc_version`(6) / `T6_rust_panic_strings`(4) /
`T7_rust_core_synch_import`(1) 是**前端证据**；`T12_msvc_rich_header`(4) 是**链接器证据**。
`identify._decide` 的判定阶梯是 `go ≥5` → `rust ≥5` → mingw → `msvc ≥4`，第二条就返回，
所以输出的是"哪个前端编译的"，而不是"哪个链接器链的"：

- `fd` / `Deno` / `zoxide` / `just` / `hyperfine` / `dust`：linker version `14.4x–14.51`，
  真值应为 `msvc`，实际输出 `rust_x64`；
- `eza`：linker version `2.30`（GNU ld），真值应为 `gcc`，实际输出 `rust_x64`。

这就是"语义错位"：检测证据本身没有错，错在把它填进了名为 `family` 的槽。按本文定义，
上述 7 个样本的正确 `family` 分别是 6 个 `msvc` + 1 个 `gcc`，而 `compiler_frontend` 才是 `rustc`。

## 4. 其余维度：附加字段，不占 `family`

`family` 是**单值、必填**。下面三项是可选的附加字段，用来描述"在族之内"的差异，不得反过来
覆盖 `family`：

| 字段 | 取值 | 证据来源（示例） |
|---|---|---|
| `compiler_frontend` | `gcc` / `clang` / `rustc` / `go` / `msvc-cl` / `unknown` | `GCC: (GNU)`、`clang version`、`/rustc/`、`.gopclntab`、Rich 头 |
| `crt_provider` | `msvcrt` / `ucrt` / `static` / `none` / `unknown` | 导入 `msvcrt.dll`、`api-ms-win-crt-*`、`VCRUNTIME140.dll`、无 CRT 导入 |
| `target_triple` | 字符串或 `null` | 构建元数据/版本串；只在可推断时填写 |

现有 `gcc` 的 `runtime=msvcrt` / `runtime=ucrt` 子组，在这个模型里就是 `family=gcc` +
`crt_provider=msvcrt|ucrt`，只作描述，不改变族归属。

## 5. 对 0.6.x 旧口径的处置（0.7.0 已落地）

- 0.6.x 的 `identify` 仍可能在 `family` 槽输出 `rust_x64` / `clang_x64`。这是**已知偏差**，
  不是本定义的扩展。
- 读 0.6.x 的报告时：`family=rust_*` 应读作 `compiler_frontend=rustc`，链接器族要看
  Rich 头 / 可选头 linker version 等证据；`family=clang_*` 同理。
- 0.7.0 起 `family` 只接受本文件 §1 列出的值，`rust` / `clang` 已迁到
  `compiler_frontend`，`schema_version` 从 2 升到 3；代码里的“clang 条件族”已删除。
- 迁移只改字段语义与文档，**不改预注册真值**，也不拿新语义去回算 A 轮 3 的成绩。
- **历史数字不可比**：0.6.x 的 4 族 80/80、clang 10/20、A 轮 3 的 per-class 数字都记在
  旧口径下，不得与 0.7 的任何数字并列、求差或画趋势。

## 6. 冻结条款

- "族"从此只指链接器提供方。新增族必须同时满足：是一个链接器提供方；有独立的外部样本池并在
  跑之前预注册；不依赖前端或 CRT 维度。
- 修改本定义等同于改评估口径：必须新开轮次、重建样本池并重新预注册，不能在评估结果出来之后回改。

## 7. 0.7.0 的指标边界（如实记录，不当作已解决）

1. **GNU `ld` 的 2.x 只覆盖 binutils `ld`。** `lld-link` 与 GNU flavor 的 `lld` 在 PE 可选头
   里写 `14.x`，与 `link.exe` 同值；因此 **llvm-mingw（clang + lld）可能被判 `msvc`**。
   当前没有可靠字节特征把两者分开，`docs/family.md` 不声称覆盖这一组合。
   实例：`curl 8.23.0 win64-mingw`（B 池，上游资产名写 `mingw`，按 §1 应为 `gcc`）的
   链接器版本是 `14.0`，现有信号会把它判成 `msvc`；该样本未用于任何评分。
2. **`.rsrc` 有无完全不参与判定。** 0.6.x 用它推断 MinGW 驱动默认 manifest；strip、
   `-mwindows`、显式 manifest 都会翻转，已降为观测信号（T10/T11，`family=None`）。
3. **strip 后的 clang 前端可能显示 `gcc`。** `clang version` 串被 strip 后，只剩链接进来的
   GCC 运行时 `.comment`（`GCC: (GNU)`）；此时 `family=gcc` 仍然正确（链接器是 GNU `ld`），
   但 `compiler_frontend` 无法区分 clang 与 gcc。这是附加字段的边界，不影响 `family`。
4. **托管程序集看 CLR 目录，不看 linker version。** Roslyn 产物写 `48.0`，不属于
   `msvc`（6–14）也不属于 GNU `ld`（2.x）；T15/T16 对它是无命中，由 T17/T18 判 `dotnet`。
5. **置信度只有档位，没有校准声明。** `hard=0.97` / `weak=0.60` / `unknown=0.30`，
   每处冲突 `-0.05`；它不表示跨样本泛化精度，也不是概率。
6. **`target_triple` 只在二进制里真出现字符串时填写。** 推不出来就是 `null`，不按族反推。
7. **旧口径数字不可比。** 见 §5；0.7 的评估必须用新预注册池，不从 0.6.x/A 轮补样本。
