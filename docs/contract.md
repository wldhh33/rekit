# 输出契约与回归校验（M6-B）

本文件记录 0.7.0 的跨子命令输出契约、快照基线、性能门与 CI 覆盖状态。
原则：**旧字段零删除，只增不改**；0.7.0 只改 `identify` 的 `family` 语义（见 §1.1），
判定阈值、冻结 signals、M4b 封存测试侧都不在本次改动范围内。

## 1. 顶层 `schema_version`

8 个子命令的 JSON 输出顶层都带 `schema_version`，位置统一，取值按各自 payload 版本：

| 子命令 | `schema_version` | 说明 |
|---|---:|---|
| `triage` | 1 | |
| `unpack` | 1 | |
| `map` | 1 | |
| `funcs` | 1 | |
| `data` | 1 | |
| `xref` | 1 | |
| `identify` | 3 | 0.7.0：`family` 改为链接器提供方语义，新增 `compiler_frontend` / `crt_provider` / `target_triple` |
| `report` | 1 | |

### 1.1 `identify` schema 3（0.7.0 口径断点）

- `family` 的取值从 `msvc_x64` / `gcc_x64` / `go_x64` / `rust_x64` / `clang_x64` 改为
  `msvc` / `gcc` / `go` / `dotnet`；`rust` / `clang` 只出现在 `compiler_frontend`。
- 新增 `compiler_frontend`（`gcc|clang|rustc|go|msvc-cl|unknown`）、
  `crt_provider`（`msvcrt|ucrt|static|none|unknown`）、`target_triple`（可推断时为字符串，否则 `null`）。
- 未删除任何旧字段：`confidence` / `basis` / `signals` / `conflicts` / `bitness` /
  `scope` / `verdict` / `packer` / `triage` 原样保留。
- **不可比声明**：0.6.x 的 4 族 80/80、clang 10/20、A 轮 3 的 per-class 数字都记在旧口径下，
  不得与 schema 3 的任何数字并列、求差或画趋势。断点见 `CHANGELOG.md` 与 `docs/family.md`。
- 快照基线随之重建为 `snapshot_v0.7.0.json`：旧基线记录的是旧 `family` 字面量，
  语义已变，保留它只会制造假红；0.6.x 基线仍可在 git 历史里查到。

实现位置：`rekit/contract.py` 的 `SCHEMA_VERSION`；CLI 通过 `_envelope()` 注入。
`report` 是单样本命令，另外补了 `analyzer` / `version` / `errors` 三个字段，并在
失败且给了 `-j` 时写出同样的错误 JSON（不写时间戳）。

## 2. 统一错误码

错误对象保留原有 `file` / `error` 两个字段不动，新增 `code` / `message`：

```json
{
  "file": "bad.exe",
  "error": "PEError: 不是 MZ 文件",
  "code": "E_PARSE",
  "message": "不是 MZ 文件"
}
```

`error` 的 `"{异常类名}: {消息}"` 格式属于既有契约，不改。

| code | 触发条件 |
|---|---|
| `E_NO_FILES` | 空目录 / 通配符无匹配 / 全是不可分析扩展名 |
| `E_NOT_FOUND` | 文件不存在（`FileNotFoundError`） |
| `E_IO` | 其他 `OSError`（权限、占用、写输出失败等） |
| `E_TOO_LARGE` | 超过大小上限（`PEFileTooLarge`） |
| `E_PARSE` | `PEError` / `ElfError` / `UnpackError` / `DotnetError` |
| `E_FORMAT` | 既不是 PE 也不是 ELF 等格式拒绝 |
| `E_VALUE` | 参数取值的其他 `ValueError` |
| `E_DEPENDENCY` | capstone / Ghidra 等依赖缺失 |
| `E_INTERNAL` | 未识别的异常（兜底） |

实现位置：`rekit/contract.py` 的 `classify()` / `error_entry()` / `no_files_entry()`。

## 3. 快照基线（先冻结，后改字段）

- 冻结时间：**2026-11-11**，代码版本 **0.7.0**（B MVP 开工前首次冻结，0.7.0 因
  `identify` 语义变更按“确认更新契约”重建；0.6.x 基线见 git 历史）。
- 生成环境：Python 3.14.0 / Windows 11 / capstone 5.0.7；这些只写在基线 `meta` 里，
  **不进报告内容**。
- 规模：**20 个固定样本**、**89 个用例**、覆盖全部 8 个子命令。
  - 13 个仓库内夹具（PE x86/x64/UPX、ELF x64/arm64、Go、clang、gcc、msvc）；
  - 7 个确定性派生坏样本（截断、坏魔数、`e_lfanew` 越界、可选头清零、节数异常、
    PE 签名破坏），运行时按固定字节手术生成，不提交额外二进制、不下载任何东西。
- 文件：
  - `tests/baseline/snapshot_v0.7.0.json`
  - `tests/baseline/snapshot_v0.7.0.json.sha256`
- 基线自身 SHA256：`ab38b497fa511084e7a5d6dbf50da7c2d46d204e7f7940debd4f04b3bc558711`
  （对规范化 JSON 计算；`tests/test_snapshot.py` 会重算并比对）。
- 重新生成（**只有确认要更新契约时才做**）：`python tests/make_snapshot.py`。

### 3.1 归一化与比对口径

- 删除 `generated_at`，`seconds` 的值统一替换成 `<SECONDS>`；报告内容不含时间戳。
  说明：7 个多文件子命令的 JSON 外层仍保留旧的 `generated_at`（旧字段不能删），
  但它在生成基线时被整体剥离；`report` 的 JSON 与所有 Markdown 报告本来就不含时间戳。
- 样本绝对路径 → `<SAMPLE:id>`，临时目录 → `<TMP>`，基线可跨机器复算。
- `rules.yara_validation` 的叶子值在比对时掩码为 `<YARA:...>`：装没装
  `yara-python` 属于环境事实，不应让 CI 因缺依赖而红；键被删除仍然会红。
- 比对是**递归子集**：基线中的键必须存在且值相等；新增键放行。这正好对应
  “旧字段零删除，只增不改”。

### 3.2 负向测试（已实测）

把 `triage` 结果里的 `sha256` 真的删掉后，`tests/test_snapshot.py` 立即变红，并逐条
报出 `triage:<样本>.results[0].sha256: 旧字段被删除`。恢复代码后重新全绿。
另保留三条不依赖真实改动的反例测试：删字段、改值、数组变短都必须抛
`AssertionError`；新增字段必须放行。

### 3.3 基线冻结时已知、但未修的旧缺陷

为了不把“修 bug”混进冻结步骤，以下组合在基线里显式跳过，修好后由
`tests/test_contract.py` 覆盖：

1. `data` 跑 arm64 Go 样本：`scan_go_strings` 提前返回缺 `naive_would_overread`，
   触发 `KeyError`。本轮已修（`applicable` 改为跟随 `supported`）。
2. `data` 跑非 PE/ELF 的 `bad_magic`：`ValueError` 未收进 `errors`。本轮已修
   （`data` 增加 `ValueError` 捕获，归类 `E_FORMAT`）。

## 4. 性能门（两条，分别命名，不混用）

### 4.1 端到端性能门（用户实际路径，主门）

- 度量对象：完整子进程调用，含解释器启动、import、解析与写输出：
  - `python -m rekit triage tests/fixtures/hello_rs.exe -o triage.json -m triage.md`
  - `python -m rekit report tests/fixtures/hello_rs.exe --rules rules/m5.json -o report.md -j report.json`
- 冷热分开记录：
  - **热态**：预热 3 轮后连续 15 轮，字节码缓存与 OS 文件缓存已热。
  - **冷态**：先丢弃 1 轮，再取 7 轮；每轮 `PYTHONPYCACHEPREFIX` 指向全新空目录，
    强制重新编译 Python 模块。**未清空 OS 文件缓存**，所以不等于磁盘冷启动，
    这一点写在基线 meta 里。
- **冷态是「人为冷」，不是用户路径**：它每轮强制重建字节码缓存；真实用户首次运行后
  字节码已落盘，不会再经历这一过程。因此冷态门是 **import 膨胀哨兵**——灵敏度高但脆，
  容易受环境（解释器版本、缓存路径、杀软扫描、磁盘状态）影响。
  - **热态门是主门**；冷态只作**上限哨兵**，两条门在报数里始终分列，不合并。
  - 冷态变红时，**先排查环境与缓存路径**（`PYTHONPYCACHEPREFIX` 是否落在可写目录、
    是否被安全软件拦截、解释器是否被替换），**不得为了让门变绿去改冷态定义**
    （如缩短轮数、复用缓存目录、放宽倍数）。
- 报数：中位数与 p90（最近秩）；只以**中位数**做门。
- 基线（2026-11-11，0.6.0，Windows 11 / Python 3.14 / 32 逻辑核）：
  `tests/baseline/perf_e2e.json`（机器信息在 meta，不进 rekit 输出内容）。

  | 命令 | 热态中位数 | 热态 p90 | 冷态中位数 | 冷态 p90 |
  |---|---:|---:|---:|---:|
  | triage | 189.7 ms | 196.2 ms | 590.7 ms | 607.6 ms |
  | report | 204.8 ms | 209.5 ms | 606.5 ms | 619.9 ms |

- 门限：**冷、热中位数均 ≤ 基线 × 1.15**（用户约定「慢不过 15%」）。
- 运行：`python bench/e2e_gate.py`（失败退出码 1）；由 `tests/test_perf_gate.py`
  调用，可用 `REKIT_SKIP_PERF=1` 跳过。

### 4.2 解析内核微基准（非端到端，保留）

之前那条 `0.187 ms / 257 KiB` 的门测的是这一层，**不是用户实际跑的路径**：它在
进程内只跑 `PE` 打开 + 节表/数据目录 + imports + exports，量级约 0.2 ms，进程
启动与 CLI 输出都被排除。保留它的理由：它能把「解析内核本身有没有变慢 / 内存有
没有涨」从进程启动噪声里隔离出来，作为主门之外的窄口径哨兵；因此不改门限，只把
脚本改名为 `bench/parse_core_gate.py`、基线改名为 `tests/baseline/perf_parse_core.json`，
并在脚本 docstring 与本节明确标注「非端到端」，避免与 4.1 混淆。

- 样本：`tests/fixtures/hello_rs.exe`（130,560 字节）。
- 方法：31 轮取中位数；同时测一段固定纯 Python 计算作为校准负载，门限比较
  `解析中位数 / 校准中位数`（ratio），避免绝对秒数受机器影响。
- 基线（2026-11-11，0.6.0）：`ratio = 0.020898`，峰值内存 `263,145` 字节。
- 门限：**ratio ≤ 基线 × 1.15**，**峰值内存 ≤ 基线 × 1.2**。
- 运行：`python bench/parse_core_gate.py`（失败退出码 1）；由
  `tests/test_perf_gate.py` 调用，可用 `REKIT_SKIP_PERF=1` 跳过。
- 本机实测（2026-11-11）：`ratio` 0.0209–0.0218（+0% ~ +4.5%），峰值 257 KiB，
  两项均通过。

## 5. CI 覆盖状态

- 现状：GitHub Actions 只有 `ubuntu-latest` × Python 3.10 / 3.12；0.7.0 已推送。
  0.7.0 主体提交 `1e1fec1` 的 CI run
  [43032640890](https://github.com/wldhh33/rekit/actions/runs/43032640890) **全部通过**
  （Python 3.10 / 3.12 两个矩阵项均绿）。tag 打在包含本节回填的提交上，其运行记录见 Actions 页。
- **Windows 行为未覆盖**：GitHub Actions 的 `windows-latest` 没有实际跑过。因此不把
  ubuntu 的绿色结果当作跨平台验证，也不加入未验证的 Windows 矩阵项。
- 本地证据（**不等于 CI 证据**）：本机 Windows 11 / Python 3.14 上
  `python -m pytest` **181 passed**（含 2 条性能门；设 `REKIT_SKIP_PERF=1` 时为
  179 passed / 2 skipped），其中包含 89 个快照用例与 7 个 0.7 族语义夹具用例。
- 若要补 Windows CI：推送后新增 `windows-latest` 矩阵项，先确认
  `pip install -e ".[dev,funcs]"` 能装上 capstone，再用同一套 pytest 跑通；
  在那之前保持“未覆盖”的表述。
