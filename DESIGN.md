# DESIGN — rekit 架构与扩展点

- 版本：0.1.0
- 目标：把「逆向分析的判断过程」变成可测、可复现、可回指字节的代码。

---

## 1. 定位与边界

**做**：编排已有能力（自写解析器、UPX 静态还原探针、Ghidra headless），把结论固化成带证据的流水线。

**不做**：

| 非目标 | 原因 |
|---|---|
| 自研反汇编器/反编译器 | Ghidra、capstone 已经足够好，自研只会产出玩具 |
| 动态调试器/沙箱 | 需要内核权限或隔离环境；本机 WDAC 也限制了部分工具 |
| 恶意样本判定结论 | 启发式只能给"可疑/置信度"，不能替代人工与沙箱 |
| GUI | 目标是批量、脚本化、可进 CI |
| 自建 YARA 引擎 | 后续只调外部 `yara`，不重写规则引擎 |

---

## 2. 分层

```
rekit/
  cli.py            子命令解析、输出落盘（argparse，无第三方依赖）
  core/
    pe.py           PE/PE32+ 解析器（标准库手写），产出所有原始字段与文件偏移
    elf.py          ELF32/64 解析器：节表、可执行节、`.dynsym` 导出、VA↔FOA
    funcs.py        函数边界：权威表（.pdata/.eh_frame/.gopclntab）+ 递归下降
                    + 指针表 + 穷举；每条入口带证据来源与口径（A / B 可达 / B 孤立）
  analyzers/
    triage.py       PE 概览 + 加壳/异常评分（v0.1）
    unpack.py       静态脱壳（v0.2）
    funcs.py        函数边界（v0.3，调用 core.funcs）
    symbols.py      Ghidra headless 函数边界（v0.3，占位）
  report/
    markdown.py     报告渲染（Markdown）
```

数据流是单向的：

```
路径 → [expand] → [analyzer.run] → dict（JSON 友好） → [cli] → out.json / out.md
```

**关键约束**：analyzer 不打印、不读环境变量、不写文件。它只接收路径、返回字典。
落盘、格式化、退出码全部由 `cli` 负责 —— 这样 analyzer 可以在测试里直接调用，也可以被别的程序 import。

---

## 3. 证据链规则

一条结论若要写进报告，必须能回答「**从哪几个字节推出来的**」。实现上：

1. `core/pe.py` 在解析时记录关键偏移：`section_table_offset`、每个节的 `header_offset`、数据目录 RVA。
2. 每个 `Signal` 强制带 `evidence: str`，字符串里必须出现 `0x…` 形式的文件偏移或明确的字段名。
3. 报告逐条渲染 evidence，读者可据此在十六进制编辑器里复核。
4. 测试 `test_evidence_points_back_to_bytes` 守住这条规则 —— 新增信号若不带偏移，测试失败。

示例：

```
S3_zero_raw_exec_section | +3 | ✓ | UPX0 节头 FO 0x200：VirtualSize=0x15000 但 RawSize=0、含 MEM_EXECUTE
```

`FO 0x200` 是节头在文件里的位置，可直接 `xxd -s 0x200 -l 40` 复核。

---

## 4. 插件契约

```python
# rekit/analyzers/xxx.py
NAME = "xxx"                            # 子命令名，唯一
DESCRIPTION = "一句话说明"               # 出现在 --help
def run(paths: list[str]) -> dict:
    """返回 {"analyzer": NAME, "results": [...], "errors": [...]}"""
```

约定：

- **不要**抛异常给 CLI：单文件失败写进 `errors`，继续处理其余文件（`PEError` / `OSError`）。
- 结果条目必须是 `dataclasses.asdict` 能序列化的类型（`str/int/float/bool/list/dict/None`）。
- 新增判据必须同时加：常量（权重/阈值）、`Signal` 条目、`tests/` 覆盖、`docs/rules.md` 说明。
- 占位插件（尚未实现）必须返回非零退出码并说明计划版本，**不得静默返回空结果**。

注册：`rekit/analyzers/__init__.py` 的 `REGISTRY`；子命令：`rekit/cli.py`。

---

## 5. 版本路线

| 版本 | 内容 | 验收 |
|---|---|---|
| **v0.1.0** | `triage`：PE 概览、6 条信号组合评分、壳识别、Markdown+JSON、证据偏移 | `pytest` 全绿；CI 跑通；两份 fixture 判定正确 |
| v0.2.0 | `unpack`：UPX 静态还原（`PackHeader` 解析 → NRV2B 解压 → filter 0x49 反向过滤 → 重建 IAT/重定位） | 产物可运行；导入表与原件多重集一致；`upx -d` 仅作对照 |
| v0.3.0 | `funcs`：PE `.pdata` / ELF `.eh_frame` / Go `.gopclntab` 权威表 + 递归下降 + 指针表 + 穷举，证据来源与 A/B 口径；`symbols`：Ghidra headless 批处理 | 自带 PE/ELF fixture 端到端召回/误报断言；`funcs` CSV/JSON 契约见 `docs/funcs.md` |
| v0.4.0 | `report` 独立成段 + 跨段汇总；统一 evidence 索引 | 一条命令产出全链报告 |
| v0.5.0 | 规则外置（YAML/JSON）+ 规则版本号；旧结果可重放 | 改规则不改代码 |
| v1.0.0 | 稳定 CLI 契约 + 语义化版本 + 插件第三方可加载 | 第三方插件示例进 `examples/` |

详细计划与学习阶段映射见学习项目的 `计划/项目-rekit.md`。

---

## 6. 已知取舍

- **不加 `pefile` 依赖**：自写解析器是学习资产本身，且能精确控制偏移；对照验证在 `tests/` 里用固定期望值做。
- **capstone 是可选依赖**：只有 `funcs` 需要，放在 extra `.[funcs]`，主包保持零运行时依赖；
  缺依赖时返回明确错误，不让 `triage` 等子命令被拖住。
- **不加 Click/Typer**：`argparse` 足够，少一个依赖。
- **Markdown 用字符串拼**：报告结构简单，模板引擎在这里是过度设计。
- **不缓存**：v0.1 输入规模小；等 `triage` 跑全量系统 DLL 时再引入缓存。
