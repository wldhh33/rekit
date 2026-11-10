# rekit

模块化的二进制分析流水线 CLI。**编排 + 证据链 + 可复现**，不重复造轮子。

A modular binary-analysis pipeline CLI. **Orchestration + evidence chain + reproducibility**, no reinventing wheels.

```
rekit triage <path...>   → PE 概览、异常评分、壳识别   [v0.1 已实现]
rekit unpack <path>      → 静态脱壳（UPX 优先）        [v0.2 计划]
rekit symbols <path>     → Ghidra headless 出函数边界  [v0.3 计划]
rekit report             → Markdown + JSON            [随各段输出]
```

设计原则（Design principles）：

- **每条结论都能回指字节**：信号里带文件偏移（FO，file offset），不是"看起来很可疑"。
- **可复现**：同一输入 + 同一命令 + 同一版本 → 同样的结果（除时间戳）。
- **不重复造轮子**：解析用标准库手写（可控、可审计），符号用 Ghidra，脱壳复用已验证探针。
- **依赖极少**：v0.1 运行时零第三方依赖，CLI 只用 `argparse`。

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

### 输出契约 / Output contract

JSON 顶层：

```json
{
  "tool": "rekit", "version": "0.1.0", "generated_at": "…",
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

## 许可 / License

MIT，见 [LICENSE](LICENSE)。

测试样本是自编译的 Hello World（Rust），可自由再分发；**仓库不含任何专有系统文件或恶意样本**，见 [tests/fixtures/README.md](tests/fixtures/README.md)。

## 状态 / Status

v0.1.0 —— 仅 `triage`。`unpack`、`symbols` 是可运行的占位（返回退出码 2 并提示计划版本），不假装成功。
