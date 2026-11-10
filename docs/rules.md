# triage 判据与阈值

- 适用版本：rekit 0.1.0
- 来源：学习项目资产 **PE-007**（`工具库/pe/pe_anomaly.py`）+ 3 组 UPX 加壳/未加壳配对实测
- 改这里必须同步改 `rekit/analyzers/triage.py` 的常量与 `tests/test_triage.py`

---

## 1. 信号表

| ID | 权重 | 判据 | 证据字段 | 为什么 |
|---|---|---|---|---|
| `S1_upx_section_pair` | +4 | 同时存在 `UPX0` 与 `UPX1` | 节表 FO + 节名列表 | UPX 默认外观；改名即可绕过，故不给高分 |
| `S2_upx_section_any` | +2 | 命中 UPX 类节名但未成对 | 节名列表 | 残缺/变种，单独不足以定案 |
| `S3_zero_raw_exec_section` | +3 | `VirtualSize>0` 且 `RawSize=0` 且 `MEM_EXECUTE` | 节头 FO + VirtualSize | 磁盘无内容、内存是解压区；加壳的强特征 |
| `S4_high_entropy_section` | +2 | 任一 `RawSize>=4096` 的节熵 > 7.8 | 节名 + 熵值 | 压缩/加密数据；单独也可能是压缩资源 |
| `S5_import_truncated` | +3 | DLL ≥ 3 且 函数数/DLL < 2.0 | 导入目录 RVA + 计数 | UPX 5 保留 DLL 名但截断函数表（一 DLL 一函数） |
| `S6_import_empty` | +1 | 导入函数数 = 0 | 计数 | **仅参考**：静态链接的 Go/Rust 也可能为空 |

置信度：`≥9 高 / 5–8 中 / 2–4 低 / <2 无`。

判定映射：`UPX0+UPX1 成对 → upx`；`score≥5 → packed?`；`score≥2 → odd`；否则 `normal`。

---

## 2. 阈值从哪来（实测）

样本：`hello_rs.exe`（未加壳，130560 B）与 `hello_rs.packed.exe`（UPX 5.0.0 `--best`，62976 B），均为自编译 Rust Hello World。

| 指标 | 未加壳 | 加壳 | 阈值取法 |
|---|---|---|---|
| 节数 | 5（`.text .rdata .data .pdata .reloc`） | 3（`UPX0 UPX1 UPX2`） | 节名直接判 |
| 最高熵 | 6.436 `.text` | 7.888 `UPX1` | 7.8 落在两者之间，且 >7.8 的节基本只剩压缩数据 |
| 导入 函数/DLL | 85/10 = 8.5 | 13/10 = 1.3 | 2.0 落在两者之间 |
| 零 Raw 可执行节 | 无 | `UPX0`（VS=0x15000，RS=0） | 布尔判据 |

`MIN_ENTROPY_SECTION=4096` 的作用：排除几百字节的小节（随机性导致熵虚高）。

`MIN_DLLS_FOR_RATIO=3` 的作用：只有 1–2 个 DLL 的小程序，比值天然低，不能作为加壳证据。

---

## 3. 误报边界（已知会被骗过）

| 情形 | 结果 | 说明 |
|---|---|---|
| 改节名的 UPX（`UPX0/UPX1` → 随意名） | 6 分/中 | S1、S2 失效，只剩 S3+S4+S5 |
| Themida / VMProtect / Enigma | 可能 0–2 分 | 保留完整导入表，S5 不触发；S3 视实现而定 |
| ASPack / PECompact / MPRESS | 视节名 | S1/S2 只认 `UPX` 前缀 |
| NSIS / Inno 安装器 | 低分 | 只有高熵，S4 单独不计结论 |
| .NET 单文件 bundle | 低分 | 同上 |
| 静态链接 Go/Rust（未加壳） | 可能触发 S6（+1） | 单独 1 分 → 置信度「无」，符合预期 |
| 把压缩数据塞进 `.rsrc` | 可能触发 S4 | 需结合资源树判断，v0.2 后再补 |

**一句话**：triage 只回答「要不要继续深挖」，不回答「有没有恶意」。

---

## 4. 可复现验证

```bash
python -m pytest -q                      # 20 项（判据 7 + 解析 6 + 边界 7）
python -m rekit triage tests/fixtures/hello_rs.exe \
                      tests/fixtures/hello_rs.packed.exe -o out.json -m out.md
```

期望：未加壳 `normal / 无 / 0`；加壳 `upx / 高 / 12`。

手工复核示例（`S3` 指向的节头）：

```bash
xxd -s 0x200 -l 40 tests/fixtures/hello_rs.packed.exe
# 节名前 8 字节 = "UPX0\0\0\0\0"，后面 VirtualSize=0x15000，SizeOfRawData=0
```
