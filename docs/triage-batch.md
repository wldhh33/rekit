# triage 真实语料跑批（System32，140 个 PE）

- 日期：2026-11-10
- 版本：rekit 0.1.0
- 目的：验证三件事 —— ①不崩溃 ②不产生离谱误报 ③耗时可用
- 证据：`实践/2026-11-10-rekit-batch/`（`sys32_140.json`、`sys32_140.md`、`run.log`、`summary.txt`、`summarize.py`）

---

## 1. 方法

```powershell
$files = Get-ChildItem C:\Windows\System32 -File |
         Where-Object {$_.Extension -in '.exe','.dll','.sys'} |
         Select-Object -First 140 -ExpandProperty FullName
python -m rekit triage @files -o sys32_140.json -m sys32_140.md
```

- 取目录中**按名称排序的前 140 个** PE（非随机抽样，见 §4 局限）。
- 只读，不修改系统文件。
- 环境：Windows 11 x64，Python 3.14.0，机械/SSD 未记录（耗时不代表冷缓存）。

## 2. 结果

| 指标 | 数值 |
|---|---|
| 输入文件 | 140 |
| 成功 | 140 |
| 失败 | 0 |
| 总耗时 | **3.12 s**（含解释器启动） |
| 单文件均值 | ≈ 22 ms |
| 判定分布 | `normal` 140 / `odd` 0 / `packed?` 0 / `upx` 0 |
| 置信度分布 | 无 140 / 低 0 / 中 0 / 高 0 |
| 分数分布 | 0 分 129 个；1 分 11 个（仅 S6 导入为空） |
| 最高分 | 1（S6 单独命中，权重 1，不足以定性） |
| 最高熵 | 7.744（`aitstatic.exe` `.data`），低于阈值 7.8，未触发 S4 |

### 2.1 11 个 1 分样本是什么

全部因为 `S6_import_empty`（导入函数数 = 0），且都判定 `normal`：

- 纯资源 DLL：`advapi32res.dll`、`adtschema.dll`、`aeevts.dll`、`APHostRes.dll`、`asferror.dll`
- API Set 描述符：`apisetschema.dll`
- 服务栈/占位 DLL（GUID 前缀，如 `0ae3b998-…-_Servicing-Stack.dll`）

结论：**S6 单独 1 分、置信度「无」的设计是对的**——这些文件确实没有导入表，但完全正常。若把 S6 权重调到 5，这批就会变成 11 个假阳性（11/140 = 7.9% 误报率）。

### 2.2 没有触发 S4 的最大熵样本

`aitstatic.exe` 的 `.data` 熵 7.744（压缩数据/加密常量区），距阈值 7.8 只差 0.056。这是**阈值贴边**的典型案例：说明 7.8 是刻意取在「真实压缩节」与「高熵数据节」之间，但也意味着多几个字节的随机数据就可能翻过来。目前它单独只值 2 分，不会定性，可接受。

## 3. 结论

1. **不崩溃**：140/140 解析成功，零异常；`errors` 为空。
2. **没有离谱误报**：System32 全部 `normal`，符合预期（系统文件不加壳）。
3. **耗时可用**：22 ms/文件，扫 1000 个文件约 22 s，可以进日常批处理。
4. **S6 权重经验证**：11 个真实「无导入表」文件没有造成误判，说明 1 分是安全值。

## 4. 局限（必须写在结论里）

- **样本非随机**：取的是字典序前 140 个（`0-9a-*` 段），未覆盖 `w-z` 段；且全是微软签名的系统文件。
- **语料无加壳样本**：只验证了「不误报」，没有验证「能检出」。检出能力靠 `tests/fixtures` 的 UPX 配对与后续 M4 的混合语料。
- **未做交叉校验**：本轮没有和 `rz-bin`/`pefile` 对导入数，只验证自洽与稳定性。导入数的交叉校验在 S1-1 已做（60/60），此处不重复。
- **耗时不代表大文件**：System32 里最大的几个文件（如 `ntoskrnl.exe`）不在前 140 内。

## 5. 复现

**一条命令复现本文所有数字**（140 个文件、0 失败、11 个 1 分、S6 提到 5 时的 7.9% 假阳性）：

```bash
python -m pytest tests/test_baseline.py -q
```

基准数据是同一次真实跑批的快照（`tests/baseline/sys32_140.json`，只含 basename，不含系统文件）。
任何权重/阈值/判定分支的改动都会让它失败——这是故意的，调权重必须同时更新基准并说明理由。

重新采集基准（仅在本机、需要 System32 时）：

```powershell
cd d:\逆向学习\rekit
python -m pytest -q                     # 25 项（含边界与基准测试）
$files = Get-ChildItem C:\Windows\System32 -File |
         Where-Object {$_.Extension -in '.exe','.dll','.sys'} |
         Select-Object -First 140 -ExpandProperty FullName
python -m rekit triage @files -o ..\实践\2026-11-10-rekit-batch\sys32_140.json -m ..\实践\2026-11-10-rekit-batch\sys32_140.md
python ..\实践\2026-11-10-rekit-batch\summarize.py ..\实践\2026-11-10-rekit-batch\sys32_140.json
python ..\实践\2026-11-10-rekit-batch\make_baseline.py
```
