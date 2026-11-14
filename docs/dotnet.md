# `rekit dotnet` —— 只读 .NET IL / 堆 / 资源事实

`rekit dotnet` 回答「这个托管程序集的 IL 结构、字符串、资源和工具链标记是什么」。
它**不反编译、不还原控制流、不判家族，也不参与 `identify` / `report` 的
`family` / `verdict` / `confidence`**。输出是取证事实，不是行为结论。

```bash
rekit dotnet app.dll                          # 人读摘要
rekit dotnet app.dll -j out.json              # 完整结构
rekit dotnet 发布目录/                          # 目录下 .dll/.exe（不递归）
rekit dotnet app.dll --allow-large            # 超过 512 MiB 才需要
```

## 1. 解析范围

| 层 | 依据 | 产出 |
|---|---|---|
| COR20 头 | PE 数据目录 #14，ECMA-335 II.25.3.3 | 元数据 RVA/大小、入口 token、资源/强名称槽 |
| 元数据根 | `BSJB` + 流表 | `#~`/`#-`、`#Strings`、`#US`、`#Blob` |
| 表流 | ECMA-335 II.22 列定义 | TypeDef / MethodDef / ManifestResource / CustomAttribute |
| 方法体 | II.25.4.2 tiny/fat 头 | IL 起止、code_size、max_stack、local sig |
| EH | II.25.4.6 | 异常子句数与每条的 try/handler 区间 |
| `#US` | II.24.2.4 | 用户字符串条数与坏长度位置 |
| 资源 | COR20 Resources + ManifestResource | 名称、偏移、大小、熵、头 24 字节 |
| 属性 | CustomAttribute + SerString | TargetFramework、程序集元信息、混淆属性 |

## 2. 判据与口径

- **方法体**：`b & 3 == 2` 为 tiny（code_size = b >> 2，头 1 字节）；
  `b & 3 == 3` 为 fat（flags/size 各 12/4 位，头 = size × 4，最小 12）。
- **EH 子句宽度**：段头 `Kind` 的 `0x40` 位为 1 → 夫子句 24 字节；否则小子句
  12 字节。`DataSize` **包含 4 字节段头**，子句字节数 = `DataSize - 4`。
  解读反了会把 511 个正常方法报成结构异常（Q1 实测踩过）。
- **`#US`**：每条长度含末尾终止字节；偏移 0 为空串，单独跳过。
- **资源**：`ManifestResource.Offset` 是相对 COR20 Resources 起点的偏移，
  不是 RVA；只统计 `Implementation == 0` 的内嵌资源。
- **类型名**：嵌套类型用 `Outer/Inner` 全名，避免把编译器生成的 `<>c` 等
  误判为重名。

## 3. JSON 字段（`-j`）

```
results[]              file, assembly, assembly_version, target_framework,
                       metadata_version, entry_point_token,
                       types{count, non_ascii[], duplicates[]},
                       methods{count, with_body, no_body, invalid},
                       il{methods_total, with_body, no_body, il_bytes, max_code,
                          eh_methods, eh_clauses, invalid[], unknown_opcode[],
                          ldstr, calls, ldftn, callees[], capability_hits{},
                          methods[]},
                       strings{us_count, us_invalid[]},
                       resources[{name, offset, size, embedded, entropy, head_hex}],
                       attributes{},
                       obfuscation_signals[{id, detail}]
errors[]               file, error
```

`capability_hits` 只是**静态调用点计数**，用于取证索引；名称里带
「进程/网络/注册表」不代表程序真的执行这些行为。

## 4. 已知边界

- 不解析方法签名（参数/返回类型），`local_sig` 只给 blob token。
- 不解析泛型实例化后的具体类型；`MethodSpec` 只标 `<>`。
- 不做控制流、不识别编译器模式、不反编译。
- 引用程序集（MethodDef RVA 全为 0）会全部计入 `no_body`，这是正常结构，
  不是损坏。
- 未压缩表流 `#-` 会报 `uncompressed_tables` 信号；它能解析，但常见于 ENC
  编辑态，需人工确认。
