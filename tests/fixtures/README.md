# 测试固定输入

| 文件 | 来源 | 许可 | 用途 |
|---|---|---|---|
| `hello_rs.exe` | 本项目自编译（`rustc -O main.rs`，源码见学习项目的 `样本/raw/hello_rs/main.rs`） | MIT/Apache-2.0（自有代码） | 未加壳基线：PE32+ / 5 节 / 85 导入 / 10 DLL |
| `hello_rs.packed.exe` | 用 UPX 5.0.0 `--best` 对上面文件加壳 | 同上（UPX 只是工具，产物无新增限制） | 加壳基线：`UPX0/UPX1/UPX2`、`UPX0.RawSize=0`、13 导入 / 10 DLL |

这两份都是可再分发的自有产物，仓库里不放任何专有系统文件或恶意样本。
