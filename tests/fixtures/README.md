# 测试固定输入

| 文件 | 来源 | 许可 | 用途 |
|---|---|---|---|
| `hello_rs.exe` | 本项目自编译（`rustc -O main.rs`，源码见学习项目的 `样本/raw/hello_rs/main.rs`） | MIT/Apache-2.0（自有代码） | 未加壳基线：PE32+ / 5 节 / 85 导入 / 10 DLL；`.pdata` 333 项 |
| `hello_rs.packed.exe` | 用 UPX 5.0.0 `--best` 对上面文件加壳 | 同上（UPX 只是工具，产物无新增限制） | 加壳基线：`UPX0/UPX1/UPX2`、`UPX0.RawSize=0`、13 导入 / 10 DLL |
| `hello_elf` | 本项目自编译（`rustc --target x86_64-unknown-linux-musl -O -C panic=abort -C force-unwind-tables=yes -C strip=symbols -C link-arg=--export-dynamic`），源码 `src/hello_elf.rs` | MIT/Apache-2.0（自有代码） | ELF64 基线：`.eh_frame` + `.eh_frame_hdr`，2360 条 FDE，`.dynsym` 有函数导出 |
| `gcc_o2.exe` / `gcc_o0.exe` | 本项目自编译（MinGW-w64 GCC 16.2，`src/build_fixtures.ps1`，源码 `src/hello_c.c`） | MIT/Apache-2.0（自有代码） | GCC x64 PE：`.pdata` 59 项，用于 GCC 工具链判别与 A 层召回 |
| `clang_o0` / `clang_o2` | 本项目自编译（zig cc 的 LLVM/Clang 后端，`-target x86_64-linux-gnu`） | 同上 | Clang x64 ELF：`clang_o0` 714 条 FDE（有效样本）；`clang_o2` 仅 10 条，只作冒烟 |
| `clang_arm64_o2` | 本项目自编译（zig cc，`-target aarch64-linux-gnu`） | 同上 | **非 x86** 样本：ARM64 ELF，9 条 FDE，验证"B 层不适用、只交权威表" |
| `msvc_x64.exe` / `msvc_x86.exe` | 本项目自编译（MSVC 19.29，`cl /O2 /MD`） | 同上 | MSVC x64（`.pdata` 28 项）/ x86（PE32 无 `.pdata`，走 B 层） |
| `go_linux_amd64` / `go_linux_arm64` | 本项目自编译（Go 1.27，`-s -w`，源码 `src/hello_go.go`） | 同上 | Go ELF64：`.gopclntab` 1799 / 1760 项（表头 1801 / 1762，各剔 2 项填充）；后者同时是非 x86 样本 |
| `struct_probe.exe` | 本项目自编译（rustc `-O -C panic=abort`，源码 `src/struct_probe.rs`） | MIT/Apache-2.0（自有代码） | `rekit data` 的结构体偏移 ground truth：`#[repr(C)]` 固定 `a@0/b@4/c@8/d@0x10`，两个导出入口必须被恢复出这四个偏移 |

`go_win.exe`（Go windows/amd64，1.6 MB）只在本地量测，不进仓库：它在 PE 上走 `.pdata`（1588 项），
与已提交的 Go ELF 样本覆盖同一能力，没必要为 1.6 MB 重复占体积。

`go119_linux` / `go119_win.exe` / `go122_linux` / `go122_win.exe`（Go 1.19.13 / 1.22.12，各约 1.2–1.3 MB）
同样**不进仓库**，只本地量测：它们唯一的用途是验证经典 `itablinks` 分支（1.18–1.24）。
重建用 `.\src\build_fixtures.ps1 -Go119 D:\tools\go1.19\go\bin\go.exe -Go122 D:\tools\go1.22\go\bin\go.exe`
（老版本装独立目录，不覆盖现行 Go；`GO111MODULE=off` + `-trimpath -ldflags="-s -w"`）。
四份样本的 SHA256、itab 数与冷启动数字记在 `docs/funcs.md` §6.3。

M2 达标门的四个族样本（Clang / Go linux / Go PE / Rust）连同 **SHA256、大小、获得方式、权威项、
A 层与冷启动数字**冻结在 `tests/baseline/m2_families.json`，由 `tests/test_m2_gate.py` 回归；
不在仓库的两个样本（`go_win.exe` 及老版本 Go）缺失时按 **skip** 计，不按通过计。

这些文件都是可再分发的自有产物，仓库里不放任何专有系统文件或恶意样本。

`hello_elf` 的构建（Windows + rustup 自带 rust-lld，无需 gcc/WSL）：

```bash
rustup target add x86_64-unknown-linux-musl
rustc --target x86_64-unknown-linux-musl -O -C panic=abort \
      -C force-unwind-tables=yes -C strip=symbols -C link-arg=--export-dynamic \
      -C linker="$HOME/.rustup/toolchains/stable-x86_64-pc-windows-msvc/lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe" \
      tests/fixtures/src/hello_elf.rs -o tests/fixtures/hello_elf
```

`-C force-unwind-tables=yes` 保证 `.eh_frame` 存在；`--export-dynamic` 让
`funcs` 的反事实口径有导出可播种（否则 PIE 静态样本只有入口，召回会失真）。
