# 重新生成跨编译器 fixture（GCC / Clang / MSVC / Go）
#
# 用途：`tests/fixtures/` 里的 gcc_o*、clang_*、msvc_*、go_linux_* 都是这里产出的。
# 源码只有 `hello_c.c` 与 `hello_go.go`，二进制可随时重建，避免"样本来源不明"。
#
# 用法（PowerShell，按需传路径；缺哪个工具就跳过对应产物）：
#   .\build_fixtures.ps1 -Gcc C:\tools\mingw64\bin\gcc.exe `
#                        -Zig "python -m ziglang" `
#                        -Go C:\tools\go\bin\go.exe `
#                        -Go119 D:\tools\go1.19\go\bin\go.exe `
#                        -Go122 D:\tools\go1.22\go\bin\go.exe `
#                        -GoWindows `
#                        -MsvcRoot "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133" `
#                        -SdkRoot  "C:\Program Files (x86)\Windows Kits\10"
#
# Go 样本分三组：
#   * `-Go`（现行版本，本机 1.27）→ `go_linux_amd64` / `go_linux_arm64`（进仓库）；
#   * `-Go119` / `-Go122`（老版本，独立目录，别覆盖现行安装）→ `go119_linux` /
#     `go119_win.exe` / `go122_linux` / `go122_win.exe`。这两组只为验证经典
#     `itablinks` 分支（Go 1.18–1.24 的 magic F0/F1、偏移 0x168/0x178），
#     合计约 5 MB，**按仓库规则不进仓库**，只本地量测并在
#     `tests/baseline/m2_families.json` / `docs/funcs.md` §6.3 记录 SHA256 与工具链版本；
#   * `-GoWindows` 额外构建 `go_win.exe`（windows/amd64，1.65 MB，同样只本地量测）。
# 老版本用 `GO111MODULE=off` + 单文件 `go build`，不需要 go.mod；`-trimpath -ldflags="-s -w"`
# 与现行版本保持一致，否则 `.gopclntab` 的填充项数会变、权威分母对不上。
#
# 已知坑：
#   * MinGW 的 ld 处理非 ASCII 路径会失败，所以先编到 $env:TEMP\rekit-fixtures 再拷回。
#   * MSVC 需要 INCLUDE/LIB，脚本按 x64/x86 两套拼，不调用 vcvars（避免 cmd 转义）。
#   * Clang 用 zig cc 驱动（LLVM 后端），只因这台机器没装独立 LLVM；换成真 clang 时
#     把 `-target x86_64-linux-gnu` 换成 `--target=x86_64-linux-gnu -nostdlib` 即可。

param(
    [string]$Gcc = "",
    [string]$Zig = "python -m ziglang",
    [string]$Go = "",
    [string]$Go119 = "",
    [string]$Go122 = "",
    [switch]$GoWindows,
    [string]$MsvcRoot = "",
    [string]$SdkRoot = "C:\Program Files (x86)\Windows Kits\10",
    [string]$SdkVer = "10.0.19041.0",
    [string]$Rustc = "rustc"
)

$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$fixtures = Split-Path -Parent $here
$tmp = Join-Path $env:TEMP "rekit-fixtures"
New-Item -ItemType Directory -Force $tmp | Out-Null
Copy-Item "$here\hello_c.c","$here\hello_go.go" $tmp -Force

function Have($exe) { return $exe -and (Test-Path $exe) }

if (Have $Gcc) {
    # MinGW-w64：PE64，带 .pdata；-s 只去符号表，不影响 .pdata
    & $Gcc -O2 -s "$tmp\hello_c.c" -o "$tmp\gcc_o2.exe"
    & $Gcc -O0 -s "$tmp\hello_c.c" -o "$tmp\gcc_o0.exe"
    Copy-Item "$tmp\gcc_o2.exe","$tmp\gcc_o0.exe" $fixtures -Force
    Write-Host "gcc: ok"
} else { Write-Host "gcc: skipped (no -Gcc)" }

if ($Zig) {
    # LLVM/Clang 后端；x86_64 与 aarch64 两个目标，后者是非 x86 样本
    Invoke-Expression "$Zig cc -target x86_64-linux-gnu -O0 -s `"$tmp\hello_c.c`" -o `"$fixtures\clang_o0`""
    Invoke-Expression "$Zig cc -target x86_64-linux-gnu -O2 -s `"$tmp\hello_c.c`" -o `"$fixtures\clang_o2`""
    Invoke-Expression "$Zig cc -target aarch64-linux-gnu -O2 -s `"$tmp\hello_c.c`" -o `"$fixtures\clang_arm64_o2`""
    Write-Host "clang(zig cc): ok"
}

if (Have $Go) {
    $env:GOOS = "linux"; $env:GOARCH = "amd64"
    & $Go build -trimpath "-ldflags=-s -w" -o "$fixtures\go_linux_amd64" "$tmp\hello_go.go"
    $env:GOARCH = "arm64"
    & $Go build -trimpath "-ldflags=-s -w" -o "$fixtures\go_linux_arm64" "$tmp\hello_go.go"
    Write-Host "go linux: ok"
    if ($GoWindows) {
        # 1.65 MB，按仓库规则不进仓库：只本地量测，SHA256 记在 baseline 与 docs/funcs.md
        $env:GOOS = "windows"; $env:GOARCH = "amd64"
        & $Go build -trimpath "-ldflags=-s -w" -o "$env:TEMP\go_win.exe" "$tmp\hello_go.go"
        Copy-Item "$env:TEMP\go_win.exe" "$fixtures\go_win.exe" -Force
        Write-Host "go windows: ok (local only)"
    }
}

foreach ($pair in @(@("go119", $Go119), @("go122", $Go122))) {
    $tag, $exe = $pair
    if (-not (Have $exe)) { Write-Host "$tag`: skipped (no -$tag)"; continue }
    # 老版本只用于验证经典 itablinks 分支（1.18–1.24）；独立目录，不覆盖现行 Go。
    $env:GO111MODULE = "off"
    foreach ($target in @(@("linux", "linux"), @("windows", "win.exe"))) {
        $env:GOOS, $env:GOARCH = $target[0], "amd64"
        & $exe build -trimpath "-ldflags=-s -w" -o "$fixtures\$tag`_$($target[1])" "$tmp\hello_go.go"
    }
    $env:GO111MODULE = ""
    Write-Host "$tag`: ok (linux + windows)"
}

if ((Have $MsvcRoot) -and (Test-Path $SdkRoot)) {
    $inc = "$MsvcRoot\include;$SdkRoot\Include\$SdkVer\ucrt;$SdkRoot\Include\$SdkVer\um;$SdkRoot\Include\$SdkVer\shared"
    foreach ($arch in @("x64", "x86")) {
        $env:INCLUDE = $inc
        if ($arch -eq "x64") {
            $env:LIB = "$MsvcRoot\lib\x64;$SdkRoot\Lib\$SdkVer\ucrt\x64;$SdkRoot\Lib\$SdkVer\um\x64"
            $bin = "$MsvcRoot\bin\Hostx64\x64"
        } else {
            $env:LIB = "$MsvcRoot\lib\x86;$SdkRoot\Lib\$SdkVer\ucrt\x86;$SdkRoot\Lib\$SdkVer\um\x86"
            $bin = "$MsvcRoot\bin\Hostx86\x86"
        }
        & "$bin\cl.exe" /nologo /O2 /MD "$tmp\hello_c.c" /Fo"$tmp\msvc_$arch.obj" /Fe"$tmp\msvc_$arch.exe"
        Copy-Item "$tmp\msvc_$arch.exe" $fixtures -Force
    }
    Write-Host "msvc: ok"
} else { Write-Host "msvc: skipped (no -MsvcRoot)" }

# 结构体字段偏移的 ground truth：#[repr(C)] 布局固定为 0/4/8/16，
# 两个 extern "C" 函数必须导出，否则链接器会按 /OPT:REF 丢掉未被引用的 COMDAT。
& $Rustc -O -C panic=abort `
    -C link-arg=/EXPORT:probe_read -C link-arg=/EXPORT:probe_write `
    -o "$fixtures\struct_probe.exe" "$PSScriptRoot\struct_probe.rs"
if ($LASTEXITCODE -eq 0) { Write-Host "rust struct_probe: ok" }
else { Write-Host "rust struct_probe: failed ($LASTEXITCODE)" }

Write-Host "done -> $fixtures"
