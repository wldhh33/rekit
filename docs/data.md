# `rekit data` —— 数据识别

`data` 回答「节里有什么」：字符串、指针数组、以及「哪些函数把入参当结构体用」。
它不做反编译，也不猜类型；每个结论都能指回一个字节地址和一段取证依据。

```bash
rekit data payload.exe                      # 人读摘要
rekit data payload.exe --json out.json      # 完整结构
rekit data payload.exe --csv strings.csv    # 字符串明细（C + Go）
rekit data payload.exe --min-run 2 --utf16  # 放宽指针数组阈值 + 扫 UTF-16
```

## 1. 字符串：三路取证

| kind | 依据 | 适用 | 主要失效场景 |
|---|---|---|---|
| `c` | NUL / 非可打印字节终止 | C/C++、部分 Rust | **Go 无终止符**，会把整段 blob 读成一条超长串；Rust `&str` 同理 |
| `go-code` | `lea reg,[rip+X]` + 相邻参数槽里的长度 | Go 1.17+ 寄存器 ABI / 栈 ABI | 全局字符串头、非直接传参的引用 |
| `go-data` | 数据节里的 `(ptr,len)` 头 | Go 全局 string/slice | 仅当 `is_go=true` 才合并；元数据节会被排除 |

`go-code` 只接受两种「相邻槽位」配对，避免把 blob 中任意偏移当起点：

1. 寄存器：`lea rax,[rip+X]` 后，长度进入 Go ABI 的**下一个**整数参数寄存器
   （顺序 `rax,rbx,rcx,rdi,rsi,r8,r9,r10,r11`）；
2. 栈：`mov [rsp/off], rax` 后，长度进入 `[rsp/off+8]`（允许先长度后指针）。

`naive_would_overread` 统计「字符串末尾仍是可打印字节」的条数——这些位置
C 串扫描必然继续读下去，是 Go blob 无终止符的直接证据。

## 2. JSON 字段（`--json`）

```
file, format(PE/ELF), arch, bits, image_base, is_go
sections[]            name, va_start, size, executable, truncated
c_strings             count, truncated, longest, items[{address,section,encoding,length,text}]
go_strings            supported, applicable, count, code_site_count, data_pair_count,
                      sites, reg_pair_sites, stack_pair_sites, naive_would_overread,
                      covered_bytes, span_bytes, truncated,
                      items[{address,length,text,section,sites,how,evidence,confidence}]
string_pairs          count, truncated, covered_bytes, span_bytes
pointer_arrays        count, truncated, min_run, arrays[{address,end,count,stride,
                      target_class(code/data),section,first_targets[],
                      all_targets_in_image,authority_start_hits,authority_start_ratio}]
struct_fields         supported, authority, function_count,
                      functions[{start,fields[{offset,width,hits}]}],
                      clusters[{functions,example_start,fields[{offset,width}]}]
```

`--csv` 固定列：`file,kind,address,length,section,encoding,text`；
`kind` 为 `c` / `go`，`encoding` 对 Go 行表示 `evidence`。

## 3. 指针数组

- 位宽：x64 8 字节、x86 4 字节；按 VA 对齐扫描**非可执行节**。
- 跳过 `.got`/`.got.plt`/`.plt`/IAT/`.edata`/`.rela*` 等重定位槽节：
  这些槽位初值指向 PLT 内部标签，不是函数表（pyyaml 上曾把 176 个 GOT 项
  误报成 176 项代码表，权威起点命中率 0%）。
- 目标必须在映射区内且同类（`code` 落可执行节、`data` 落数据节），
  连续 `≥min_run` 项才成组。
- 代码表额外给出 `authority_start_ratio`：目标中有多少比例命中权威函数起点
  （`.pdata` / `.eh_frame` / `.gopclntab`）。这是判断「函数指针表」最硬的证据。
- 叶子函数可能没有 unwind 信息，因此 100% 不是常态；`struct_probe.exe` 的
  Rust vtable 只有 43%–71% 命中，不能据此判假。

## 4. 结构体字段统计（`struct_fields`）

逐函数收集 `[参数寄存器 + disp]`（`disp∈[0,0x800]`），记录访问宽度；同一函数内
允许一次 `mov rbx, rcx` 形式的寄存器别名。按「偏移+宽度」签名聚类，输出被多个
函数共享的布局候选。

明确边界：

- 只支持 x86-64；32 位栈传参不推断；
- 不跨函数、不追栈上复制、不追 PHI/合并；
- 含 index 的 `[reg+index*stride+disp]` 视为数组访问，不计字段；
- 权威表缺失的函数（PE 叶子函数）用导出表/入口补齐，仍可能漏；
- 只回答「访问了哪些偏移、多宽」，**不推断字段类型**，也不合并不同结构体。

## 5. 已知限制

- 单节最多扫 64 MiB，超出部分截断并在 `sections[].truncated` 标注；
- `(ptr,len)` 扫描排除 `pclntab/type/debug/symtab/...` 等元数据节，否则随机字节
  会拼出大量假串；
- Go 代码扫描在 `.text` 内线性反汇编，`skipdata` 会吞掉嵌入数据后的少量指令；
- 非 Go 二进制不输出 Go 串（`applicable=false`），避免偶发假阳性被误读。
