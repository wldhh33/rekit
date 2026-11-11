# -*- coding: utf-8 -*-
"""数据识别：字符串（C / UTF-16 / Go 的指针+长度）、指针数组、结构体字段偏移。

回答三个问题：

1. 这个二进制里有哪些字符串？C 串按 NUL 终止，Go 串**没有终止符**，必须从
   「`lea` 取地址 + 后继立即数给长度」或数据节里的 `(ptr,len)` 对恢复，否则会把
   整段字符串 blob 读成一条超长串。
2. 数据节里哪些是**指针数组**（函数指针表、vtable、字符串表）？按位宽步长扫，
   值必须落在可执行节或数据节内，连续 ≥min_run 个同类值才算一组。
3. 哪些代码在把某个入参当**结构体**用？按权威函数区间逐函数统计
   `[参数寄存器 + 偏移]` 的偏移与访问宽度，再按「偏移+宽度」签名聚类。
   只报「被访问的字段形状」，不做类型推断，也不跨函数合并不同结构体。

输出契约见 `rekit/docs/data.md`；CLI 入口是 `rekit data`。
"""

from __future__ import annotations

import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from .elf import Elf, open_image

MAX_SECTION_SCAN = 64 << 20      # 单节最多扫 64 MiB，超出截断并标注
DEFAULT_MAX_ITEMS = 20000


class DataUnavailable(Exception):
    """缺少反汇编后端（capstone）。"""


# ---------------------------------------------------------------------------
# 统一的节视图：PE / ELF 的 VA 口径
# ---------------------------------------------------------------------------

@dataclass
class SectionView:
    name: str
    va_start: int
    data: bytes
    executable: bool
    truncated: bool = False

    @property
    def va_end(self) -> int:
        return self.va_start + len(self.data)


def _image_views(img: Any, limit: int = MAX_SECTION_SCAN) -> list[SectionView]:
    out: list[SectionView] = []
    base = 0 if isinstance(img, Elf) else img.image_base
    for s in img.sections:
        raw = s.raw
        if not raw:
            continue
        truncated = False
        if len(raw) > limit:
            raw = raw[:limit]
            truncated = True
        out.append(SectionView(
            name=s.name,
            va_start=base + s.virtual_address,
            data=bytes(raw),
            executable=bool(s.is_executable),
            truncated=truncated,
        ))
    out.sort(key=lambda v: v.va_start)
    return out


def _section_of(views: list[SectionView], va: int) -> SectionView | None:
    for v in views:
        if v.va_start <= va < v.va_end:
            return v
    return None


def _read(views: list[SectionView], va: int, size: int) -> bytes | None:
    v = _section_of(views, va)
    if v is None:
        return None
    off = va - v.va_start
    if off + size > len(v.data):
        return None
    return v.data[off:off + size]


# ---------------------------------------------------------------------------
# 字符串
# ---------------------------------------------------------------------------

_C_PRINT = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
_ASCII_RUN = re.compile(rb"[\x20-\x7e\t\r\n]{4,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def _text_ok(raw: bytes) -> str | None:
    """Go 字符串可以是任意字节；这里只接受「解码成功且全部可打印」的 UTF-8。"""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    if not all(ch.isprintable() or ch in "\t\r\n" for ch in text):
        return None
    return text


def scan_c_strings(img: Any, min_len: int = 6, *, utf16: bool = False,
                   max_items: int = DEFAULT_MAX_ITEMS,
                   views: list[SectionView] | None = None) -> dict[str, Any]:
    """扫非可执行节里的 NUL 终止串（可选 UTF-16LE）。"""
    views = views or _image_views(img)
    items: list[dict[str, Any]] = []
    truncated = False
    for v in views:
        if v.executable:
            continue
        for m in _ASCII_RUN.finditer(v.data):
            s = m.group()
            if len(s) < min_len:
                continue
            # 只有「后面紧跟非可打印字节」才算真正的 NUL/分隔终止，
            # 否则说明这段仍属于更长的可打印串，交给同一次匹配即可。
            items.append({
                "address": v.va_start + m.start(),
                "section": v.name,
                "encoding": "ascii",
                "length": len(s),
                "text": s.decode("ascii", "replace"),
            })
            if len(items) >= max_items:
                truncated = True
                break
        if truncated:
            break
    if utf16 and not truncated:
        for v in views:
            if v.executable:
                continue
            for m in _UTF16_RUN.finditer(v.data):
                chars = len(m.group()) // 2
                if chars < max(4, min_len // 2):
                    continue
                items.append({
                    "address": v.va_start + m.start(),
                    "section": v.name,
                    "encoding": "utf-16le",
                    "length": chars,
                    "text": m.group().decode("utf-16le", "replace"),
                })
                if len(items) >= max_items:
                    truncated = True
                    break
            if truncated:
                break
    items.sort(key=lambda x: (x["address"], x["encoding"]))
    return {"count": len(items), "truncated": truncated, "items": items}


# `(ptr,len)` 扫描只看可能存放全局变量头的节；名字元数据节里的
# 随机字节极易拼出「像指针又像长度」的组合，必须排除。
_PAIR_SKIP_SECTIONS = (
    "pclntab", "go.type", "go.func", "buildinfo", "buildid", "note",
    "symtab", "strtab", "debug", "rela", "dynsym", "dynamic", "hash",
    "eh_frame", "gcc_except", "comment", "shstrtab", "dynstr",
)


def _pair_scan_skip(name: str) -> bool:
    low = name.lower()
    return any(k in low for k in _PAIR_SKIP_SECTIONS)


def scan_string_pairs(img: Any, min_len: int = 4, *, max_len: int = 65536,
                      max_items: int = DEFAULT_MAX_ITEMS,
                      views: list[SectionView] | None = None) -> dict[str, Any]:
    """数据节里的 `(ptr,len)` 对——Go 的 string/slice 头就是这个形状。

    这是**与终止符无关**的恢复方式：只要一个 8 字节槽位指向映射区、紧跟的
    8 字节是可打印串的精确长度，就认为是一处字符串头。
    """
    views = views or _image_views(img)
    stride = 8
    seen: dict[tuple[int, int], int] = defaultdict(int)
    truncated = False
    for v in views:
        if v.executable or _pair_scan_skip(v.name):
            continue
        end = len(v.data) - 2 * stride + 1
        if end <= 0:
            continue
        align = (-v.va_start) % stride
        for off in range(align, end, stride):
            ptr, length = struct.unpack_from("<QQ", v.data, off)
            if not (min_len <= length <= max_len):
                continue
            target = _read(views, ptr, length)
            if target is None:
                continue
            text = _text_ok(target)
            if text is None:
                continue
            seen[(ptr, length)] += 1
            if len(seen) >= max_items:
                truncated = True
                break
        if truncated:
            break

    items = []
    intervals: list[tuple[int, int]] = []
    for (ptr, length), refs in sorted(seen.items()):
        text = _text_ok(_read(views, ptr, length) or b"") or ""
        items.append({
            "address": ptr,
            "length": length,
            "refs": refs,
            "text": text,
            "section": (_section_of(views, ptr).name if _section_of(views, ptr) else ""),
        })
        intervals.append((ptr, ptr + length))
    return {
        "count": len(items),
        "truncated": truncated,
        "items": items,
        "covered_bytes": _covered(intervals),
        "span_bytes": _merged_span(intervals),
    }


# Go amd64 内部 ABI 的整数参数寄存器顺序（Go 1.17+ 寄存器传参）。
# 字符串的 (ptr,len) 一定占据**相邻**的两个槽位。
_GO_ARG_ORDER = ("rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11")
_REG32_TO_64 = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edi": "rdi", "esi": "rsi",
    "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
    "ax": "rax", "bx": "rbx", "cx": "rcx", "di": "rdi", "si": "rsi",
    "r8w": "r8", "r9w": "r9", "r10w": "r10", "r11w": "r11",
    "al": "rax", "bl": "rbx", "cl": "rcx", "dil": "rdi", "sil": "rsi",
    "r8b": "r8", "r9b": "r9", "r10b": "r10", "r11b": "r11",
}


def _norm_reg(name: str) -> str:
    return _REG32_TO_64.get(name, name)


def _next_go_arg(reg: str) -> str | None:
    try:
        i = _GO_ARG_ORDER.index(_norm_reg(reg))
    except ValueError:
        return None
    return _GO_ARG_ORDER[i + 1] if i + 1 < len(_GO_ARG_ORDER) else None


def scan_go_strings(img: Any, min_len: int = 4, *, max_len: int = 65536,
                    window: int = 16, max_items: int = DEFAULT_MAX_ITEMS,
                    views: list[SectionView] | None = None,
                    pairs: dict[str, Any] | None = None) -> dict[str, Any]:
    """从调用点恢复 Go 字符串：`lea reg,[rip+X]` + **成对**的长度。

    Go 的字符串常量在 `.rodata`/`.rdata` 里是一大段**无终止符**的 blob，
    字面量边界不落在数据里，只出现在传参处：

    - 寄存器传参：`lea rax,[rip+X]` 之后，长度进入 Go ABI 的下一个整数
      参数寄存器（如 `mov ebx, 0xd`）；
    - 栈传参：`mov [rsp+off], rax` 之后，长度进入 `[rsp+off+8]`。

    只接受这两种「相邻槽位」配对，避免把 blob 中任意偏移当成字符串起点。
    """
    views = views or _image_views(img)
    pairs = pairs or scan_string_pairs(img, min_len, max_len=max_len,
                                       views=views)
    pair_set = {(i["address"], i["length"]) for i in pairs["items"]}
    if not _is_x86(img):
        return {"supported": False, "reason": "只支持 x86 / x86-64",
                "applicable": False, "sites": 0, "count": 0, "items": [],
                "truncated": False, "reg_pair_sites": 0, "stack_pair_sites": 0,
                "naive_would_overread": 0, "covered_bytes": 0, "span_bytes": 0}

    cs = _capstone(_bits(img))
    found: dict[tuple[int, int], dict[str, Any]] = {}
    sites = 0
    overread = 0
    reg_hits = 0
    stack_hits = 0
    truncated = False

    def accept(target: int, length: int, how: str) -> None:
        nonlocal sites, overread, reg_hits, stack_hits, truncated
        if not (min_len <= length <= max_len):
            return
        raw = _read(views, target, length)
        if raw is None:
            return
        text = _text_ok(raw)
        if text is None:
            return
        key = (target, length)
        sites += 1
        if how == "reg-pair":
            reg_hits += 1
        else:
            stack_hits += 1
        nxt = _read(views, target + length, 1)
        would_overread = bool(nxt and _is_printable_byte(nxt))
        if would_overread:
            overread += 1
        entry = found.get(key)
        if entry is None:
            sec = _section_of(views, target)
            found[key] = {
                "address": target,
                "length": length,
                "text": text,
                "section": sec.name if sec else "",
                "sites": 1,
                "how": how,
                "confidence": "pair" if key in pair_set else how,
            }
            if len(found) >= max_items:
                truncated = True
        else:
            entry["sites"] += 1

    for v in views:
        if not v.executable or not v.data:
            continue
        pending: dict[str, Any] | None = None
        slot_ptr: dict[int, int] = {}
        index = 0
        for insn in cs.disasm(v.data, v.va_start):
            index += 1
            if insn.id == 0:          # skipdata 伪指令，无 operands
                continue
            mnem = insn.mnemonic
            if mnem.startswith(("ret", "call", "jmp", "int3")):
                pending = None
                slot_ptr.clear()
                continue
            ops = insn.operands
            if mnem == "lea" and len(ops) == 2 and ops[0].type == X86_OP_REG \
                    and ops[1].type == X86_OP_MEM \
                    and insn.reg_name(ops[1].mem.base) == "rip":
                target = insn.address + insn.size + ops[1].mem.disp
                if _section_of(views, target) is not None:
                    pending = {"target": target, "reg": _norm_reg(
                        insn.reg_name(ops[0].reg)), "index": index, "slots": set()}
                continue
            if pending and index - pending["index"] > window:
                pending = None
            if not mnem.startswith("mov") or len(ops) != 2:
                continue
            dst, src = ops[0], ops[1]
            if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                if pending and _norm_reg(insn.reg_name(src.reg)) == pending["reg"]:
                    pending["reg"] = _norm_reg(insn.reg_name(dst.reg))
                continue
            if dst.type == X86_OP_MEM:
                base = insn.reg_name(dst.mem.base)
                if base not in ("rsp", "rbp"):
                    continue
                off = int(dst.mem.disp)
                if src.type == X86_OP_REG:
                    if pending and _norm_reg(insn.reg_name(src.reg)) == pending["reg"]:
                        pending["slots"].add(off)
                        slot_ptr[off] = pending["target"]
                    continue
                if src.type != X86_OP_IMM:
                    continue
                length = src.imm & 0xFFFFFFFF
                if pending and (off - 8) in pending["slots"]:
                    accept(pending["target"], length, "stack-pair")
                elif (off - 8) in slot_ptr:
                    accept(slot_ptr[off - 8], length, "stack-pair")
                elif pending and (off + 8) in pending["slots"]:
                    accept(pending["target"], length, "stack-pair")
                continue
            if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                if pending and _norm_reg(insn.reg_name(dst.reg)) == \
                        _next_go_arg(pending["reg"]):
                    accept(pending["target"], src.imm & 0xFFFFFFFF, "reg-pair")
        if truncated:
            break

    items = sorted(found.values(), key=lambda x: (x["address"], x["length"]))
    intervals = [(i["address"], i["address"] + i["length"]) for i in items]
    return {
        "supported": True,
        "sites": sites,
        "reg_pair_sites": reg_hits,
        "stack_pair_sites": stack_hits,
        "count": len(items),
        "truncated": truncated,
        # 无终止符的直接证据：这些串后面紧跟可打印字节，C 串扫描必然读长。
        "naive_would_overread": overread,
        "covered_bytes": _covered(intervals),
        "span_bytes": _merged_span(intervals),
        "items": items,
    }


def _is_printable_byte(b: bytes) -> bool:
    return bool(b) and (b[0] in _C_PRINT or b[0] >= 0x80)


def _covered(intervals: list[tuple[int, int]]) -> int:
    return sum(e - s for s, e in _merge(intervals))


def _merged_span(intervals: list[tuple[int, int]]) -> int:
    merged = _merge(intervals)
    if not merged:
        return 0
    return merged[-1][1] - merged[0][0]


def _merge(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not intervals:
        return []
    intervals = sorted(intervals)
    out = [list(intervals[0])]
    for s, e in intervals[1:]:
        if s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(s, e) for s, e in out]


# ---------------------------------------------------------------------------
# 指针数组
# ---------------------------------------------------------------------------

# `.got`/`.got.plt` 里的槽位初始指向 PLT 内部标签（惰性绑定时才被改写），
# 它们是重定位槽而不是「表」；按普通指针数组报会把 176 个 GOT 项当成
# 176 个函数指针，权威起点命中率 0% 已经暴露了这一点。
_ARRAY_SKIP_SECTIONS = ("got", "plt", "iat", "idata", ".edata", "reloc",
                        "dynamic", "dynsym")


def _array_skip(name: str) -> bool:
    low = name.lower()
    return any(k in low for k in _ARRAY_SKIP_SECTIONS)


def scan_pointer_arrays(img: Any, min_run: int = 4, *, max_arrays: int = 5000,
                        views: list[SectionView] | None = None,
                        authority_starts: set[int] | None = None) -> dict[str, Any]:
    """扫数据节里连续的指针组：目标必须全部落在同一个映射节内。"""
    views = views or _image_views(img)
    stride = 8 if _bits(img) == 64 else 4
    fmt = "<Q" if stride == 8 else "<I"
    arrays: list[dict[str, Any]] = []
    truncated = False

    for v in views:
        if v.executable or _array_skip(v.name) or len(v.data) < stride * min_run:
            continue
        align = (-v.va_start) % stride
        cur: dict[str, Any] | None = None
        for off in range(align, len(v.data) - stride + 1, stride):
            target = struct.unpack_from(fmt, v.data, off)[0]
            tsec = _section_of(views, target)
            cls = None if tsec is None else ("code" if tsec.executable else "data")
            va = v.va_start + off
            if cls is None:
                if cur:
                    _flush_array(arrays, cur, authority_starts, min_run)
                    cur = None
                continue
            if cur and cur["target_class"] == cls and va == cur["end"]:
                cur["end"] = va + stride
                cur["count"] += 1
            else:
                if cur:
                    _flush_array(arrays, cur, authority_starts, min_run)
                cur = {"address": va, "end": va + stride, "count": 1,
                       "stride": stride, "target_class": cls, "section": v.name,
                       "targets": [target]}
                continue
            cur["targets"].append(target)
            if len(cur["targets"]) > 4096:
                cur["targets"] = cur["targets"][:4096]
        if cur:
            _flush_array(arrays, cur, authority_starts, min_run)
        if len(arrays) >= max_arrays:
            truncated = True
            break

    arrays.sort(key=lambda a: (a["count"], -a["address"]), reverse=True)
    return {"count": len(arrays), "truncated": truncated,
            "min_run": min_run, "arrays": arrays[:max_arrays]}


def _flush_array(arrays: list[dict[str, Any]], cur: dict[str, Any],
                 starts: set[int] | None, min_run: int) -> None:
    if cur["count"] < min_run:
        return
    targets = cur["targets"]
    entry = {
        "address": cur["address"],
        "end": cur["end"],
        "count": cur["count"],
        "stride": cur["stride"],
        "target_class": cur["target_class"],
        "section": cur["section"],
        "first_targets": targets[:8],
        "all_targets_in_image": True,
    }
    if cur["target_class"] == "code" and starts:
        hit = sum(1 for t in targets if t in starts)
        entry["authority_start_hits"] = hit
        entry["authority_start_ratio"] = round(hit / len(targets), 4)
    arrays.append(entry)


# ---------------------------------------------------------------------------
# 结构体字段偏移
# ---------------------------------------------------------------------------

_ARG_REGS = {
    "win64": ("rcx", "rdx", "r8", "r9"),
    "sysv": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
}


def infer_struct_fields(img: Any, *, max_disp: int = 0x800,
                        min_fields: int = 2, max_functions: int = 3000,
                        max_span: int = 4096,
                        views: list[SectionView] | None = None) -> dict[str, Any]:
    """按函数统计「入参被当作结构体」的字段偏移与访问宽度。

    边界：只跟**同一函数内**的寄存器别名（`mov rbx, rcx`），不跨调用、
    不追栈上复制、不做类型推断；`[reg + index*stride + disp]` 的数组访问
    因含 index 被排除。
    """
    if _bits(img) != 64 or not _is_x86(img):
        return {"supported": False, "reason": "只支持 x86-64", "functions": [],
                "clusters": [], "authority": ""}
    from .funcs import authority_table

    auth = authority_table(img)
    views = views or _image_views(img)
    if auth.usable:
        spans = list(auth.spans[:max_functions])
        source = auth.name
        # 叶子函数可能没有 .pdata/.eh_frame（无栈帧就无 unwind），
        # 但导出的入口仍然是真函数，补进来避免 ground truth 漏检。
        known = {s for s, _ in spans}
        extra: set[int] = set()
        try:
            if not isinstance(img, Elf):
                if getattr(img, "entry_rva", 0):
                    extra.add(img.image_base + img.entry_rva)
                extra.update(img.image_base + e.rva for e in img.exports())
        except Exception:  # pragma: no cover - 导出表损坏不影响主流程
            extra = set()
        extra -= known
        if extra:
            starts = sorted(known | extra)
            nxt = {s: (starts[i + 1] if i + 1 < len(starts) else s + max_span)
                   for i, s in enumerate(starts)}
            spans.extend((s, nxt[s]) for s in sorted(extra))
    else:
        spans = _linear_spans(img, views)[:max_functions]
        source = "linear-sweep"
    cs = _capstone(64)
    regs = _ARG_REGS["win64" if not isinstance(img, Elf) else "sysv"]

    per_func: list[dict[str, Any]] = []
    clusters: Counter[tuple[tuple[int, int], ...]] = Counter()
    cluster_example: dict[tuple[tuple[int, int], ...], int] = {}

    for start, end in spans:
        span_end = min(start + max_span, end)
        v = _section_of(views, start)
        if v is None or not v.executable:
            continue
        base = start - v.va_start
        code = v.data[base:base + (span_end - start)]
        aliases: set[str] = set()
        counts: Counter[tuple[int, int]] = Counter()
        for insn in cs.disasm(code, start):
            if insn.id == 0:
                continue
            mnem = insn.mnemonic
            if mnem.startswith(("ret", "int3", "ud2")):
                break
            ops = insn.operands
            # 寄存器别名：入参寄存器被复制到别的寄存器后继续当结构体基址
            if mnem == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG \
                    and ops[1].type == X86_OP_REG:
                dst, src = insn.reg_name(ops[0].reg), insn.reg_name(ops[1].reg)
                if src in aliases or src in regs:
                    aliases.add(dst)
                elif dst in aliases:
                    aliases.discard(dst)
            elif mnem.startswith("call"):
                aliases.clear()
            if mnem == "lea":
                continue
            for op in ops:
                if op.type != X86_OP_MEM:
                    continue
                if op.mem.index != 0 or op.mem.disp < 0 or op.mem.segment != 0:
                    continue
                if op.mem.disp > max_disp:
                    continue
                bname = insn.reg_name(op.mem.base) if op.mem.base else ""
                if bname not in regs and bname not in aliases:
                    continue
                counts[(int(op.mem.disp), int(op.size))] += 1
        if len({d for d, _ in counts}) < min_fields:
            continue
        fields = [{"offset": d, "width": w, "hits": c}
                  for (d, w), c in sorted(counts.items())]
        per_func.append({"start": start, "fields": fields})
        sig = tuple((d, w) for d, w in sorted(counts))
        clusters[sig] += 1
        cluster_example.setdefault(sig, start)

    top = []
    for sig, n in clusters.most_common(20):
        top.append({
            "functions": n,
            "example_start": cluster_example[sig],
            "fields": [{"offset": d, "width": w} for d, w in sig],
        })
    return {
        "supported": True,
        "authority": source,
        "functions": per_func[:200],
        "function_count": len(per_func),
        "clusters": top,
    }


def _linear_spans(img: Any, views: list[SectionView]) -> list[tuple[int, int]]:
    """无权威表时的兜底：可执行节整体作为一段，由 `ret`/`int3` 切窗由调用方处理。"""
    return [(v.va_start, v.va_end) for v in views if v.executable]


# ---------------------------------------------------------------------------
# 总入口
# ---------------------------------------------------------------------------

def _pclntab_header_ok(data: bytes, off: int) -> bool:
    """校验 pclntab 头：magic + 2 字节 pad + minLC + ptrSize + nfunc。

    只匹配 4 字节 magic 会把随便一个 `fb ff ff ff` 当成 Go（notepad.exe 就踩过），
    必须连同头部结构一起验证。
    """
    if off + 16 > len(data):
        return False
    if data[off + 4:off + 6] != b"\x00\x00":
        return False
    if data[off + 6] not in (1, 2, 4):
        return False
    if data[off + 7] not in (4, 8):
        return False
    nfunc = int.from_bytes(data[off + 8:off + 16], "little")
    return 100 <= nfunc <= 5_000_000


def detect_go(views: list[SectionView]) -> bool:
    """Go 判定：buildinfo 标记 / `.gopclntab` 节 / 合法 pclntab 头，三者取一。"""
    skip = ("shstrtab", "strtab", "symtab", "debug")
    magics = (b"\xf1\xff\xff\xff", b"\xf0\xff\xff\xff",
              b"\xfa\xff\xff\xff", b"\xfb\xff\xff\xff")
    for v in views:
        if v.executable or any(k in v.name.lower() for k in skip):
            continue
        if b"\xff Go buildinf:" in v.data or "gopclntab" in v.name.lower():
            return True
        for magic in magics:
            pos = v.data.find(magic)
            while pos >= 0:
                if _pclntab_header_ok(v.data, pos):
                    return True
                pos = v.data.find(magic, pos + 1)
    return False


def _merge_pair_items(go: dict[str, Any], pairs: dict[str, Any],
                      max_items: int) -> dict[str, Any]:
    """合并「代码站点」与「数据头」两路证据，按 (地址,长度) 去重。"""
    merged: dict[tuple[int, int], dict[str, Any]] = {
        (i["address"], i["length"]): dict(i, evidence=i.get("how", ""))
        for i in go.get("items", [])
    }
    data_only = 0
    for p in pairs.get("items", []):
        key = (p["address"], p["length"])
        if key in merged:
            merged[key]["evidence"] = "code+data"
            merged[key]["data_refs"] = p["refs"]
        else:
            merged[key] = {
                "address": p["address"],
                "length": p["length"],
                "text": p["text"],
                "section": p["section"],
                "sites": p["refs"],
                "evidence": "data-pair",
                "confidence": "data-pair",
            }
            data_only += 1
            if len(merged) >= max_items:
                go["truncated"] = True
                break
    items = sorted(merged.values(), key=lambda x: (x["address"], x["length"]))
    intervals = [(i["address"], i["address"] + i["length"]) for i in items]
    go = dict(go)
    go.update({
        "count": len(items),
        "data_pair_count": data_only,
        "items": items,
        "covered_bytes": _covered(intervals),
        "span_bytes": _merged_span(intervals),
    })
    return go


def _bits(img: Any) -> int:
    return int(getattr(img, "bits", 64))


def _is_x86(img: Any) -> bool:
    if isinstance(img, Elf):
        return img.machine in (0x03, 0x3E)
    return img.machine in (0x14C, 0x8664)


def _capstone(bits: int):
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    except ImportError as e:  # pragma: no cover - 环境问题
        raise DataUnavailable(
            "data 需要反汇编后端：python -m pip install capstone") from e
    cs = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    cs.detail = True
    cs.skipdata = True
    return cs


def _op_consts():
    try:
        from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    except ImportError as e:  # pragma: no cover - 环境问题
        raise DataUnavailable(
            "data 需要反汇编后端：python -m pip install capstone") from e
    return X86_OP_REG, X86_OP_IMM, X86_OP_MEM


try:
    X86_OP_REG, X86_OP_IMM, X86_OP_MEM = _op_consts()
except DataUnavailable:  # 延迟到真正调用时再报错，避免影响无关子命令
    X86_OP_REG = X86_OP_IMM = X86_OP_MEM = None


def analyze_image_data(path: str, *, min_c_len: int = 6, min_go_len: int = 4,
                       utf16: bool = False, arrays: bool = True,
                       structs: bool = True, max_items: int = DEFAULT_MAX_ITEMS,
                       min_run: int = 4, allow_large: bool = False) -> dict[str, Any]:
    img = open_image(path, allow_large=allow_large)
    views = _image_views(img)
    is_go = detect_go(views)
    c = scan_c_strings(img, min_c_len, utf16=utf16, max_items=max_items, views=views)
    pairs = scan_string_pairs(img, min_go_len, max_items=max_items, views=views)
    go = scan_go_strings(img, min_go_len, max_items=max_items, views=views, pairs=pairs)
    code_count = go["count"]
    if is_go:
        go = _merge_pair_items(go, pairs, max_items)
        # 非 x86（如 arm64）时 scan_go_strings 明确返回 supported=False，
        # 不能因为“是 Go”就宣称两路证据可用。
        go["applicable"] = bool(go.get("supported", True))
    else:
        # 这套恢复规则依赖 Go 的传参约定；在 C/Rust 上跑只会得到偶发假阳性。
        go = {"supported": go.get("supported", True), "applicable": False,
              "count": 0, "sites": 0, "reg_pair_sites": 0,
              "stack_pair_sites": 0, "truncated": False,
              "naive_would_overread": 0, "covered_bytes": 0,
              "span_bytes": 0, "items": []}

    out: dict[str, Any] = {
        "file": str(path),
        "format": "ELF" if isinstance(img, Elf) else "PE",
        "arch": getattr(img, "arch", ""),
        "bits": _bits(img),
        "image_base": f"0x{getattr(img, 'image_base', 0):X}",
        "is_go": is_go,
        "sections": [{"name": v.name, "va_start": f"0x{v.va_start:X}",
                      "size": len(v.data), "executable": v.executable,
                      "truncated": v.truncated} for v in views],
        "c_strings": c,
        "go_strings": go,
        "string_pairs": {k: pairs[k] for k in
                         ("count", "truncated", "covered_bytes", "span_bytes")},
    }
    if is_go:
        out["go_strings"]["code_site_count"] = code_count
    if arrays:
        from .funcs import authority_table
        try:
            starts = set(authority_table(img).starts)
        except Exception:  # pragma: no cover - 权威表失败不影响字符串
            starts = set()
        out["pointer_arrays"] = scan_pointer_arrays(
            img, min_run=min_run, views=views, authority_starts=starts)
    if structs:
        out["struct_fields"] = infer_struct_fields(img, views=views)
    return out
