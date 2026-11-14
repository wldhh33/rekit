# -*- coding: utf-8 -*-
"""`rekit xref` 核心：回答“谁引用了这个目标”。

口径（与 `docs/xref.md` 一致，改这里必须同步改文档与 `tests/test_xref.py`）：

1. **指令流只来自 `funcs` 的递归下降**（`discover(..., insn_out=...)`），
   这里不再写第二套线性扫描。召回上限因此等于函数发现率：没被
   `funcs` 发现的函数体里的引用不会出现在结果里。
2. **确定**（`certain`）只收三类可机械判定的引用：
   - RIP 相对内存操作数（`lea` / `mov` / 其它指令）；
   - 直接分支 `rel32`（call / jmp / jcc）；
   - 重定位表 addend（ELF `R_*_RELATIVE`、PE `IMAGE_REL_BASED_DIR64/HIGHLOW`）。
3. **疑似**（`suspected`）单列，绝不混进确定集：
   - 绝对立即数（可能是整数常量，不是地址）；
   - `.data` / `.rdata` 等数据节里的 8/4 字节字（可能是巧合值）；
   - 可选的 `.text` 字节扫描（**可能命中操作数内部**，默认关闭）。
"""

from __future__ import annotations

import bisect
import struct
import time
from dataclasses import dataclass
from typing import Any, Iterable

from .elf import Elf
from .funcs import (
    PTR_SIZE, discover, image_bits, is_x86, open_image, section_name_at,
)
from .pe import PE

MAX_LITERAL_HITS = 32
MAX_DATA_HITS = 64
MAX_BYTE_SCAN_HITS = 256
PREVIEW_BYTES = 64
MASK64 = (1 << 64) - 1


class XrefUnavailable(Exception):
    """目标解析不了或架构不支持。"""


@dataclass
class Ref:
    target: int
    ref_type: str
    confidence: str          # certain / suspected
    va: int
    size: int = 0
    mnemonic: str = ""
    text: str = ""
    function: int | None = None
    section: str | None = None
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target, "ref_type": self.ref_type,
            "confidence": self.confidence, "va": self.va, "size": self.size,
            "mnemonic": self.mnemonic, "text": self.text,
            "function": self.function, "section": self.section,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# 目标解析
# ---------------------------------------------------------------------------

def _read_va(img: Any, va: int, size: int) -> bytes | None:
    for s in img.sections:
        base = img.image_base + s.virtual_address
        raw = bytes(s.raw) if s.raw else b""
        if base <= va < base + len(raw):
            off = va - base
            return raw[off:off + size]
    return None


def _preview(img: Any, va: int, size: int = PREVIEW_BYTES) -> str:
    raw = _read_va(img, va, size) or b""
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in raw)


def _find_literal(img: Any, needle: str, *, utf16: bool = False,
                  limit: int = MAX_LITERAL_HITS) -> list[dict[str, Any]]:
    """在**非可执行节**里按字节找字面量。这是数据搜索，不是 `.text` 搜索。"""
    encodings = [("ascii", needle.encode("utf-8", "surrogateescape"))]
    if utf16:
        encodings.append(("utf16le", needle.encode("utf-16le", "surrogatepass")))
    hits: list[dict[str, Any]] = []
    seen: set[int] = set()
    for s in img.sections:
        if s.is_executable or not s.raw:
            continue
        raw = bytes(s.raw)
        base = img.image_base + s.virtual_address
        for enc, pat in encodings:
            if not pat:
                continue
            off = raw.find(pat)
            while off >= 0 and len(hits) < limit:
                va = base + off
                if va not in seen:
                    seen.add(va)
                    hits.append({"va": va, "section": s.name, "encoding": enc,
                                 "preview": _preview(img, va)})
                off = raw.find(pat, off + 1)
        if len(hits) >= limit:
            break
    return hits


def _is_literal_in_exec(img: Any, needle: str) -> list[dict[str, Any]]:
    """字面量只出现在可执行节时的补充线索（标字节扫描，不当确定集）。"""
    pat = needle.encode("utf-8", "surrogateescape")
    if not pat:
        return []
    hits: list[dict[str, Any]] = []
    for s in img.sections:
        if not s.is_executable or not s.raw:
            continue
        raw = bytes(s.raw)
        base = img.image_base + s.virtual_address
        off = raw.find(pat)
        while off >= 0 and len(hits) < MAX_LITERAL_HITS:
            hits.append({"va": base + off, "section": s.name,
                         "encoding": "ascii", "preview": _preview(img, base + off)})
            off = raw.find(pat, off + 1)
    return hits


# ---------------------------------------------------------------------------
# 重定位
# ---------------------------------------------------------------------------

def _elf_reloc_addends(elf: Elf) -> list[tuple[int, int]]:
    """(槽位 VA, addend)；只认 `R_*_RELATIVE`（x86-64=8 / aarch64=1027）。"""
    out: list[tuple[int, int]] = []
    for name in (".rela.dyn", ".rela.plt"):
        sec = elf.section_by_name(name)
        if sec is None or not sec.raw:
            continue
        raw = bytes(sec.raw)
        entsize = sec.entsize or 24
        if elf.bits != 64:
            entsize = 12
        for off in range(0, len(raw) - entsize + 1, entsize):
            if elf.bits == 64:
                r_offset = struct.unpack_from("<Q", raw, off)[0]
                r_info, addend = struct.unpack_from("<Qq", raw, off + 8)
                rtype = r_info & 0xFFFFFFFF
            else:
                r_offset = struct.unpack_from("<I", raw, off)[0]
                r_info, addend = struct.unpack_from("<II", raw, off + 4)
                rtype = r_info & 0xFF
            if rtype in (8, 1027) and addend:
                out.append((r_offset, addend))
    return out


def _pe_reloc_values(pe: PE) -> list[tuple[int, int, int]]:
    """(槽位 VA, 宽度, 文件里的值)；只认 DIR64(10) / HIGHLOW(3)。"""
    out: list[tuple[int, int, int]] = []
    if len(pe.directories) <= 5:
        return out
    rva, size = pe.directories[5]
    if not rva or size < 8:
        return out
    foa = pe.rva_to_foa(rva)
    if foa is None:
        return out
    pos, end = foa, min(foa + size, len(pe.data))
    while pos + 8 <= end:
        page_rva, block_size = pe.r.u32(pos), pe.r.u32(pos + 4)
        if block_size < 8:
            break
        stop = min(pos + block_size, end)
        for ent_off in range(pos + 8, stop - 1, 2):
            ent = pe.r.u16(ent_off)
            rtype, off = ent >> 12, ent & 0x0FFF
            if rtype not in (10, 3):
                continue
            width = 8 if rtype == 10 else 4
            slot_rva = page_rva + off
            slot_foa = pe.rva_to_foa(slot_rva)
            if slot_foa is None or slot_foa + width > len(pe.data):
                continue
            value = pe.r.u64(slot_foa) if width == 8 else pe.r.u32(slot_foa)
            if value:
                out.append((pe.image_base + slot_rva, width, value))
        pos += block_size
    return out


# ---------------------------------------------------------------------------
# 指令流与引用
# ---------------------------------------------------------------------------

def _owner_lookup(funcs: dict[int, Any]):
    starts = sorted(funcs)
    ends = [funcs[s].end for s in starts]

    def owner(va: int) -> int | None:
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and va < ends[i]:
            return starts[i]
        return None

    return owner


def _imm_value(op: Any) -> tuple[int, int]:
    size = int(getattr(op, "size", 0) or 0)
    value = int(op.imm)
    if size:
        value &= (1 << (size * 8)) - 1
    return value, size


def _refs_in_insn(img: Any, insn: Any, owner, va: int, target: int,
                  *, target_is_address: bool) -> list[Ref]:
    """单条指令的引用判定（原 `_insn_refs` 的循环体）。"""
    from capstone import CS_OP_IMM, CS_OP_MEM
    from capstone.x86 import X86_REG_RIP

    out: list[Ref] = []

    def add(ref_type: str, confidence: str, detail: str) -> None:
        out.append(Ref(target=target, ref_type=ref_type,
                       confidence=confidence, va=va, size=insn.size,
                       mnemonic=insn.mnemonic,
                       text=f"{insn.mnemonic} {insn.op_str}".strip(),
                       function=owner(va), section=section_name_at(img, va),
                       detail=detail))

    mn = insn.mnemonic
    direct = None
    if mn == "call" or mn == "jmp" or mn.startswith("j"):
        # 只有**立即数**操作数才是直接相对分支。`jmp rdx` 的 op 是寄存器，
        # `op.imm` 会回落到寄存器枚举值（RDX=0x28），曾被误判成 `jmp 0x28`。
        op0 = insn.operands[0] if insn.operands else None
        if op0 is not None and op0.type == CS_OP_IMM:
            try:
                direct = int(op0.imm)
            except (AttributeError, ValueError):
                direct = None
    if direct is not None and direct == target:
        add("rel32", "certain", "直接相对分支 rel32")
        return out
    for op in insn.operands:
        if op.type == CS_OP_MEM:
            base_reg = getattr(op.mem, "base", 0)
            index_reg = getattr(op.mem, "index", 0)
            seg_reg = getattr(op.mem, "segment", 0)
            disp = int(getattr(op.mem, "disp", 0))
            if base_reg == X86_REG_RIP:
                computed = va + insn.size + disp
                if computed == target:
                    kind = ("rip-lea" if mn == "lea"
                            else "rip-mov" if mn.startswith("mov")
                            else "rip-other")
                    add(kind, "certain",
                        f"RIP 相对：0x{va:X}+{insn.size}+{disp:#x} = 0x{computed:X}")
            elif base_reg == 0 and index_reg == 0 and seg_reg == 0 \
                    and disp == target and target_is_address:
                add("abs-mem", "certain", f"绝对内存操作数 [0x{disp:X}]")
        elif op.type == CS_OP_IMM:
            value, size = _imm_value(op)
            if value != target:
                continue
            if not target_is_address:
                add(f"imm{size * 8}" if size else "imm",
                    "suspected",
                    f"立即数等于常量 0x{value:X}（是否为引用需人判）")
            else:
                add(f"imm{size * 8}" if size else "imm", "suspected",
                    f"立即数等于目标地址 0x{value:X}（可能是地址常量，也可能是整数）")
    return out


def _insn_refs(img: Any, insns: dict[int, Any], owner, target: int,
               *, target_is_address: bool) -> list[Ref]:
    """从 funcs 递归下降产出的指令流里找引用（单目标入口，保留给调用方/测试）。"""
    out: list[Ref] = []
    for va in sorted(insns):
        out.extend(_refs_in_insn(img, insns[va], owner, va, target,
                                 target_is_address=target_is_address))
    return out


def _candidate_targets(insn: Any, addr_targets: set[int],
                       const_targets: set[int],
                       small_targets: bool) -> set[int]:
    """字节级预筛：返回这条指令**可能**引用的目标集合。

    必须是对 `_refs_in_insn` 判定条件的超集——命中后仍走原 operand 逻辑，
    所以多报的候选只会被丢弃，不会改变结果。预筛只读 `insn.bytes`，
    不触发 capstone 的 operand 惰性物化（52 MB 样本上这是主要耗时）。
    """
    b = insn.bytes
    n = len(b)
    if not n:
        return set()
    va = insn.address
    hits: set[int] = set()

    # 4 字节窗口：RIP disp32、绝对 disp32、任意位置的 imm32
    for i in range(n - 3):
        raw = int.from_bytes(b[i:i + 4], "little")
        if raw in addr_targets or raw in const_targets:
            hits.add(raw)
        signed = raw - 0x100000000 if raw & 0x80000000 else raw
        if signed in addr_targets:
            hits.add(signed)
        rip = va + n + signed
        if rip in addr_targets:
            hits.add(rip)

    # 末字节：imm8 / rel8 短分支。注意 capstone 的 op.size 是**操作数宽度**，
    # 不是立即数编码宽度：`cmp ecx, -1` 编码 imm8，但 `_imm_value` 会按 32 位
    # 掩码成 0xFFFFFFFF，所以这里要把符号扩展后的 16/32/64 位值都列入候选。
    last = b[-1]
    s8 = last - 0x100 if last & 0x80 else last
    for v in (last, s8 & 0xFFFF, s8 & 0xFFFFFFFF, s8 & MASK64):
        if v in addr_targets or v in const_targets:
            hits.add(v)
    rel8 = va + n + s8
    if rel8 in addr_targets:
        hits.add(rel8)

    if n >= 2:
        v16 = int.from_bytes(b[-2:], "little")
        s16 = v16 - 0x10000 if v16 & 0x8000 else v16
        for v in (v16, s16 & 0xFFFFFFFF, s16 & MASK64):
            if v in addr_targets or v in const_targets:
                hits.add(v)
    if n >= 4:
        v32 = int.from_bytes(b[-4:], "little")
        s32 = v32 - 0x100000000 if v32 & 0x80000000 else v32
        for v in (v32, s32 & MASK64):
            if v in addr_targets or v in const_targets:
                hits.add(v)
        rel32 = va + n + s32
        if rel32 in addr_targets:
            hits.add(rel32)
    if n >= 8:
        v64 = int.from_bytes(b[-8:], "little")
        if v64 in addr_targets or v64 in const_targets:
            hits.add(v64)

    # `enter imm16, imm8` 这类多立即数指令的 imm16 不在末尾；只在存在
    # < 0x10000 的目标时才扫 1/2 字节全窗口（否则不可能命中）。
    if small_targets:
        for i in range(n - 1):
            v = int.from_bytes(b[i:i + 2], "little")
            if v in addr_targets or v in const_targets:
                hits.add(v)
        if any(t < 0x100 for t in addr_targets | const_targets):
            for byte in b:
                if byte in addr_targets or byte in const_targets:
                    hits.add(byte)
    return hits


def _insn_refs_batch(img: Any, insns: dict[int, Any], owner,
                     targets: dict[int, tuple[bool, ...]]
                     ) -> dict[tuple[int, bool], list[Ref]]:
    """一次遍历指令流，为所有目标收集引用。

    结果与逐目标调用 `_insn_refs` 完全一致；区别只是每条指令的 operand
    只物化一次，且用字节预筛跳过绝大多数无关指令。键是 `(目标, 是否地址)`，
    避免同一数值同时作为常量/地址目标时互相污染。
    """
    out: dict[tuple[int, bool], list[Ref]] = {
        (t, m): [] for t, modes in targets.items() for m in modes}
    addr_targets = {t for t, modes in targets.items() if True in modes}
    const_targets = {t for t, modes in targets.items() if False in modes}
    if not out:
        return out
    small = any(0 <= t < 0x10000 for t in targets)
    for va in sorted(insns):
        insn = insns[va]
        cand = _candidate_targets(insn, addr_targets, const_targets, small)
        if not cand:
            continue
        for target in cand:
            for is_addr in targets[target]:
                out[(target, is_addr)].extend(
                    _refs_in_insn(img, insn, owner, va, target,
                                  target_is_address=is_addr))
    return out


def _data_refs(img: Any, target: int, *, target_is_address: bool
               ) -> list[Ref]:
    """数据节里 8/4 字节字等于目标。**一律疑似**：值相等不等于语义引用。"""
    out: list[Ref] = []
    ptr = PTR_SIZE[image_bits(img)]
    widths = [ptr] if ptr == 4 else [8, 4]
    for s in img.sections:
        if s.is_executable or not s.raw:
            continue
        raw = bytes(s.raw)
        base = img.image_base + s.virtual_address
        for width in widths:
            for off in range(0, len(raw) - width + 1, width):
                value = int.from_bytes(raw[off:off + width], "little")
                how = ""
                if value == target:
                    how = f"{width} 字节字 = 目标"
                elif (width == 4 and target_is_address
                      and img.image_base and value == target - img.image_base):
                    how = f"4 字节 RVA = 目标 - ImageBase"
                if not how:
                    continue
                out.append(Ref(target=target, ref_type=f"data-pointer-{width}",
                               confidence="suspected", va=base + off, size=width,
                               section=s.name,
                               detail=f"{how}（数据值相等，不保证是引用）"))
                if len(out) >= MAX_DATA_HITS:
                    return out
    return out


def _data_refs_batch(img: Any, addr_targets: set[int]
                     ) -> dict[int, list[Ref]]:
    """一次扫完数据节，为所有目标收集 8/4 字节字命中（一律疑似）。

    与逐目标 `_data_refs` 的结果一致：每个目标按扫描顺序取前 `MAX_DATA_HITS` 条。
    """
    out: dict[int, list[Ref]] = {t: [] for t in addr_targets}
    if not out:
        return out
    ptr = PTR_SIZE[image_bits(img)]
    widths = [ptr] if ptr == 4 else [8, 4]
    rva_map: dict[int, int] = {}
    if img.image_base:
        for t in addr_targets:
            rva = t - img.image_base
            if 0 <= rva < (1 << 32):
                rva_map[rva] = t
    full: set[int] = set()

    def add(target: int, width: int, section, va: int, how: str) -> None:
        if len(out[target]) >= MAX_DATA_HITS:
            full.add(target)
            return
        out[target].append(Ref(
            target=target, ref_type=f"data-pointer-{width}",
            confidence="suspected", va=va, size=width, section=section,
            detail=f"{how}（数据值相等，不保证是引用）"))

    for s in img.sections:
        if s.is_executable or not s.raw:
            continue
        raw = bytes(s.raw)
        base = img.image_base + s.virtual_address
        for width in widths:
            for off in range(0, len(raw) - width + 1, width):
                if len(full) >= len(out):
                    return out
                value = int.from_bytes(raw[off:off + width], "little")
                if value in out:
                    add(value, width, s.name, base + off, f"{width} 字节字 = 目标")
                if width == 4:
                    t = rva_map.get(value)
                    if t is not None:
                        add(t, width, s.name, base + off, "4 字节 RVA = 目标 - ImageBase")
    return out


def _reloc_refs_batch(img: Any, addr_targets: set[int]
                      ) -> dict[int, list[Ref]]:
    """重定位表只解析一次，再按值分发。"""
    out: dict[int, list[Ref]] = {t: [] for t in addr_targets}
    if not out:
        return out
    if isinstance(img, Elf):
        for slot, addend in _elf_reloc_addends(img):
            if addend in out:
                out[addend].append(Ref(
                    target=addend, ref_type="reloc-addend", confidence="certain",
                    va=slot, size=8, section=section_name_at(img, slot),
                    detail=f"ELF RELATIVE addend = 0x{addend:X}"))
    elif isinstance(img, PE):
        for slot, width, value in _pe_reloc_values(img):
            if value in out:
                out[value].append(Ref(
                    target=value, ref_type="reloc-addend", confidence="certain",
                    va=slot, size=width, section=section_name_at(img, slot),
                    detail=f"PE base reloc {width * 8} 位值 = 0x{value:X}"))
    return out


def _reloc_refs(img: Any, target: int) -> list[Ref]:
    out: list[Ref] = []
    if isinstance(img, Elf):
        for slot, addend in _elf_reloc_addends(img):
            if addend == target:
                out.append(Ref(target=target, ref_type="reloc-addend",
                               confidence="certain", va=slot, size=8,
                               section=section_name_at(img, slot),
                               detail=f"ELF RELATIVE addend = 0x{addend:X}"))
    elif isinstance(img, PE):
        for slot, width, value in _pe_reloc_values(img):
            if value == target:
                out.append(Ref(target=target, ref_type="reloc-addend",
                               confidence="certain", va=slot, size=width,
                               section=section_name_at(img, slot),
                               detail=f"PE base reloc {width * 8} 位值 = 0x{value:X}"))
    return out


def _byte_scan_refs(img: Any, target: int, insns: dict[int, Any],
                    owner) -> list[Ref]:
    """`.text` 字节扫描（显式开启）。命中必须当作疑似，且标注可能落在操作数内部。"""
    out: list[Ref] = []
    intervals = sorted((va, va + insn.size) for va, insn in insns.items())
    starts = [a for a, _ in intervals]

    def inside_insn(va: int) -> bool:
        i = bisect.bisect_right(starts, va) - 1
        return i >= 0 and va < intervals[i][1]

    patterns: list[tuple[str, bytes]] = []
    widths = [PTR_SIZE[image_bits(img)]] if image_bits(img) == 64 else [4]
    for width in widths:
        if target < (1 << (width * 8)):
            patterns.append((f"{width}B 绝对目标", target.to_bytes(width, "little")))
    if isinstance(img, PE) and img.image_base and target >= img.image_base:
        rva = target - img.image_base
        if rva < (1 << 32):
            patterns.append(("4B RVA", rva.to_bytes(4, "little")))
    for s in img.sections:
        if not s.is_executable or not s.raw:
            continue
        raw = bytes(s.raw)
        base = img.image_base + s.virtual_address
        for label, pat in patterns:
            off = raw.find(pat)
            while off >= 0:
                va = base + off
                detail = (f"字节扫描（{label}）：可能命中操作数内部；"
                          + ("落在已解码指令内部" if inside_insn(va)
                             else "不在已解码指令边界内"))
                out.append(Ref(target=target, ref_type="byte-scan",
                               confidence="suspected", va=va, size=len(pat),
                               function=owner(va),
                               section=section_name_at(img, va), detail=detail))
                if len(out) >= MAX_BYTE_SCAN_HITS:
                    return out
                off = raw.find(pat, off + 1)
    return out


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def analyze_xref(path: str, specs: Iterable[dict[str, Any]], *,
                 byte_scan: bool = False, pointers: bool = True,
                 utf16: bool = False, allow_large: bool = False) -> dict[str, Any]:
    """分析一个 PE/ELF 的交叉引用。`specs` 形如
    `{"kind": "string"|"va"|"rva"|"function"|"const", "value": ...}`。
    """
    t0 = time.perf_counter()
    specs = list(specs)
    if not specs:
        raise XrefUnavailable("没有目标：用 --string / --va / --rva / --const 指定")
    img = open_image(path, allow_large=allow_large)
    if not is_x86(img):
        raise XrefUnavailable(f"非 x86 架构（{getattr(img, 'machine_name', img.arch)}）："
                              f"xref 的指令流依赖 x86 递归下降，尚未实现")
    insns: dict[int, Any] = {}
    funcs, notes, _refs, _ev, _idx = discover(
        img, pointers=pointers, detail=True, insn_out=insns)
    owner = _owner_lookup(funcs)
    covered = len(insns)

    # 第一阶段：先解析全部目标，再对指令流只做一次遍历（多目标共享预筛）。
    plan: list[dict[str, Any]] = []
    targets: dict[int, set[bool]] = {}
    for spec in specs:
        kind, raw_value = spec["kind"], spec["value"]
        tnotes: list[str] = []
        resolved: list[dict[str, Any]] = []

        if kind == "string":
            hits = _find_literal(img, raw_value, utf16=utf16)
            resolved = [{"va": h["va"], "section": h["section"],
                         "encoding": h["encoding"], "preview": h["preview"]}
                        for h in hits]
            if not resolved:
                exec_hits = _is_literal_in_exec(img, raw_value)
                resolved = [{"va": h["va"], "section": h["section"],
                             "encoding": h["encoding"], "preview": h["preview"]}
                            for h in exec_hits]
                if resolved:
                    tnotes.append("字面量只出现在可执行节：按字节扫描定位，命中可能落在"
                                  "操作数内部，仅作目标线索")
                else:
                    tnotes.append("非可执行节与可执行节都没有这个字面量")
        elif kind in ("va", "function"):
            va = int(raw_value)
            resolved = [{"va": va, "section": section_name_at(img, va),
                         "preview": _preview(img, va)}]
            if va in funcs:
                resolved[0]["function_start"] = va
            else:
                tnotes.append("该 VA 不是 funcs 认定的函数起点（仍按地址目标查引用）")
        elif kind == "rva":
            va = img.image_base + int(raw_value)
            resolved = [{"va": va, "section": section_name_at(img, va),
                         "preview": _preview(img, va)}]
            if va not in funcs:
                tnotes.append("该 RVA 对应的 VA 不是 funcs 认定的函数起点")
        elif kind == "const":
            resolved = [{"va": None, "value": int(raw_value), "preview": ""}]
        else:
            raise XrefUnavailable(f"未知目标类型：{kind}")

        plan.append({"kind": kind, "raw": raw_value, "resolved": resolved,
                     "notes": tnotes})
        if kind == "const":
            targets.setdefault(int(raw_value), set()).add(False)
        else:
            for res in resolved:
                targets.setdefault(res["va"], set()).add(True)

    modes = {t: tuple(sorted(m, reverse=True)) for t, m in targets.items()}
    insn_hits = _insn_refs_batch(img, insns, owner, modes)
    addr_targets = {t for t, m in modes.items() if True in m}
    data_hits = _data_refs_batch(img, addr_targets)
    reloc_hits = _reloc_refs_batch(img, addr_targets)

    # 第二阶段：按目标组装结果（顺序、去重、排序与原实现一致）。
    targets_out: list[dict[str, Any]] = []
    for item in plan:
        kind, raw_value = item["kind"], item["raw"]
        resolved, tnotes = item["resolved"], item["notes"]
        target_blocks: list[dict[str, Any]] = []
        if kind == "const":
            value = int(raw_value)
            all_refs = list(insn_hits.get((value, False), []))
            if byte_scan:
                all_refs += _byte_scan_refs(img, value, insns, owner)
            target_blocks.append({"va": value, "section": None,
                                  "refs": all_refs, "notes": tnotes})
        else:
            for res in resolved:
                va = res["va"]
                refs = list(insn_hits.get((va, True), []))
                refs += reloc_hits.get(va, [])
                refs += data_hits.get(va, [])
                if byte_scan:
                    refs += _byte_scan_refs(img, va, insns, owner)
                # 去重：同一槽位可能同时命中指令/数据/重定位
                dedup: dict[tuple[str, int], Ref] = {}
                for r in refs:
                    dedup.setdefault((r.ref_type, r.va), r)
                target_blocks.append({"va": va, "section": res["section"],
                                      "refs": list(dedup.values()),
                                      "notes": list(tnotes)})

        blocks = []
        for blk in target_blocks:
            refs = sorted(blk["refs"], key=lambda r: (r.va, r.ref_type))
            certain = [r for r in refs if r.confidence == "certain"]
            suspected = [r for r in refs if r.confidence == "suspected"]
            by_func: dict[int, dict[str, Any]] = {}
            for r in certain + suspected:
                if r.function is None:
                    continue
                item = by_func.setdefault(r.function, {
                    "start": r.function,
                    "end": funcs[r.function].end if r.function in funcs else None,
                    "certain": 0, "suspected": 0,
                    "mnemonics": [],
                })
                item[r.confidence] += 1
                if r.mnemonic and r.mnemonic not in item["mnemonics"]:
                    item["mnemonics"].append(r.mnemonic)
            blocks.append({
                "va": blk["va"], "section": blk["section"],
                "refs": [r.as_dict() for r in refs],
                "counts": {"certain": len(certain),
                           "suspected": len(suspected),
                           "functions": len(by_func)},
                "referencing_functions": sorted(
                    by_func.values(), key=lambda x: x["start"]),
                "notes": blk["notes"],
            })

        targets_out.append({
            "input": {"kind": kind, "value": raw_value},
            "resolved": resolved,
            "blocks": blocks,
            "counts": {
                "resolved": len(resolved),
                "certain": sum(b["counts"]["certain"] for b in blocks),
                "suspected": sum(b["counts"]["suspected"] for b in blocks),
            },
        })

    stream_note = ("指令流来自 funcs 递归下降；只覆盖已发现函数体，"
                   "未发现函数里的引用不会出现在结果里（召回上限 = 函数发现率）")
    return {
        "file": path,
        "format": "ELF" if isinstance(img, Elf) else "PE",
        "arch": img.arch,
        "machine": getattr(img, "machine_name", None) or img.arch,
        "bits": image_bits(img),
        "image_base": f"0x{img.image_base:X}",
        "instruction_stream": {
            "source": "funcs 递归下降",
            "functions": len(funcs),
            "instructions": covered,
            "notes": notes + [stream_note],
        },
        "targets": targets_out,
        "seconds": round(time.perf_counter() - t0, 3),
    }
