# -*- coding: utf-8 -*-
"""函数边界发现：权威表 + 递归下降 + 指针表 + 穷举，每条入口带证据来源。

能力自 `工具库/asm/disasm_kit.py` 回流，rekit 现在是唯一实现：

- **权威表**：PE64 的 `.pdata`、ELF64 的 `.eh_frame`（DWARF FDE）、Go 的 `.gopclntab`。
  这是 A 层；没有权威表的样本才落 B 层（可达 / 含孤立两个口径）。
- **递归下降**：从权威表 + 入口 + 导出播种，跟 call/jcc，`jmp` 按尾调用处理。
- **指针表**：扫数据节里按位宽对齐的函数指针，过形状 + 栈平衡验证后收录。
- **穷举**：按工具链形状库扫可执行节，CFG 可达的进 `exhaust-reachable`，
  不可达的单独进 `exhaust-isolated`，不混算。

输出契约见 `docs/funcs.md`；CLI 入口是 `rekit funcs`。
"""

from __future__ import annotations

import bisect
import csv
import struct
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from .elf import (
    ELF_MAGIC, ET_DYN, SHF_EXECINSTR, SHT_NOBITS, Elf, ElfError, open_image,
)
from .pe import PE, PEError

# 递归下降 / 指针表 / 穷举形状库目前只有 x86 两代（capstone x86 + 字节形状）。
_X86_MACHINES = {0x03, 0x3E}          # ELF: i386 / x86_64
_PE_X86_MACHINES = {0x14C, 0x8664}    # PE:  I386 / AMD64


def is_x86(img: Any) -> bool:
    if isinstance(img, Elf):
        return img.machine in _X86_MACHINES
    return img.machine in _PE_X86_MACHINES

# ---------------------------------------------------------------------------
# 证据来源与口径
# ---------------------------------------------------------------------------

EVIDENCE_GROUPS = {
    "pdata": "权威表",
    "eh_frame": "权威表",
    "gopclntab": "权威表",
    "entry": "直接引用",
    "export": "直接引用",
    "call": "直接引用",
    "jmp": "直接引用",
    "icall": "间接调用",
    "itab": "间接调用",
    "ptr": "指针表",
    "rel": "重定位表",
    "addr": "代码取址",
    "init": "数据表",
    "plt": "PLT/GOT",
    "str": "字符串引用",
    "exhaust-reachable": "穷举+可达",
    "exhaust-isolated": "穷举+孤立",
}
# 一条入口可能有多个证据；分组取"最强"的那个（权威表 > 直接引用 > 指针表 > 穷举）。
EVIDENCE_ORDER = ("gopclntab", "eh_frame", "pdata", "entry", "export", "call", "jmp",
                  "icall", "itab", "ptr", "rel", "addr", "init", "plt", "str",
                  "exhaust-reachable", "exhaust-isolated")

LAYER_A = "A"
LAYER_B_REACHABLE = "B-reachable"
LAYER_B_ISOLATED = "B-isolated"

NONVOLATILE = {"rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"}
NONVOLATILE32 = {"ebx", "ebp", "esi", "edi"}
STOP_MNEMONICS = {"ret", "retf", "int3", "ud2", "hlt", "iret", "iretq"}
PTR_SIZE = {32: 4, 64: 8}

PE_DATA_SECTIONS = (".rdata", ".data")
ELF_DATA_SECTIONS = (".rodata", ".data", ".data.rel.ro", ".init_array", ".fini_array")

TOOLCHAIN_PROFILES = ("auto", "legacy", "msvc_x86", "msvc_x64", "gcc_x64", "go_x64",
                      "generic")
PROFILE_MIN_ALIGN = {"go_x64": 16}
PROFILE_SHAPES = {
    "legacy": {"framepush", "calleepush", "stackalloc", "homeslot", "seh"},
    "msvc_x86": {"framepush", "calleepush", "stackalloc", "seh"},
    "msvc_x64": {"framepush", "calleepush", "stackalloc", "homeslot", "endbr"},
    "gcc_x64": {"endbr", "framepush", "calleepush", "stackalloc"},
    # Go 1.20+ 的函数头是 `CMPQ SP,0x10(R14); JBE; PUSHQ BP; MOVQ SP,BP`：
    # `push rbp` 在函数内部也会出现，不能当起点，否则每个带帧指针的函数都会切出中段。
    "go_x64": {"gosplit", "calleepush"},
    "generic": {"framepush", "calleepush", "stackalloc", "homeslot", "seh",
                "endbr", "gosplit"},
}
PROFILE_FIRST = {
    "msvc_x86": {0x8B, 0x55, 0x53, 0x56, 0x57, 0x83, 0x81, 0x68, 0xF3},
    "msvc_x64": {0x55, 0x53, 0x56, 0x57, 0x41, 0x48, 0x4C, 0x89, 0xF3},
    "gcc_x64": {0x55, 0x53, 0x56, 0x57, 0x41, 0x48, 0x49, 0x4C, 0x89, 0xF3},
    "go_x64": {0x49, 0x4C, 0x4D, 0x55, 0x48, 0x53, 0x41, 0x89},
}
EXHAUST_ALIGN = {"fast": 4, "normal": 2, "full": 1}


class FuncsUnavailable(Exception):
    """缺少反汇编后端（capstone），调用方应给出安装提示。"""


_MD_CACHE: dict[int, Any] = {}


def _md(bits: int):
    """按位宽取 capstone 实例；延迟导入，避免 `rekit triage` 被可选依赖拖住。"""
    if bits in _MD_CACHE:
        return _MD_CACHE[bits]
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    except ImportError as e:  # pragma: no cover - 环境问题
        raise FuncsUnavailable(
            "funcs 需要反汇编后端：python -m pip install capstone") from e
    md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    md.detail = False
    _MD_CACHE[bits] = md
    return md


_MDD_CACHE: dict[int, Any] = {}


def _md_detail(bits: int):
    """带操作数/regs_access 的实例，只在冷启动的间接调用解析里用。"""
    if bits in _MDD_CACHE:
        return _MDD_CACHE[bits]
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    except ImportError as e:  # pragma: no cover - 环境问题
        raise FuncsUnavailable(
            "funcs 需要反汇编后端：python -m pip install capstone") from e
    md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    md.detail = True
    _MDD_CACHE[bits] = md
    return md


@dataclass
class Function:
    entry: int
    end: int
    source: str = ""
    insn_count: int = 0
    callees: set[int] = field(default_factory=set)


@dataclass
class AuthorityTable:
    """A 层的权威函数区间；`usable` 为假时只能走 B 层。"""
    name: str
    spans: list[tuple[int, int]] = field(default_factory=list)
    starts: list[int] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)
    reason: str = ""

    @property
    def usable(self) -> bool:
        return bool(self.starts)


class CodeSpace:
    """可执行节拼成的地址空间；跨节时按 VA 找到所属节再解码。

    `detail=True` 用带 detail 的 capstone（冷启动解析间接调用需要操作数信息），
    常规口径仍用无 detail 的实例，避免给所有分析加解码开销。
    """

    def __init__(self, segments: list[tuple[int, bytes]], bits: int = 64,
                 detail: bool = False):
        self.segments = sorted(segments, key=lambda s: s[0])
        self.bits = bits
        self.md = _md_detail(bits) if detail else _md(bits)

    def segment_of(self, va: int) -> tuple[int, bytes] | None:
        for start, data in self.segments:
            if start <= va < start + len(data):
                return start, data
        return None

    def has(self, va: int) -> bool:
        return self.segment_of(va) is not None

    def decode(self, va: int):
        seg = self.segment_of(va)
        if seg is None:
            return None
        start, data = seg
        off = va - start
        got = list(self.md.disasm(bytes(data[off:off + 16]), va, count=1))
        return got[0] if got else None


def image_bits(img: Any) -> int:
    if isinstance(img, Elf):
        return img.bits
    return 64 if getattr(img, "is_64", True) else 32


def exec_span(img: Any, va: int) -> tuple[int, int] | None:
    for s in img.sections:
        if not s.is_executable:
            continue
        base = img.image_base + s.virtual_address
        if base <= va < base + max(len(s.raw), s.virtual_size):
            return (base, base + max(len(s.raw), s.virtual_size))
    return None


def section_name_at(img: Any, va: int) -> str | None:
    for s in img.sections:
        base = img.image_base + s.virtual_address
        if base <= va < base + max(len(s.raw), s.virtual_size):
            return s.name
    return None


# ---------------------------------------------------------------------------
# 权威表 1：PE `.pdata`
# ---------------------------------------------------------------------------

def pdata_spans(pe: PE) -> list[tuple[int, int]]:
    """x64 异常目录：每项 12 字节 Begin RVA / End RVA / UnwindInfo RVA。"""
    if image_bits(pe) != 64:
        return []
    rva, size = pe.directories[3]
    if not rva or size < 12:
        return []
    foa = pe.rva_to_foa(rva)
    if foa is None:
        return []
    out: list[tuple[int, int]] = []
    for off in range(foa, min(foa + size, len(pe.data)) - 11, 12):
        begin, end = pe.r.u32(off), pe.r.u32(off + 4)
        if begin and end > begin:
            out.append((pe.image_base + begin, pe.image_base + end))
    return out


# ---------------------------------------------------------------------------
# 权威表 2：ELF `.eh_frame`（DWARF CFI）
# ---------------------------------------------------------------------------

DW_EH_PE_OMIT = 0xFF
_EH_FMT_SIZES = {0x02: 2, 0x03: 4, 0x04: 8, 0x0A: 2, 0x0B: 4, 0x0C: 8}


def _rd_uleb(data: bytes, off: int) -> tuple[int, int]:
    result, shift = 0, 0
    while off < len(data):
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7
        if shift > 63:
            break
    raise ValueError("uleb128 越界")


def _rd_sleb(data: bytes, off: int) -> tuple[int, int]:
    result, shift, b = 0, 0, 0
    while off < len(data):
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            if b & 0x40:
                result -= 1 << shift
            return result, off
        if shift > 63:
            break
    raise ValueError("sleb128 越界")


def _read_encoded_ptr(data: bytes, off: int, enc: int, *, field_va: int,
                      ptr_size: int, datarel: int = 0, textrel: int = 0,
                      funcrel: int = 0, reader: Any = None,
                      mem: bytes | None = None) -> tuple[int | None, int]:
    """按 DW_EH_PE_* 解一个指针，返回 `(值, 新偏移)`；`0xFF` 表示 omit。"""
    if enc == DW_EH_PE_OMIT:
        return None, off
    fmt = enc & 0x0F
    if fmt == 0x00:
        if off + ptr_size > len(data):
            raise ValueError("absptr 越界")
        val = int.from_bytes(data[off:off + ptr_size], "little")
        off += ptr_size
    elif fmt == 0x01:
        val, off = _rd_uleb(data, off)
    elif fmt == 0x09:
        val, off = _rd_sleb(data, off)
    elif fmt in _EH_FMT_SIZES:
        size = _EH_FMT_SIZES[fmt]
        if off + size > len(data):
            raise ValueError("定长指针越界")
        val = int.from_bytes(data[off:off + size], "little", signed=fmt >= 0x09)
        off += size
    else:
        raise ValueError(f"未支持的 DW_EH_PE 格式 0x{fmt:X}")
    app = enc & 0x70
    if app == 0x10:
        val += field_va
    elif app == 0x20:
        val += textrel
    elif app == 0x30:
        val += datarel
    elif app == 0x40:
        val += funcrel
    elif app == 0x50:
        val = (val + ptr_size - 1) & ~(ptr_size - 1)
    elif app != 0x00:
        raise ValueError(f"未支持的 DW_EH_PE 应用位 0x{app:X}")
    if enc & 0x80:
        if reader is None:
            raise ValueError("indirect 编码缺少取址器")
        pos = reader(val)
        src = mem if mem is not None else data
        if pos is None or pos + ptr_size > len(src):
            raise ValueError(f"indirect 目标 0x{val:X} 不可读")
        val = int.from_bytes(src[pos:pos + ptr_size], "little")
    return val, off


@dataclass
class Cie:
    offset: int
    version: int
    aug: str
    has_z: bool
    code_align: int
    data_align: int
    ret_reg: int
    fde_enc: int


@dataclass
class Fde:
    start: int
    end: int
    cie_off: int
    rec_off: int
    enc: int


@dataclass
class EhFrameTable:
    section_va: int
    fdes: list[Fde]
    spans: list[tuple[int, int]]
    starts: list[int]
    cies: int
    hdr_present: bool
    hdr_count: int | None
    hdr_version: int | None
    hdr_encodings: tuple[int, int, int, int] | None
    hdr_matched: int
    hdr_only: int
    fde_only: int
    hdr_truncated: int
    zero_range: int
    duplicate_starts: int
    empty_records: int
    errors: list[str]

    @property
    def source(self) -> str:
        return ".eh_frame_hdr + 线性" if self.hdr_present else "线性兜底"


def _parse_cie(raw: bytes, rec_off: int, body: int, rec_end: int, sec_va: int,
               ptr_size: int, reader: Any, mem: bytes | None) -> Cie:
    o = body + 4
    if o >= rec_end:
        raise ValueError("CIE 截断")
    version = raw[o]
    o += 1
    cut = raw.find(b"\0", o, rec_end)
    if cut < 0:
        raise ValueError("CIE 增补串未终止")
    aug = raw[o:cut].decode("latin-1")
    o = cut + 1
    code_align, o = _rd_uleb(raw, o)
    data_align, o = _rd_sleb(raw, o)
    if version == 1:
        ret_reg = raw[o]
        o += 1
    else:
        ret_reg, o = _rd_uleb(raw, o)
    has_z = aug.startswith("z")
    fde_enc = 0x00
    if has_z:
        aug_len, o = _rd_uleb(raw, o)
        aug_end = min(o + aug_len, rec_end)
        for ch in aug[1:]:
            if o >= aug_end:
                break
            if ch == "L":
                o += 1
            elif ch == "R":
                fde_enc = raw[o]
                o += 1
            elif ch == "P":
                enc = raw[o]
                o += 1
                _, o = _read_encoded_ptr(raw, o, enc, field_va=sec_va + o,
                                         ptr_size=ptr_size, reader=reader, mem=mem)
            elif ch in ("S", "B"):
                pass
            else:
                break
    return Cie(rec_off, version, aug, has_z, code_align, data_align, ret_reg, fde_enc)


def _parse_fde(raw: bytes, rec_off: int, body: int, rec_end: int, cie: Cie,
               sec_va: int, ptr_size: int, text_va: int, reader: Any,
               mem: bytes | None) -> Fde | None:
    if cie.fde_enc == DW_EH_PE_OMIT:
        return None
    o = body + 4
    start, o = _read_encoded_ptr(raw, o, cie.fde_enc, field_va=sec_va + o,
                                 ptr_size=ptr_size, datarel=sec_va,
                                 textrel=text_va, reader=reader, mem=mem)
    if start is None:
        return None
    rng, o = _read_encoded_ptr(raw, o, cie.fde_enc & 0x0F, field_va=0,
                               ptr_size=ptr_size)
    if rng is None or rng < 0:
        raise ValueError("FDE 区间长度为负")
    if cie.has_z:
        _aug_len, o = _rd_uleb(raw, o)
    if o > rec_end:
        raise ValueError("FDE 越界")
    return Fde(start, start + rng, cie.offset, rec_off, cie.fde_enc)


def parse_eh_frame(raw: bytes, sec_va: int, ptr_size: int = 8,
                   reader: Any = None, mem: bytes | None = None,
                   text_va: int = 0
                   ) -> tuple[list[Fde], dict[int, Cie], list[str], int]:
    """线性扫描 `.eh_frame`：长度前缀 → CIE（id=0）/ FDE（id=回指距离）。"""
    fdes: list[Fde] = []
    cies: dict[int, Cie] = {}
    errors: list[str] = []
    empty = 0
    off = 0
    while off + 4 <= len(raw):
        length = struct.unpack_from("<I", raw, off)[0]
        if length == 0:
            off += 4
            empty += 1
            continue
        body = off + 4
        if length == 0xFFFFFFFF:
            errors.append(f"0x{off:X}: 64 位 DWARF 记录未支持")
            break
        rec_end = body + length
        if rec_end > len(raw):
            errors.append(f"0x{off:X}: 记录长度越界")
            break
        idv = struct.unpack_from("<I", raw, body)[0]
        if idv == 0:
            try:
                cies[off] = _parse_cie(raw, off, body, rec_end, sec_va,
                                       ptr_size, reader, mem)
            except (ValueError, IndexError) as e:
                errors.append(f"0x{off:X}: CIE 解析失败 {e}")
        else:
            cie_off = body - idv
            cie = cies.get(cie_off)
            if cie is None:
                errors.append(f"0x{off:X}: FDE 找不到 CIE")
            else:
                try:
                    fde = _parse_fde(raw, off, body, rec_end, cie, sec_va,
                                     ptr_size, text_va, reader, mem)
                    if fde is not None:
                        fdes.append(fde)
                except (ValueError, IndexError) as e:
                    errors.append(f"0x{off:X}: FDE 解析失败 {e}")
        off = rec_end
    return fdes, cies, errors, empty


def parse_eh_frame_hdr(raw: bytes, hdr_va: int, ptr_size: int = 8,
                       reader: Any = None, mem: bytes | None = None
                       ) -> dict[str, Any] | None:
    """`.eh_frame_hdr`：version + 3 个编码字节 + eh_frame_ptr + FDE 数 + 二分表。"""
    if len(raw) < 4:
        return None
    version, eh_enc, cnt_enc, tbl_enc = raw[0], raw[1], raw[2], raw[3]
    out: dict[str, Any] = {"version": version,
                           "encodings": (version, eh_enc, cnt_enc, tbl_enc),
                           "count": None, "entries": [], "truncated": 0,
                           "error": ""}
    o = 4
    try:
        eh_ptr, o = _read_encoded_ptr(raw, o, eh_enc, field_va=hdr_va + o,
                                      ptr_size=ptr_size, datarel=hdr_va,
                                      reader=reader, mem=mem)
        count, o = _read_encoded_ptr(raw, o, cnt_enc, field_va=hdr_va + o,
                                     ptr_size=ptr_size, datarel=hdr_va,
                                     reader=reader, mem=mem)
    except (ValueError, IndexError) as e:
        out["error"] = f"头部解析失败：{e}"
        return out
    out["eh_frame_ptr"] = eh_ptr
    if count is None or count < 0:
        out["error"] = "FDE 计数非法"
        return out
    stride = (ptr_size if (tbl_enc & 0x0F) == 0x00
              else _EH_FMT_SIZES.get(tbl_enc & 0x0F, 0))
    if not stride:
        out["error"] = f"二分表编码 0x{tbl_enc:X} 未支持"
        return out
    out["count"] = count
    room = max(0, (len(raw) - o) // (stride * 2))
    for _ in range(min(count, room)):
        try:
            start, o = _read_encoded_ptr(raw, o, tbl_enc, field_va=hdr_va + o,
                                         ptr_size=ptr_size, datarel=hdr_va,
                                         reader=reader, mem=mem)
            fde_va, o = _read_encoded_ptr(raw, o, tbl_enc, field_va=hdr_va + o,
                                          ptr_size=ptr_size, datarel=hdr_va,
                                          reader=reader, mem=mem)
        except (ValueError, IndexError) as e:
            out["error"] = f"二分表第 {len(out['entries'])} 项解析失败：{e}"
            break
        if start is not None:
            out["entries"].append((start, fde_va))
    out["truncated"] = max(0, count - len(out["entries"]))
    return out


def eh_frame_table(elf: Elf, use_hdr: bool = True) -> EhFrameTable | None:
    sec = elf.section_by_name(".eh_frame")
    if sec is None or not sec.raw:
        return None
    ptr_size = elf.bits // 8
    sec_va = elf.image_base + sec.virtual_address
    text = elf.section_by_name(".text")
    text_va = elf.image_base + text.virtual_address if text else 0
    fdes, cies, errors, empty = parse_eh_frame(
        bytes(sec.raw), sec_va, ptr_size, elf.rva_to_foa, elf.data, text_va)

    hdr_present, hdr_count, hdr_version, hdr_enc = False, None, None, None
    hdr_starts: list[int] = []
    hdr_truncated = 0
    if use_hdr:
        hsec = elf.section_by_name(".eh_frame_hdr")
        if hsec is not None and hsec.raw:
            hdr = parse_eh_frame_hdr(bytes(hsec.raw),
                                     elf.image_base + hsec.virtual_address,
                                     ptr_size, elf.rva_to_foa, elf.data)
            if hdr:
                hdr_present = True
                hdr_count = hdr["count"]
                hdr_version = hdr["version"]
                hdr_enc = hdr["encodings"]
                hdr_truncated = hdr["truncated"]
                if hdr["error"]:
                    errors.append(f".eh_frame_hdr: {hdr['error']}")
                hdr_starts = sorted({s for s, _f in hdr["entries"] if s})

    by_start: dict[int, int] = {}
    zero_range = dup = 0
    for f in fdes:
        if f.start <= 0:
            continue
        if f.end <= f.start:
            zero_range += 1
        prev = by_start.get(f.start)
        if prev is None:
            by_start[f.start] = f.end
        else:
            dup += 1
            by_start[f.start] = max(prev, f.end)
    starts = sorted(by_start)
    spans = [(s, by_start[s]) for s in starts]

    fde_set, hdr_set = set(starts), set(hdr_starts)
    return EhFrameTable(
        section_va=sec_va, fdes=fdes, spans=spans, starts=starts, cies=len(cies),
        hdr_present=hdr_present, hdr_count=hdr_count, hdr_version=hdr_version,
        hdr_encodings=hdr_enc, hdr_matched=len(fde_set & hdr_set),
        hdr_only=len(hdr_set - fde_set), fde_only=len(fde_set - hdr_set),
        hdr_truncated=hdr_truncated, zero_range=zero_range,
        duplicate_starts=dup, empty_records=empty, errors=errors[:12])


# ---------------------------------------------------------------------------
# 权威表 3：Go `.gopclntab`
# ---------------------------------------------------------------------------

GO_MAGIC_118 = 0xFFFFFFF0
GO_MAGIC_120 = 0xFFFFFFF1
GO_MAGIC_116 = 0xFFFFFFFA
GO_MAGIC_OLD = 0xFFFFFFFB          # Go 1.2–1.15（functab 项是绝对 PC，不是 entryoff）


@dataclass
class GoPclnTable:
    spans: list[tuple[int, int]]
    starts: list[int]
    magic: int
    nfunc: int
    text_start: int
    detail: dict[str, Any]
    va: int = 0                 # pclntab 自身的 VA（moduledata.pcHeader 指向它）
    funcname_offset: int = 0    # 表头 funcnameOffset，用于校验 moduledata.funcnametab
    # 函数起点 → 名字。取不到就留空，并由 `name_status` 明确写“不可恢复”，不编造。
    names: dict[int, str] = field(default_factory=dict)
    name_status: str = ""


def _go_name(raw: bytes, funcname_base: int, nameoff: int,
             limit: int = 2048) -> str:
    """读 `_func.nameoff` 指向的 NUL 终止名字；不合格的一律返回空串。

    旧格式（Go 1.2–1.15）里名字直接放在 pclntab 里（`funcname_base=0`）；
    1.16+ 放在独立的 funcnametab（`funcname_base=funcnameOffset`）。
    """
    if nameoff <= 0:
        return ""
    off = funcname_base + nameoff
    if off <= 0 or off >= len(raw):
        return ""
    end = raw.find(b"\x00", off, min(off + limit, len(raw)))
    if end < 0:
        return ""
    try:
        name = raw[off:end].decode("utf-8")
    except UnicodeDecodeError:
        return ""
    if len(name) < 2 or not name.isprintable():
        return ""
    return name


def parse_gopclntab(raw: bytes, text_start: int, text_end: int | None = None
                    ) -> GoPclnTable | None:
    """Go 1.16+ 的 `.gopclntab`：functab 是 `(entryoff, funcoff)` 的 u32 对。

    函数起点 = textStart + entryoff；结束 = 下一条 entryoff（最后一条用 sentinel）。
    Go 1.20 起 `textStart` 字段在部分样本里为 0（链接器按 text 节重定位），
    此时用 `.text` 节地址兜底，并在 detail 里标 `text_start_source`。

    头布局有两代（`debug/gosym/pclntab.go` 的 parsePclnTab）：
    - 1.16：nfunc / nfiles / funcname / cu / filetab / pctab / pcln（无 textStart）；
    - 1.18+：nfunc / nfiles / textStart / funcname / cu / filetab / pctab / pcln。
    函数名从 funcname 表读 NUL 终止串；`_func` 第一字段在 1.18 起由 uintptr 变 uint32，
    因此 nameoff 的列偏移在两种布局里不同（1.16 是 ptrSize，1.18+ 是 4）。
    """
    if len(raw) < 72:
        return None
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic == GO_MAGIC_OLD:
        return _parse_gopclntab_old(raw, text_start, text_end)
    if magic not in (GO_MAGIC_116, GO_MAGIC_118, GO_MAGIC_120):
        return None
    ptr_size = raw[7]
    if ptr_size not in (4, 8):
        return None
    u = "<Q" if ptr_size == 8 else "<I"
    step = 8 if ptr_size == 8 else 4
    nfunc = struct.unpack_from(u, raw, 8)[0]
    if not nfunc or nfunc > 2_000_000:
        return None
    if magic == GO_MAGIC_116:
        # 无 textStart 字段：偏移字段从 offset 24 开始
        text_field = 0
        offs = [struct.unpack_from(u, raw, 24 + step * k)[0] for k in range(5)]
        name_field_off = ptr_size
    else:
        base = 24                          # textStart 在 nfiles 之后
        text_field = struct.unpack_from(u, raw, base)[0]
        offs = [struct.unpack_from(u, raw, base + step * (k + 1))[0] for k in range(5)]
        name_field_off = 4
    pcln = offs[4]
    if pcln <= 0 or pcln + 8 * (nfunc + 1) > len(raw):
        return None
    src = "表头 textStart" if text_field else ".text 节兜底"
    base_va = text_field or text_start
    entries = [struct.unpack_from("<I", raw, pcln + 8 * i)[0]
               for i in range(nfunc + 1)]
    if entries != sorted(entries):
        return None
    spans: list[tuple[int, int]] = []
    for i in range(nfunc):
        start = base_va + entries[i]
        end = base_va + entries[i + 1]
        if text_end is not None:
            end = min(end, text_end)
        if end > start:
            spans.append((start, end))
    starts = [s for s, _ in spans]

    # 函数名：functab 第 i 项的 funcoff 指向 `_func`，其 nameoff 再指向 funcname 表。
    names: dict[int, str] = {}
    for i in range(nfunc):
        # funcoff 相对 funcdata（1.16+ 与 functab 同址），不是相对文件/节起点。
        func_off = pcln + struct.unpack_from("<I", raw, pcln + 8 * i + 4)[0]
        if func_off <= pcln or func_off + name_field_off + 4 > len(raw):
            continue
        nameoff = struct.unpack_from("<I", raw, func_off + name_field_off)[0]
        name = _go_name(raw, offs[0], nameoff)
        start = base_va + entries[i]
        if name and (not text_end or start <= text_end):
            names[start] = name
    if not names:
        name_status = "不可恢复：funcnametab/nameoff 读取失败"
    elif len(names) < len(starts):
        name_status = f"部分恢复 {len(names)}/{len(starts)}"
    else:
        name_status = "ok"
    return GoPclnTable(spans, starts, magic, nfunc, base_va, {
        "magic": f"0x{magic:08X}", "nfunc": nfunc, "text_start": f"0x{base_va:X}",
        "text_start_source": src,
        "first_entry": f"0x{starts[0]:X}" if starts else "-",
        "last_end": f"0x{spans[-1][1]:X}" if spans else "-",
        "name_status": name_status, "names": len(names),
    }, funcname_offset=offs[0], names=names, name_status=name_status)


def _parse_gopclntab_old(raw: bytes, text_start: int, text_end: int | None = None
                         ) -> GoPclnTable | None:
    """Go 1.2–1.15 的旧 `.gopclntab`（magic `0xFFFFFFFB`）。

    与 1.16+ 的头不同：**没有** `textStart` 与 5 个偏移字段，`functab` 紧跟在
    `nfunc` 后面，每项是 `(entry uintptr, funcoff uintptr)`，`entry` 是**绝对 PC**
    （链接器已按 image base 重定位），不是相对 `textStart` 的 `entryoff`。

    函数区间取相邻 `entry` 的差；名字按 `_func` 布局读：`entry uintptr` 之后的
    `nameoff uint32` 是**相对 pclntab 起点**的偏移，指向 NUL 终止串
    （`debug/gosym` ver12 的 `t.funcnametab = t.Data`）。读不出来就留空并标
    `name_status`，不猜、不用地址充数。
    """
    if len(raw) < 16:
        return None
    ptr_size = raw[7]
    if ptr_size not in (4, 8):
        return None
    u = "<Q" if ptr_size == 8 else "<I"
    nfunc = struct.unpack_from(u, raw, 8)[0]
    if not nfunc or nfunc > 2_000_000:
        return None
    entry_size = ptr_size * 2
    tab_off = 8 + ptr_size
    if tab_off + entry_size * (nfunc + 1) > len(raw):
        return None
    entries = [struct.unpack_from(u, raw, tab_off + i * entry_size)[0]
               for i in range(nfunc + 1)]
    if entries != sorted(entries) or len(set(entries)) != len(entries):
        return None
    lo = text_start
    hi = text_end if text_end is not None else text_start + (1 << 32)
    inside = sum(1 for pc in entries if lo <= pc <= hi)
    # 假魔数（字符串常量/字符串表里也常见 FB FF FF FF）会让条目散落各处
    if inside < len(entries) * 0.9:
        return None
    spans: list[tuple[int, int]] = []
    for i in range(nfunc):
        start, end = entries[i], entries[i + 1]
        if text_end is not None:
            end = min(end, text_end)
        if end > start:
            spans.append((start, end))
    starts = [s for s, _ in spans]
    if not spans:
        return None

    names: dict[int, str] = {}
    for i in range(nfunc):
        func_off = struct.unpack_from(u, raw, tab_off + i * entry_size + ptr_size)[0]
        if func_off < tab_off or func_off + ptr_size + 4 > len(raw):
            continue
        nameoff = struct.unpack_from("<I", raw, func_off + ptr_size)[0]
        name = _go_name(raw, 0, nameoff)
        if name:
            names[entries[i]] = name
    if not names:
        name_status = "不可恢复：旧格式 _func.nameoff 读取失败"
    elif len(names) < len(starts):
        name_status = f"部分恢复 {len(names)}/{len(starts)}"
    else:
        name_status = "ok"
    return GoPclnTable(spans, starts, GO_MAGIC_OLD, nfunc, text_start, {
        "magic": f"0x{GO_MAGIC_OLD:08X}", "nfunc": nfunc,
        "layout": "go1.2（functab 绝对 PC）",
        "ptr_size": ptr_size,
        "header_bytes": tab_off,
        "text_start": f"0x{text_start:X}",
        "text_start_source": "functab 绝对 PC（旧头无 textStart 字段）",
        "first_entry": f"0x{starts[0]:X}" if starts else "-",
        "last_end": f"0x{spans[-1][1]:X}",
        "entries_outside_text": len(entries) - inside,
        "name_status": name_status, "names": len(names),
    }, names=names, name_status=name_status)


def _drop_padding_entries(tab: GoPclnTable, text_raw: bytes,
                          text_start: int) -> GoPclnTable:
    """functab 的 `nfunc` 里含链接器填充项（`CC`/`00` 或 1 字节尾巴），不是函数。

    Go 的 functab 末尾会有 `runtime.etext` 之后的填充；不剔掉会让权威表多数两项，
    并在输出里造出两个"纯 int3 函数"。只按**内容全为 CC/00** 或长度 <2 判定。
    被剔掉的起点同步从 `names` 里删掉，避免“名字比区间多”。
    """
    spans, starts, dropped = [], [], 0
    for st, en in tab.spans:
        body = text_raw[st - text_start: en - text_start]
        if en - st < 2 or (body and all(b in (0xCC, 0x00) for b in body)):
            dropped += 1
            continue
        spans.append((st, en))
        starts.append(st)
    if dropped:
        keep = set(starts)
        tab.spans, tab.starts = spans, starts
        tab.names = {s: n for s, n in tab.names.items() if s in keep}
        tab.detail["header_nfunc"] = tab.nfunc
        tab.detail["padding_entries"] = dropped
        tab.detail["names"] = len(tab.names)
    return tab


def gopclntab_table(elf: Elf) -> GoPclnTable | None:
    sec = elf.section_by_name(".gopclntab")
    if sec is None or not sec.raw:
        return None
    text = elf.section_by_name(".text")
    text_start = text.virtual_address if text else 0
    text_end = text_start + len(text.raw) if text else None
    tab = parse_gopclntab(bytes(sec.raw), text_start, text_end)
    if tab is not None:
        tab.va = sec.virtual_address
    if tab is not None and text is not None:
        tab = _drop_padding_entries(tab, bytes(text.raw), text_start)
    return tab


GO_MAGICS = (GO_MAGIC_OLD, GO_MAGIC_116, GO_MAGIC_118, GO_MAGIC_120)


def pclntab_from_data(img: Any, min_func: int = 10) -> GoPclnTable | None:
    """在数据节里按魔数找 pclntab（Go PE 没有 `.gopclntab` 这个节名）。

    只认表头自洽的结果：`nfunc` 合理、`pcln` 偏移在节内、entryoff 单调不减。
    `0xFFFFFFF1` / `0xFFFFFFF0` / `0xFFFFFFFA` 分别是 Go 1.20+ / 1.18 / 1.16 的表头。
    """
    text = next((s for s in img.sections if s.name == ".text"), None)
    text_start = img.image_base + text.virtual_address if text else 0
    text_end = text_start + len(text.raw) if text else None
    for s in img.sections:
        if s.is_executable or s.size_of_raw_data < 72:
            continue
        raw = bytes(s.raw)
        for off in range(0, len(raw) - 71):
            if int.from_bytes(raw[off:off + 4], "little") not in GO_MAGICS:
                continue
            tab = parse_gopclntab(raw[off:], text_start, text_end)
            if tab is not None and tab.nfunc >= min_func:
                tab.va = img.image_base + s.virtual_address + off
                if text is not None:
                    tab = _drop_padding_entries(tab, bytes(text.raw), text_start)
                tab.detail["found_in"] = s.name
                tab.detail["found_offset"] = f"0x{off:X}"
                tab.detail["source"] = "数据节魔数扫描"
                return tab
    return None


# ---------------------------------------------------------------------------
# Go moduledata / itab（公开的运行时结构，用于播种接口方法）
# ---------------------------------------------------------------------------

# `runtime.moduledata` 的布局有两代，magic 都是 0xFFFFFFF1（1.20+），所以只能先按
# 结构探测、再按 magic 选偏移：
#   A. 经典：`itablinks []*itab`（Go 1.20–1.24，字段见 runtime/symtab.go）。
#      itablinks 偏移随 covctrs/ecovctrs 是否存在于 1.18/1.19 与 1.20+ 而不同。
#   B. Go 1.27.3（本机 SDK 源码）：`types, typedesclen, etypes` 之后是
#      `itaboffset, itabsize`，itab 变成一段连续可变长 blob：
#      `p := types + itaboffset; end := p + itabsize; p += itab.Size()`。
#      对应 runtime/iface.go 的 addModuleItabs()。
# 未知版本按已知结构试，全部校验不过就返回空集（不猜）。
GO_ITABLINKS_OFF = {GO_MAGIC_120: 0x178, GO_MAGIC_118: 0x168}
GO_ITAB_BLOB_OFF = 0x140     # Go 1.27：itaboffset
GO_ITAB_BLOB_SIZE = 0x148    # Go 1.27：itabsize
ITAB_FUN_OFF = 0x18          # itab.fun[0]
ITAB_STRUCT = 0x20           # itab 固定部分（inter/_type/hash/fun[0]）
# InterfaceType = Type(0x30) + PkgPath Name(8) + Methods []Imethod(0x18)：
# `Name` 只有 `Bytes *byte` 一个字段，所以 Methods 的指针在 0x38、len 在 0x40。
ITAB_MHDR_OFF = 0x38         # interfacetype.Methods 的 data 指针
ITAB_MHDR_LEN = 0x40         # interfacetype.Methods 的 len


def _read_bytes(img: Any, va: int, size: int, partial: bool = False) -> bytes | None:
    for s in img.sections:
        base = img.image_base + s.virtual_address
        if base <= va < base + len(s.raw):
            off = va - base
            end = min(off + size, len(s.raw))
            if not partial and end - off < size:
                return None
            return bytes(s.raw[off:end])
    return None


def _u64(buf: bytes, off: int) -> int:
    if off + 8 > len(buf):
        return 0
    return int.from_bytes(buf[off:off + 8], "little")


def _itab_methods(img: Any, ita: int) -> int:
    """一个 itab 的方法数（`interfacetype.Methods` 的 len）；形状不对返回 0。"""
    raw = _read_bytes(img, ita, ITAB_STRUCT)
    if raw is None:
        return 0
    inter, typ = _u64(raw, 0), _u64(raw, 8)
    if not section_name_at(img, inter) or not section_name_at(img, typ):
        return 0
    mh = _read_bytes(img, inter, ITAB_MHDR_LEN + 8)
    if mh is None:
        return 0
    count = _u64(mh, ITAB_MHDR_LEN)
    if not 0 < count <= 128:
        return 0
    if not section_name_at(img, _u64(mh, ITAB_MHDR_OFF)):
        return 0
    fun0 = _u64(raw, ITAB_FUN_OFF)
    return count if section_name_at(img, fun0) == ".text" else 0


def _valid_itab(img: Any, va: int) -> bool:
    return _itab_methods(img, va) > 0


def _go_moduledata(img: Any, tab: GoPclnTable, space: CodeSpace) -> dict[str, Any]:
    """在数据节里找 `moduledata`：它的 `pcHeader` 字段正好等于 pclntab 的 VA。

    校验用 `text`/`etext`（必须落在 `.text` 里）与 `funcnametab`（= pclntab +
    funcnameOffset）；再按"经典 itablinks"和"Go 1.27 itaboffset/itabsize"两种结构
    各试一次，都不过就跳过，不猜。
    """
    if image_bits(img) != 64 or not tab.va or tab.magic in (GO_MAGIC_116,
                                                            GO_MAGIC_OLD):
        return {}
    for s in img.sections:
        if s.is_executable or not s.size_of_raw_data:
            continue
        raw = bytes(s.raw)
        base = img.image_base + s.virtual_address
        for off in range(0, len(raw) - 7, 8):
            if _u64(raw, off) != tab.va:
                continue
            md_va = base + off
            blob = _read_bytes(img, md_va, 0x240, partial=True)
            if blob is None:
                continue
            text, etext = _u64(blob, 0xB0), _u64(blob, 0xB8)
            if not (tab.text_start <= text < etext) or not space.has(text):
                continue
            if _u64(blob, 0x08) not in (tab.va + tab.funcname_offset, tab.va):
                continue
            found = _probe_itablinks(img, blob, tab.magic, md_va, text, etext)
            if found is None:
                found = _probe_itab_blob(img, blob, md_va, text, etext)
            if found is not None:
                return found
    return {}


def _probe_itablinks(img: Any, blob: bytes, magic: int, md_va: int,
                     text: int, etext: int) -> dict[str, Any] | None:
    """经典布局：`itablinks []*itab`（Go 1.20–1.24）。"""
    offs = [GO_ITABLINKS_OFF.get(magic, 0x178)]
    offs.append(0x168 if offs[0] == 0x178 else 0x178)
    offs.extend(range(0x100, 0x190, 8))      # 未知小版本：在结构体里扫
    for io in dict.fromkeys(offs):
        if io + 24 > len(blob):
            continue
        links, count, cap = _u64(blob, io), _u64(blob, io + 8), _u64(blob, io + 16)
        if not (0 < count <= 65536 and cap >= count):
            continue
        if links <= 0 or not section_name_at(img, links):
            continue
        head = _read_bytes(img, links, 8)
        if head is None or not _valid_itab(img, _u64(head, 0)):
            continue
        return {"kind": "itablinks", "va": md_va, "text": text, "etext": etext,
                "links": links, "count": count,
                "layout": "itablinks", "offset": f"0x{io:X}"}
    return None


def _probe_itab_blob(img: Any, blob: bytes, md_va: int,
                     text: int, etext: int) -> dict[str, Any] | None:
    """Go 1.27：`types + itaboffset` 起、`itabsize` 长的连续 itab blob。"""
    types, etypes = _u64(blob, 0x128), _u64(blob, 0x138)
    itab_off, itab_size = _u64(blob, GO_ITAB_BLOB_OFF), _u64(blob, GO_ITAB_BLOB_SIZE)
    if not (section_name_at(img, types) and types < etypes):
        return None
    if not 0 < itab_size <= 64 << 20:
        return None
    start = types + itab_off
    if not section_name_at(img, start) or not _valid_itab(img, start):
        return None
    if not section_name_at(img, start + itab_size - 1):
        return None
    return {"kind": "offsets", "va": md_va, "text": text, "etext": etext,
            "types": types, "itab_start": start, "itab_size": itab_size,
            "layout": "itaboffset/itabsize", "offset": f"0x{GO_ITAB_BLOB_OFF:X}"}


def _itab_targets(img: Any, md: dict[str, Any], space: CodeSpace,
                  limit: int = 20000) -> tuple[set[int], dict[str, Any]]:
    """`itablinks[] -> itab.fun[]`（或 1.27 的连续 blob）：接口方法的真实入口。"""
    out: set[int] = set()
    itabs = entries = rejected = 0

    def take(ita: int, count: int) -> None:
        nonlocal entries
        for k in range(count):
            slot = _read_bytes(img, ita + ITAB_FUN_OFF + 8 * k, 8)
            if slot is None:
                break
            fun = _u64(slot, 0)
            if md["text"] <= fun < md["etext"] and space.has(fun):
                out.add(fun)
                entries += 1

    if md["kind"] == "offsets":
        p, end = md["itab_start"], md["itab_start"] + md["itab_size"]
        while p + ITAB_STRUCT <= end and itabs < limit:
            count = _itab_methods(img, p)
            if not count:            # blob 里有非 itab 就停，不继续猜
                rejected += 1
                break
            itabs += 1
            take(p, count)
            p += ITAB_STRUCT + (count - 1) * 8
        return out, {"itabs": itabs, "methods": entries, "rejected": rejected,
                     "layout": md["layout"]}

    for i in range(min(md["count"], limit)):
        head = _read_bytes(img, md["links"] + 8 * i, 8)
        if head is None:
            break
        ita = _u64(head, 0)
        count = _itab_methods(img, ita)
        if not count:
            rejected += 1
            continue
        itabs += 1
        take(ita, count)
    return out, {"itabs": itabs, "methods": entries, "rejected": rejected,
                 "layout": md["layout"]}


def go_itab_seeds(img: Any, space: CodeSpace) -> tuple[set[int], dict[str, Any]]:
    """冷启动的 Go 接口方法播种；非 Go / 不支持的版本返回空集，不猜。"""
    tab = gopclntab_table(img) if isinstance(img, Elf) else pclntab_from_data(img)
    if tab is None:
        return set(), {"supported": False, "reason": "没有可识别的 gopclntab"}
    if tab.magic in (GO_MAGIC_116, GO_MAGIC_OLD):
        return set(), {"supported": False,
                       "reason": f"Go {tab.magic:#x} 的 moduledata 布局不同（不支持）"}
    md = _go_moduledata(img, tab, space)
    if not md:
        return set(), {"supported": True, "moduledata": False}
    targets, stats = _itab_targets(img, md, space)
    stats.update({"supported": True, "moduledata": True,
                  "moduledata_va": f"0x{md['va']:X}",
                  "itablinks_offset": md["offset"],
                  "layout": md["layout"]})
    if md["kind"] == "itablinks":
        stats["itablinks"] = md["count"]
    else:
        stats.update({"itab_offset": f"0x{md['itab_start']:X}",
                      "itab_size": md["itab_size"]})
    return targets, stats


# ---------------------------------------------------------------------------
# 权威表选择
# ---------------------------------------------------------------------------

def authority_table(img: Any, use_eh_frame: bool = True) -> AuthorityTable:
    bits = image_bits(img)
    names = {s.name for s in img.sections}
    if isinstance(img, Elf):
        if bits != 64:
            return AuthorityTable("ELF", [], [],
                                  reason="ELF32 的 .eh_frame 未纳入 A 层（未实测）")
        go = gopclntab_table(img) if ".gopclntab" in names else None
        if go is not None:
            return AuthorityTable(".gopclntab", go.spans, go.starts,
                                  {"source": "Go functab",
                                   "functions": len(go.starts), **go.detail})
        if not use_eh_frame:
            return AuthorityTable(".eh_frame", [], [], reason="已用 --no-eh-frame 关闭")
        table = eh_frame_table(img)
        if table is None:
            if ".gopclntab" in names:
                reason = "有 .gopclntab 但表头版本未识别（只支持 Go 1.16+）"
            elif ".debug_frame" in names:
                reason = "只有 .debug_frame（不在装载段、strip 即失），不能当权威表"
            else:
                reason = ("无 .eh_frame：典型于 -fno-asynchronous-unwind-tables "
                          "或 strip --remove-section=.eh_frame")
            return AuthorityTable(".eh_frame", [], [], reason=reason)
        detail = {"fdes": len(table.fdes), "cies": table.cies, "source": table.source,
                  "hdr_present": table.hdr_present, "hdr_count": table.hdr_count,
                  "hdr_version": table.hdr_version, "hdr_encodings": table.hdr_encodings,
                  "hdr_matched": table.hdr_matched, "hdr_only": table.hdr_only,
                  "fde_only": table.fde_only, "hdr_truncated": table.hdr_truncated,
                  "zero_range": table.zero_range,
                  "duplicate_starts": table.duplicate_starts,
                  "empty_records": table.empty_records, "errors": table.errors}
        return AuthorityTable(".eh_frame", table.spans, table.starts, detail)
    # Go PE 优先 `.gopclntab`（没有同名节，只能按魔数在数据节里找）；
    # 它比 `.pdata` 多出 Go 运行时与 goroutine 调度相关的函数。
    go = pclntab_from_data(img)
    if go is not None:
        return AuthorityTable(".gopclntab", go.spans, go.starts,
                              {"source": "Go functab",
                               "functions": len(go.starts), **go.detail})
    spans = pdata_spans(img)
    detail: dict[str, Any] = {"entries": len(spans)}
    if not spans:
        detail["reason"] = ("32 位 PE 无 .pdata（SAFESEH 不是边界表）"
                            if bits == 32 else "未找到有效的 .pdata 项")
    return AuthorityTable(".pdata", spans,
                          sorted({b for b, e in spans if e > b}), detail,
                          detail.get("reason", ""))


# ---------------------------------------------------------------------------
# 工具链与形状库
# ---------------------------------------------------------------------------

@dataclass
class Toolchain:
    family: str
    bits: int
    confidence: float
    evidence: list[str] = field(default_factory=list)

    @property
    def profile(self) -> str:
        if self.family == "msvc":
            return "msvc_x86" if self.bits == 32 else "msvc_x64"
        if self.family == "go" and self.bits == 64:
            return "go_x64"
        if self.family == "gcc" and self.bits == 64:
            return "gcc_x64"
        return "generic"


def _is_go_section(name: str) -> bool:
    return (name.startswith(".go.") or name in (".gopclntab", ".gosymtab")
            or name == ".note.go.buildid")


def detect_toolchain(img: Any) -> Toolchain:
    bits = image_bits(img)
    names = {s.name for s in img.sections}
    blob = b"".join(bytes(s.raw) for s in img.sections if s.size_of_raw_data)
    exec_blob = b"".join(bytes(s.raw) for s in img.sections if s.is_executable)
    if isinstance(img, Elf):
        go_secs = sorted(n for n in names if _is_go_section(n))
        if go_secs:
            return Toolchain("go", bits, 0.98, ["节 " + ",".join(go_secs)])
        comment = next((bytes(s.raw) for s in img.sections if s.name == ".comment"), b"")
        if b"GCC:" in comment:
            return Toolchain("gcc", bits, 0.97, [".comment 含 GCC"])
        if b"clang version" in comment:
            return Toolchain("gcc", bits, 0.95, [".comment 含 clang"])
        ev = []
        if ".note.gnu.property" in names:
            ev.append(".note.gnu.property")
        if b"\xf3\x0f\x1e\xfa" in exec_blob:
            ev.append("endbr64")
        if ev:
            return Toolchain("gcc", bits, 0.8, ev)
        return Toolchain("generic", bits, 0.3, ["无工具链指纹"])
    if b"Go build ID" in blob or any(_is_go_section(n) for n in names):
        return Toolchain("go", bits, 0.9, ["Go build ID / .go 节"])
    if ".eh_frame" in names or b"GCC: (" in blob:
        return Toolchain("gcc", bits, 0.9, [".eh_frame / GCC 串"])
    if b"clang version" in blob:
        return Toolchain("gcc", bits, 0.9, ["clang version 串"])
    ev = [s.decode() for s in (b"ucrtbase", b"vcruntime140", b"msvcrt.dll",
                               b"api-ms-win-crt") if s in blob]
    hot = exec_blob.count(b"\x8b\xff\x55")
    if hot > 20:
        ev.append(f"hotpatch {hot} 处")
    return Toolchain("msvc", bits, 0.95 if ev else 0.75, ev or ["PE 默认按 MSVC"])


def _prologue_tags(space: CodeSpace, va: int, bits: int, window: int = 3) -> set[str]:
    sp = "rsp" if bits == 64 else "esp"
    bp = "rbp" if bits == 64 else "ebp"
    saved = NONVOLATILE if bits == 64 else NONVOLATILE32
    if bits == 32:
        prev = space.decode(va - 2)
        if prev is not None and prev.mnemonic == "mov" and prev.op_str == "edi, edi" \
                and va - 2 + prev.size == va:
            return set()
        prev1 = space.decode(va - 1)
        if prev1 is not None and prev1.mnemonic == "push" and prev1.op_str == "ebp" \
                and va - 1 + prev1.size == va:
            return set()
    insns, cur, tags = [], va, set()
    for _ in range(8):
        insn = space.decode(cur)
        if insn is None:
            return set()
        insns.append(insn)
        cur += insn.size
        if bits == 32 and insn.mnemonic == "mov" and insn.op_str == "edi, edi":
            tags.add("hotpatch")
            continue
        if insn.mnemonic in ("endbr64", "endbr32"):
            tags.add("endbr")
            continue
        break
    ri = len(insns) - 1
    first = insns[ri]
    mn, op = first.mnemonic, first.op_str
    tail = []
    for _ in range(window):
        insn = space.decode(cur)
        if insn is None:
            break
        tail.append(insn)
        cur += insn.size
    tail_txt = [f"{i.mnemonic} {i.op_str}" for i in tail]
    if mn == "push" and op == bp:
        return tags | {"framepush"}
    if mn == "push" and op in saved:
        if any("mov " + bp + ", " + sp in t for t in tail_txt[:3]):
            tags.add("framepush")
        elif any(t.startswith("sub " + sp + ", ") for t in tail_txt):
            tags.add("calleepush")
        return tags
    if mn == "sub" and op.startswith(sp + ", "):
        return tags | {"stackalloc"}
    if (mn == "mov" and op == f"{bp}, {sp}") \
            or (mn == "lea" and op.startswith(f"{bp}, [{sp}")):
        if ri > 0 and insns[ri - 1].mnemonic == "push" and insns[ri - 1].op_str == bp:
            tags.add("framepush")
        return tags
    if bits == 64 and mn == "mov" and (op.startswith(f"qword ptr [{sp}")
                                       or op.startswith(f"dword ptr [{sp}")):
        return tags | {"homeslot"}
    if bits == 32 and mn == "push" and op.startswith("0x"):
        if len(tail_txt) > 1 and tail_txt[0].startswith("push 0x") \
                and tail_txt[1].startswith("call"):
            tags.add("seh")
        return tags
    if bits == 64:
        if mn == "cmp" and op.startswith("rsp, qword ptr [r14"):
            tags.add("gosplit")
        elif mn == "lea" and op.startswith("r12, [rsp") and tail:
            nxt = tail[0]
            if nxt.mnemonic == "cmp" and nxt.op_str.startswith("r12,"):
                tags.add("gosplit")
    return tags


def _strong_prologue(space: CodeSpace, va: int, bits: int,
                     profile: str = "generic") -> str | None:
    window = 7 if profile in ("gcc_x64", "go_x64") else 3
    tags = _prologue_tags(space, va, bits, window)
    hit = tags & PROFILE_SHAPES.get(profile, PROFILE_SHAPES["generic"])
    return sorted(hit)[0] if hit else None


# ---------------------------------------------------------------------------
# 区间索引与边界
# ---------------------------------------------------------------------------

def _merged_spans(pairs: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for a, b in sorted(pairs):
        if b <= a:
            continue
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def _range_index(pairs: Iterable[tuple[int, int]]
                 ) -> tuple[list[int], list[tuple[int, int]]]:
    ordered = sorted(pairs)
    return [a for a, _ in ordered], ordered


def _covering(spans: list[tuple[int, int]], va: int,
              starts: list[int] | None = None) -> tuple[int, int] | None:
    """`va` 落在哪个已合并区间里。`starts` 可传入预建的起点表（同一 `spans` 反复查询时省一次 O(n)）。"""
    if starts is None:
        starts = [s for s, _ in spans]
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and va < spans[i][1]:
        return spans[i]
    return None


def _owner_of(va: int, index: tuple[list[int], list[tuple[int, int]]]) -> int | None:
    starts, ordered = index
    i = bisect.bisect_left(starts, va) - 1
    if i >= 0 and ordered[i][0] < va < ordered[i][1]:
        return ordered[i][0]
    return None


def _insn_conflict(va: int, insn_index: tuple[list[int], list[int]] | None) -> bool:
    """va 是否落在某条**已知指令**的内部（不是指令起点）。

    这是 align=1 穷举的核心防线：错位候选通常比真函数头晚 1 字节，
    落在 `push rbp`（55）或 `sub rsp,imm`（48 83 EC）的第二/第三个字节上。
    """
    if insn_index is None:
        return False
    starts, ends = insn_index
    if not starts:
        return False
    i = bisect.bisect_right(starts, va) - 1
    return i >= 0 and starts[i] < va < ends[i]


def _direct_target(op_str: str) -> int | None:
    if op_str.startswith("0x"):
        try:
            return int(op_str, 16)
        except ValueError:
            return None
    return None


_PAD_BYTES = {0x00, 0x90, 0xCC}
# 这些指令结束处天然是边界；入口前一条是它们（或填充）时，边界可信。
_BOUNDARY_MNEMONICS = STOP_MNEMONICS | {"jmp", "nop", "hlt"}


def _boundary_conflict(img: Any, space: CodeSpace, va: int) -> bool:
    """align=1 专用：入口是否落在别人的指令流中间（且前一条不是边界）。

    真实函数头前面通常是填充（`CC`/`90`/`00`）或终止指令（`ret`/`jmp`）；
    若前一条是普通指令并且恰好顺序流入 `va`，`va` 只是函数中段的一个基本块，
    不是入口。这一步必须在形状验证**之前**做，否则 `sub rsp, imm` 这类
    中段块会因为栈平衡漂亮而被误收。
    """
    fo = img.rva_to_foa(va - img.image_base)
    if fo is None or fo < 1:
        return False
    b1 = img.data[fo - 1]
    if b1 in _PAD_BYTES:
        return False
    prev = space.decode(va - 1)
    if prev is None:
        return False
    if va - 1 + prev.size > va:
        # 前一条指令跨过入口：入口是它的第二/第三个字节（常见于 41/48 前缀错位）。
        return True
    if va - 1 + prev.size < va:
        return False
    return prev.mnemonic not in _BOUNDARY_MNEMONICS


# ---------------------------------------------------------------------------
# 递归下降
# ---------------------------------------------------------------------------

def code_space(img: Any, detail: bool = False) -> CodeSpace:
    return CodeSpace([(img.image_base + s.virtual_address, bytes(s.raw))
                      for s in img.sections if s.is_executable and s.size_of_raw_data],
                     bits=image_bits(img), detail=detail)


_ELF_INIT_SECTIONS = (".init_array", ".fini_array", ".preinit_array")
_ELF_GOT_SECTIONS = (".got", ".got.plt", ".plt.got")
_PROLOGUE_BYTES = {0x55, 0x53, 0x56, 0x57, 0x41, 0x48, 0x4C, 0xF3, 0x40}


def _pe_tls_callbacks(pe: PE) -> list[int]:
    """PE 的 TLS 回调数组（数据目录 9）；它们是构造期代码，等价于 ELF 的 `.init_array`。"""
    if len(pe.directories) <= 9:
        return []
    rva, size = pe.directories[9]
    if not rva or size < 8:
        return []
    foa = pe.rva_to_foa(rva)
    if foa is None:
        return []
    word = 8 if pe.is_64 else 4
    if foa + word * 4 > len(pe.data):
        return []
    cb_va = pe.r.u64(foa + word * 3) if pe.is_64 else pe.r.u32(foa + word * 3)
    out: list[int] = []
    va = cb_va
    for _ in range(256):
        if not va:
            break
        pos = pe.rva_to_foa(va - pe.image_base)
        if pos is None or pos + word > len(pe.data):
            break
        val = pe.r.u64(pos) if pe.is_64 else pe.r.u32(pos)
        if not val:
            break
        out.append(val)
        va += word
    return out


def _pointer_slots(raw: bytes, ptr: int) -> list[int]:
    out: list[int] = []
    for off in range(0, len(raw) - ptr + 1, ptr):
        v = int.from_bytes(raw[off:off + ptr], "little")
        if v:
            out.append(v)
    return out


def _looks_like_string(img: Any, va: int) -> bool:
    for s in img.sections:
        if s.is_executable or not s.size_of_raw_data:
            continue
        base = img.image_base + s.virtual_address
        if base <= va < base + len(s.raw):
            chunk = bytes(s.raw[va - base:va - base + 24])
            if len(chunk) < 4 or chunk[0] == 0:
                return False
            printable = sum(1 for b in chunk if 0x20 <= b < 0x7F)
            return printable >= min(6, len(chunk) - 1)
    return False


def _string_xrefs(img: Any, space: CodeSpace, limit: int = 4096) -> list[int]:
    """扫 `lea reg,[rip+disp]` 指向字符串的位置，返回**指令末尾**地址。

    冷启动不靠符号，但"代码引用了字符串"本身就是数据证据；调用方再用
    `_nearest_prologue` 把引用点挂回所属函数。
    """
    bits = image_bits(img)
    out: list[int] = []
    for seg_start, data in space.segments:
        i, n = 0, len(data)
        while i < n - 6:
            b0 = data[i]
            if bits == 64 and b0 == 0x48 and data[i + 1] == 0x8D \
                    and (data[i + 2] & 0xC7) == 0x05:
                disp = int.from_bytes(data[i + 3:i + 7], "little", signed=True)
                end = seg_start + i + 7
                if _looks_like_string(img, end + disp):
                    out.append(end)
                    if len(out) >= limit:
                        return out
                i += 7
                continue
            if bits == 32 and b0 == 0x8D and (data[i + 1] & 0xC7) == 0x05:
                disp = int.from_bytes(data[i + 2:i + 6], "little", signed=True)
                end = seg_start + i + 6
                if _looks_like_string(img, end + disp):
                    out.append(end)
                    if len(out) >= limit:
                        return out
                i += 6
                continue
            i += 1
    return out


def _code_addr_refs(img: Any, space: CodeSpace, limit: int = 8192) -> list[int]:
    """扫 `lea reg,[rip+disp]` 指向**可执行节**的位置，返回被取址的代码地址。

    这是冷启动里 `main` 的来源：`_start` 把 `main` 的地址 `lea` 给
    `__libc_start_main`，没有直接 `call` 边可跟。
    """
    bits = image_bits(img)
    ranges = [(img.image_base + s.virtual_address,
               img.image_base + s.virtual_address + len(s.raw))
              for s in img.sections if s.is_executable and s.size_of_raw_data]
    out: list[int] = []
    for seg_start, data in space.segments:
        i, n = 0, len(data)
        while i < n - 6:
            b0 = data[i]
            if bits == 64 and b0 == 0x48 and data[i + 1] == 0x8D \
                    and (data[i + 2] & 0xC7) == 0x05:
                disp = int.from_bytes(data[i + 3:i + 7], "little", signed=True)
                target = seg_start + i + 7 + disp
                if any(a <= target < b for a, b in ranges):
                    out.append(target)
                    if len(out) >= limit:
                        return out
                i += 7
                continue
            if bits == 32 and b0 == 0x8D and (data[i + 1] & 0xC7) == 0x05:
                disp = int.from_bytes(data[i + 2:i + 6], "little", signed=True)
                target = seg_start + i + 6 + disp
                if any(a <= target < b for a, b in ranges):
                    out.append(target)
                    if len(out) >= limit:
                        return out
                i += 6
                continue
            i += 1
    return out


def _byte_at(space: CodeSpace, va: int) -> int | None:
    seg = space.segment_of(va)
    if seg is None:
        return None
    start, data = seg
    off = va - start
    return data[off] if off < len(data) else None


def _nearest_prologue(space: CodeSpace, va: int, bits: int, profile: str,
                      back: int = 320, align: int = 1) -> int | None:
    """从 `va` 往回找最近的序言起点（先按首字节过滤，再做形状校验）。

    `align` 用于 Go：函数入口按 16 字节对齐（`PROFILE_MIN_ALIGN`），按址回退
    既快又不会在函数中段"碰巧"匹配到 `push rbp`。
    """
    start = va - (va % align) if align > 1 else va
    for cand in range(start, start - back, -align):
        b = _byte_at(space, cand)
        if b is None:
            break
        if cand != start and b not in _PROLOGUE_BYTES:
            continue
        if _strong_prologue(space, cand, bits, profile):
            return cand
    return None


def _relative_relocs(elf: Elf) -> list[int]:
    """PIE 的指针表在文件里不可见：vtable 槽位是 `R_X86_64_RELATIVE` 重定位，
    真实目标只存在 `.rela.dyn` 的 addend 里。不解重定位就找不到这些函数。
    """
    out: list[int] = []
    if elf.bits != 64:
        return out
    for name in (".rela.dyn", ".rela.plt"):
        sec = elf.section_by_name(name)
        if sec is None or not sec.raw:
            continue
        raw = bytes(sec.raw)
        entsize = sec.entsize or 24
        for off in range(0, len(raw) - entsize + 1, entsize):
            r_info, addend = struct.unpack_from("<Qq", raw, off + 8)
            # R_X86_64_RELATIVE=8，R_AARCH64_RELATIVE=1027
            if (r_info & 0xFFFFFFFF) in (8, 1027) and addend > 0:
                out.append(addend)
    return out


def _cold_seeds(img: Any, space: CodeSpace) -> list[tuple[int, str]]:
    """冷启动可用、且不依赖任何符号的播种源（入口点由 `discover` 另加）。

    - ELF：`.init_array` / `.fini_array` / `.preinit_array`，`.got` / `.got.plt` 指针；
    - PE：`.CRT*` 节、TLS 回调数组（PE 没有 `.init_array`）。
    """
    ptr = PTR_SIZE[image_bits(img)]
    out: list[tuple[int, str]] = []
    for s in img.sections:
        if not s.size_of_raw_data:
            continue
        name = s.name.lower()
        if isinstance(img, Elf):
            tok = ("init" if name in _ELF_INIT_SECTIONS
                   else "plt" if name in _ELF_GOT_SECTIONS else None)
        else:
            tok = ("init" if name.startswith(".crt") or name in (".init", ".tls")
                   else None)
        if tok is None:
            continue
        out.extend((v, tok) for v in _pointer_slots(bytes(s.raw), ptr)
                   if space.has(v))
    if isinstance(img, PE):
        out.extend((v, "init") for v in _pe_tls_callbacks(img) if space.has(v))
    return out


def _after_terminator(space: CodeSpace, va: int, bits: int) -> bool:
    """`va` 前一条是否是终止指令/填充：0xC3/0xCC/0x90/`jmp` 等。

    冷启动没有权威表时用于过滤"函数中段"的 `call` 目标：真函数起点前面通常是
    `ret`/`jmp`/对齐填充，而误码产生的假起点前面是普通指令。
    """
    prev = _byte_at(space, va - 1)
    if prev in (0xCC, 0x90, 0x00, 0xC3, 0xCB, 0xC2, 0xCA):
        return True
    for back in (2, 3, 5):
        insn = space.decode(va - back)
        if insn is not None and insn.size == back \
                and (insn.mnemonic in STOP_MNEMONICS or insn.mnemonic == "jmp"):
            return True
    return False


def _body_targets(space: CodeSpace, funcs: dict[int, Function],
                  memo: dict[int, int] | None = None) -> set[int]:
    """重新走一遍所有已确认函数体，收集 `call` 的直接目标（不动点用）。

    只收 `call`：`jmp` 在下降阶段已按"必须自身像函数起点"（`_strong_prologue`）处理过，
    能过的早已入队；剩下没过的都是函数内部的跳转标签（Go 的尾调用/分支尤其多），
    再按 `_after_terminator` 放宽一次只会把"ret/填充之后的分支标签"当成函数入口。
    实测（见 docs/funcs.md §6.1）：去掉 `jmp` 后 go_linux 的误报 233→5、Rust 631→310，
    召回只掉 94 / 7；Clang 114→98、召回掉 2。

    `memo` 是**按 VA 的解码结果缓存**：`decode(va)` 只取决于节内容，同一 VA 反复线性扫到
    时不必重解。编码 `(call目标 << 4) | 指令长度`，`0` 表示该 VA 解码失败；x86 指令最长
    15 字节，4 位足够。函数体区间大量重叠（共享尾部）时，这一层把「扫 N 遍」降为「每 VA 解一次」，
    不改变任何候选集合与判定。
    """
    out: set[int] = set()
    for fn in funcs.values():
        va = fn.entry
        while va < fn.end:
            if memo is not None:
                packed = memo.get(va)
                if packed is not None:
                    if not packed:
                        break
                    target = packed >> 4
                    if target:
                        out.add(target)
                    va += packed & 0xF
                    continue
            insn = space.decode(va)
            if insn is None:
                if memo is not None:
                    memo[va] = 0
                break
            target = 0
            if insn.mnemonic == "call":
                t = _direct_target(insn.op_str)
                if t is not None:
                    out.add(t)
                    target = t
            if memo is not None and insn.size < 16:
                memo[va] = (target << 4) | insn.size
            va += insn.size
    return out


def _relative_reloc_map(elf: Elf) -> dict[int, int]:
    """`槽位 VA -> addend`：PIE 的 vtable 槽位在文件里是 0，真值只在重定位里。"""
    out: dict[int, int] = {}
    if elf.bits != 64:
        return out
    for name in (".rela.dyn", ".rela.plt"):
        sec = elf.section_by_name(name)
        if sec is None or not sec.raw:
            continue
        raw = bytes(sec.raw)
        entsize = sec.entsize or 24
        for off in range(0, len(raw) - entsize + 1, entsize):
            r_offset = struct.unpack_from("<Q", raw, off)[0]
            r_info, addend = struct.unpack_from("<Qq", raw, off + 8)
            # R_X86_64_RELATIVE=8，R_AARCH64_RELATIVE=1027
            if (r_info & 0xFFFFFFFF) in (8, 1027) and addend > 0:
                out[r_offset] = addend
    return out


def _relative_relocs(elf: Elf) -> list[int]:
    """PIE 的指针表在文件里不可见：vtable 槽位是 `R_X86_64_RELATIVE` 重定位，
    真实目标只存在 `.rela.dyn` 的 addend 里。不解重定位就找不到这些函数。
    """
    return list(_relative_reloc_map(elf).values())


def _read_uint(img: Any, va: int, size: int) -> int | None:
    for s in img.sections:
        base = img.image_base + s.virtual_address
        if base <= va < base + len(s.raw):
            off = va - base
            if off + size <= len(s.raw):
                return int.from_bytes(s.raw[off:off + size], "little")
            return None
    return None


def _ptr_kind(img: Any, space: CodeSpace, value: int | None
              ) -> tuple[str, int] | None:
    """把指针值分成"代码地址"/"数据地址"；两者都不是就不猜。"""
    if not value:
        return None
    if space.has(value):
        return ("code", value)
    if section_name_at(img, value) is not None:
        return ("addr", value)
    return None


# 调用会破坏 caller-saved 寄存器，跨 call 的值一律作废（只做基本块内有限值流）
_VOLATILE = {
    64: ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"),
    32: ("eax", "ecx", "edx", "esi", "edi"),
}


def _apply_value_flow(insn, vals: dict[str, tuple[str, int] | None], md: Any,
                      img: Any, space: CodeSpace, bits: int) -> None:
    """基本块内的有限值流：只认 `lea reg,[rip+x]`、`mov reg,{reg|imm|mem}`。

    解析不出来的写入一律把目标寄存器置为未知——不跨块、不追别名、不合并 PHI。
    """
    try:
        from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    except ImportError:  # pragma: no cover - 依赖问题
        return
    ops = insn.operands
    if not ops:
        return
    dst = md.reg_name(ops[0].reg) if ops[0].type == X86_OP_REG else None
    done = False
    if dst is not None and len(ops) == 2:
        src = ops[1]
        if insn.mnemonic == "lea" and src.type == X86_OP_MEM:
            mem = src.mem
            base = md.reg_name(mem.base) if mem.base else ""
            if base in ("rip", "eip"):
                addr = insn.address + insn.size + mem.disp
                vals[dst] = ("addr", addr) if section_name_at(img, addr) else None
                done = True
            elif not mem.base and not mem.index and not mem.segment:
                addr = mem.disp & ((1 << bits) - 1)
                vals[dst] = ("addr", addr) if section_name_at(img, addr) else None
                done = True
        elif insn.mnemonic == "mov":
            if src.type == X86_OP_REG:
                vals[dst] = vals.get(md.reg_name(src.reg))
                done = True
            elif src.type == X86_OP_IMM:
                vals[dst] = None
                done = True
            elif src.type == X86_OP_MEM:
                mem = src.mem
                base = md.reg_name(mem.base) if mem.base else ""
                slot = None
                if base in ("rip", "eip") and not mem.index:
                    slot = insn.address + insn.size + mem.disp
                elif base in vals and vals[base] and vals[base][0] == "addr" \
                        and not mem.index:
                    slot = vals[base][1] + mem.disp
                elif not mem.base and not mem.index and not mem.segment:
                    slot = mem.disp & ((1 << bits) - 1)
                if slot is not None:
                    vals[dst] = _ptr_kind(img, space, _read_uint(img, slot, bits // 8))
                    done = True
    if done:
        return
    try:
        _read, written = insn.regs_access()
    except Exception:  # pragma: no cover - 个别指令没有访问信息
        written = ()
    for reg in written:
        vals.pop(md.reg_name(reg), None)


def _indirect_target(insn, vals: dict[str, tuple[str, int] | None], md: Any,
                     img: Any, space: CodeSpace, bits: int,
                     reloc_map: dict[int, int]) -> int | None:
    """解析 `call reg` / `call [reg+off]`；解析不出返回 None（不猜）。"""
    try:
        from capstone.x86_const import X86_OP_MEM, X86_OP_REG
    except ImportError:  # pragma: no cover
        return None
    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type == X86_OP_REG:
        val = vals.get(md.reg_name(op.reg))
        return val[1] if val and val[0] == "code" else None
    if op.type != X86_OP_MEM or op.mem.index:
        return None
    mem = op.mem
    base = md.reg_name(mem.base) if mem.base else ""
    slot = None
    if base in ("rip", "eip"):
        slot = insn.address + insn.size + mem.disp
    elif base in vals and vals[base] and vals[base][0] == "addr":
        slot = vals[base][1] + mem.disp
    elif not mem.base and not mem.segment:
        slot = mem.disp & ((1 << bits) - 1)
    if slot is None:
        return None
    target = reloc_map.get(slot)
    if target is None:
        target = _read_uint(img, slot, bits // 8)
    if target and space.has(target):
        return target
    return None


def discover(img: Any, max_functions: int = 50000, pointers: bool = False,
             ptr_sections: Iterable[str] | None = None,
             authority: Iterable[tuple[int, int]] | None = None,
             authority_source: str = "pdata",
             cold: bool = False, profile: str = "generic",
             cold_stats: dict[str, Any] | None = None,
             detail: bool = False,
             insn_out: dict[int, Any] | None = None
             ) -> tuple[dict[int, Function], list[str], set[int],
                        dict[int, set[str]], tuple[list[int], list[int]]]:
    """权威表 + 入口 + 导出播种，递归下降补叶子函数。

    `cold=True` 是冷启动口径：不拿符号、不拿权威表播种，只用代码与数据本身——
    入口、初始化表、GOT 指针、字符串交叉引用、指针表，再用 `call` 边做不动点补全。
    `detail=True` 用带操作数的 capstone（`xref` 要读 RIP 相对/立即数）；
    `insn_out` 非空时记录本次下降实际解码到的每条指令（`va -> Insn`），
    **这就是 xref 的指令流来源**，不要再另写一遍线性扫描。
    返回结构不变：
    - `evidence[entry]` 是证据 token 集合（可多个）；
    - `insn_index` 是"全部已解码指令的 (起点, 终点)"，供穷举做错位校验。
    """
    space = code_space(img, detail=cold or detail)
    bits = image_bits(img)
    notes: list[str] = []
    refs: set[int] = set()
    funcs: dict[int, Function] = {}
    evidence: dict[int, set[str]] = {}
    insn_starts: dict[int, int] = {}
    reloc_map = _relative_reloc_map(img) if (cold and isinstance(img, Elf)) else {}
    indirect_targets: set[int] = set()
    icall_attempts = icall_resolved = 0

    auth_pairs = authority_table(img).spans if authority is None else list(authority)
    bounds = {begin: end for begin, end in auth_pairs if space.has(begin)}
    auth_index = _range_index(bounds.items())

    seeds: list[tuple[int, str]] = [(va, authority_source) for va in bounds]
    entry_va = img.image_base + img.entry_rva
    if space.has(entry_va):
        seeds.append((entry_va, "entry"))
    if cold:
        seeds.extend((va, tok) for va, tok in _cold_seeds(img, space)
                     if va not in bounds)
        if isinstance(img, Elf):
            # PIE：vtable / 函数指针数组只体现在 RELATIVE 重定位里
            seeds.extend((va, "rel") for va in _relative_relocs(img)
                         if va not in bounds and space.has(va))
        # Go：moduledata 的 itab 表（`itablinks[]` 或 1.27 的连续 blob）
        # -> itab.fun[] 的接口方法入口；这是运行时自己写的表，不过序言门
        itab_targets, itab_stats = go_itab_seeds(img, space)
        if cold_stats is not None and itab_stats:
            cold_stats["itab"] = itab_stats
        if itab_targets:
            seeds.extend((va, "itab") for va in sorted(itab_targets)
                         if va not in bounds)
            if cold_stats is not None:
                cold_stats["itab_targets"] = sorted(itab_targets)
                cold_stats["itab_seeded"] = sum(
                    1 for va in itab_targets if va not in bounds)
    else:
        for exp in img.exports():
            va = img.image_base + exp.rva
            if space.has(va):
                seeds.append((va, "export"))

    queue = deque(seeds)
    queued = {va for va, _ in seeds}
    covered: dict[int, int] = {}
    skipped_covered = 0

    def add_ev(va: int, why: str) -> None:
        evidence.setdefault(va, set()).add(why)

    def enqueue(va: int, why: str) -> None:
        if va in funcs or va in queued or not space.has(va):
            return
        queued.add(va)
        queue.append((va, why))

    def trace(start: int, why: str) -> bool:
        """从一个入口下降，跟 call/jcc，jmp 按尾调用处理。"""
        nonlocal skipped_covered, icall_attempts, icall_resolved
        if start in funcs or not space.has(start):
            return False
        if start in covered:
            skipped_covered += 1
            return False
        fn = Function(start, start, why)
        add_ev(start, why)
        limit = bounds.get(start)
        work = [start]
        while work:
            va = work.pop()
            # 每个基本块各自一份寄存器值表：不跨块、不合并
            vals: dict[str, tuple[str, int] | None] = {}
            while True:
                if limit is not None and va >= limit:
                    break
                if va in covered:
                    break
                insn = space.decode(va)
                if insn is None:
                    break
                if insn_out is not None:
                    insn_out[va] = insn
                if insn.mnemonic in {"int3", "ud2", "hlt", "iret", "iretq"}:
                    break
                covered[va] = start
                insn_starts[va] = va + insn.size
                fn.insn_count += 1
                fn.end = max(fn.end, va + insn.size)
                mn, op = insn.mnemonic, insn.op_str
                target = _direct_target(op)
                if target is not None:
                    refs.add(target)
                if cold and mn != "call":
                    _apply_value_flow(insn, vals, space.md, img, space, bits)
                if mn == "call":
                    if target is not None:
                        fn.callees.add(target)
                        if space.has(target):
                            # 冷启动：假起点会产生假 call 边，先过序言/边界两道门
                            seedable = not cold or (
                                _strong_prologue(space, target, image_bits(img),
                                                 profile)
                                or _after_terminator(space, target,
                                                     image_bits(img)))
                            if seedable:
                                add_ev(target, "call")
                                enqueue(target, "call")
                    elif cold:
                        # 间接调用：只做基本块内有限值流，解析不出就记为未解析
                        icall_attempts += 1
                        itarget = _indirect_target(insn, vals, space.md, img,
                                                   space, bits, reloc_map)
                        if itarget is not None and space.has(itarget):
                            icall_resolved += 1
                            fn.callees.add(itarget)
                            refs.add(itarget)
                            if (_strong_prologue(space, itarget, bits, profile)
                                    or _after_terminator(space, itarget, bits)):
                                indirect_targets.add(itarget)
                                add_ev(itarget, "icall")
                                enqueue(itarget, "icall")
                    if cold:
                        # call 会破坏 caller-saved 寄存器
                        for reg in _VOLATILE[bits]:
                            vals.pop(reg, None)
                elif mn == "jmp":
                    if target is not None and space.has(target):
                        # 冷启动没有权威表可查，`jmp` 目标必须自身像函数起点，
                        # 否则是函数内部的跳转标签（Go 的尾调用/跳转表尤其多）
                        if cold and not _strong_prologue(
                                space, target, image_bits(img), profile):
                            break
                        add_ev(target, "jmp")
                        # 权威区间内的 `jmp` 是同一函数的基本块跳转（Rust/Clang
                        # 的 `jmp` 到下一块很常见），必须继续下降；以前一律 break，
                        # 会把函数体在第一个块跳转处截断，xref 因此看不到后半段。
                        if limit is not None and start <= target < limit:
                            work.append(target)
                            break
                        if _owner_of(target, auth_index) is None:
                            enqueue(target, "jmp")
                    break
                elif mn.startswith("j") and target is not None:
                    work.append(target)
                elif mn in STOP_MNEMONICS:
                    break
                va += insn.size
        funcs[start] = fn
        return True

    while queue and len(funcs) < max_functions:
        start, why = queue.popleft()
        trace(start, why)

    if not funcs:
        notes.append("没有可执行节，或入口/导出都不在可执行节内")
    if skipped_covered:
        notes.append(f"跳过 {skipped_covered} 个已被函数体覆盖的入口（共享尾部/跳转表分支）")

    if pointers:
        sections = tuple(ptr_sections) if ptr_sections else default_data_sections(img)
        found, pstats = _pointer_functions(img, funcs, space, sections,
                                           covered=covered, profile=profile,
                                           cold=cold)
        for fn in found:
            if fn.entry not in funcs:
                # `insn_out` 是 xref 的取流模式：指针表召回的条目也要真正下降一次，
                # 否则这些函数在 `functions` 里有条目却没有任何指令，xref 看不到
                # 它们对字符串/常量的引用（whoami 的 9 个 thunk 就是这种）。
                if insn_out is not None and not cold and trace(fn.entry, "ptr"):
                    refs.add(fn.entry)
                    continue
                funcs[fn.entry] = fn
                add_ev(fn.entry, "ptr")
                refs.add(fn.entry)
        notes.append(f"指针表召回 {pstats['validated']} 个（候选 {pstats['in_text']}，"
                     f"落在已有函数体 {pstats['inside_span']}，形状不符 {pstats['rejected']}，"
                     f"绝对跳转表排除 {pstats['abs_jt_excluded']}）")

    if cold:
        # `_merged_spans` 只依赖已确认的函数体，而 `Function` 一旦写进 `funcs` 就不再变
        # （`trace` 是写完 end/insn_count 才落库），所以 `len(funcs)` 就是区间表的版本号：
        # 版本没变时反复校验候选不必重算合并，合并语义一字未改。
        span_version = -1
        span_table: list[tuple[int, int]] = []

        def cold_spans() -> list[tuple[int, int]]:
            nonlocal span_version, span_table
            if span_version != len(funcs):
                span_table = _merged_spans((f.entry, f.end)
                                           for f in funcs.values() if f.insn_count)
                span_version = len(funcs)
            return span_table

        # 代码取址（`lea rdi,[rip+main]` 这一类）：目标本身就是函数起点
        addr_seeds = 0
        for target in _code_addr_refs(img, space):
            if target in covered or target in funcs:
                continue
            spans = cold_spans()
            ok, _why = _validate_candidate(space, spans, target, image_bits(img),
                                           covered=covered)
            if ok is None:
                continue
            add_ev(target, "addr")
            if trace(target, "addr"):
                addr_seeds += 1
        # 字符串交叉引用：只补"还没被任何函数体覆盖"的引用点
        str_seeds = 0
        for xref in _string_xrefs(img, space):
            if xref in covered:
                continue
            cand = _nearest_prologue(space, xref, image_bits(img), profile,
                                     back=4096 if profile == "go_x64" else 320,
                                     align=PROFILE_MIN_ALIGN.get(profile, 1))
            if cand is None or cand in funcs:
                continue
            # 序言形状还不够：整个函数体要能解到 ret/jmp 且栈平衡，否则是"函数中段"
            spans = cold_spans()
            ok, _why = _validate_candidate(space, spans, cand, image_bits(img),
                                           covered=covered)
            if ok is None:
                continue
            add_ev(cand, "str")
            if trace(cand, "str"):
                str_seeds += 1
            if str_seeds >= 512:
                break
        # call 边不动点：从所有已确认函数体（含指针表召回的）继续下降。
        # `_body_targets` 对同一函数体（entry/end 已冻结）的结果是确定的，因此已扫过的
        # 函数体不必每轮重扫：每轮只扫「上一轮新增的函数」，其余沿用累计集合。
        # 累计集合恒等于「对当前全部函数体重算一次」的结果，候选逐轮内容与顺序都不变。
        body_targets: set[int] = set()
        body_memo: dict[int, int] = {}   # VA -> (call 目标 << 4) | 指令长度，见 `_body_targets`
        scanned: set[int] = set()
        rounds = 0
        while rounds < 4 and len(funcs) < max_functions:
            rounds += 1
            before = len(funcs)
            fresh = {va: fn for va, fn in funcs.items() if va not in scanned}
            if fresh:
                scanned.update(fresh)
                body_targets |= _body_targets(space, fresh, body_memo)
            for target in sorted(body_targets | indirect_targets):
                if target in funcs or not space.has(target):
                    continue
                # 与首轮同一条门：假起点产生的假 call 边不能再往下扩散
                if not (_strong_prologue(space, target, image_bits(img), profile)
                        or _after_terminator(space, target, image_bits(img))):
                    continue
                add_ev(target, "call")
                trace(target, "call")
            if len(funcs) == before:
                break
        icall_seeded = sum(1 for t in indirect_targets
                           if t in funcs or t in covered)
        notes.append(f"冷启动：入口/初始化表/GOT/取址/字符串引用/指针表播种，"
                     f"call 边 {rounds} 轮不动点补全"
                     f"（取址 {addr_seeds}，字符串 {str_seeds}）；"
                     f"间接调用解析 {icall_resolved}/{icall_attempts}"
                     f"（可用作起点 {icall_seeded}）")
        if cold_stats is not None:
            cold_stats.update({"icall_attempts": icall_attempts,
                               "icall_resolved": icall_resolved,
                               "icall_seeded": icall_seeded,
                               "icall_rate": (icall_resolved / icall_attempts)
                               if icall_attempts else None})
    insn_index = (sorted(insn_starts), [insn_starts[k] for k in sorted(insn_starts)])
    return funcs, notes, refs, evidence, insn_index


def default_data_sections(img: Any) -> tuple[str, ...]:
    if isinstance(img, Elf):
        return ELF_DATA_SECTIONS
    return PE_DATA_SECTIONS + (".text",) if image_bits(img) == 32 else PE_DATA_SECTIONS


# ---------------------------------------------------------------------------
# 指针表召回
# ---------------------------------------------------------------------------

def _jmp_table_site(raw: bytes, o: int, va: int, bits: int) -> tuple[int, int] | None:
    if o + 3 > len(raw) or raw[o] != 0xFF:
        return None
    modrm = raw[o + 1]
    if (modrm >> 6) == 3 or ((modrm >> 3) & 7) != 4 or (modrm & 7) != 4:
        return None
    sib = raw[o + 2]
    index, base_reg = (sib >> 3) & 7, sib & 7
    if index == 4:
        return None
    mod = modrm >> 6
    rex = raw[o - 1] if o > 0 and 0x40 <= raw[o - 1] <= 0x4F else 0
    if bits == 32:
        if mod != 0 or base_reg != 5:
            return None
        return 7, int.from_bytes(raw[o + 3:o + 7], "little")
    if mod == 0 and base_reg == 5:
        return None
    base_full = base_reg + (8 if rex & 1 else 0)
    for back in range(2, 31):
        i = o - back
        if i < 0 or i + 7 > len(raw):
            continue
        if raw[i] not in (0x48, 0x4C) or raw[i + 1] != 0x8D or (raw[i + 2] & 0xC7) != 0x05:
            continue
        reg = ((raw[i + 2] >> 3) & 7) + (8 if raw[i] & 0x04 else 0)
        if reg != base_full:
            continue
        disp = int.from_bytes(raw[i + 3:i + 7], "little", signed=True)
        tbl = va - back + 7 + disp
        for insn in _md(64).disasm(raw[i:o + 8], va - back):
            if insn.address == va:
                return (1, tbl) if insn.mnemonic == "jmp" else None
            if insn.address > va:
                break
        return None
    return None


def _abs_jump_table_ranges(img: Any) -> list[tuple[int, int]]:
    bits = image_bits(img)
    ptr = PTR_SIZE[bits]
    exec_ranges = [(img.image_base + s.virtual_address,
                    img.image_base + s.virtual_address + max(len(s.raw), s.virtual_size))
                   for s in img.sections if s.is_executable]

    def in_exec(v: int) -> bool:
        return any(a <= v < b for a, b in exec_ranges)

    ranges: list[tuple[int, int]] = []
    seen: set[int] = set()
    for s in img.sections:
        if not s.is_executable or len(s.raw) < 8:
            continue
        raw = bytes(s.raw)
        sec_va = img.image_base + s.virtual_address
        for o in range(0, len(raw) - 8):
            if raw[o] != 0xFF:
                continue
            site = _jmp_table_site(raw, o, sec_va + o, bits)
            if site is None:
                continue
            _ilen, tbl = site
            if tbl in seen:
                continue
            seen.add(tbl)
            n = 0
            while n < 4096:
                fo = img.rva_to_foa(tbl + n * ptr - img.image_base)
                if fo is None or fo + ptr > len(img.data):
                    break
                v = int.from_bytes(img.data[fo:fo + ptr], "little")
                if not v or not in_exec(v):
                    break
                n += 1
            if n >= 2:
                ranges.append((tbl, tbl + n * ptr))
    ranges.sort()
    merged: list[tuple[int, int]] = []
    for a, b in ranges:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def _pointer_values(img: Any, sections: Iterable[str]
                    ) -> tuple[int, dict[int, list[int]]]:
    ptr = PTR_SIZE[image_bits(img)]
    wanted = {s.lower() for s in sections}
    values: dict[int, list[int]] = {}
    total = 0
    exec_ranges = [(img.image_base + s.virtual_address,
                    img.image_base + s.virtual_address + len(s.raw))
                   for s in img.sections if s.is_executable]
    for s in img.sections:
        if s.name.lower() not in wanted or s.size_of_raw_data < ptr:
            continue
        raw = bytes(s.raw)
        for off in range(0, len(raw) - ptr + 1, ptr):
            total += 1
            v = int.from_bytes(raw[off:off + ptr], "little")
            if v and any(a <= v < b for a, b in exec_ranges):
                values.setdefault(v, []).append(
                    img.image_base + s.virtual_address + off)
    return total, values


def _ptr_covered(va: int, covered: dict[int, int] | None,
                 spans: list[tuple[int, int]], sparse: set[int] | None,
                 starts: list[int] | None = None) -> int | None:
    if covered is not None:
        cov = covered.get(va)
        if cov is not None:
            return cov
    span = _covering(spans, va, starts)
    if span is None:
        return None
    if sparse and span[0] in sparse:
        return None
    return span[0]


def _validate_candidate(space: CodeSpace, spans: list[tuple[int, int]], entry: int,
                        bits: int, covered: dict[int, int] | None = None,
                        sparse: set[int] | None = None,
                        max_insns: int = 200, trust_slot: bool = False):
    """从 `entry` 线性走一遍函数体，判断它是不是一个"完整"函数起点。

    线性走到第一个 `ret`/`jmp` 就停，因此**多块函数**（-O0 或 Go 的
    `cmp rsp,[r14+0x10]; jbe ...` 头部）会在中途的 `jmp` 处 `delta != 0`，
    首指令也不是 `push`/`sub rsp`。这两种拒绝对"数据节里对齐的函数指针"
    是错的：指针槽位本身就是直接证据。`trust_slot=True`（指针表路径 +
    序言门已过时）把栈平衡与首指令形状降为参考，仍拒绝 decode/stop/overlap。
    """
    word = PTR_SIZE[bits]
    sp = "rsp" if bits == 64 else "esp"
    bp = "rbp" if bits == 64 else "ebp"
    saved = NONVOLATILE if bits == 64 else NONVOLATILE32
    insns: list[tuple[int, Any]] = []
    starts = [s for s, _ in spans]   # 每次调用建一次，而不是每条指令建一次
    va, delta, bp_delta = entry, 0, None
    while len(insns) < max_insns:
        insn = space.decode(va)
        if insn is None:
            return None, "decode"
        cov = _ptr_covered(va, covered, spans, sparse, starts)
        if cov is not None and cov != entry:
            return None, "overlap"
        insns.append((va, insn))
        mn, op = insn.mnemonic, insn.op_str
        if mn == "push":
            delta -= word
        elif mn == "pop":
            delta += word
        elif mn in ("sub", "add") and op.startswith(sp + ", "):
            try:
                imm = int(op.split(", ")[1], 16)
            except ValueError:
                return None, "bad_frame"
            delta += -imm if mn == "sub" else imm
        elif mn == "mov" and op == f"{bp}, {sp}":
            bp_delta = delta
        elif mn == "lea" and op.startswith(f"{bp}, [{sp}") and ", " in op:
            try:
                bp_delta = delta + int(op.split(", ")[1].rstrip("]").split("+ ")[1], 16)
            except (IndexError, ValueError):
                return None, "bad_frame"
        elif mn == "leave":
            if bp_delta is None:
                return None, "bad_frame"
            delta = bp_delta + word
        if mn in ("ret", "retf"):
            end = va + insn.size
            break
        if mn == "jmp":
            end = va + insn.size
            break
        if mn in STOP_MNEMONICS:
            return None, "stop"
        va += insn.size
    else:
        return None, "too_long"
    if delta != 0 and not trust_slot:
        return None, "unbalanced"
    first = insns[0][1]
    has_call = any(i.mnemonic == "call" for _, i in insns)
    if insns[-1][1].mnemonic == "jmp" and len(insns) <= 3 and not has_call:
        return Function(entry, end, "ptr", len(insns)), "thunk"
    looks_prologue = (
        (first.mnemonic == "push" and first.op_str in saved)
        or (first.mnemonic == "sub" and first.op_str.startswith(sp + ", "))
        or (first.mnemonic == "mov" and first.op_str.endswith(f", {sp}"))
        or (first.mnemonic == "mov" and first.op_str.startswith(f"qword ptr [{sp}"))
        or (first.mnemonic == "mov" and first.op_str.startswith(f"dword ptr [{sp}"))
        or (first.mnemonic == "lea" and first.op_str.startswith(f"{bp}, [{sp}"))
    )
    if looks_prologue:
        shape = "prologue"
    elif len(insns) <= 60 and not has_call and insns[-1][1].mnemonic in ("ret", "retf"):
        shape = "leaf"
    elif trust_slot:
        shape = "slot"
    else:
        return None, "shape"
    return Function(entry, end, "ptr", len(insns)), shape


def _pointer_functions(img: Any, funcs: dict[int, Function], space: CodeSpace,
                       data_sections: Iterable[str],
                       covered: dict[int, int] | None = None,
                       profile: str = "generic", cold: bool = False
                       ) -> tuple[list[Function], dict[str, Any]]:
    bits = image_bits(img)
    # 冷启动不得读权威表：`.pdata` 的 Begin 会让"指针正好指向函数起点"被判成
    # 落在已有函数体里而被丢掉（go_win 实测 160 个），同时也违反冷启动口径。
    known = [] if cold else list(pdata_spans(img) if isinstance(img, PE) else [])
    spans = _merged_spans(known
                          + [(f.entry, f.end) for f in funcs.values() if f.insn_count])
    sparse = {f.entry for f in funcs.values()
              if f.insn_count and (f.end - f.entry) > 4096
              and (f.end - f.entry) > f.insn_count * 32}
    total_ptrs, targets = _pointer_values(img, data_sections)
    abs_tables = _abs_jump_table_ranges(img)
    stats: dict[str, Any] = {"ptrs": total_ptrs, "in_text": len(targets),
                             "known": 0, "inside_span": 0, "rejected": 0,
                             "abs_tables": len(abs_tables), "abs_jt_excluded": 0,
                             "validated": 0, "shapes": {}, "reject_reasons": {}}
    found: list[Function] = []
    seen: set[int] = set()
    for va in sorted(targets):
        if va in funcs or va in seen:
            stats["known"] += 1
            continue
        if abs_tables and all(_covering(abs_tables, slot) is not None
                              for slot in targets[va]):
            stats["abs_jt_excluded"] += 1
            continue
        cov = _ptr_covered(va, covered, spans, sparse)
        if cov is not None:
            stats["inside_span"] += 1
            continue
        # 指针槽位是直接证据：门收紧成"序言形状 或 前一字节是 0xCC 填充"。
        # 不用 `_after_terminator`——它含 0x00（Go 的 jmp 位移尾字节），实测
        # go_linux 44 个误报全从这里来；0xCC 填充边界是 130/130、26/26、8/8 真。
        gate = (_strong_prologue(space, va, bits, profile) is not None
                or _byte_at(space, va - 1) == 0xCC)
        fn, why = _validate_candidate(space, spans, va, bits, covered=covered,
                                      sparse=sparse, trust_slot=gate)
        if fn is None:
            stats["rejected"] += 1
            stats["reject_reasons"][why] = stats["reject_reasons"].get(why, 0) + 1
            continue
        seen.add(va)
        found.append(fn)
        stats["validated"] += 1
        stats["shapes"][why] = stats["shapes"].get(why, 0) + 1
    return found, stats


# ---------------------------------------------------------------------------
# 穷举扫描
# ---------------------------------------------------------------------------

def _validate_exhaustive(space: CodeSpace, spans: list[tuple[int, int]], entry: int,
                         bits: int, insn_index: tuple[list[int], list[int]] | None,
                         max_insns: int = 400, max_states: int = 120):
    word = PTR_SIZE[bits]
    sp = "esp" if bits == 32 else "rsp"
    bp = "ebp" if bits == 32 else "rbp"
    work = [(entry, 0, None)]
    seen: dict[int, set[int]] = {}
    n, end, ret_ok = 0, entry, False
    while work:
        va, delta, bp_delta = work.pop()
        while True:
            if n >= max_insns or len(seen) >= max_states:
                return None, "too_long"
            prev = seen.get(va)
            if prev is not None and (delta in prev or len(prev) >= 2):
                break
            seen.setdefault(va, set()).add(delta)
            cov = _covering(spans, va)
            if cov is not None and cov[0] != entry:
                return None, "overlap"
            if _insn_conflict(va, insn_index):
                return None, "misaligned"
            insn = space.decode(va)
            if insn is None:
                return None, "decode"
            n += 1
            end = max(end, va + insn.size)
            mn, op = insn.mnemonic, insn.op_str
            if mn == "push":
                delta -= word
            elif mn == "pop":
                delta += word
            elif mn in ("sub", "add") and op.startswith(sp + ", "):
                try:
                    imm = int(op.split(", ")[1], 16)
                except ValueError:
                    return None, "bad_frame"
                delta += -imm if mn == "sub" else imm
            elif mn == "mov" and op == f"{bp}, {sp}":
                bp_delta = delta
            elif mn == "leave":
                if bp_delta is None:
                    return None, "bad_frame"
                delta = bp_delta + word
            if mn in ("ret", "retf"):
                if delta == 0:
                    ret_ok = True
                break
            tgt = _direct_target(op)
            if mn == "call":
                va += insn.size
                continue
            if mn == "jmp":
                if delta == 0:
                    ret_ok = True
                    break
                if tgt is not None and space.has(tgt):
                    work.append((tgt, delta, bp_delta))
                break
            if mn.startswith("j") and tgt is not None:
                work.append((tgt, delta, bp_delta))
                va += insn.size
                continue
            if mn in STOP_MNEMONICS:
                return None, "stop"
            va += insn.size
    if not ret_ok:
        return None, "unbalanced"
    return Function(entry, end, "exhaust", n), "ok"


def _exhaust_functions(img: Any, funcs: dict[int, Function], space: CodeSpace,
                       refs: set[int], align: int = 4, profile: str = "auto",
                       insn_index: tuple[list[int], list[int]] | None = None
                       ) -> tuple[list[tuple[Function, bool]], dict[str, Any]]:
    bits = image_bits(img)
    toolchain = detect_toolchain(img)
    if profile == "auto":
        profile = toolchain.profile if toolchain.confidence >= 0.6 else "generic"
    elif profile not in PROFILE_SHAPES:
        profile = "generic"
    shapes = PROFILE_SHAPES.get(profile, PROFILE_SHAPES["generic"])
    first_ok = PROFILE_FIRST.get(profile)
    align = max(align, PROFILE_MIN_ALIGN.get(profile, 1))
    spans = _merged_spans(list(pdata_spans(img) if isinstance(img, PE) else [])
                          + [(f.entry, f.end) for f in funcs.values() if f.insn_count])
    stats: dict[str, Any] = {"align": align, "prologues": 0, "tried": 0,
                             "accepted": 0, "nested_dropped": 0,
                             "reachable": 0, "isolated": 0, "reasons": {},
                             "misaligned": 0, "boundary_rejected": 0,
                             "profile": profile,
                             "shapes": sorted(shapes),
                             "toolchain": {"family": toolchain.family,
                                           "bits": toolchain.bits,
                                           "confidence": round(toolchain.confidence, 2),
                                           "evidence": list(toolchain.evidence)}}
    t0 = time.perf_counter()
    candidates: list[Function] = []
    for s in img.sections:
        if not s.is_executable or len(s.raw) < 8:
            continue
        raw = bytes(s.raw)
        base = img.image_base + s.virtual_address
        for off in range(0, len(raw) - 4, align):
            if first_ok is not None and raw[off] not in first_ok:
                continue
            va = base + off
            if _covering(spans, va) is not None:
                continue
            if _insn_conflict(va, insn_index):
                stats["misaligned"] += 1
                continue
            if align == 1 and _boundary_conflict(img, space, va):
                stats["boundary_rejected"] += 1
                continue
            if _strong_prologue(space, va, bits, profile) is None:
                continue
            stats["prologues"] += 1
            if va in funcs:
                continue
            stats["tried"] += 1
            fn, why = _validate_exhaustive(space, spans, va, bits, insn_index)
            if fn is None:
                stats["reasons"][why] = stats["reasons"].get(why, 0) + 1
                continue
            candidates.append(fn)
    kept: list[tuple[Function, bool]] = []
    cur_end = -1
    for fn in sorted(candidates, key=lambda f: (f.entry, -f.end)):
        if align == 1 and _boundary_conflict(img, space, fn.entry):
            stats["boundary_rejected"] += 1
            continue
        if fn.entry < cur_end:
            stats["nested_dropped"] += 1
            continue
        reachable = fn.entry in refs
        fn.source = "exhaust-reachable" if reachable else "exhaust-isolated"
        kept.append((fn, reachable))
        stats["reachable" if reachable else "isolated"] += 1
        cur_end = max(cur_end, fn.end)
    stats["accepted"] = len(kept)
    stats["seconds"] = round(time.perf_counter() - t0, 3)
    return kept, stats


# ---------------------------------------------------------------------------
# 汇总输出
# ---------------------------------------------------------------------------

def _primary_group(tokens: Iterable[str]) -> str:
    found = set(tokens)
    for tok in EVIDENCE_ORDER:
        if tok in found:
            return EVIDENCE_GROUPS.get(tok, tok)
    return "-"


# ---------------------------------------------------------------------------
# 孤立桶：口径上"不可交付（内部参考）"
# ---------------------------------------------------------------------------

ISOLATED_LABEL = "不可交付（内部参考）"
ISOLATED_DELIVERABLE_PRECISION = 0.97   # 达到也不自动交付，需用户批准
ISOLATED_DELIVERABLE_N = 100


def _wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n <= 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return ((c - r) / d, (c + r) / d)


def reference_base(img: Any) -> int | None:
    """Ghidra CSV 的 `base` 列要不要平移：ET_DYN 从 0x100000 搬回 0，其它不平移。"""
    if isinstance(img, Elf):
        return 0 if img.etype == ET_DYN else None
    return img.image_base


def load_reference(path: str, image_base: int | None = None
                   ) -> list[tuple[int, int]]:
    """读 `gh_count.py` 导出的参照表 CSV（name,entry,end,size,is_thunk,is_external,base）。

    只用于**验算孤立桶精度**，不参与发现。`is_thunk` / `is_external` 排除，
    与 B 层参照口径一致。返回按起点排序的 `[(start, end)]`。
    """
    spans: list[tuple[int, int]] = []
    with open(path, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            try:
                start = int(row["entry"], 16)
            except (KeyError, TypeError, ValueError):
                continue
            if row.get("is_thunk") == "1" or row.get("is_external") == "1":
                continue
            try:
                end = int(row["end"], 16) if row.get("end") else start
            except ValueError:
                end = start
            shift = 0
            if image_base is not None and row.get("base"):
                try:
                    shift = image_base - int(row["base"], 16)
                except ValueError:
                    shift = 0
            spans.append((start + shift, max(end, start) + shift))
    spans.sort()
    return spans


def isolated_metrics(starts: Iterable[int],
                     spans: list[tuple[int, int]] | None) -> dict[str, Any]:
    """孤立桶精度：`1 − 落在参照函数体内 / n`（参照漏建不算假，与 M2 同口径）。

    没有参照表时只给 n，并明确"精度未验证"。无论精度多高，`deliverable` 恒为
    False —— 孤立桶默认不对外交付，达标也只是"可以提交用户批准"。
    """
    starts = sorted(starts)
    n = len(starts)
    out: dict[str, Any] = {
        "n": n, "inside": None, "exact": None, "not_found": None,
        "precision": None, "precision_ci": None,
        "meets_thresholds": False, "deliverable": False,
        "label": ISOLATED_LABEL,
    }
    if spans is None:
        out["note"] = "未提供 --reference：该样本孤立桶精度未验证"
        return out
    if n == 0:
        out["note"] = "孤立桶为空，无需验算"
        return out
    starts_sorted = [s for s, _ in spans]
    inside = exact = 0
    for va in starts:
        i = bisect.bisect_right(starts_sorted, va) - 1
        if i < 0:
            continue
        b, e = spans[i]
        if b == va:
            exact += 1
        elif va < e:
            inside += 1
    precision = 1 - inside / n
    out.update({
        "inside": inside, "exact": exact, "not_found": n - inside - exact,
        "precision": precision, "precision_ci": _wilson(n - inside, n),
        "meets_thresholds": precision >= ISOLATED_DELIVERABLE_PRECISION
        and n >= ISOLATED_DELIVERABLE_N,
    })
    return out


def _layer(start: int, tokens: set[str], authority_starts: set[int]) -> str:
    if start in authority_starts:
        return LAYER_A
    if tokens & {"entry", "export", "call", "icall", "itab", "jmp", "ptr", "rel",
                 "addr", "init", "plt", "str", "exhaust-reachable"}:
        return LAYER_B_REACHABLE
    return LAYER_B_ISOLATED


def _reachable_authority(img: Any, space: CodeSpace, auth: AuthorityTable,
                         roots: Iterable[int]) -> set[int]:
    """从入口/数据表出发，沿权威函数体自身的 call/jmp 边可达的权威起点。

    只用于**评估分母**：边界来自权威表，边来自指令本身；不参与发现。
    这样"13.6%"可以拆成"可达子集召回"与"本来就摸不到"两部分。
    """
    starts = sorted(s for s in auth.starts if space.has(s))
    if not starts:
        return set()
    bounds = {b: e for b, e in auth.spans if space.has(b)}

    def owner(va: int) -> int | None:
        i = bisect.bisect_right(starts, va) - 1
        if i < 0:
            return None
        begin = starts[i]
        return begin if va < bounds.get(begin, begin) else None

    edges: dict[int, set[int]] = {}
    for begin, end in auth.spans:
        out: set[int] = set()
        va = begin
        while va < end:
            insn = space.decode(va)
            if insn is None:
                break
            if insn.mnemonic in ("call", "jmp"):
                target = _direct_target(insn.op_str)
                if target is not None:
                    out.add(target)
            va += insn.size
        edges[begin] = out

    reach: set[int] = set()
    work: deque[int] = deque()
    for root in roots:
        begin = owner(root)
        if begin is not None and begin not in reach:
            reach.add(begin)
            work.append(begin)
    while work:
        begin = work.popleft()
        for target in edges.get(begin, ()):
            owner_start = owner(target)
            if owner_start is not None and owner_start not in reach:
                reach.add(owner_start)
                work.append(owner_start)
    return reach


def analyze_image(path: str, *, pointers: bool = True,
                  data_sections: Iterable[str] | None = None,
                  exhaust: str | None = None, profile: str = "auto",
                  use_eh_frame: bool = True,
                  allow_large: bool = False,
                  reference: str | None = None,
                  cold: bool = False) -> dict[str, Any]:
    """分析一个 PE/ELF，返回 JSON 友好的函数表与两层指标。

    `reference` 是可选的外部参照表（`gh_count.py` 的 CSV），只用来验算
    **孤立桶精度**，不参与发现；不给就明确报"未验证"，不猜。
    `cold=True` 追加冷启动口径（`metrics.cold_start`）：不用符号/权威表播种，
    只用入口、初始化表、GOT、字符串引用、指针表与 call 边补全，再拿权威表当分母。
    """
    t0 = time.perf_counter()
    img = open_image(path, allow_large=allow_large)
    bits = image_bits(img)
    space = code_space(img)
    tc = detect_toolchain(img)
    auth = authority_table(img, use_eh_frame=use_eh_frame)
    authority_starts = set(auth.starts)
    auth_token = auth.name.lstrip(".")

    sections = tuple(data_sections) if data_sections else None
    x86 = is_x86(img)
    if x86:
        funcs, notes, refs, evidence, insn_index = discover(
            img, pointers=pointers, ptr_sections=sections,
            authority=auth.spans if auth.usable else [],
            authority_source=auth_token)
    else:
        # 非 x86：解码器与形状库都还没有，只交权威表区间，不假装能发现
        funcs = {b: Function(entry=b, end=e, source=auth_token or "authority")
                 for b, e in auth.spans if e > b}
        notes, refs, evidence, insn_index = [], {}, {}, {}
        arch_name = getattr(img, "machine_name", img.arch)
        notes.append(f"非 x86 架构（{arch_name}）：B 层（递归下降/指针/穷举）尚未实现，"
                     f"只交权威表，end 取自权威表区间")
    if not auth.usable:
        notes.append(f"A 层不适用：{auth.reason}")

    # 反事实：不拿权威表播种，量"我们自己的发现能力"，避免自证。
    cf_funcs: dict[int, Function] = {}
    cf_evidence: dict[int, set[str]] = {}
    if auth.usable and x86:
        cf_funcs, _cf_notes, _cf_refs, cf_evidence, _cf_index = discover(
            img, pointers=pointers, ptr_sections=sections, authority=[],
            authority_source=auth_token)

    authoritative_evidence = {"pdata", "eh_frame", "gopclntab"}
    for start in authority_starts:
        evidence.setdefault(start, set()).add(auth_token)

    exhaust_result: dict[str, Any] | None = None
    if exhaust and x86:
        found, est = _exhaust_functions(
            img, funcs, space, refs, EXHAUST_ALIGN[exhaust], profile, insn_index)
        for fn, reachable in found:
            tok = "exhaust-reachable" if reachable else "exhaust-isolated"
            if fn.entry not in funcs:
                funcs[fn.entry] = fn
                evidence.setdefault(fn.entry, set()).add(tok)
        exhaust_result = est
        exhaust_result["isolated_starts"] = sorted(
            fn.entry for fn, r in found if not r)
        exhaust_result["reachable_starts"] = sorted(
            fn.entry for fn, r in found if r)
        ref_spans = None
        if reference:
            ref_spans = load_reference(reference, reference_base(img))
        exhaust_result["isolated_metrics"] = isolated_metrics(
            exhaust_result["isolated_starts"], ref_spans)
        if reference:
            exhaust_result["isolated_metrics"]["reference_file"] = reference
    elif exhaust:
        notes.append("非 x86：穷举形状库未实现，--exhaust 已跳过")

    # ---- 指标 ----
    index = _range_index((b, e) for b, e in auth.spans if e > b and space.has(b))
    fp_all = sorted(va for va in funcs if _owner_of(va, index) is not None)
    fp_plt = [va for va in fp_all if section_name_at(img, va) == ".plt"]
    fp_text = [va for va in fp_all if section_name_at(img, va) != ".plt"]
    starts_text = [s for s in auth.starts if section_name_at(img, s) != ".plt"]
    hit_text = sorted(authority_starts & set(funcs) &
                      {s for s in starts_text})
    emitted = len(authority_starts & set(funcs))
    recall = emitted / len(auth.starts) if auth.starts else None
    recall_text = (len(hit_text) / len(starts_text)) if starts_text else None

    cf_emitted = cf_fp = cf_fp_text = None
    cf_recall = cf_fp_rate = None
    if auth.usable:
        cf_emitted = len(authority_starts & set(cf_funcs))
        cf_recall = cf_emitted / len(auth.starts) if auth.starts else None
        cf_fp_all = [va for va in cf_funcs if _owner_of(va, index) is not None]
        cf_fp = len(cf_fp_all)
        cf_fp_text = len([v for v in cf_fp_all if section_name_at(img, v) != ".plt"])
        cf_fp_rate = cf_fp_text / len(starts_text) if starts_text else None

    # 冷启动：strip + PIE、导出表空、无调试信息、无权威表时的真实召回。
    cold_result: dict[str, Any] | None = None
    if cold and x86:
        t_cold = time.perf_counter()
        cold_stats: dict[str, Any] = {}
        cold_funcs, cold_notes, _cr, cold_ev, _ci = discover(
            img, pointers=pointers, ptr_sections=sections, authority=[],
            authority_source="entry", cold=True, profile=tc.profile,
            cold_stats=cold_stats)
        cold_fp_all = [va for va in cold_funcs if _owner_of(va, index) is not None]
        cold_fp_text = [v for v in cold_fp_all if section_name_at(img, v) != ".plt"]
        cold_counts: dict[str, int] = {}
        for toks in cold_ev.values():
            for tok in toks:
                cold_counts[tok] = cold_counts.get(tok, 0) + 1
        cold_hit = len(authority_starts & set(cold_funcs))
        # 分母拆分：只算从入口/数据表沿权威函数体自身 call/jmp 可达的起点
        roots: set[int] = {img.image_base + img.entry_rva}
        roots.update(va for va, _tok in _cold_seeds(img, space) if space.has(va))
        if isinstance(img, Elf):
            roots.update(va for va in _relative_relocs(img) if space.has(va))
        ptr_size = PTR_SIZE[image_bits(img)]
        ptr_sections = tuple(default_data_sections(img))
        for s in img.sections:
            if s.is_executable or not s.size_of_raw_data \
                    or s.name not in ptr_sections:
                continue
            roots.update(v for v in _pointer_slots(s.raw, ptr_size) if space.has(v))
        # itablinks 也是数据表，按"指针"边计入可达子集的 root
        roots.update(cold_stats.get("itab_targets") or ())
        reach = _reachable_authority(img, space, auth, roots)
        reach_hit = len(reach & set(cold_funcs))
        cold_result = {
            "emitted": cold_hit,
            "recall": (cold_hit / len(auth.starts)) if auth.starts else None,
            "reachable": {
                "total": len(reach),
                "emitted": reach_hit,
                "recall": (reach_hit / len(reach)) if reach else None,
                "unreachable": len(auth.starts) - len(reach),
            },
            "indirect": {
                "attempts": cold_stats.get("icall_attempts", 0),
                "resolved": cold_stats.get("icall_resolved", 0),
                "seeded": cold_stats.get("icall_seeded", 0),
                "rate": cold_stats.get("icall_rate"),
            },
            "itab": cold_stats.get("itab") or {"supported": False},
            "itab_seeded": cold_stats.get("itab_seeded", 0),
            "fp": len(cold_fp_all),
            "fp_text": len(cold_fp_text),
            "fp_text_rate": (len(cold_fp_text) / len(starts_text)) if starts_text else None,
            "functions": len(cold_funcs),
            "evidence_counts": cold_counts,
            "notes": cold_notes,
            "seconds": round(time.perf_counter() - t_cold, 3),
        }

    rows: list[dict[str, Any]] = []
    for start in sorted(funcs):
        fn = funcs[start]
        tokens = evidence.get(start, set())
        if not tokens:
            tokens = {fn.source} if fn.source else set()
        rows.append({
            "start": start, "end": fn.end, "size": max(0, fn.end - start),
            "insns": fn.insn_count,
            "evidence": [t for t in EVIDENCE_ORDER if t in tokens],
            "evidence_group": _primary_group(tokens),
            "layer": _layer(start, tokens, authority_starts),
            "section": section_name_at(img, start),
        })

    counts: dict[str, int] = {}
    groups: dict[str, int] = {}
    for r in rows:
        for tok in r["evidence"]:
            counts[tok] = counts.get(tok, 0) + 1
        groups[r["evidence_group"]] = groups.get(r["evidence_group"], 0) + 1

    payload: dict[str, Any] = {
        "file": path,
        "format": "ELF" if isinstance(img, Elf) else "PE",
        "arch": img.arch,
        "machine": getattr(img, "machine_name", None) or img.arch,
        "bits": bits,
        "image_base": f"0x{img.image_base:X}",
        "toolchain": {"family": tc.family, "bits": tc.bits,
                      "confidence": round(tc.confidence, 2),
                      "profile": tc.profile, "evidence": tc.evidence},
        "authority": {
            "name": auth.name, "usable": auth.usable,
            "starts": len(auth.starts), "starts_text": len(starts_text),
            "reason": auth.reason, "detail": auth.detail,
        },
        "metrics": {
            "seeded": {
                "emitted": emitted, "recall": recall,
                "recall_text": recall_text,
                "fp": len(fp_all), "fp_plt": len(fp_plt), "fp_text": len(fp_text),
                "fp_text_rate": (len(fp_text) / len(starts_text)) if starts_text else None,
                "outside_authority": len(set(funcs) - authority_starts),
            },
            "counterfactual": {
                "emitted": cf_emitted, "recall": cf_recall,
                "fp": cf_fp, "fp_text": cf_fp_text, "fp_text_rate": cf_fp_rate,
            } if (auth.usable and x86) else None,
            "cold_start": cold_result,
            "evidence_counts": counts,
            "evidence_groups": groups,
        },
        "functions": rows,
        "exhaust": ({k: v for k, v in exhaust_result.items()
                     if k not in ("reachable_starts", "isolated_starts")}
                    if exhaust_result else None),
        "notes": notes,
        "seconds": round(time.perf_counter() - t0, 3),
    }
    if exhaust_result:
        payload["exhaust"]["reachable"] = exhaust_result.get("reachable", 0)
        payload["exhaust"]["isolated"] = exhaust_result.get("isolated", 0)
    return payload


CSV_FIELDS = ("file", "format", "arch", "bits", "layer", "deliverable",
              "evidence", "evidence_group",
              "start", "end", "size", "insns", "section")


def csv_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """把一份 `analyze_image` 结果摊平成 CSV 行（字段含义见 docs/funcs.md）。

    `deliverable` 是给下游的硬标记：B-isolated 恒为 `false`（内部参考，不可交付）。
    """
    out = []
    for f in payload["functions"]:
        out.append({
            "file": payload["file"], "format": payload["format"],
            "arch": payload["arch"], "bits": payload["bits"],
            "layer": f["layer"],
            "deliverable": "true" if f["layer"] != "B-isolated" else "false",
            "evidence": "+".join(f["evidence"]),
            "evidence_group": f["evidence_group"],
            "start": f"0x{f['start']:X}", "end": f"0x{f['end']:X}",
            "size": f["size"], "insns": f["insns"],
            "section": f["section"] or "",
        })
    return out
