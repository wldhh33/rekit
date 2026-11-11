"""手工脱 UPX（PE32+ / NRV2B）：解压 + IAT 重建 + 重定位重建 + 按原布局写文件。

不调用 ``upx -d``，只依据文件字节与 UPX 5.0.0 源码里的格式定义：

  src/packhead.cpp          PackHeader 布局与在 UPX1.rawdataptr-64 起的搜索
  src/pefile.cpp:2949       压缩流起点 = UPX1.rawdataptr - 64 + buf_offset + 32
  src/pefile.cpp:2954-2973  解压尾部：原始 PE 头 + 原节表（skip = le32(blob[u_len-4])）
  src/pefile.cpp:2382-2407  extra_info 顺序：imports(8) → relocs(5) → resources(2)
  src/pefile.cpp:2841-2930  rebuildImports
  src/pefile.cpp:2717-2777  rebuildRelocs + packer_r.cpp:109 unoptimizeReloc
  src/pefile.cpp:2010-2050  写文件：stub + oh + 节表 + 对齐补零 + 各节数据 + overlay
  src/p_w64pe_amd64.cpp:241 SizeOfHeaders = align(pe_offset + 264 + 40*objs, filealign)

对外入口（`rekit unpack`）：
  python -m rekit unpack 样本/packed/hello_rs.packed.exe --out-dir out

每条检查都带"通过/失败 + 证据"，失败时能指到具体环节（PackHeader / 解压 / 反过滤 /
IAT / 重定位 / TLS / DOS stub / 原布局 / 导入表对照）。
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from ..contract import error_entry, no_files_entry
from .files import expand_paths
from .pe import PE, PEError

__all__ = ["UnpackError", "unpack", "unpack_many", "method_name"]

MAGIC = b"UPX!"
PH_SIZE = 32
METHODS = {2: "NRV2B_LE32", 5: "NRV2D_LE32", 8: "NRV2E_LE32", 11: "CL1B_LE32", 14: "LZMA"}

IMPORT, RESOURCE, BASERELOC = 1, 2, 5
DEBUG, BOUND_IMPORT, IAT = 6, 11, 12
DIR64, RELOC_HIGH, RELOC_LOW = 10, 1, 2
ORD_MASK64 = 1 << 63
MASK64 = (1 << 64) - 1


class UnpackError(Exception):
    pass


def align_up(value: int, align: int) -> int:
    return (value + align - 1) // align * align


def method_name(method: int) -> str:
    return METHODS.get(method, f"未知({method})")


def _dir(pe: PE, index: int) -> tuple[int, int]:
    """数据目录 (RVA, size)；缺省返回 (0, 0)。"""
    return pe.directories[index] if index < len(pe.directories) else (0, 0)


def _code_range(oh: bytes) -> tuple[int, int]:
    """可选头里的 (BaseOfCode, SizeOfCode)。

    两者都在基址之后 **+20 / +4**。``+16`` 是 AddressOfEntryPoint，曾经误把它当
    SizeOfCode（见 tests/test_unpack.py::test_size_of_code_offset_regression）：
    反过滤范围被截短后产物照样能跑，只有与原件逐字节比对才暴露。
    对应 UPX 源码 pefile.cpp:2419 ``ft.buf_len = ih.codesize``。
    """
    return u32(oh, 24 + 20), u32(oh, 24 + 4)


def u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def put32(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", buf, off, value)


def put64(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<Q", buf, off, value & MASK64)


def cstr(buf: bytes, off: int, limit: int = 512) -> str:
    end = buf.find(b"\x00", off, off + limit)
    if end < 0:
        raise UnpackError(f"0x{off:X} 处字符串没有 NUL 结尾")
    return buf[off:end].decode("latin-1")


# ---------------------------------------------------------------------------
# PackHeader / 解压 / 反过滤
# ---------------------------------------------------------------------------

@dataclass
class PackHeader:
    file_offset: int
    buf_offset: int
    version: int
    fmt: int
    method: int
    level: int
    u_adler: int
    c_adler: int
    u_len: int
    c_len: int
    u_file_size: int
    filter: int
    filter_cto: int
    n_mru: int
    checksum_ok: bool


def parse_pack_header(data: bytes, upx1_rawptr: int) -> PackHeader:
    lo = max(0, upx1_rawptr - 64)
    hi = min(len(data), upx1_rawptr + 1024)
    pos = data.find(MAGIC, lo, hi)
    if pos < 0:
        raise UnpackError("UPX1 附近没有 'UPX!' 魔数")
    h = data[pos:pos + PH_SIZE]
    return PackHeader(
        file_offset=pos,
        buf_offset=pos - (upx1_rawptr - 64),
        version=h[4], fmt=h[5], method=h[6], level=h[7],
        u_adler=u32(h, 8), c_adler=u32(h, 12),
        u_len=u32(h, 16), c_len=u32(h, 20), u_file_size=u32(h, 24),
        filter=h[28], filter_cto=h[29], n_mru=h[30],
        checksum_ok=h[31] == sum(h[4:31]) % 251,
    )


def nrv2b_le32_decompress(src: bytes, limit: int) -> tuple[bytes, int, str]:
    """UCL getbit_le32 + n2b_d.c，逐位复刻。"""
    ip = 0
    bb = 0
    bc = 0

    def getbit() -> int:
        nonlocal ip, bb, bc
        if bc > 0:
            bc -= 1
            return (bb >> bc) & 1
        bc = 31
        bb = struct.unpack_from("<I", src, ip)[0]
        ip += 4
        return (bb >> 31) & 1

    dst = bytearray()
    last_m_off = 1
    while True:
        while getbit():
            if ip >= len(src):
                return bytes(dst), ip, "src-eof"
            dst.append(src[ip])
            ip += 1
        m_off = 1
        while True:
            m_off = m_off * 2 + getbit()
            if getbit():
                break
        if m_off == 2:
            m_off = last_m_off
        else:
            if ip >= len(src):
                return bytes(dst), ip, "src-eof"
            m_off = (m_off - 3) * 256 + src[ip]
            ip += 1
            if m_off == 0xFFFFFFFF:
                return bytes(dst), ip, "eof"
            last_m_off = m_off + 1
            m_off += 1
        m_len = getbit()
        m_len = m_len * 2 + getbit()
        if m_len == 0:
            m_len += 1
            while True:
                m_len = m_len * 2 + getbit()
                if getbit():
                    break
            m_len += 2
        m_len += 1 if m_off > 0xD00 else 0
        pos = len(dst) - m_off
        if pos < 0:
            return bytes(dst), ip, f"bad-dist({m_off})"
        dst.append(dst[pos])
        pos += 1
        n = m_len
        while n > 0:
            if pos >= len(dst):
                dst.append(0)
            dst.append(dst[pos])
            pos += 1
            n -= 1
        if len(dst) > limit:
            return bytes(dst), ip, "overrun"


def nrv2e_le32_decompress(src: bytes, limit: int) -> tuple[bytes, int, str]:
    """UCL getbit_le32 + n2e_d.S：偏移三位一组，且偏移最低位当作长度的首位。"""
    ip = 0
    bb = 0
    bc = 0

    def getbit() -> int:
        nonlocal ip, bb, bc
        if bc > 0:
            bc -= 1
            return (bb >> bc) & 1
        bc = 31
        bb = struct.unpack_from("<I", src, ip)[0]
        ip += 4
        return (bb >> 31) & 1

    dst = bytearray()
    last_m_off = 1

    def len_more() -> int:
        # lenmore_n2e：len 先置 1，再看一位决定走 lenlast 还是长编码
        n = 1
        if getbit():
            return n * 2 + getbit()
        while True:
            n = n * 2 + getbit()
            if getbit():
                break
        return n + 2

    while True:
        while getbit():
            if ip >= len(src):
                return bytes(dst), ip, "src-eof"
            dst.append(src[ip])
            ip += 1
        m_off = 1
        while True:
            m_off = m_off * 2 + getbit()
            if getbit():
                break
            m_off = (m_off - 1) * 2 + getbit()
        if m_off == 2:
            m_off = last_m_off
            # 上一偏移：先读一位，1 走 lenlast(len=0)，0 走 lenmore
            m_len = getbit() if getbit() else len_more()
        else:
            if ip >= len(src):
                return bytes(dst), ip, "src-eof"
            raw = (m_off - 3) * 256 + src[ip]
            ip += 1
            if raw == 0xFFFFFFFF:
                return bytes(dst), ip, "eof"
            last_m_off = (raw >> 1) + 1
            m_off = last_m_off
            # 汇编先 xorl $~0 再 sar，故取反后的 bit0（即 raw 为偶数）走 lenlast
            m_len = getbit() if not (raw & 1) else len_more()
        m_len += 2 + (1 if m_off > 0x500 else 0)
        pos = len(dst) - m_off
        if pos < 0:
            return bytes(dst), ip, f"bad-dist({m_off})"
        while m_len > 0:
            if pos >= len(dst):
                return bytes(dst), ip, "bad-dist-overrun"
            dst.append(dst[pos])
            pos += 1
            m_len -= 1
        if len(dst) > limit:
            return bytes(dst), ip, "overrun"


def unfilter_ctok32_e8e9(image: bytearray, start: int, length: int, cto8: int) -> tuple[int, int]:
    """filter/ctok.h 的 u_ctok32_e8e9_bswap_le：base 从 codebase 起算，addvalue=0。"""
    size5 = start + length - 5
    cto = cto8 << 24
    lastcall = 0
    calls = noncalls = 0
    ic = start
    while ic < size5:
        x = image[ic]
        cond = x == 0xE8 or x == 0xE9
        if not cond and ic > start:
            cond = lastcall != ic and image[ic - 1] == 0x0F and 0x80 <= x <= 0x8F
        if cond:
            jc = int.from_bytes(image[ic + 1:ic + 5], "big")
            if image[ic + 1] == cto8:
                value = (jc - (ic - start) - 1 - cto) & 0xFFFFFFFF
                image[ic + 1:ic + 5] = value.to_bytes(4, "little")
                calls += 1
                ic += 4
                lastcall = ic + 1
            else:
                noncalls += 1
        ic += 1
    return calls, noncalls


# ---------------------------------------------------------------------------
# 原始头 / 尾部 extra_info
# ---------------------------------------------------------------------------

@dataclass
class Section:
    name: str
    vsize: int
    vaddr: int
    size: int
    rawptr: int


@dataclass
class ExtraInfo:
    cimports: int = 0
    inamespos: int = 0
    crelocs: int = 0
    big: int = 0
    icondir: int = 0
    next_off: int = 0


@dataclass
class Report:
    checks: list[tuple[str, bool, str]] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str) -> None:
        self.checks.append((name, ok, detail))

    @property
    def ok(self) -> bool:
        return all(ok for _n, ok, _d in self.checks)


def parse_original_header(blob: bytes, u_len: int) -> tuple[bytes, list[Section], bytes]:
    skip = u32(blob, u_len - 4)
    if blob[skip:skip + 4] != b"PE\0\0":
        raise UnpackError(f"skip=0x{skip:X} 处不是 PE\\0\\0")
    soh = u16(blob, skip + 20)
    magic = u16(blob, skip + 24)
    if magic != 0x20B:
        raise UnpackError(f"只支持 PE32+（Magic=0x{magic:X}）")
    objs = u16(blob, skip + 6)
    oh = bytes(blob[skip:skip + 24 + soh])
    sec_off = skip + 24 + soh
    secs = []
    for i in range(objs):
        b = sec_off + i * 40
        secs.append(Section(
            name=blob[b:b + 8].rstrip(b"\x00").decode("latin-1"),
            vsize=u32(blob, b + 8), vaddr=u32(blob, b + 12),
            size=u32(blob, b + 16), rawptr=u32(blob, b + 20),
        ))
    return oh, secs, bytes(blob[sec_off:sec_off + objs * 40])


def parse_extra_info(blob: bytes, off: int, oh: bytes, secs: list[Section],
                     packed: PE) -> ExtraInfo:
    ex = ExtraInfo()

    def ddir(index: int) -> tuple[int, int]:
        base = 24 + 112 + index * 8
        return u32(oh, base), u32(oh, base + 4)

    imp_va, imp_sz = ddir(IMPORT)
    if imp_va and imp_sz > 20:
        ex.cimports = u32(blob, off)
        ex.inamespos = u32(blob, off + 4)
        off += 8
    rel_va, rel_sz = ddir(BASERELOC)
    flags = u16(oh, 22)
    if rel_va and rel_sz and not flags & 0x0001:
        ex.crelocs = u32(blob, off)
        ex.big = blob[off + 4] & 6
        off += 5
    res_va, res_sz = ddir(RESOURCE)
    packed_res_va, packed_res_sz = _dir(packed, RESOURCE)
    if res_va and res_sz and packed_res_sz:
        ex.icondir = u16(blob, off)
        off += 2
    ex.next_off = off
    return ex


# ---------------------------------------------------------------------------
# 补洞：IAT / 重定位 / TLS / 头 / 布局
# ---------------------------------------------------------------------------

def rebuild_imports(blob: bytes, image: bytearray, oh: bytes, rvamin: int,
                    ex: ExtraInfo, packed: PE, report: Report) -> dict[str, int]:
    imp_va, imp_sz = u32(oh, 24 + 112 + 8), u32(oh, 24 + 112 + 12)
    if not imp_va or imp_sz <= 20:
        report.add("IAT", True, "原始文件没有导入目录，跳过")
        return {"dlls": 0, "names": 0, "ordinals": 0, "raw": 0}
    if not ex.cimports:
        report.add("IAT", True, "导入表未被搬移（soimport=0），解压数据里保持原样")
        return {"dlls": 0, "names": 0, "ordinals": 0, "raw": 0}
    if len(packed.sections) < 3:
        raise UnpackError("有导入表但 packed 文件不足 3 个节")
    sec2 = packed.sections[2]
    sec2_data = packed.data[sec2.pointer_to_raw_data:
                              sec2.pointer_to_raw_data + sec2.size_of_raw_data]
    import_rva = packed.sections[2].virtual_address
    # 打包时 IDADDR(IMPORT) 指向构建好的 stub 导入表（section 2 内），
    # 表内偏移都以该点为基准。
    packed_imp_va, _ = _dir(packed, IMPORT)
    import_base = packed_imp_va - import_rva
    if import_base < 0 or import_base >= len(sec2_data):
        raise UnpackError(f"packed 导入目录不在 section 2 内（base=0x{import_base:X}）")

    p = ex.cimports
    desc_off = imp_va - rvamin
    dll_cursor = (ex.inamespos - rvamin) if ex.inamespos else None
    names_start = None
    if dll_cursor is not None:
        # 先算 dll 名总长，importednames 从对齐后的位置开始
        q = p
        total = 0
        while u32(blob, q) != 0:
            name_off = u32(blob, q)
            total += len(cstr(sec2_data, import_base + name_off)) + 1
            q += 8
            while blob[q] != 0:
                if blob[q] == 1:
                    q += 1
                    q += len(cstr(blob, q)) + 1
                elif blob[q] == 0xFF:
                    q += 3
                else:
                    q += 5
            q += 1
        names_start = dll_cursor + align_up(total, 2)
        dll_cursor = ex.inamespos - rvamin

    descs: list[tuple[str, int, list[tuple]]] = []
    while u32(blob, p) != 0:
        dll_name = cstr(sec2_data, import_base + u32(blob, p))
        iat_rva = u32(blob, p + 4) + rvamin
        p += 8
        thunks: list[tuple] = []
        while blob[p] != 0:
            if blob[p] == 1:
                name = cstr(blob, p + 1)
                thunks.append(("name", name))
                p += 1 + len(name.encode("latin-1")) + 1
            elif blob[p] == 0xFF:
                thunks.append(("ord", u16(blob, p + 1)))
                p += 3
            else:
                thunks.append(("raw", u64(sec2_data, import_base + u32(blob, p + 1))))
                p += 5
        p += 1
        descs.append((dll_name, iat_rva, thunks))

    name_cursor = names_start
    n_names = n_ord = n_raw = 0
    for index, (dll_name, iat_rva, thunks) in enumerate(descs):
        d = desc_off + index * 20
        raw = dll_name.encode("latin-1") + b"\x00"
        if dll_cursor is not None:
            put32(image, d + 12, dll_cursor + rvamin)
            image[dll_cursor:dll_cursor + len(raw)] = raw
            dll_cursor += len(raw)
        else:
            # inamespos=0：名称区不连续，名字仍在原位，只需把被清零的字符串写回
            at = u32(image, d + 12) - rvamin
            image[at:at + len(raw)] = raw
        put32(image, d + 16, iat_rva)
        iat_off = iat_rva - rvamin
        for j, thunk in enumerate(thunks):
            slot = iat_off + j * 8
            if thunk[0] == "name":
                if name_cursor is not None:
                    if (name_cursor - (names_start or 0)) & 1:
                        name_cursor -= 1
                    value = name_cursor + rvamin
                    put64(image, name_cursor, 0)          # hint = 0
                    raw = thunk[1].encode("latin-1") + b"\x00"
                    image[name_cursor + 2:name_cursor + 2 + len(raw)] = raw
                    name_cursor += 2 + len(raw)
                else:
                    value = u64(image, slot)
                    raw = thunk[1].encode("latin-1") + b"\x00"
                    image[value - rvamin + 2:value - rvamin + 2 + len(raw)] = raw
                n_names += 1
            elif thunk[0] == "ord":
                value = thunk[1] | ORD_MASK64
                n_ord += 1
            else:
                value = thunk[1]
                n_raw += 1
            put64(image, slot, value)
        put64(image, iat_off + len(thunks) * 8, 0)
    # 描述符数组的结束项
    end = desc_off + len(descs) * 20
    if end + 20 <= len(image):
        image[end:end + 20] = b"\x00" * 20
    report.add("IAT", True,
               f"{len(descs)} 个 DLL / {n_names + n_ord + n_raw} 个符号"
               f"（名称 {n_names}、序号 {n_ord}、预置 {n_raw}）")
    return {"dlls": len(descs), "names": n_names, "ordinals": n_ord, "raw": n_raw}


def rebuild_relocs(blob: bytes, image: bytearray, oh: bytes, rvamin: int,
                   ex: ExtraInfo, report: Report) -> dict[str, int]:
    rel_va, rel_sz = u32(oh, 24 + 112 + 5 * 8), u32(oh, 24 + 112 + 5 * 8 + 4)
    flags = u16(oh, 22)
    if not rel_va or not rel_sz or flags & 0x0001:
        report.add("重定位", True, "原始文件无重定位目录（或被标记 stripped），跳过")
        return {"dir64": 0, "other": 0, "bytes": 0}
    imagebase = u64(oh, 24 + 24)
    image_len = ex.crelocs
    q = ex.crelocs
    pc = -4
    positions: list[int] = []
    while blob[q] != 0:
        b = blob[q]
        if b < 0xF0:
            delta = b
            q += 1
        else:
            delta = (b & 0x0F) * 0x10000 + u16(blob, q + 1)
            q += 3
            if delta == 0:
                delta = u32(blob, q)
                q += 4
        if delta < 4:
            raise UnpackError("重定位增量 < 4（overlapping fixups）")
        pc += delta
        if pc < 0 or pc + 8 > image_len:
            raise UnpackError(f"重定位位置越界：pc=0x{pc:X}，image_len=0x{image_len:X}")
        positions.append(pc)
    q += 1  # 跳过结束符

    for pc in positions:
        value = int.from_bytes(image[pc:pc + 8], "big")  # 打包时 bswap 成 BE
        value = (value + imagebase + rvamin) & MASK64
        put64(image, pc, value)

    relocs: list[tuple[int, int]] = [(rvamin + pc, DIR64) for pc in positions]
    if ex.big & 6:
        extra_positions = []
        r = q
        while u32(blob, r) != 0:
            extra_positions.append(u32(blob, r))
            r += 4
        r += 4
        for pos in extra_positions:
            relocs.append((pos + rvamin, RELOC_LOW if ex.big & 4 else RELOC_HIGH))
        if (ex.big & 6) == 6:
            while u32(blob, r) != 0:
                relocs.append((u32(blob, r) + rvamin, RELOC_HIGH))
                r += 4

    blocks = bytearray()
    current_page = None
    entries: list[int] = []
    for pos, rtype in sorted(relocs):
        page = pos & ~0xFFF
        if current_page is None or page != current_page:
            if current_page is not None:
                blocks += _reloc_block(current_page, entries)
            current_page = page
            entries = []
        entries.append((rtype << 12) | (pos & 0xFFF))
    if current_page is not None:
        blocks += _reloc_block(current_page, entries)

    off = rel_va - rvamin
    if off + len(blocks) > len(image):
        raise UnpackError(f".reloc 放不下：需要 0x{len(blocks):X} 字节")
    image[off:off + len(blocks)] = blocks
    put32(oh, 24 + 112 + 5 * 8 + 4, len(blocks))
    report.add("重定位", True,
               f"{len(positions)} 条 64 位 + {len(relocs) - len(positions)} 条 16 位，"
               f".reloc 重建 {len(blocks)} 字节，指针已加回 ImageBase+0x{rvamin:X}")
    return {"dir64": len(positions), "other": len(relocs) - len(positions), "bytes": len(blocks)}


def _reloc_block(page: int, entries: list[int]) -> bytes:
    data = b"".join(struct.pack("<H", e) for e in entries)
    size = 8 + len(data)
    pad = (-size) % 4
    data += b"\x00" * pad
    size += pad
    return struct.pack("<II", page, size) + data


def check_tls(oh: bytes, image: bytearray, rvamin: int, report: Report) -> None:
    tls_va, tls_sz = u32(oh, 24 + 112 + 9 * 8), u32(oh, 24 + 112 + 9 * 8 + 4)
    if not tls_va or not tls_sz:
        report.add("TLS", True, "原始文件无 TLS 目录，无需补")
        return
    off = tls_va - rvamin
    if off < 0 or off + tls_sz > len(image):
        report.add("TLS", False, f"TLS 目录越界：RVA=0x{tls_va:X}")
        return
    # rebuildTls 在 UPX 源码里是空函数：TLS 结构原本就在镜像数据里，只需确认它还在
    imagebase = u64(oh, 24 + 24)
    start = u64(image, off + 8)
    report.add("TLS", start >= imagebase,
               f"TLS 目录 RVA=0x{tls_va:X}，StartAddressOfRawData=0x{start:X}"
               f"（UPX 的 rebuildTls 为空，原结构在解压数据中）")


def check_exception(oh: bytes, image: bytearray, rvamin: int, report: Report) -> None:
    """异常表（.pdata / RUNTIME_FUNCTION）随镜像一起解压，只验证未被截断。"""
    va, size = u32(oh, 24 + 112 + 3 * 8), u32(oh, 24 + 112 + 3 * 8 + 4)
    if not va or not size:
        report.add("异常表", True, "原始文件无异常目录（非 x64 或已 stripped），跳过")
        return
    off = va - rvamin
    ok = off >= 0 and off + size <= len(image)
    report.add("异常表", ok,
               f"{size // 12} 条 RUNTIME_FUNCTION，RVA=0x{va:X} 起 {size} 字节"
               + ("" if ok else "，超出解压镜像"))


RT_GROUP_ICON = 14


class _ResBranch:
    """资源目录节点：原始 16+8n 字节头 + 子节点。"""

    __slots__ = ("id", "name", "data", "children")

    def __init__(self, data: bytes):
        self.id = 0
        self.name: bytes | None = None
        self.data = data
        self.children: list = []


class _ResLeaf:
    """资源数据项：16 字节 IMAGE_RESOURCE_DATA_ENTRY。"""

    __slots__ = ("id", "name", "data", "type_id", "newoff")

    def __init__(self, data: bytes, type_id: int):
        self.id = 0
        self.name: bytes | None = None
        self.data = data
        self.type_id = type_id
        self.newoff = 0

    @property
    def offset(self) -> int:
        return u32(self.data, 0)

    @property
    def size(self) -> int:
        return align_up(u32(self.data, 4), 4)


def _parse_resource_tree(blob: bytes, start: int) -> tuple[_ResBranch | None, list[_ResLeaf],
                                                           int, int]:
    """按 UPX Resource::convert 的层级规则（0/1 目录、2 数据项）建树。

    返回 (root, leaves, dsize, ssize)；dsize 是全部目录结构字节数，ssize 是名称区字节数。
    """
    end = len(blob)
    leaves: list[_ResLeaf] = []
    dsize = ssize = 0

    def convert(off: int, level: int, type_id: int):
        nonlocal dsize, ssize
        if off < start or off + 16 > end:
            raise UnpackError(f"资源目录越界：blob 偏移 0x{off:X}")
        if level == 3:
            leaf = _ResLeaf(blob[off:off + 16], type_id)
            leaves.append(leaf)
            dsize += 16
            return leaf

        named, ident = u16(blob, off + 12), u16(blob, off + 14)
        n = named + ident
        if n == 0:
            return None
        if off + 16 + 8 * n > end:
            raise UnpackError(f"资源目录条目越界：blob 偏移 0x{off:X}，{n} 项")
        node = _ResBranch(blob[off:off + 16 + 8 * n])
        for i in range(n):
            entry = off + 16 + i * 8
            tnl, child = u32(blob, entry), u32(blob, entry + 4)
            if bool(child & 0x80000000) != (level < 2):
                raise UnpackError(f"资源目录结构异常：层 {level} 的 child=0x{child:08X}")
            sub = convert(child & 0x7FFFFFFF, level + 1,
                          tnl if level == 0 and not (tnl & 0x80000000) else type_id)
            if sub is None:
                continue
            sub.id = tnl
            if tnl & 0x80000000:
                p = start + (tnl & 0x7FFFFFFF)
                if p + 2 > end:
                    raise UnpackError(f"资源名称越界：blob 偏移 0x{p:X}")
                name = blob[p:p + 2 + 2 * u16(blob, p)]
                if p + len(name) > end:
                    raise UnpackError(f"资源名称越界：blob 偏移 0x{p:X}")
                sub.name = name
                ssize += len(name)
            node.children.append(sub)
        dsize += 16 + 8 * n
        return node

    return convert(start, 0, 0), leaves, dsize, ssize


def _build_resource_tree(root: _ResBranch, dsize: int, dirsize: int, spos: int) -> bytes:
    """复刻 Resource::build：目录按遍历顺序排，名称区从 dsize 起。"""
    buf = bytearray(dirsize)
    bpos = 0

    def build(node, level: int) -> None:
        nonlocal bpos, spos
        if level == 3:
            buf[bpos:bpos + 16] = node.data
            if node.newoff:
                put32(buf, bpos, node.newoff)
            bpos += 16
            return
        base = bpos
        buf[base:base + len(node.data)] = node.data
        bpos = base + len(node.data)
        for i, child in enumerate(node.children):
            entry = base + 16 + i * 8
            put32(buf, entry, child.id)
            put32(buf, entry + 4, bpos | (0x80000000 if level < 2 else 0))
            if child.name is not None:
                put32(buf, entry, spos | 0x80000000)
                buf[spos:spos + len(child.name)] = child.name
                spos += len(child.name)
            build(child, level + 1)

    build(root, 0)
    return bytes(buf)


def rebuild_resources(packed: PE, image: bytearray, oh: bytes, rvamin: int,
                      ex: ExtraInfo, report: Report) -> dict[str, int]:
    """复刻 PeFile::rebuildResources：把未压缩资源从壳区拷回原 RVA 并重建目录。"""
    out_va, out_sz = u32(oh, 24 + 112 + 2 * 8), u32(oh, 24 + 112 + 2 * 8 + 4)
    in_va, in_sz = _dir(packed, RESOURCE)
    if not out_sz or not in_sz:
        report.add("资源", True, "原始文件无资源目录，跳过")
        return {"entries": 0, "copied": 0, "dir_bytes": 0}

    # 打包后资源目录与数据被搬到最后一个节（3 节样本是 UPX2/.rsrc，4 节样本是第 4 节）
    sec = packed.sections[3] if packed.number_of_sections >= 4 else packed.sections[2]
    blob = sec.raw
    lastvaddr = sec.virtual_address
    if in_va < lastvaddr or in_va - lastvaddr > len(blob):
        raise UnpackError(f"资源目录 RVA=0x{in_va:X} 不在壳区 0x{lastvaddr:X} 之后")

    root, leaves, dsize, ssize = _parse_resource_tree(blob, in_va - lastvaddr)
    if root is None:
        report.add("资源", True, "资源目录为空，跳过")
        return {"entries": 0, "copied": 0, "dir_bytes": 0}

    icondir = ex.icondir
    copied = 0
    for leaf in leaves:
        offs = leaf.offset
        if offs <= in_va:
            continue  # 仍在镜像里的条目（压缩资源），不搬
        src = offs - in_va
        if src < 4 or src + leaf.size > len(blob):
            raise UnpackError(f"资源数据越界：RVA=0x{offs:X}")
        origoffs = u32(blob, src - 4)
        leaf.newoff = origoffs
        dst = origoffs - rvamin
        if dst < 0 or dst + leaf.size > len(image):
            raise UnpackError(f"资源写回越界：RVA=0x{origoffs:X}")
        image[dst:dst + leaf.size] = blob[src:src + leaf.size]
        if icondir and leaf.type_id == RT_GROUP_ICON:
            struct.pack_into("<H", image, dst + 4, icondir)
            icondir = 0
        copied += 1

    dirsize = align_up(dsize + ssize, 4)
    newdir = _build_resource_tree(root, dsize, dirsize, dsize)
    diraddr = out_va - rvamin
    if diraddr < 0 or diraddr + dirsize > len(image):
        raise UnpackError(f"资源目录写回越界：RVA=0x{out_va:X}")
    wrote = u32(image, diraddr + 12) == 0  # 原目录区被清零时才写回
    if wrote:
        image[diraddr:diraddr + dirsize] = newdir

    report.add("资源", True,
               f"{len(leaves)} 个数据项，搬回 {copied} 个；目录重建 {dirsize} 字节"
               f"（dsize={dsize}, names={ssize}）{'，已写回' if wrote else '，原位保留'}")
    return {"entries": len(leaves), "copied": copied, "dir_bytes": dirsize}


def check_layout(sections: int, oep: int, headers: int, raw: PE, report: Report) -> None:
    ok = sections == raw.number_of_sections and oep == raw.entry_rva
    report.add("原布局", ok,
               f"{sections} 个节、OEP=0x{oep:X}、SizeOfHeaders=0x{headers:X}"
               f"（原件 {raw.number_of_sections} 个节、OEP=0x{raw.entry_rva:X}）")


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def unpack(packed_path: Path, out_path: Path | None, verify_only: bool = False) -> dict:
    data = packed_path.read_bytes()
    packed = PE(str(packed_path))
    report = Report()

    upx1 = next((s for s in packed.sections if s.name == "UPX1"), None)
    if upx1 is None:
        raise UnpackError("找不到 UPX1 节，不是标准 UPX 样本")
    ph = parse_pack_header(data, upx1.pointer_to_raw_data)
    decoders = {2: nrv2b_le32_decompress, 8: nrv2e_le32_decompress}
    if ph.method not in decoders:
        raise UnpackError(f"暂只实现 NRV2B（method=2）/ NRV2E（method=8），本样本 method={ph.method}"
                          f"（{METHODS.get(ph.method, '未知')}）")
    report.add("PackHeader", ph.checksum_ok,
               f"method={ph.method}（{METHODS[ph.method]}），u_len=0x{ph.u_len:X}，c_len=0x{ph.c_len:X}")

    stream_off = upx1.pointer_to_raw_data - 64 + ph.buf_offset + PH_SIZE
    blob, consumed, status = decoders[ph.method](data[stream_off:stream_off + ph.c_len],
                                                 ph.u_len + 16)
    ok_stream = consumed == ph.c_len and status == "eof"
    ok_len = len(blob) == ph.u_len
    ok_adler = (zlib.adler32(blob) & 0xFFFFFFFF) == ph.u_adler
    report.add("解压", ok_stream and ok_len and ok_adler,
               f"{len(blob):,} 字节，消费 {consumed:,}/{ph.c_len:,}，adler "
               f"{'一致' if ok_adler else '不一致'}")

    oh_bytes, secs, sec_table = parse_original_header(blob, ph.u_len)
    oh = bytearray(oh_bytes)
    rvamin = secs[0].vaddr
    sizeimage = u32(oh, 24 + 56)
    filealign = u32(oh, 24 + 36)
    image = bytearray(blob[:sizeimage - rvamin])

    codebase, codesize = _code_range(oh)
    unfilter = {"filter": f"0x{ph.filter:02X}", "start": codebase - rvamin,
                "size": codesize, "calls": 0, "skipped": 0}
    if ph.filter == 0x49:
        start = codebase - rvamin
        calls, skipped = unfilter_ctok32_e8e9(image, start, codesize, ph.filter_cto)
        unfilter["calls"], unfilter["skipped"] = calls, skipped
        report.add("反过滤", True,
                   f"filter=0x49，范围 [0x{start:X}, +0x{codesize:X}) = SizeOfCode，"
                   f"改写 {calls} 处，跳过 {skipped} 处")
    elif ph.filter == 0:
        report.add("反过滤", True, "无过滤器")
    else:
        raise UnpackError(f"不支持的过滤器 0x{ph.filter:02X}")

    skip = _skip(blob, ph.u_len)
    extra_off = skip + 24 + u16(blob, skip + 20) + len(secs) * 40
    ex = parse_extra_info(blob, extra_off, oh, secs, packed)
    iat = rebuild_imports(blob, image, oh, rvamin, ex, packed, report)
    reloc = rebuild_relocs(blob, image, oh, rvamin, ex, report)
    resrc = rebuild_resources(packed, image, oh, rvamin, ex, report)
    check_tls(oh, image, rvamin, report)
    check_exception(oh, image, rvamin, report)

    # 头部修正：headersize、chksum、清掉 debug/IAT/bound（与 UPX 一致）
    pe_offset = packed.e_lfanew
    put32(oh, 24 + 60, align_up(pe_offset + len(oh) + 40 * len(secs), filealign))
    put32(oh, 24 + 64, 0)
    for index in (DEBUG, IAT, BOUND_IMPORT):
        put32(oh, 24 + 112 + index * 8, 0)
        put32(oh, 24 + 112 + index * 8 + 4, 0)

    out = bytearray(data[:pe_offset])
    out += oh
    out += sec_table
    first_raw = next((s.rawptr for s in secs if s.rawptr), 0)
    if len(out) > first_raw:
        raise UnpackError(f"头部 0x{len(out):X} 超过首节 RawPtr 0x{first_raw:X}")
    out += b"\x00" * (first_raw - len(out))
    for s in secs:
        if not s.rawptr:
            continue
        n = align_up(s.size, filealign)
        chunk = bytes(image[s.vaddr - rvamin:s.vaddr - rvamin + n])
        if len(chunk) < n:
            chunk += b"\x00" * (n - len(chunk))
        if len(out) < s.rawptr:
            out += b"\x00" * (s.rawptr - len(out))
        out += chunk

    last = packed.sections[-1]
    overlay = len(data) - align_up(last.pointer_to_raw_data + last.size_of_raw_data,
                                   packed.file_alignment)
    if overlay > 0:
        out += blob[ph.u_len - overlay:]

    report.add("DOS stub", out[:2] == b"MZ" and out[pe_offset:pe_offset + 4] == b"PE\0\0"
               and bytes(out[:pe_offset]) == data[:pe_offset],
               f"复制原始 stub 0x{pe_offset:X} 字节")

    out_bytes = bytes(out)
    written = out_path is not None and not verify_only
    if written:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(out_bytes)

    diff = {"reference": None, "text_size": None, "text_mismatch": None,
            "file_size": None, "file_mismatch": None}
    raw_path = _guess_raw(packed_path)
    if raw_path is not None:
        raw_pe = PE(str(raw_path))
        diff["reference"] = str(raw_path)
        diff.update(_diff_against(out_bytes, raw_pe))
        check_layout(len(secs), u32(oh, 24 + 16), u32(oh, 24 + 60), raw_pe, report)
        if written:
            _compare_imports(PE(str(out_path)), raw_pe, report)
        else:
            total = iat["names"] + iat["ordinals"] + iat["raw"]
            raw_total = len(raw_pe.imports())
            report.add("导入表对照", total == raw_total, f"脱壳 {total} / 原件 {raw_total} 个符号")
        report.add("逐字节对照", diff["text_mismatch"] == 0,
                   f".text {diff['text_size']:,} 字节中 {diff['text_mismatch']:,} 字节不同；"
                   f"整文件 {diff['file_size']:,} 字节中 {diff['file_mismatch']:,} 字节不同"
                   f"（DEBUG/IAT 目录项、调试记录与导入名区由 UPX 规范化）")

    return {
        "packed": str(packed_path),
        "raw": diff["reference"],
        "out": str(out_path) if written else None,
        "path_used": f"静态还原（UPX {ph.version} / {METHODS[ph.method]} / filter=0x{ph.filter:02X}）",
        "upx": {
            "version": ph.version, "format": ph.fmt, "method": ph.method,
            "method_name": METHODS[ph.method], "level": ph.level,
            "header_offset": f"0x{ph.file_offset:X}", "checksum_ok": ph.checksum_ok,
        },
        "unpacked_bytes": ph.u_len,
        "compressed_bytes": ph.c_len,
        "consumed_bytes": consumed,
        "adler": {"declared": f"0x{ph.u_adler:08X}",
                  "actual": f"0x{zlib.adler32(blob) & 0xFFFFFFFF:08X}", "ok": ok_adler},
        "unfilter": unfilter,
        "imports": iat,
        "relocs": reloc,
        "resources": resrc,
        "layout": {
            "sections": len(secs), "oep": f"0x{u32(oh, 24 + 16):X}",
            "size_of_headers": f"0x{u32(oh, 24 + 60):X}", "file_size": len(out_bytes),
        },
        "diff": diff,
        "checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in report.checks],
        "ok": report.ok,
    }


def _skip(blob: bytes, u_len: int) -> int:
    return u32(blob, u_len - 4)


def _guess_raw(packed_path: Path) -> Path | None:
    name = packed_path.name
    raw_name = None
    for suffix in (".packed.exe", ".packed"):
        if name.endswith(suffix):
            raw_name = name[:-len(suffix)] + ".exe"
            break
    if not raw_name:
        return None
    for candidate in (packed_path.with_name(raw_name),
                      packed_path.parent.parent / "raw" / raw_name):
        if candidate.exists():
            return candidate
    return None


def _import_set(pe: PE) -> set[tuple[str, str]]:
    return {(imp.dll.lower(), (imp.name or f"#{imp.ordinal}").lower()) for imp in pe.imports()}


def _compare_imports(out: PE, raw: PE, report: Report) -> None:
    mine, theirs = _import_set(out), _import_set(raw)
    missing = sorted(theirs - mine)[:5]
    extra = sorted(mine - theirs)[:5]
    ok = not missing and not extra
    report.add("导入表对照", ok,
               f"脱壳 {len(mine)} / 原件 {len(theirs)} 个符号"
               + ("" if ok else f"；缺 {missing}；多 {extra}"))


def _diff_against(out_bytes: bytes, raw: PE) -> dict[str, int | None]:
    """与未加壳原件逐字节对照：.text 单列，整文件含头部/overlay。"""
    text = next((s for s in raw.sections if s.name == ".text"), None)
    text_size = text_mismatch = None
    if text is not None:
        lo = text.pointer_to_raw_data
        hi = lo + text.size_of_raw_data
        a, b = out_bytes[lo:hi], raw.data[lo:hi]
        text_size = len(b)
        text_mismatch = sum(x != y for x, y in zip(a, b)) + abs(len(a) - len(b))

    n = min(len(out_bytes), len(raw.data))
    return {
        "text_size": text_size,
        "text_mismatch": text_mismatch,
        "file_size": len(raw.data),
        "file_mismatch": sum(x != y for x, y in zip(out_bytes[:n], raw.data[:n]))
                         + abs(len(out_bytes) - len(raw.data)),
    }


def unpack_many(paths: list[str], out_dir: Path | None,
                verify_only: bool = False) -> dict:
    """批量入口：展开路径，逐个脱壳，返回 ``{results, errors}``。"""
    files = expand_paths(paths)
    if not files:
        return {"results": [], "errors": [no_files_entry(paths, "可脱壳")]}

    results: list[dict] = []
    errors: list[dict[str, str]] = []
    for path in files:
        src = Path(path)
        out_path = None
        if not verify_only:
            target_dir = out_dir or Path.cwd() / "unpacked"
            stem = src.name[:-len(".packed.exe")] if src.name.lower().endswith(".packed.exe") \
                else (src.name[:-4] if src.name.lower().endswith(".exe") else src.name)
            out_path = target_dir / f"{stem}.unpacked.exe"
        try:
            results.append(unpack(src, out_path, verify_only=verify_only))
        except (UnpackError, PEError, OSError) as exc:
            errors.append(error_entry(path, exc))
    return {"results": results, "errors": errors}
