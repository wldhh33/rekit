# -*- coding: utf-8 -*-
"""只读的 Rust 语言证据：rustc 提交哈希、crate 清单、panic 站点、`&str` 布局。

**不参与** `identify` 的 family / verdict / confidence，也不改任何冻结口径。
判据与边界见 `docs/rust.md`。

为什么单独一层：Windows 上的 Rust 官方目标 `x86_64-pc-windows-msvc` 用的是
MSVC 链接器，Rich 头、linker version、CRT 导入集与 C/C++ 产物无法区分——
那些是**工具链证据**，不是语言证据。Rust 的语言证据只落在字符串与节布局里。
"""

from __future__ import annotations

import re
import struct
from typing import Any, Iterable

from . import funcs
from .pe import PE

# `/rustc/<40 位提交>/library\std\...`：官方发行版在编译 std 时把源码根替换成这个前缀。
# 提交号后的分隔符两种都见过：fd 用 `/`，eza 用 `\`。
RUSTC_RE = re.compile(r"/rustc/([0-9a-f]{40})[\\/]")
# cargo registry 里的依赖源码路径：`...\.cargo\registry\src\<index>-<hash>\<name>-<ver>\src\...`
# 版本可带预发布或构建元数据（`libgit2-sys-0.18.5+1.9.4`、`ash-0.38.0+1.3.281`）。
CRATE_RE = re.compile(
    r"[\\/]registry[\\/]src[\\/][^\\/]{1,80}[\\/]"
    r"([A-Za-z0-9_.+-]{1,64})-([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?)(?:[\\/]|$)")
# rustup 工具链目录：`...\.rustup\toolchains\stable-x86_64-pc-windows-msvc\...`
RUSTUP_RE = re.compile(r"[\\/]\.rustup[\\/]toolchains[\\/]([^\\/]{1,80})")
# 构建机用户目录：`C:\Users\<user>\...`
USERDIR_RE = re.compile(r"^([A-Za-z]:[\\/]Users[\\/][^\\/]{1,64})")

# 路径串必须从「根」开始才算独立路径：`.rdata` 里相邻字面量会被链接器尾部合并，
# 直接按「以 .rs 结尾」切会把 `...stdinsrc/main.rs` 当成源码路径。
ROOT_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/]|src[\\/]|library[\\/]|crates[\\/]|rustc[\\/])")

PANIC_MARKERS = (
    "panicked at",
    "called `Result::unwrap()`",
    "called `Option::unwrap()`",
    "index out of bounds",
    "attempt to subtract with overflow",
    "attempt to add with overflow",
    "slice index starts at",
    "byte index",
)

_PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")
# UTF-16LE 路径（Windows 宽字符字面量）：deno 的 `libz-sys-1.1.20` 只以这种形式存在。
_PRINTABLE_W = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
# 链接器尾部合并会把消息与它后面的路径粘成一串（fd 实测有一条 1,016 字节），
# 截得太短会把 crate 路径切掉；上限只用于挡住无 NUL 的数据块。
MAX_STRING = 4096


def ascii_strings(pe: PE, *, min_len: int = 6) -> list[tuple[int, bytes]]:
    """非可执行节里的字符串（UTF-8/ASCII 与 UTF-16LE），返回 (VA, bytes)。

    只扫非可执行节：Rust 的路径与 panic 消息都在 `.rdata`/`.data`，扫 `.text`
    只会把指令字节切成伪字符串。UTF-16LE 一侧用于宽字符路径（实测只有 deno 命中）。
    """
    out: list[tuple[int, bytes]] = []
    for sec in pe.sections:
        if sec.is_executable:
            continue
        base = pe.image_base + sec.virtual_address
        raw = bytes(sec.raw)
        for m in _PRINTABLE.finditer(raw):
            s = m.group(0)
            if len(s) < min_len:
                continue
            # 长串按 MAX_STRING 截断，避免把整块数据当成一个字符串
            if len(s) > MAX_STRING:
                s = s[:MAX_STRING]
            out.append((base + m.start(), s))
        for m in _PRINTABLE_W.finditer(raw):
            s = m.group(0).decode("utf-16-le").encode("latin-1", "replace")
            if len(s) < min_len:
                continue
            out.append((base + m.start(), s[:MAX_STRING]))
    return out


def _classify(strings: Iterable[tuple[int, bytes]]) -> dict[str, Any]:
    rustc: dict[str, int] = {}
    crates: dict[str, int] = {}
    rustup: dict[str, int] = {}
    users: dict[str, int] = {}
    rs_paths: dict[str, int] = {}
    buckets = {"std": 0, "crate": 0, "app": 0}
    embedded = 0
    markers: dict[str, int] = {}
    for _va, raw in strings:
        s = raw.decode("latin-1")
        for m in RUSTC_RE.finditer(s):
            rustc[m.group(1)] = rustc.get(m.group(1), 0) + 1
        for m in CRATE_RE.finditer(s):
            key = f"{m.group(1)}-{m.group(2)}"
            crates[key] = crates.get(key, 0) + 1
        for m in RUSTUP_RE.finditer(s):
            rustup[m.group(1)] = rustup.get(m.group(1), 0) + 1
        um = USERDIR_RE.match(s)
        if um:
            users[um.group(1)] = users.get(um.group(1), 0) + 1
        if s.endswith(".rs"):
            rs_paths[s] = rs_paths.get(s, 0) + 1
            low = s.lower()
            if not ROOT_RE.match(s):
                embedded += 1
            elif "/rustc/" in low or "library\\" in low or "library/" in low:
                buckets["std"] += 1
            elif ".cargo" in low or "registry\\src" in low or "registry/src" in low:
                buckets["crate"] += 1
            else:
                buckets["app"] += 1
        for mk in PANIC_MARKERS:
            if mk in s:
                markers[mk] = markers.get(mk, 0) + 1
    return {
        "rustc_commits": sorted(rustc, key=lambda k: -rustc[k]),
        "crates": [{"crate": k, "strings": v} for k, v in sorted(crates.items())],
        "rustup_toolchains": sorted(rustup, key=lambda k: -rustup[k]),
        "build_users": sorted(users, key=lambda k: -users[k]),
        "path_strings": {"total": len(rs_paths), "embedded": embedded, **buckets},
        "app_paths": [k for k in sorted(rs_paths)[:12]],
        "panic_markers": markers,
    }


def _header_facts(pe: PE) -> dict[str, Any]:
    """符号/节/调试目录事实：用来回答「能不能恢复函数名」。"""
    fh = pe.e_lfanew + 4
    ptr_sym = pe.r.u32(fh + 12)
    n_sym = pe.r.u32(fh + 16)
    names = [s.name for s in pe.sections]
    fp = next((s for s in pe.sections if s.name == ".fptable"), None)
    fp_zero = None
    if fp is not None:
        raw = bytes(fp.raw)
        fp_zero = bool(raw) and not any(raw)
    try:
        exports = len(pe.exports())
    except Exception:  # 导出目录损坏时不阻断其余事实
        exports = None
    dbg_type = 6
    debug: list[dict[str, Any]] = []
    pdb = None
    if len(pe.directories) > dbg_type:
        rva, size = pe.directories[dbg_type]
        foa = pe.rva_to_foa(rva) if rva else None
        if foa is not None and size >= 28:
            for off in range(foa, min(foa + size, len(pe.data)) - 27, 28):
                typ = pe.r.u32(off + 12)
                sz = pe.r.u32(off + 16)
                ptr = pe.r.u32(off + 24)
                debug.append({"type": typ, "size": sz})
                if typ == 2 and ptr and sz >= 25:  # CodeView RSDS
                    blob = bytes(pe.data[ptr:ptr + sz])
                    if blob[:4] == b"RSDS":
                        end = blob.find(b"\x00", 24)
                        pdb = blob[24:end if end > 0 else len(blob)].decode("latin-1")
    return {
        "coff_symbols": n_sym if ptr_sym else 0,
        "exports": exports,
        "name_status": "coff" if (ptr_sym and n_sym) else (
            "export" if exports else "none"),
        "sections": names,
        "text_size": sum(len(s.raw) for s in pe.sections if s.is_executable),
        "pdata_entries": len(funcs.pdata_spans(pe)),
        "debug_entries": debug,
        "pdb": pdb,
        "fptable": None if fp is None else {
            "present": True, "size": int(fp.virtual_size), "all_zero": fp_zero},
    }


def str_pair_index(pe: PE, strings: Iterable[tuple[int, bytes]]) -> dict[int, int]:
    """找 `&'static str` 常量对：返回 {常量对 VA: 字符串 VA}。

    Rust 把 `&str` 常量存成 (ptr, len) 两个 u64，代码里 `lea` 的是**常量对的地址**，
    不是字符串本身。所以要把 crate 路径归到函数，必须从常量对反查字符串。
    """
    want = {va: len(s) for va, s in strings if s.endswith(b".rs")}
    if not want:
        return {}
    out: dict[int, int] = {}
    for sec in pe.sections:
        if sec.is_executable:
            continue
        base = pe.image_base + sec.virtual_address
        raw = bytes(sec.raw)
        for i in range(0, len(raw) - 15, 8):
            va = struct.unpack_from("<Q", raw, i)[0]
            ln = want.get(va)
            if ln is not None and struct.unpack_from("<Q", raw, i + 8)[0] == ln:
                out[base + i] = va
    return out


def static_str_pairs(pe: PE, strings: Iterable[tuple[int, bytes]]) -> dict[str, Any]:
    """核对 `&'static str` 的 (ptr, len) 布局，只做只读事实统计。"""
    checked = sum(1 for _va, s in strings if s.endswith(b".rs"))
    idx = str_pair_index(pe, strings)
    return {"checked": checked, "with_pair": len(set(idx.values())), "pairs": len(idx)}


def map_refs(pe: PE, targets: dict[int, str], *, max_text_mb: int = 64) -> dict[str, Any]:
    """`.text` 单遍解码，找 `lea r64,[rip+disp]` 命中目标字符串的引用。

    返回「字符串 → 引用指令 → 所属 `.pdata` 函数起点」的聚合。
    没有 `.pdata` 或 `.text` 超过上限时返回 `reason`，不猜。
    """
    spans = funcs.pdata_spans(pe)
    if not spans:
        return {"reason": "无 .pdata，无法把引用归到函数", "refs": 0, "functions": 0}
    text = sum(len(s.raw) for s in pe.sections if s.is_executable)
    if text > max_text_mb * 2 ** 20:
        return {"reason": f"可执行字节 {text / 2**20:.1f} MiB 超过上限"
                          f"（--max-text-mb {max_text_mb}）", "refs": 0, "functions": 0}
    import bisect
    starts = [s for s, _ in spans]

    def owner(va: int) -> int | None:
        k = bisect.bisect_right(starts, va) - 1
        if k >= 0 and spans[k][0] <= va < spans[k][1]:
            return spans[k][0]
        return None

    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, CS_MODE_32, Cs
        from capstone.x86 import X86_OP_MEM, X86_REG_RIP
    except Exception as e:  # pragma: no cover - capstone 是硬依赖
        return {"reason": f"capstone 不可用: {e}", "refs": 0, "functions": 0}

    md = Cs(CS_ARCH_X86, CS_MODE_64 if pe.is_64 else CS_MODE_32)
    md.detail = True
    refs = 0
    per_target: dict[str, dict[str, Any]] = {}
    hits: set[str] = set()
    edges: list[list[int]] = []
    for sec in pe.sections:
        if not sec.is_executable:
            continue
        va = pe.image_base + sec.virtual_address
        for insn in md.disasm(bytes(sec.raw), va):
            if insn.mnemonic != "lea" or not insn.operands:
                continue
            op = insn.operands[-1]
            if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                continue
            target = insn.address + insn.size + op.mem.disp
            name = targets.get(target)
            if name is None:
                continue
            refs += 1
            hits.add(name)
            f = owner(insn.address)
            if f is None:
                continue
            rec = per_target.setdefault(name, {"refs": 0, "functions": []})
            rec["refs"] += 1
            edges.append([target, f, insn.address])
            if f not in rec["functions"]:
                rec["functions"].append(f)
    return {
        "refs": refs,
        "targets_hit": len(hits),
        "functions": len({insn for r in per_target.values() for insn in r["functions"]}),
        "per_string": per_target,
        "edges": edges,
    }


def scan(pe: PE, *, refs: bool = False, max_text_mb: int = 64) -> dict[str, Any]:
    """一次只读扫描，返回 JSON 友好的事实字典。"""
    strings = ascii_strings(pe)
    facts = _classify(strings)
    facts["structure"] = _header_facts(pe)
    facts["str_pairs"] = static_str_pairs(pe, strings)
    facts["language_evidence"] = {
        "rustc_commit": facts["rustc_commits"][0] if facts["rustc_commits"] else None,
        "rust_paths": facts["path_strings"]["total"],
        "panic_markers": sum(facts["panic_markers"].values()),
    }
    if refs:
        # 目标同时包含字符串本身与它的 &str 常量对：代码里 lea 的多半是常量对
        pairs = str_pair_index(pe, strings)
        tgt: dict[int, str] = {}
        for va, s in strings:
            txt = s.decode("latin-1")
            if s.endswith(b".rs") and CRATE_RE.search(txt):
                tgt[va] = txt
        for pair_va, str_va in pairs.items():
            if str_va in tgt:
                tgt[pair_va] = tgt[str_va]
        facts["crate_refs"] = map_refs(pe, tgt, max_text_mb=max_text_mb) if tgt else {
            "reason": "无 crate 路径字符串", "refs": 0, "functions": 0}
    return facts
