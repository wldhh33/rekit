# -*- coding: utf-8 -*-
"""`rekit funcs` 端到端：自带 PE/ELF fixture 的召回与误报。

样本都是本项目自有编译产物，不依赖系统目录或第三方二进制：

- `hello_rs.exe`：Rust/MSVC PE64，带 `.pdata`（333 项）；
- `hello_elf`：Rust musl ELF64，带 `.eh_frame` / `.eh_frame_hdr`（2360 条 FDE），
  源码与构建命令见 `fixtures/src/hello_elf.rs`。

断言分三层：
1. 权威表结构（`.pdata` / `.eh_frame` / `.eh_frame_hdr` 三方一致）；
2. A 层播种后召回 100%、严格误报 0（解析器与反汇编器互相校验）；
3. 反事实（不拿权威表播种）仍有可观召回，证明"发现能力"不是自证。
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

pytest.importorskip("capstone")

from rekit.core.elf import Elf
from rekit.core.funcs import (
    CSV_FIELDS, analyze_image, csv_rows, parse_gopclntab,
)

FIXTURES = Path(__file__).parent / "fixtures"
PE_SAMPLE = FIXTURES / "hello_rs.exe"
ELF_SAMPLE = FIXTURES / "hello_elf"


def test_pe_pdata_is_authoritative():
    r = analyze_image(str(PE_SAMPLE), pointers=True)
    a, m = r["authority"], r["metrics"]
    assert r["format"] == "PE" and r["bits"] == 64
    assert a["name"] == ".pdata" and a["usable"]
    assert a["starts"] == 333
    assert m["seeded"]["recall"] == 1.0
    assert m["seeded"]["fp"] == 0
    assert m["seeded"]["fp_text"] == 0
    assert m["evidence_counts"]["pdata"] == 333
    # 指针表是真实生效的，不是恒为 0 的占位。
    assert m["evidence_counts"].get("ptr", 0) >= 1
    assert all("pdata" in f["evidence"] for f in r["functions"] if f["layer"] == "A")


def test_pe_counterfactual_recall_is_not_self_proving():
    r = analyze_image(str(PE_SAMPLE), pointers=True)
    cf = r["metrics"]["counterfactual"]
    assert cf is not None
    assert 0.10 < cf["recall"] < 1.0
    # 反事实的误报全部是"进了已知函数体中部"，不是凭空造函数。
    assert cf["fp_text"] == cf["fp"]


def test_elf_eh_frame_is_authoritative():
    r = analyze_image(str(ELF_SAMPLE), pointers=True)
    a, m = r["authority"], r["metrics"]
    assert r["format"] == "ELF" and r["bits"] == 64
    assert a["name"] == ".eh_frame" and a["usable"]
    assert a["starts"] > 2000
    d = a["detail"]
    assert d["hdr_present"] is True
    assert d["hdr_count"] == a["starts"]
    assert d["hdr_matched"] == a["starts"]
    assert d["fde_only"] == 0 and d["hdr_only"] == 0
    assert d["errors"] == []
    assert m["seeded"]["recall"] == 1.0
    assert m["seeded"]["fp"] == 0
    assert m["evidence_counts"]["eh_frame"] == a["starts"]


def test_elf_exports_land_in_a_layer_without_symbols():
    """导出表只用于播种：`.dynsym` 的函数全部被覆盖，且与 FDE 起点一致的是 A 层。"""
    elf = Elf(str(ELF_SAMPLE))
    r = analyze_image(str(ELF_SAMPLE), pointers=False)
    starts = {f["start"] for f in r["functions"]}
    authority = {f["start"] for f in r["functions"] if f["layer"] == "A"}
    exported = {s.rva for s in elf.exports()}
    assert exported and exported <= starts
    # 导出符号可以指向函数中部（别名/局部标签），这类只能算 B 层可达；
    # 但绝大多数导出应当与 FDE 起点完全重合。
    assert len(exported & authority) > len(exported) * 0.7
    assert all(next(f for f in r["functions"] if f["start"] == va)["layer"]
               in ("A", "B-reachable") for va in exported)


def test_elf_counterfactual_recall_exceeds_half():
    r = analyze_image(str(ELF_SAMPLE), pointers=True)
    cf = r["metrics"]["counterfactual"]
    assert cf["recall"] > 0.5


def test_elf_without_hdr_uses_linear_fallback(tmp_path):
    """删掉 `.eh_frame_hdr` 后必须走线性扫描，结果不变且在输出里标注。"""
    data = bytearray(ELF_SAMPLE.read_bytes())
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize = struct.unpack_from("<H", data, 58)[0]
    shnum = struct.unpack_from("<H", data, 60)[0]
    shstrndx = struct.unpack_from("<H", data, 62)[0]
    str_off = struct.unpack_from("<Q", data, shoff + shstrndx * shentsize + 24)[0]
    str_size = struct.unpack_from("<Q", data, shoff + shstrndx * shentsize + 32)[0]
    names = bytes(data[str_off:str_off + str_size])

    target = None
    for i in range(shnum):
        off = shoff + i * shentsize
        name_off = struct.unpack_from("<I", data, off)[0]
        name = names[name_off:names.find(b"\0", name_off)].decode()
        if name == ".eh_frame_hdr":
            target = off
            break
    assert target is not None
    # sh_name/sh_type/sh_flags/sh_addr/sh_offset/sh_size 全清零：等价于删节。
    struct.pack_into("<IIQQQQ", data, target, 0, 0, 0, 0, 0, 0)
    tmp = tmp_path / "hello_elf_no_hdr"
    tmp.write_bytes(data)

    r = analyze_image(str(tmp), pointers=False)
    a, m = r["authority"], r["metrics"]
    assert a["usable"]
    assert a["detail"]["hdr_present"] is False
    assert a["detail"]["source"] == "线性兜底"
    assert a["starts"] > 2000
    assert m["seeded"]["recall"] == 1.0
    assert m["seeded"]["fp"] == 0


def test_csv_contract_columns_and_layers():
    r = analyze_image(str(PE_SAMPLE), pointers=False)
    rows = csv_rows(r)
    assert len(rows) == len(r["functions"])
    assert tuple(rows[0].keys()) == CSV_FIELDS
    assert {row["layer"] for row in rows} <= {"A", "B-reachable", "B-isolated"}
    assert all(row["deliverable"] == ("false" if row["layer"] == "B-isolated"
                                      else "true") for row in rows)
    assert all(row["start"].startswith("0x") for row in rows)
    assert all("+" not in row["evidence"] or len(row["evidence"].split("+")) > 1
               for row in rows)


def _fake_gopclntab(entries: list[int], text_start: int = 0x400000) -> bytes:
    """手工拼一个 Go 1.20 头 + functab；entries 是相对 textStart 的偏移。"""
    pcln = 0x80
    buf = bytearray(pcln + 8 * len(entries))
    struct.pack_into("<I", buf, 0, 0xFFFFFFF1)
    buf[6], buf[7] = 1, 8
    struct.pack_into("<Q", buf, 8, len(entries) - 1)   # nfunc（不含 sentinel）
    struct.pack_into("<Q", buf, 16, 3)                 # nfiles
    struct.pack_into("<Q", buf, 24, text_start)
    for k, off in enumerate((0x48, 0x100, 0x180, 0x200, 0x280)):
        struct.pack_into("<Q", buf, 32 + 8 * k, off)
    struct.pack_into("<Q", buf, 64, pcln)
    for i, entry in enumerate(entries):
        struct.pack_into("<II", buf, pcln + 8 * i, entry, 0)
    return bytes(buf)


def test_gopclntab_spans_from_functab():
    raw = _fake_gopclntab([0, 0x20, 0x50, 0x80])
    table = parse_gopclntab(raw, text_start=0x400000)
    assert table is not None
    assert table.nfunc == 3
    assert table.starts == [0x400000, 0x400020, 0x400050]
    assert table.spans == [(0x400000, 0x400020), (0x400020, 0x400050),
                           (0x400050, 0x400080)]


def test_gopclntab_rejects_unknown_magic():
    raw = bytearray(_fake_gopclntab([0, 0x20]))
    struct.pack_into("<I", raw, 0, 0xFFFFFFFC)   # 不属于任何已知代
    assert parse_gopclntab(bytes(raw), text_start=0x400000) is None


def _fake_gopclntab_old(entries: list[int]) -> bytes:
    """Go 1.2–1.15 头：magic/pad/minLC/ptrSize/nfunc + functab（绝对 PC, funcoff）。

    旧头没有偏移字段，`functab` 紧跟在 `nfunc`（offset 8）后，即 offset 16。
    """
    pcln = 16
    buf = bytearray(pcln + 16 * len(entries))
    struct.pack_into("<I", buf, 0, 0xFFFFFFFB)
    buf[6], buf[7] = 1, 8
    struct.pack_into("<Q", buf, 8, len(entries) - 1)   # nfunc（不含 sentinel）
    for i, entry in enumerate(entries):
        struct.pack_into("<QQ", buf, pcln + 16 * i, entry, 0)
    return bytes(buf)


def test_gopclntab_old_magic_uses_absolute_pc():
    raw = _fake_gopclntab_old([0x401000, 0x401020, 0x401050, 0x401080])
    table = parse_gopclntab(raw, text_start=0x401000)
    assert table is not None
    assert table.magic == 0xFFFFFFFB
    assert table.nfunc == 3
    assert table.starts == [0x401000, 0x401020, 0x401050]
    assert table.spans == [(0x401000, 0x401020), (0x401020, 0x401050),
                           (0x401050, 0x401080)]


def test_gopclntab_old_magic_rejects_entries_outside_text():
    raw = _fake_gopclntab_old([0x1000, 0x1020, 0x1050, 0x1080])
    assert parse_gopclntab(raw, text_start=0x401000,
                           text_end=0x402000) is None


# ---------------------------------------------------------------------------
# 孤立桶：口径上不可交付，精度必须由参照表现算
# ---------------------------------------------------------------------------

def test_isolated_metrics_precision_and_label():
    from rekit.core.funcs import ISOLATED_LABEL, isolated_metrics
    spans = [(0x1000, 0x1100), (0x1200, 0x1250)]
    starts = [0x1000, 0x1040, 0x1400, 0x1500]   # 1 exact / 1 体内 / 2 参照漏建
    m = isolated_metrics(starts, spans)
    assert (m["n"], m["inside"], m["exact"], m["not_found"]) == (4, 1, 1, 2)
    assert m["precision"] == 0.75
    assert m["precision_ci"] is not None
    assert m["deliverable"] is False
    assert m["label"] == ISOLATED_LABEL == "不可交付（内部参考）"

    # 没有参照表：只给 n，明确"未验证"，不猜精度
    m2 = isolated_metrics(starts, None)
    assert m2["n"] == 4 and m2["precision"] is None
    assert m2["deliverable"] is False and m2["label"] == ISOLATED_LABEL
    assert "未验证" in m2["note"]


def test_load_reference_base_shift_and_filters(tmp_path):
    from rekit.core.funcs import load_reference
    csv_path = tmp_path / "ref.csv"
    csv_path.write_text(
        "name,entry,end,size,is_thunk,is_external,base\n"
        "a,00101000,00101020,32,0,0,100000\n"
        "b,00101100,00101110,14,1,0,100000\n"
        "c,00101200,00101210,16,0,1,100000\n", encoding="utf-8")
    # thunk / external 不计入参照；base=0x100000 按目标基址 0 平移回来
    assert load_reference(str(csv_path), 0) == [(0x1000, 0x1020)]


def test_exhaust_reports_isolated_bucket_with_reference(tmp_path):
    """`--exhaust --reference` 必须给出孤立桶 n / 精度，并标"不可交付"。"""
    from rekit.core.funcs import ISOLATED_LABEL
    base = analyze_image(str(ELF_SAMPLE), pointers=False)
    csv_path = tmp_path / "ref.csv"
    lines = ["name,entry,end,size,is_thunk,is_external,base"]
    for f in base["functions"]:
        lines.append(f"F_{f['start']:X},{f['start']:X},{f['end']:X},"
                     f"{f['size']},0,0,{int(base['image_base'], 16):X}")
    csv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    r = analyze_image(str(ELF_SAMPLE), pointers=False, exhaust="fast",
                      reference=str(csv_path))
    e, im = r["exhaust"], r["exhaust"]["isolated_metrics"]
    assert im["n"] == e["isolated"] > 0
    assert im["precision"] is not None
    assert im["reference_file"] == str(csv_path)
    assert im["deliverable"] is False and im["label"] == ISOLATED_LABEL
    # 参照表就是自己的结果，因此不会有"落在体内"的孤立入口
    assert im["inside"] == 0


# ---------------------------------------------------------------------------
# 跨工具链 / 跨架构：同一份源码，不同编译器产物的判别与口径
# ---------------------------------------------------------------------------

def test_gcc_pe_is_not_misdetected_as_msvc():
    r = analyze_image(str(FIXTURES / "gcc_o2.exe"), pointers=False)
    assert r["toolchain"]["family"] == "gcc"
    assert r["toolchain"]["profile"] == "gcc_x64"
    assert r["authority"]["name"] == ".pdata"
    assert r["metrics"]["seeded"]["recall"] == 1.0
    assert r["metrics"]["seeded"]["fp_text"] == 0


def test_msvc_x86_falls_to_b_layer():
    r = analyze_image(str(FIXTURES / "msvc_x86.exe"), pointers=False)
    assert r["bits"] == 32
    assert r["authority"]["usable"] is False       # PE32 没有 .pdata
    assert r["metrics"]["seeded"]["recall"] is None
    assert r["functions"]                        # 仍要有 B 层产出


def test_non_x86_ships_authority_only():
    """ARM64：只交权威表区间，明确不假装 B 层可用。"""
    r = analyze_image(str(FIXTURES / "clang_arm64_o2"))
    assert r["machine"] == "aarch64"
    assert r["authority"]["usable"] is True
    assert r["metrics"]["seeded"]["recall"] == 1.0
    assert r["metrics"]["counterfactual"] is None
    assert any("非 x86" in n for n in r["notes"])
    assert {f["layer"] for f in r["functions"]} == {"A"}


def test_go_arm64_uses_gopclntab():
    r = analyze_image(str(FIXTURES / "go_linux_arm64"), pointers=False)
    assert r["machine"] == "aarch64"
    assert r["authority"]["name"] == ".gopclntab"
    assert r["authority"]["starts"] > 1500
    assert r["metrics"]["seeded"]["recall"] == 1.0
    assert r["metrics"]["seeded"]["fp_text"] == 0


# ---------------------------------------------------------------------------
# 冷启动口径：不用符号 / 权威表播种，只用代码与数据本身
# ---------------------------------------------------------------------------

def test_cold_start_absent_by_default():
    r = analyze_image(str(FIXTURES / "gcc_o2.exe"), pointers=False)
    assert r["metrics"]["cold_start"] is None


def test_cold_start_never_seeds_from_symbols_or_authority():
    r = analyze_image(str(FIXTURES / "gcc_o2.exe"), pointers=False, cold=True)
    c = r["metrics"]["cold_start"]
    assert c is not None
    assert c["evidence_counts"].keys().isdisjoint({"export", "pdata", "eh_frame",
                                                  "gopclntab"})
    # 入口点是唯一允许的"非数据"起点；其余全部来自指令/数据本身
    assert c["evidence_counts"].get("entry") == 1
    assert c["recall"] > 0.1
    assert c["fp_text"] == 0
    assert any("冷启动" in n for n in c["notes"])


def test_cold_start_elf_recovers_vtables_from_relative_relocs():
    """strip + PIE：文件里 vtable 槽位全是 0，真值只在 `.rela.dyn` 的 addend。"""
    r = analyze_image(str(ELF_SAMPLE), pointers=True, cold=True)
    c = r["metrics"]["cold_start"]
    assert c is not None
    ec = c["evidence_counts"]
    assert ec.get("rel", 0) > 100            # 861 条 RELATIVE 重定位播种
    assert "eh_frame" not in ec
    assert c["recall"] > 0.3                 # 基线 42.7%，不是自证
    assert c["functions"] > 1000
    # 冷启动允许误报，但必须小于函数总数的 1/3
    assert c["fp_text"] < c["functions"] / 3
    # 分母拆分：可达子集必须比全量高，且不可达项单列
    rc = c["reachable"]
    assert 0 < rc["total"] < r["authority"]["starts"]
    assert rc["recall"] > c["recall"]
    assert rc["unreachable"] == r["authority"]["starts"] - rc["total"]
    # 间接调用解析：尝试数必须真实存在，解析率是"值流没瞎猜"的证据
    ic = c["indirect"]
    assert ic["attempts"] > 100
    assert 0 <= ic["resolved"] <= ic["attempts"]


def test_cold_start_pe_filters_mid_function_calls():
    r = analyze_image(str(PE_SAMPLE), pointers=True, cold=True)
    c = r["metrics"]["cold_start"]
    assert c is not None
    assert "pdata" not in c["evidence_counts"]
    assert c["evidence_counts"].get("call", 0) > 100
    assert c["recall"] > 0.4                 # 基线 59.5%
    assert c["fp_text"] < 100                # 中段假 call 边被序言/边界门挡住


def test_cold_start_skipped_on_non_x86():
    r = analyze_image(str(FIXTURES / "clang_arm64_o2"), cold=True)
    assert r["metrics"]["cold_start"] is None


def test_validate_candidate_trust_slot_accepts_multiblock():
    """数据节指针 + 序言门已过时，不再要求"首个 jmp 处栈平衡"。

    Go 的 `CMPQ SP,0x10(R14); JBE; PUSHQ BP; MOVQ SP,BP; SUBQ $0x18,SP; JMP`
    是合法函数头，但线性校验会在中途的 jmp 处看到 delta=-0x20。
    """
    from rekit.core.funcs import CodeSpace, _validate_candidate

    code = bytes.fromhex("493B6610" "760A" "55" "4889E5" "4883EC18" "E9F0000000")
    space = CodeSpace([(0x1000, code)], 64)
    fn, why = _validate_candidate(space, [], 0x1000, 64)
    assert fn is None and why == "unbalanced"
    fn2, why2 = _validate_candidate(space, [], 0x1000, 64, trust_slot=True)
    assert fn2 is not None, why2
    assert fn2.entry == 0x1000 and fn2.end > 0x1000


def test_cold_start_go_itab_seeds_interface_methods():
    """moduledata -> itab.fun[] 播种：Go 1.27 用 types+itaboffset/itabsize 的连续 blob。"""
    r = analyze_image(str(FIXTURES / "go_linux_amd64"), pointers=True, cold=True)
    c = r["metrics"]["cold_start"]
    it = c["itab"]
    assert it["supported"] is True and it["moduledata"] is True
    assert it["layout"] == "itaboffset/itabsize"
    assert it["itabs"] >= 10
    assert it["methods"] >= 20
    assert c["itab_seeded"] > 0
    # 播种的每个地址都是 gopclntab 起点，所以命中数与播种数一致
    assert c["evidence_counts"].get("itab") == c["itab_seeded"]
    # itab 播种不能把中段入口带进来：修掉 jmp 不动点后应为个位数
    assert c["fp_text"] <= 10
    # M2 达标口径（长期目标.md）：可达子集 ≥50%、严格误报 ≤2%
    assert c["reachable"]["recall"] >= 0.5
    assert c["fp_text"] / r["authority"]["starts"] <= 0.02


def test_cold_start_itab_absent_on_non_go():
    r = analyze_image(str(ELF_SAMPLE), pointers=True, cold=True)
    it = r["metrics"]["cold_start"]["itab"]
    assert it["supported"] is False
    assert it.get("moduledata") is not True


# ---------------------------------------------------------------------------
# Go PE：没有 `.gopclntab` 节名，只能在数据节按魔数扫
# ---------------------------------------------------------------------------

class _Sec:
    def __init__(self, name: str, va: int, raw: bytes, executable: bool = False):
        self.name, self.virtual_address, self.raw = name, va, raw
        self.size_of_raw_data = len(raw)
        self.virtual_size = len(raw)
        self.is_executable = executable


class _FakeImg:
    image_base = 0x400000

    def __init__(self, sections):
        self.sections = sections


def _fake_pe_with_pclntab(entries: list[int], pad: int = 0x40,
                          text: bytes | None = None) -> _FakeImg:
    body = text if text is not None else b"\x90" * 0x400
    sec = _Sec(".text", 0, body, executable=True)
    data = _Sec(".rdata", 0x1000, b"\0" * pad + _fake_gopclntab(entries))
    return _FakeImg([sec, data])


def test_pclntab_scanned_from_pe_data_section():
    from rekit.core.funcs import pclntab_from_data
    entries = [0x10 + i * 0x20 for i in range(13)]
    img = _fake_pe_with_pclntab(entries)
    tab = pclntab_from_data(img)
    assert tab is not None
    assert tab.nfunc == 12
    assert tab.starts[0] == 0x400010
    assert tab.starts[-1] == 0x400000 + entries[-2]
    assert tab.detail["found_in"] == ".rdata"
    assert tab.detail["found_offset"] == "0x40"
    assert tab.detail["source"] == "数据节魔数扫描"


def test_pclntab_drops_padding_entries():
    """functab 末尾的 `CC` 填充不是函数：`go_win.exe` 因此从 1892 变 1890。"""
    from rekit.core.funcs import pclntab_from_data
    entries = [0x10 + i * 0x20 for i in range(13)]
    text = bytearray(b"\x90" * 0x400)
    last = entries[-2]
    text[last:last + 0x20] = b"\xcc" * 0x20
    tab = pclntab_from_data(_fake_pe_with_pclntab(entries, text=bytes(text)))
    assert tab is not None
    assert len(tab.starts) == 11
    assert tab.detail["header_nfunc"] == 12
    assert tab.detail["padding_entries"] == 1


def test_pclntab_scan_requires_min_functions():
    """短小的自洽表头会误命中：`min_func` 是防误报的最低门槛。"""
    from rekit.core.funcs import pclntab_from_data
    img = _fake_pe_with_pclntab([0, 0x20, 0x40])
    assert pclntab_from_data(img) is None
    assert pclntab_from_data(img, min_func=2) is not None

