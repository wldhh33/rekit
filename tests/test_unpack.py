# -*- coding: utf-8 -*-
"""unpack 端到端 + SizeOfCode 偏移回归（自有样本 hello_rs，许可允许进库）。"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from rekit.core import upx
from rekit.core.pe import PE

FIXTURES = Path(__file__).parent / "fixtures"
RAW = FIXTURES / "hello_rs.exe"
PACKED = FIXTURES / "hello_rs.packed.exe"
ROOT = Path(__file__).resolve().parents[1]

TEXT_SIZE = 0x16000
SIZE_OF_CODE = 0x16000
ENTRY_RVA = 0x15350


def _opt_u32(pe: PE, delta: int) -> int:
    """读可选头字段（delta 相对 OptionalHeader 起点）。"""
    return struct.unpack_from("<I", pe.data, pe.e_lfanew + 24 + delta)[0]


def test_hello_rs_end_to_end(tmp_path):
    out = tmp_path / "hello_rs.unpacked.exe"
    r = upx.unpack(PACKED, out, verify_only=False)

    assert r["ok"], [c for c in r["checks"] if not c["ok"]]
    assert r["path_used"].startswith("静态还原")
    assert r["upx"]["method_name"] == "NRV2B_LE32"
    assert r["unpacked_bytes"] == 141660
    assert r["consumed_bytes"] == r["compressed_bytes"]
    assert r["adler"]["ok"]

    # .text 与原件逐字节一致（最硬的一条）
    assert r["diff"]["text_size"] == TEXT_SIZE
    assert r["diff"]["text_mismatch"] == 0

    # IAT 条数与原件一致
    raw = PE(str(RAW))
    assert r["imports"]["dlls"] == 10
    assert r["imports"]["names"] + r["imports"]["ordinals"] + r["imports"]["raw"] == len(raw.imports()) == 85

    # 按原布局写出，且产物能运行
    assert out.exists()
    out_pe = PE(str(out))
    assert out_pe.number_of_sections == 5
    assert out_pe.entry_rva == ENTRY_RVA
    proc = subprocess.run([str(out)], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0
    assert proc.stdout.strip() == "hello from rustc, sum=385"


def test_unfilter_range_equals_size_of_code():
    """反过滤必须覆盖真实 SizeOfCode，而不是 AddressOfEntryPoint（+16 的旧坑）。"""
    raw = PE(str(RAW))
    size_of_code = _opt_u32(raw, 4)
    entry = _opt_u32(raw, 16)
    base_of_code = _opt_u32(raw, 20)
    assert size_of_code != entry, "样本不足以区分两个偏移，换一个仍有 E8/E9 尾部的样本"

    r = upx.unpack(PACKED, None, verify_only=True)
    assert r["unfilter"]["filter"] == "0x49"
    assert r["unfilter"]["size"] == size_of_code == SIZE_OF_CODE
    assert r["unfilter"]["start"] == base_of_code - raw.sections[0].virtual_address == 0
    assert (r["unfilter"]["calls"], r["unfilter"]["skipped"]) == (2097, 491)
    assert r["diff"]["text_mismatch"] == 0


def test_size_of_code_mutation_is_caught(monkeypatch):
    """变异验证：把 codesize 退回 +16 的旧错误，逐字节对照必须报错。"""

    def wrong_code_range(oh: bytes) -> tuple[int, int]:
        return struct.unpack_from("<I", oh, 44)[0], struct.unpack_from("<I", oh, 40)[0]

    monkeypatch.setattr(upx, "_code_range", wrong_code_range)
    r = upx.unpack(PACKED, None, verify_only=True)

    assert r["unfilter"]["size"] == ENTRY_RVA
    assert r["diff"]["text_mismatch"] > 0, "旧错误没有被 .text 逐字节对照抓住"
    assert not r["ok"]
    failed = {c["name"] for c in r["checks"] if not c["ok"]}
    assert "逐字节对照" in failed


def test_resource_tree_round_trip():
    """资源目录 解析→重建 必须逐字节还原（三层目录、名称区、数据项对齐）。"""
    blob = bytearray(0xA4)
    struct.pack_into("<HH", blob, 12, 0, 2)                    # root：2 个 ID 项
    struct.pack_into("<II", blob, 16, 3, 0x80000020)          # type 3 → dirA
    struct.pack_into("<II", blob, 24, 0x800000A0, 0x80000060)  # type "M" → dirB

    struct.pack_into("<HH", blob, 0x20 + 12, 0, 1)
    struct.pack_into("<II", blob, 0x20 + 16, 1, 0x80000038)   # name 1 → 语言目录
    struct.pack_into("<HH", blob, 0x38 + 12, 0, 1)
    struct.pack_into("<II", blob, 0x38 + 16, 0x409, 0x50)     # lang 0x409 → dataA
    struct.pack_into("<IIII", blob, 0x50, 0x1000, 0x11, 0, 0)  # 0x11 → 对齐到 0x14

    struct.pack_into("<HH", blob, 0x60 + 12, 0, 1)
    struct.pack_into("<II", blob, 0x60 + 16, 1, 0x80000078)
    struct.pack_into("<HH", blob, 0x78 + 12, 0, 1)
    struct.pack_into("<II", blob, 0x78 + 16, 0x409, 0x90)
    struct.pack_into("<IIII", blob, 0x90, 0x1100, 8, 0, 0)

    struct.pack_into("<H", blob, 0xA0, 1)                      # 名称 "M"（长度 1 = 2 字节 UTF-16）
    blob[0xA2:0xA4] = "M".encode("utf-16le")

    root, leaves, dsize, ssize = upx._parse_resource_tree(bytes(blob), 0)
    assert (dsize, ssize) == (160, 4)
    assert [leaf.type_id for leaf in leaves] == [3, 0]  # 0 = 命名类型，不参与图标判定
    assert [leaf.size for leaf in leaves] == [0x14, 8]
    assert leaves[1].name is None and root.children[1].name is not None

    dirsize = upx.align_up(dsize + ssize, 4)
    assert upx._build_resource_tree(root, dsize, dirsize, dsize) == bytes(blob)


# 7z 样本受许可限制不进仓库，只在本地跑；CI 自动跳过
LOCAL_7Z = ROOT.parent / "样本" / "packed" / "7z.packed.exe"


@pytest.mark.skipif(not LOCAL_7Z.exists(), reason="7z 样本受许可限制，默认不进仓库")
def test_local_7z_resource_rebuild(tmp_path):
    r = upx.unpack(LOCAL_7Z, tmp_path / "7z.exe")
    assert r["ok"]
    assert r["diff"]["text_mismatch"] == 0
    assert r["resources"]["entries"] == 2
    assert r["resources"]["copied"] == 2


def test_cli_unpack_writes_file_and_json(tmp_path):
    out_dir = tmp_path / "unpacked"
    out_json = tmp_path / "unpack.json"
    proc = subprocess.run(
        [sys.executable, "-m", "rekit", "unpack", str(PACKED),
         "-d", str(out_dir), "-j", str(out_json)],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert (out_dir / "hello_rs.unpacked.exe").exists()
    assert "反过滤" in proc.stdout and "SizeOfCode" in proc.stdout

    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["analyzer"] == "unpack"
    assert payload["errors"] == []
    assert payload["results"][0]["ok"] is True
    assert payload["results"][0]["diff"]["text_mismatch"] == 0


def test_cli_verify_only_writes_nothing(tmp_path):
    out_dir = tmp_path / "unpacked"
    proc = subprocess.run(
        [sys.executable, "-m", "rekit", "unpack", str(PACKED),
         "--verify-only", "-d", str(out_dir)],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert not out_dir.exists()


def test_cli_non_upx_reports_not_crashes(tmp_path):
    proc = subprocess.run([sys.executable, "-m", "rekit", "unpack", str(RAW)],
                          cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "UnpackError" in proc.stderr and "UPX1" in proc.stderr
    assert "Traceback" not in proc.stderr
