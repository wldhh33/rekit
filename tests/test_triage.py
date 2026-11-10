# -*- coding: utf-8 -*-
"""triage 判据回归 + CLI 端到端（不需要 Ghidra / 网络）。"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from rekit.analyzers import triage

FIXTURES = Path(__file__).parent / "fixtures"
RAW = FIXTURES / "hello_rs.exe"
PACKED = FIXTURES / "hello_rs.packed.exe"
ROOT = Path(__file__).resolve().parents[1]


def test_raw_is_normal():
    r = triage.analyze_file(str(RAW))
    assert r.verdict == "normal"
    assert r.score == 0
    assert r.shell_guess == "未发现加壳迹象"


def test_packed_is_upx_high_confidence():
    r = triage.analyze_file(str(PACKED))
    assert r.verdict == "upx"
    assert r.score >= 9
    assert r.confidence == "高"
    assert "UPX" in r.shell_guess


def test_signal_weights_sum_to_score():
    r = triage.analyze_file(str(PACKED))
    assert r.score == sum(s.weight for s in r.signals if s.hit)
    hit = {s.id for s in r.signals if s.hit}
    assert {"S1_upx_section_pair", "S3_zero_raw_exec_section",
            "S4_high_entropy_section", "S5_import_truncated"} <= hit


def test_evidence_points_back_to_bytes():
    """证据链要求：关键信号必须含文件偏移（0x 开头）。"""
    r = triage.analyze_file(str(PACKED))
    by_id = {s.id: s for s in r.signals}
    for sid in ("S1_upx_section_pair", "S3_zero_raw_exec_section", "S5_import_truncated"):
        assert "0x" in by_id[sid].evidence, sid


def test_import_empty_alone_is_not_conclusive():
    """S6 单独命中不得把文件判成 packed?（静态链接产物可能没导入）。"""
    assert triage.W_IMPORT_EMPTY < 5
    assert triage._confidence(triage.W_IMPORT_EMPTY) == "无"


def test_cli_writes_json_and_markdown(tmp_path):
    out_json = tmp_path / "out.json"
    out_md = tmp_path / "out.md"
    proc = subprocess.run(
        [sys.executable, "-m", "rekit", "triage", str(RAW), str(PACKED),
         "-o", str(out_json), "-m", str(out_md)],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr

    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["analyzer"] == "triage"
    assert len(payload["results"]) == 2
    assert payload["errors"] == []
    verdicts = {Path(r["file"]).name: r["verdict"] for r in payload["results"]}
    assert verdicts == {"hello_rs.exe": "normal", "hello_rs.packed.exe": "upx"}

    md = out_md.read_text(encoding="utf-8")
    assert "# rekit triage 报告" in md
    assert "UPX" in md
    assert "判据说明与边界" in md


# --------------------------------------------------------------------------
# 真实世界的边界：不存在的文件、非 PE、目录、写不出去的输出路径
# --------------------------------------------------------------------------
def test_missing_file_is_reported_not_crashed(tmp_path):
    missing = tmp_path / "nope.exe"
    proc = subprocess.run([sys.executable, "-m", "rekit", "triage", str(missing)],
                          cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "[跳过]" in proc.stderr
    assert "FileNotFoundError" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_non_pe_file_is_reported(tmp_path):
    fake = tmp_path / "not_a_pe.bin"
    fake.write_bytes(b"hello, this is not a PE file\n" * 4)
    proc = subprocess.run([sys.executable, "-m", "rekit", "triage", str(fake)],
                          cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "PEError" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_empty_directory_reports_no_files(tmp_path):
    proc = subprocess.run([sys.executable, "-m", "rekit", "triage", str(tmp_path)],
                          cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "NoFilesFound" in proc.stderr


def test_glob_without_match_reports_no_files():
    proc = subprocess.run([sys.executable, "-m", "rekit", "triage",
                           str(ROOT / "tests" / "fixtures" / "*.does-not-exist")],
                          cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "NoFilesFound" in proc.stderr


def test_directory_input_scans_pe_files(tmp_path):
    # 目录里放一个 PE 和一个非 PE，只应处理 PE，且不算失败
    shutil.copy(RAW, tmp_path / "a.exe")
    (tmp_path / "readme.txt").write_text("not a pe", encoding="utf-8")
    out = tmp_path / "out.json"
    proc = subprocess.run([sys.executable, "-m", "rekit", "triage", str(tmp_path),
                           "-o", str(out)], cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert [Path(r["file"]).name for r in payload["results"]] == ["a.exe"]
    assert payload["errors"] == []


def test_unwritable_output_path_exits_cleanly(tmp_path):
    bad = tmp_path / "no-such-dir" / "out.json"
    proc = subprocess.run([sys.executable, "-m", "rekit", "triage", str(RAW),
                           "-o", str(bad)], cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "[输出失败]" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_mixed_good_and_bad_returns_zero_with_summary(tmp_path):
    proc = subprocess.run([sys.executable, "-m", "rekit", "triage", str(RAW),
                           str(tmp_path / "missing.exe")],
                          cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 0          # 有成功结果就不算失败退出
    assert "[汇总] 成功 1 / 失败 1" in proc.stdout
