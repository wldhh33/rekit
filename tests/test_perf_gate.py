# -*- coding: utf-8 -*-
"""性能门：端到端（整进程）为主，解析内核微基准（进程内）为辅。"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKIP = os.environ.get("REKIT_SKIP_PERF") == "1"


def _run(script: str) -> None:
    proc = subprocess.run(
        [sys.executable, script],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.skipif(SKIP, reason="REKIT_SKIP_PERF=1")
def test_e2e_perf_gate() -> None:
    """triage / report 整进程冷热中位数 ≤1.15× 基线。"""
    _run("bench/e2e_gate.py")


@pytest.mark.skipif(SKIP, reason="REKIT_SKIP_PERF=1")
def test_parse_core_perf_gate() -> None:
    """进程内解析内核 ratio ≤1.15×、峰值内存 ≤1.2× 基线。"""
    _run("bench/parse_core_gate.py")
