# -*- coding: utf-8 -*-
"""输出契约：8 个子命令的顶层 schema_version 与统一错误码。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rekit import contract
from snapshot_util import run_cli, sample_paths

COMMANDS = ["triage", "unpack", "map", "funcs", "data", "xref", "identify", "report"]


@pytest.fixture(scope="module")
def samples(tmp_path_factory) -> dict[str, Path]:
    return sample_paths(tmp_path_factory.mktemp("contract") / "samples")


def _run(argv: list[str], out: Path) -> tuple[int, dict | None]:
    code, _, _ = run_cli(argv)
    payload = json.loads(out.read_text(encoding="utf-8")) if out.is_file() else None
    return code, payload


def test_schema_version_table_covers_eight_commands() -> None:
    assert set(contract.SCHEMA_VERSION) == set(COMMANDS)
    assert all(isinstance(v, int) and v >= 1 for v in contract.SCHEMA_VERSION.values())
    assert contract.SCHEMA_VERSION["identify"] == 3  # 0.7：family 改为链接器提供方


@pytest.mark.parametrize("command", COMMANDS)
def test_every_command_has_top_level_schema_version(
        command: str, samples: dict[str, Path], tmp_path: Path) -> None:
    sample = samples["hello_rs.packed.exe"] if command == "unpack" else samples["msvc_x64.exe"]
    out = tmp_path / f"{command}.json"
    argv = [command, str(sample)]
    if command == "unpack":
        argv.append("--verify-only")
    if command == "xref":
        sample = samples["gcc_o2.exe"]
        argv = [command, str(sample), "--string",
                "hello from C, sum=%d leaf=%d"]
    if command == "report":
        argv += ["--rules", "rules/m5.json"]
    argv += ["-o" if command == "triage" else "-j", str(out)]

    code, payload = _run(argv, out)
    assert code == 0, f"{command} 退出码 {code}"
    assert payload is not None
    assert payload["schema_version"] == contract.SCHEMA_VERSION[command]
    assert payload["tool"] == "rekit"
    assert payload["version"]


@pytest.mark.parametrize("command", ["triage", "unpack", "map", "data", "identify"])
def test_parse_error_has_unified_code(
        command: str, samples: dict[str, Path], tmp_path: Path) -> None:
    out = tmp_path / f"{command}-bad.json"
    argv = [command, str(samples["bad_magic"])]
    if command == "unpack":
        argv.append("--verify-only")
    argv += ["-o" if command == "triage" else "-j", str(out)]

    code, payload = _run(argv, out)
    assert code == 1
    assert payload["errors"], f"{command} 没有把坏文件收进 errors"
    err = payload["errors"][0]
    assert err["code"] in contract.ERROR_CODES
    assert err["code"] in {contract.E_FORMAT, contract.E_PARSE}
    assert err["message"] and isinstance(err["message"], str)
    # 旧字段 error 的格式不变
    assert err["error"].startswith(("PEError:", "ValueError:", "UnpackError:"))


def test_no_files_error_code(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    out = tmp_path / "nofiles.json"
    code, payload = _run(["triage", str(empty), "-o", str(out)], out)
    assert code == 1
    err = payload["errors"][0]
    assert err["code"] == contract.E_NO_FILES
    assert err["error"].startswith("NoFilesFound: ")
    assert err["message"] == err["error"].split(": ", 1)[1]


def test_report_failure_writes_json_with_code(
        samples: dict[str, Path], tmp_path: Path) -> None:
    out = tmp_path / "report-missing.json"
    missing = tmp_path / "nope.exe"
    code, payload = _run(["report", str(missing), "-j", str(out)], out)
    assert code == 1
    assert payload["schema_version"] == contract.SCHEMA_VERSION["report"]
    assert payload["analyzer"] == "report"
    assert payload["errors"][0]["code"] == contract.E_NOT_FOUND
    assert payload["errors"][0]["error"].startswith("FileNotFoundError: ")


def test_report_success_keeps_unified_fields(samples: dict[str, Path],
                                             tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    code, payload = _run(
        ["report", str(samples["msvc_x64.exe"]), "--rules", "rules/m5.json",
         "-j", str(out)], out)
    assert code == 0
    assert payload["schema_version"] == 1
    assert payload["analyzer"] == "report"
    assert payload["errors"] == []
    assert "generated_at" not in payload  # 报告内容不出现时间戳


def test_data_arm64_go_no_longer_crashes(samples: dict[str, Path],
                                        tmp_path: Path) -> None:
    """旧缺陷：arm64 Go 上 scan_go_strings 提前返回缺键，CLI KeyError。"""
    out = tmp_path / "arm64.json"
    code, payload = _run(
        ["data", str(samples["go_linux_arm64"]),
         "--no-arrays", "--no-structs", "-j", str(out)], out)
    assert code == 0
    go = payload["results"][0]["go_strings"]
    assert go["applicable"] is False
    assert go["reason"] == "只支持 x86 / x86-64"
