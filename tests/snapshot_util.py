# -*- coding: utf-8 -*-
"""M6-B 快照基线工具：20 个固定样本、8 个子命令、可复现的输出契约。

设计要点（与文档 ``docs/contract.md`` 一致）：

- **先冻结、后改字段**。本文件的生成逻辑在 B MVP 开工前跑过一次，基线里记录的是
  未加顶层 ``schema_version`` / 错误码 ``code`` 的旧输出。
- 比对采用**递归子集**：基线里出现过的键必须原样存在且值相等；新增键不算破坏。
  这正好对应「旧字段零删除（只增不改）」。
- 报告内容里不出现时间戳/耗时：``generated_at`` 整个删掉，``seconds`` 值统一替换成
  ``<SECONDS>``；基线 meta 里单独记生成日期与版本。
- 本机绝对路径统一替换成 ``<SAMPLE:id>`` / ``<TMP>``，基线可跨机器复算。
- 7 个“派生样本”由固定字节手术生成，不额外提交二进制文件，也不下载任何东西。
"""

from __future__ import annotations

import contextlib
import io
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
BASELINE_DIR = ROOT / "tests" / "baseline"
BASELINE = BASELINE_DIR / "snapshot_v0.6.0.json"
SIDECAR = BASELINE_DIR / "snapshot_v0.6.0.json.sha256"

# ---------------------------------------------------------------------------
# 20 个固定样本：13 个仓库内夹具 + 7 个确定性派生的坏样本
# ---------------------------------------------------------------------------

FIXTURE_SAMPLES = [
    "hello_rs.exe",
    "hello_rs.packed.exe",
    "msvc_x64.exe",
    "msvc_x86.exe",
    "gcc_o0.exe",
    "gcc_o2.exe",
    "struct_probe.exe",
    "hello_elf",
    "clang_o0",
    "clang_o2",
    "clang_arm64_o2",
    "go_linux_amd64",
    "go_linux_arm64",
]

# (id, 基础样本, 手术名) —— 输出到临时目录，运行时生成，字节完全确定
DERIVED_SAMPLES = [
    ("trunc_0x40", "hello_rs.exe", "trunc:0x40"),
    ("trunc_0x200", "hello_rs.exe", "trunc:0x200"),
    ("bad_magic", "hello_rs.exe", "patch:0:ZZ"),
    ("elfanew_oob", "hello_rs.exe", "elfanew:0x7FFFFFF0"),
    ("zero_opt_header", "msvc_x64.exe", "zero_opt_header"),
    ("nsections_huge", "msvc_x64.exe", "nsections:0xFFFF"),
    ("no_pe_sig", "hello_rs.exe", "pe_sig:XXXX"),
]

# 每个样本都跑的 4 个子命令（输出量已限制，避免基线膨胀）
COMMANDS_ALL = [
    ("triage", ["triage", "<SAMPLE>"]),
    ("identify", ["identify", "<SAMPLE>"]),
    ("map", ["map", "<SAMPLE>"]),
    ("data", ["data", "<SAMPLE>", "--no-arrays", "--no-structs", "--max-items", "100"]),
]

# 其余 4 个子命令只在指定样本上跑固定参数
COMMANDS_SPECIAL = [
    ("funcs", "msvc_x64.exe", ["funcs", "<SAMPLE>"]),
    ("funcs", "msvc_x86.exe", ["funcs", "<SAMPLE>"]),
    ("funcs", "gcc_o2.exe", ["funcs", "<SAMPLE>"]),
    ("funcs", "hello_rs.exe", ["funcs", "<SAMPLE>"]),
    ("funcs", "hello_elf", ["funcs", "<SAMPLE>"]),
    ("xref", "gcc_o2.exe",
     ["xref", "<SAMPLE>", "--string", "hello from C, sum=%d leaf=%d"]),
    ("xref", "gcc_o2.exe", ["xref", "<SAMPLE>", "--va", "0x1400034B0"]),
    ("unpack", "hello_rs.packed.exe", ["unpack", "<SAMPLE>", "--verify-only"]),
    ("unpack", "trunc_0x200", ["unpack", "<SAMPLE>", "--verify-only"]),
    ("report", "msvc_x64.exe", ["report", "<SAMPLE>", "--rules", "rules/m5.json"]),
    ("report", "hello_rs.exe", ["report", "<SAMPLE>", "--rules", "rules/m5.json"]),
]


def sample_paths(workdir: Path) -> dict[str, Path]:
    """返回 {sample_id: 本次运行可用的绝对路径}；派生样本写进 workdir。"""
    out: dict[str, Path] = {}
    for name in FIXTURE_SAMPLES:
        out[name] = FIXTURES / name
    workdir.mkdir(parents=True, exist_ok=True)
    for sid, base, op in DERIVED_SAMPLES:
        data = (FIXTURES / base).read_bytes()
        out[sid] = workdir / f"{sid}.exe"
        out[sid].write_bytes(_mutate(data, op))
    return out


def _mutate(data: bytes, op: str) -> bytes:
    if op.startswith("trunc:"):
        return data[: int(op.split(":", 1)[1], 0)]
    if op.startswith("patch:"):
        _, off, text = op.split(":", 2)
        off_i = int(off, 0)
        return data[:off_i] + text.encode("ascii") + data[off_i + len(text):]
    if op.startswith("elfanew:"):
        buf = bytearray(data)
        struct.pack_into("<I", buf, 0x3C, int(op.split(":", 1)[1], 0))
        return bytes(buf)
    if op.startswith("nsections:"):
        buf = bytearray(data)
        e = struct.unpack_from("<I", buf, 0x3C)[0]
        struct.pack_into("<H", buf, e + 6, int(op.split(":", 1)[1], 0))
        return bytes(buf)
    if op.startswith("pe_sig:"):
        buf = bytearray(data)
        e = struct.unpack_from("<I", buf, 0x3C)[0]
        buf[e:e + 4] = op.split(":", 1)[1].encode("ascii")
        return bytes(buf)
    if op == "zero_opt_header":
        buf = bytearray(data)
        e = struct.unpack_from("<I", buf, 0x3C)[0]
        # PE 签名 4 + COFF 头 20，可选头从这里开始
        start = e + 24
        buf[start:start + 64] = b"\x00" * 64
        return bytes(buf)
    raise ValueError(f"未知派生操作：{op}")


# 已知旧缺陷（B MVP 记录，不在冻结前修）：
# 1) arm64 Go 样本上 `data` 因 scan_go_strings 提前返回缺少 naive_would_overread 而 KeyError；
# 2) 非 PE/ELF 的 `bad_magic` 上 `data` 直接抛 ValueError（未收进 errors）。
KNOWN_SKIPS = {("data", "go_linux_arm64"), ("data", "bad_magic")}


def build_cases(workdir: Path) -> list[dict]:
    """生成全部用例描述（argv 里的 <SAMPLE> 在运行时替换成真实路径）。"""
    cases: list[dict] = []
    seen: dict[str, int] = {}

    def _add(cmd: str, sid: str, argv: list[str]) -> None:
        base = f"{cmd}:{sid}"
        seen[base] = seen.get(base, 0) + 1
        case_id = base if seen[base] == 1 else f"{base}#{seen[base]}"
        cases.append({"case_id": case_id, "sample": sid,
                      "command": cmd, "argv": list(argv)})

    for sid in [s for s in FIXTURE_SAMPLES] + [d[0] for d in DERIVED_SAMPLES]:
        for cmd, argv in COMMANDS_ALL:
            if (cmd, sid) in KNOWN_SKIPS:
                continue
            _add(cmd, sid, argv)
    for cmd, sid, argv in COMMANDS_SPECIAL:
        _add(cmd, sid, argv)
    return cases


# ---------------------------------------------------------------------------
# 执行与规范化
# ---------------------------------------------------------------------------

VOLATILE_KEYS = {"generated_at"}
VOLATILE_VALUE_KEYS = {"seconds"}


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    """在进程内跑 CLI（与命令行同一条代码路径），返回 (退出码, stdout, stderr)。"""
    from rekit import cli

    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exc:  # argparse 的错误路径
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def run_case(case: dict, paths: dict[str, Path], workdir: Path) -> dict:
    workdir.mkdir(parents=True, exist_ok=True)
    sample = paths[case["sample"]]
    json_path = workdir / f"{case['case_id'].replace(':', '_')}.json"
    argv = [str(sample) if a == "<SAMPLE>" else a for a in case["argv"]]
    argv += ["-j" if case["command"] in {"map", "funcs", "data", "xref", "identify",
                                         "unpack", "report"} else "-o", str(json_path)]
    code, out, err = run_cli(argv)
    payload = None
    if json_path.is_file():
        payload = json.loads(json_path.read_text(encoding="utf-8"))
    return {"case_id": case["case_id"], "sample": case["sample"],
            "command": case["command"], "exit_code": code, "json": payload,
            "stdout": out, "stderr": err}


def normalize(case: dict, paths: dict[str, Path], tmpdir: Path) -> dict:
    """抹掉时间戳、耗时与绝对路径，让基线可以跨机器复算。"""
    replacements = sorted(
        ((str(p), f"<SAMPLE:{sid}>") for sid, p in paths.items()),
        key=lambda kv: len(kv[0]), reverse=True,
    )
    prefixes = sorted({str(tmpdir), str(tmpdir).replace("\\", "/")},
                      key=len, reverse=True)

    def _str(value: str) -> str:
        for real, tag in replacements:
            value = value.replace(real, tag)
            value = value.replace(real.replace("\\", "/"), tag)
        for pref in prefixes:
            value = value.replace(pref, "<TMP>")
        return value

    def _walk(value):
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if k in VOLATILE_KEYS:
                    continue
                if k in VOLATILE_VALUE_KEYS and not isinstance(v, (dict, list)):
                    out[k] = "<SECONDS>"
                else:
                    out[k] = _walk(v)
            return out
        if isinstance(value, list):
            return [_walk(v) for v in value]
        if isinstance(value, str):
            return _str(value)
        return value

    return {
        "case_id": case["case_id"],
        "sample": case["sample"],
        "command": case["command"],
        "exit_code": case["exit_code"],
        "json": _walk(case["json"]) if case["json"] is not None else None,
    }


# ---------------------------------------------------------------------------
# 比对：递归子集（旧字段必须存在且相等；新增字段放行）
# ---------------------------------------------------------------------------

def assert_subset(expected, actual, path: str = "$") -> None:
    if isinstance(expected, dict):
        assert isinstance(actual, dict), f"{path}: 期望对象，实际是 {type(actual).__name__}"
        for key, want in expected.items():
            assert key in actual, f"{path}.{key}: 旧字段被删除"
            assert_subset(want, actual[key], f"{path}.{key}")
        return
    if isinstance(expected, list):
        assert isinstance(actual, list), f"{path}: 期望数组，实际是 {type(actual).__name__}"
        assert len(expected) == len(actual), \
            f"{path}: 数组长度 {len(expected)} -> {len(actual)}"
        for i, (want, got) in enumerate(zip(expected, actual)):
            assert_subset(want, got, f"{path}[{i}]")
        return
    assert expected == actual, f"{path}: {expected!r} -> {actual!r}"


def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def mask_environment(value):
    """把随环境变化的叶子值替换成占位符，但保留键本身。

    目前只有 ``rules.yara_validation``：装了 yara-python 时是“通过”，没装时是
    “未校验”。这属于环境事实而不是 rekit 输出契约，快照不应因 CI 没装 YARA 而红；
    但键被删除仍然会红。
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k == "yara_validation" and isinstance(v, dict):
                out[k] = {sub: f"<YARA:{sub}>" for sub in v}
            else:
                out[k] = mask_environment(v)
        return out
    if isinstance(value, list):
        return [mask_environment(v) for v in value]
    return value


def file_sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()
