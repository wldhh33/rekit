# -*- coding: utf-8 -*-
"""跨子命令输出契约：顶层 ``schema_version`` 与统一错误码。

规则（B MVP，2026-11-11 起）：

- ``schema_version`` 放在每个子命令 JSON 的**顶层**，取值见 ``SCHEMA_VERSION``；
  只增不改，旧字段一个都不删。
- 错误对象保留原有 ``file`` / ``error`` 两个字段不动，新增 ``code`` / ``message``。
  ``code`` 取自固定集合 ``ERROR_CODES``，消费方可以据此分支；``message`` 是去掉
  异常类名前缀后的可读文本。
- ``error`` 字段的格式（``"{类名}: {消息}"``）属于既有契约，不改。
"""

from __future__ import annotations

from typing import Iterable

# 每个子命令自己的 payload schema 版本。identify 在 M4b 加壳字段时已经到 2。
SCHEMA_VERSION = {
    "triage": 1,
    "unpack": 1,
    "map": 1,
    "funcs": 1,
    "data": 1,
    "xref": 1,
    "identify": 2,
    "report": 1,
}

E_NO_FILES = "E_NO_FILES"
E_NOT_FOUND = "E_NOT_FOUND"
E_IO = "E_IO"
E_TOO_LARGE = "E_TOO_LARGE"
E_PARSE = "E_PARSE"
E_FORMAT = "E_FORMAT"
E_VALUE = "E_VALUE"
E_DEPENDENCY = "E_DEPENDENCY"
E_INTERNAL = "E_INTERNAL"

ERROR_CODES = frozenset({
    E_NO_FILES, E_NOT_FOUND, E_IO, E_TOO_LARGE, E_PARSE,
    E_FORMAT, E_VALUE, E_DEPENDENCY, E_INTERNAL,
})

_BY_CLASS = {
    "PEFileTooLarge": E_TOO_LARGE,
    "PEError": E_PARSE,
    "ElfError": E_PARSE,
    "UnpackError": E_PARSE,
    "DotnetError": E_PARSE,
    "FuncsUnavailable": E_DEPENDENCY,
    "XrefUnavailable": E_DEPENDENCY,
    "DataUnavailable": E_DEPENDENCY,
}

_FORMAT_HINTS = ("既不是 PE 也不是 ELF", "不是 MZ", "不是 'PE", "未知 OptionalHeader")


def classify(exc: BaseException) -> str:
    """把异常映射到稳定错误码；未识别的异常一律 E_INTERNAL。"""
    if isinstance(exc, FileNotFoundError):
        return E_NOT_FOUND
    if isinstance(exc, OSError):
        return E_IO
    for cls in type(exc).__mro__:
        code = _BY_CLASS.get(cls.__name__)
        if code:
            return code
    if isinstance(exc, ValueError):
        text = str(exc)
        if any(hint in text for hint in _FORMAT_HINTS):
            return E_FORMAT
        return E_VALUE
    return E_INTERNAL


def error_entry(path: str, exc: BaseException) -> dict:
    """统一错误对象：旧字段 file/error 原样，新增 code/message。"""
    return {
        "file": path,
        "error": f"{type(exc).__name__}: {exc}",
        "code": classify(exc),
        "message": str(exc),
    }


def no_files_entry(paths: Iterable[str], what: str = "可分析") -> dict:
    """空目录 / 通配符无匹配：显式错误，不假装成功处理 0 个文件。"""
    message = f"没有匹配到{what}的文件（检查路径、扩展名或通配符）"
    return {
        "file": ", ".join(paths),
        "error": f"NoFilesFound: {message}",
        "code": E_NO_FILES,
        "message": message,
    }


def envelope(analyzer: str, payload: dict, generated_at: str | None = None) -> dict:
    """统一外层：tool/version/schema_version/generated_at + 分析器 payload。"""
    from . import __version__

    return {
        "tool": "rekit",
        "version": __version__,
        "schema_version": SCHEMA_VERSION[analyzer],
        "generated_at": generated_at,
        **payload,
    }
