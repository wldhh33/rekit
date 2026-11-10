# -*- coding: utf-8 -*-
"""rekit 命令行入口。

    rekit triage <路径...> [-o out.json] [-m out.md]
    rekit unpack <路径...>    # v0.2
    rekit symbols <路径...>   # v0.3

v0.1 只实现 triage；另两个子命令报"未实现 + 计划版本"，不用假输出糊弄。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from . import __version__
from .analyzers import REGISTRY
from .report import render_triage

STAGE_OF = {"triage": "v0.1", "unpack": "v0.2", "symbols": "v0.3"}


def _write_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def cmd_triage(args: argparse.Namespace) -> int:
    payload = REGISTRY["triage"].run(args.paths)
    payload = {
        "tool": "rekit",
        "version": __version__,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        **payload,
    }

    for r in payload["results"]:
        print(f"{r['verdict']:<9} {r['confidence']:<2} {r['score']:>2}分  "
              f"{r['shell_guess']:<28} {r['file']}")
    for e in payload["errors"]:
        print(f"[跳过] {e['file']}: {e['error']}", file=sys.stderr)

    if args.json or args.markdown:
        try:
            if args.json:
                _write_json(args.json, payload)
                print(f"[JSON] {args.json}")
            if args.markdown:
                with open(args.markdown, "w", encoding="utf-8") as f:
                    f.write(render_triage(payload, __version__))
                print(f"[MD]   {args.markdown}")
        except OSError as e:
            print(f"[输出失败] {type(e).__name__}: {e}（目录不存在或无写权限）", file=sys.stderr)
            return 1

    if len(payload["results"]) + len(payload["errors"]) > 1:
        print(f"[汇总] 成功 {len(payload['results'])} / 失败 {len(payload['errors'])}")

    if payload["results"] or not payload["errors"]:
        return 0
    return 1


def cmd_not_implemented(name: str) -> int:
    mod = REGISTRY[name]
    print(f"{name} 未实现：计划 v{mod.PLANNED_VERSION}。{mod.DESCRIPTION}", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rekit",
        description="模块化二进制分析流水线：triage → unpack → symbols → report",
    )
    p.add_argument("--version", action="version", version=f"rekit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("triage", help="PE 概览 + 加壳/结构异常评分")
    t.add_argument("paths", nargs="+", help="文件、目录或通配符（如 样本/packed/*.exe）")
    t.add_argument("-o", "--json", metavar="PATH", help="输出 JSON")
    t.add_argument("-m", "--markdown", metavar="PATH", help="输出 Markdown 报告")
    t.set_defaults(func=cmd_triage)

    for name in ("unpack", "symbols"):
        sp = sub.add_parser(name, help=f"{REGISTRY[name].DESCRIPTION}")
        sp.add_argument("paths", nargs="+")
        sp.set_defaults(func=lambda _a, _n=name: cmd_not_implemented(_n))

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
