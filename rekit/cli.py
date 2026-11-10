# -*- coding: utf-8 -*-
"""rekit 命令行入口。

    rekit triage <路径...> [-o out.json] [-m out.md]
    rekit unpack <路径...> [-d out_dir] [--verify-only] [-j out.json]
    rekit map    <路径...> [--rva 0x...] [-j out.json]
    rekit symbols <路径...>   # v0.3

triage / unpack 已实现；symbols 报"未实现 + 计划版本"，不用假输出糊弄。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from . import __version__
from .analyzers import REGISTRY
from .report import render_triage


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


def cmd_unpack(args: argparse.Namespace) -> int:
    payload = REGISTRY["unpack"].run(args.paths, args.out_dir, args.verify_only)
    payload = {
        "tool": "rekit",
        "version": __version__,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        **payload,
    }

    for r in payload["results"]:
        d = r["diff"]
        total = r["imports"]["names"] + r["imports"]["ordinals"] + r["imports"]["raw"]
        print(f"{'OK  ' if r['ok'] else 'FAIL'} {r['packed']}")
        print(f"  路径   {r['path_used']}")
        print(f"  解压   {r['unpacked_bytes']:,} 字节（压缩 {r['compressed_bytes']:,}），"
              f"adler {'一致' if r['adler']['ok'] else '不一致'} {r['adler']['declared']}")
        print(f"  IAT    {r['imports']['dlls']} 个 DLL / {total} 个符号；"
              f"重定位 {r['relocs']['dir64']} 条")
        if r["resources"]["entries"]:
            print(f"  资源   {r['resources']['entries']} 个数据项，搬回 "
                  f"{r['resources']['copied']} 个；目录重建 {r['resources']['dir_bytes']} 字节")
        if d["text_size"] is not None:
            print(f"  对照   .text {d['text_size']:,} 字节中 {d['text_mismatch']:,} 字节不同；"
                  f"整文件 {d['file_mismatch']:,} 字节不同")
        if r["out"]:
            print(f"  输出   {r['out']}")
        for c in r["checks"]:
            print(f"  [{'通过' if c['ok'] else '失败'}] {c['name']}：{c['detail']}")
        print()

    for e in payload["errors"]:
        print(f"[跳过] {e['file']}: {e['error']}", file=sys.stderr)

    if args.json:
        try:
            _write_json(args.json, payload)
            print(f"[JSON] {args.json}")
        except OSError as e:
            print(f"[输出失败] {type(e).__name__}: {e}（目录不存在或无写权限）", file=sys.stderr)
            return 1

    if len(payload["results"]) + len(payload["errors"]) > 1:
        print(f"[汇总] 成功 {len(payload['results'])} / 失败 {len(payload['errors'])}")

    if not payload["results"] or payload["errors"]:
        return 1
    return 0 if all(r["ok"] for r in payload["results"]) else 1


def cmd_map(args: argparse.Namespace) -> int:
    probes = [int(x, 0) for x in (args.rva or [])]
    payload = REGISTRY["map"].run(args.paths, probes)
    payload = {
        "tool": "rekit",
        "version": __version__,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        **payload,
    }

    for r in payload["results"]:
        print(f"{r['file']}  {r['format']} {r['arch']}  ImageBase={r['image_base']}  "
              f"SectionAlign={r['section_alignment']} FileAlign={r['file_alignment']}")
        print(f"  {'#':>2} {'节':<9}{'RVA 区间':<24}{'FOA 区间':<24}"
              f"{'内存':>9}{'文件':>9}{'补零':>9}{'多出':>7}  权限")
        for s in r["sections"]:
            perm = "".join(c for c, ok in (("R", s["readable"]), ("W", s["writable"]),
                                           ("X", s["executable"])) if ok) or "-"
            print(f"  {s['index']:>2} {s['name']:<9}{s['rva']:<24}{s['foa']:<24}"
                  f"{s['rva_end'] - s['rva_start']:>9,}{s['raw_size']:>9,}"
                  f"{s['zero_fill']:>9,}{s['file_slack']:>7,}  {perm}")
        for p in r["probes"]:
            foa = f" FOA=0x{p['foa']:X}" if p["foa"] is not None else ""
            print(f"  探针 RVA 0x{p['rva']:X} -> {p['kind']} 节={p['section'] or '-'}{foa}")
            print(f"       {p['detail']}")
        for n in r["notes"]:
            print(f"  [注意] {n}")
        print()

    for e in payload["errors"]:
        print(f"[跳过] {e['file']}: {e['error']}", file=sys.stderr)

    if args.json:
        try:
            _write_json(args.json, payload)
            print(f"[JSON] {args.json}")
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

    u = sub.add_parser("unpack", help=REGISTRY["unpack"].DESCRIPTION)
    u.add_argument("paths", nargs="+", help="文件、目录或通配符")
    u.add_argument("-d", "--out-dir", default=None, help="输出目录（默认 ./unpacked）")
    u.add_argument("--verify-only", action="store_true", help="只解压校验，不写文件")
    u.add_argument("-j", "--json", metavar="PATH", help="输出 JSON 报告")
    u.set_defaults(func=cmd_unpack)

    m = sub.add_parser("map", help=REGISTRY["map"].DESCRIPTION)
    m.add_argument("paths", nargs="+", help="文件、目录或通配符")
    m.add_argument("--rva", action="append", metavar="0xRVA",
                   help="探针 RVA（可重复），说明它在文件/内存里的归属")
    m.add_argument("-j", "--json", metavar="PATH", help="输出 JSON 报告")
    m.set_defaults(func=cmd_map)

    for name in ("symbols",):
        sp = sub.add_parser(name, help=f"{REGISTRY[name].DESCRIPTION}")
        sp.add_argument("paths", nargs="+")
        sp.set_defaults(func=lambda _a, _n=name: cmd_not_implemented(_n))

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
