# -*- coding: utf-8 -*-
"""rekit 命令行入口。

    rekit triage <路径...> [-o out.json] [-m out.md]
    rekit unpack <路径...> [-d out_dir] [--verify-only] [-j out.json]
    rekit map    <路径...> [--rva 0x...] [-j out.json]
    rekit funcs  <路径...> [--json out.json] [--csv out.csv] [--exhaust full]
    rekit xref   <路径...> (--string S | --va 0x.. | --rva 0x.. | --const N)...
    rekit symbols <路径...>   # v0.3

triage / unpack / map / funcs / data / xref 已实现；symbols 报"未实现 + 计划版本"，
不用假输出糊弄。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

from . import __version__
from .analyzers import REGISTRY
from .contract import SCHEMA_VERSION, envelope, error_entry
from .report import render_triage


def _envelope(analyzer: str, payload: dict) -> dict:
    """统一外层：每个子命令都带顶层 schema_version。"""
    return envelope(analyzer, payload,
                    datetime.now().isoformat(timespec="seconds"))


def _write_json(path: str, payload: dict) -> None:
    # newline="\n"：跨机器重跑时不让 Windows 把换行改成 CRLF
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _write_report_error(args: argparse.Namespace, exc: BaseException) -> None:
    """report 失败时若给了 -j，也写一份统一错误 JSON；不写时间戳。"""
    if not getattr(args, "json", None):
        return
    payload = {
        "tool": "rekit",
        "version": __version__,
        "schema_version": SCHEMA_VERSION["report"],
        "analyzer": "report",
        "results": [],
        "errors": [error_entry(args.sample, exc)],
    }
    try:
        _write_json(args.json, payload)
    except OSError:
        pass


def cmd_triage(args: argparse.Namespace) -> int:
    payload = REGISTRY["triage"].run(args.paths, allow_large=args.allow_large)
    payload = _envelope("triage", payload)

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
    payload = _envelope("unpack", payload)

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
    payload = REGISTRY["map"].run(args.paths, probes, allow_large=args.allow_large)
    payload = _envelope("map", payload)

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


def cmd_funcs(args: argparse.Namespace) -> int:
    try:
        from .core.funcs import CSV_FIELDS, csv_rows
    except ImportError as e:  # pragma: no cover - 环境问题
        print(f"[依赖缺失] {e}", file=sys.stderr)
        return 2
    payload = REGISTRY["funcs"].run(
        args.paths, pointers=not args.no_pointers,
        data_sections=args.data_sections.split(",") if args.data_sections else None,
        exhaust=args.exhaust, profile=args.profile,
        use_eh_frame=not args.no_eh_frame, allow_large=args.allow_large,
        reference=args.reference, cold=args.cold_start)
    payload = _envelope("funcs", payload)

    layer_cn = {"A": "A", "B-reachable": "B 可达", "B-isolated": "B 孤立"}
    for r in payload["results"]:
        a, m = r["authority"], r["metrics"]
        tc = r["toolchain"]
        print(f"{r['file']}  {r['format']}{r['bits']}  "
              f"工具链={tc['family']}({tc['confidence']})/{tc['profile']}  "
              f"权威表={a['name']}  {a['starts']} 项"
              + (f"，名称 {a['names_recovered']}" if a.get("names_recovered") else ""))
        has_names = any(f.get("name") for f in r["functions"])
        if has_names:
            print(f"  起点        终点        大小  函数名"
                  f"{'':<32}{'证据':<28}{'组':<8}{'口径':<8}节")
        else:
            print(f"  起点        终点        大小  {'证据':<28}{'组':<8}{'口径':<8}节")
        for f in r["functions"]:
            ev = "+".join(f["evidence"]) or "-"
            name = f"{(f.get('name') or '-')[:38]:<38}  " if has_names else ""
            print(f"  0x{f['start']:<10X} 0x{f['end']:<10X} {f['size']:>5}  "
                  f"{name}{ev:<28}{f['evidence_group']:<8}"
                  f"{layer_cn.get(f['layer'], f['layer']):<8}{f['section'] or '-'}")
        s = m["seeded"]
        if a["usable"]:
            print(f"  [A 层] 起点 {s['emitted']}/{a['starts']}  "
                  f"召回 {s['recall'] * 100:.1f}%  "
                  f"（.text 口径 {a['starts_text']} 项，召回 "
                  f"{(s['recall_text'] or 0) * 100:.1f}%）")
            print(f"         严格误报 {s['fp']}（.text {s['fp_text']}，"
                  f".plt 单列 {s['fp_plt']}）；权威表外 {s['outside_authority']} 个入口")
            cf = m["counterfactual"]
            if cf:
                print(f"  [自证]   不拿权威表播种：召回 {cf['recall'] * 100:.1f}%，"
                      f"严格误报 {cf['fp']}（.text {cf['fp_text']}）")
        else:
            print(f"  [A 层] 不适用：{a['reason']}")
        cold = m.get("cold_start")
        if cold:
            ec = cold.get("evidence_counts") or {}
            rc = cold.get("reachable") or {}
            ic = cold.get("indirect") or {}
            print(f"  [冷启动] 全量召回 {(cold['recall'] or 0) * 100:.1f}%"
                  f"（{cold['emitted']}/{a['starts']}）  "
                  f"可达子集 {(rc.get('recall') or 0) * 100:.1f}%"
                  f"（{rc.get('emitted', 0)}/{rc.get('total', 0)}）  "
                  f".text 误报 {cold['fp_text']}  函数 {cold['functions']}  "
                  f"{cold['seconds']}s")
            print(f"           分母拆分：不可达 {rc.get('unreachable', 0)} 项；"
                  f"间接调用解析 {ic.get('resolved', 0)}/{ic.get('attempts', 0)}"
                  f"（{(ic.get('rate') or 0) * 100:.1f}%，可作起点 {ic.get('seeded', 0)}）")
            print(f"           播种 evidence：" + "；".join(
                f"{k} {v}" for k, v in sorted(ec.items())))
        print(f"  [证据]   " + "；".join(
            f"{k} {v}" for k, v in sorted(m["evidence_groups"].items())))
        if r["exhaust"]:
            e = r["exhaust"]
            print(f"  [B 层] 穷举 align={e['align']} profile={e['profile']}："
                  f"可达 {e['reachable']} / 含孤立 {e['reachable'] + e['isolated']}"
                  f"  {e['seconds']}s")
            im = e.get("isolated_metrics") or {}
            if not im.get("n"):
                print(f"  [孤立桶] n=0  空桶  → "
                      f"{im.get('label', '不可交付（内部参考）')}")
            elif im.get("precision") is None:
                print(f"  [孤立桶] n={im['n']}  "
                      f"精度未验证（{im.get('note', '无参照表')}）  "
                      f"→ {im.get('label', '不可交付（内部参考）')}")
            else:
                lo, hi = im["precision_ci"]
                print(f"  [孤立桶] n={im['n']}  精度 {im['precision'] * 100:.1f}%"
                      f"（95% CI {lo * 100:.1f}–{hi * 100:.1f}）  "
                      f"落在参照函数体内 {im['inside']}  "
                      f"→ {im['label']}")
        if r["notes"]:
            for n in r["notes"]:
                print(f"  [注] {n}")
        print(f"  用时 {r['seconds']}s")
        print()

    for e in payload["errors"]:
        print(f"[跳过] {e['file']}: {e['error']}", file=sys.stderr)

    if args.json:
        try:
            _write_json(args.json, payload)
            print(f"[JSON] {args.json}")
        except OSError as e:
            print(f"[输出失败] {type(e).__name__}: {e}", file=sys.stderr)
            return 1
    if args.csv:
        rows = [row for r in payload["results"] for row in csv_rows(r)]
        try:
            import csv
            with open(args.csv, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
                w.writeheader()
                w.writerows(rows)
            print(f"[CSV]  {args.csv}（{len(rows)} 行）")
        except OSError as e:
            print(f"[输出失败] {type(e).__name__}: {e}", file=sys.stderr)
            return 1

    if payload["results"] or not payload["errors"]:
        return 0
    return 1


def cmd_data(args: argparse.Namespace) -> int:
    try:
        from .analyzers.data import CSV_FIELDS, csv_rows
    except ImportError as e:  # pragma: no cover - 环境问题
        print(f"[依赖缺失] {e}", file=sys.stderr)
        return 2
    payload = REGISTRY["data"].run(
        args.paths, min_c_len=args.min_c_len, min_go_len=args.min_go_len,
        utf16=args.utf16, arrays=not args.no_arrays,
        structs=not args.no_structs, max_items=args.max_items,
        min_run=args.min_run, allow_large=args.allow_large)
    payload = _envelope("data", payload)

    for r in payload["results"]:
        print(f"{r['file']}  {r['format']}{r['bits']}  Go={r['is_go']}")
        c = r["c_strings"]
        print(f"  [C 串]   {c['count']}{'（截断）' if c['truncated'] else ''} 条，"
              f"最长 {c.get('longest', 0)} 字节")
        g = r["go_strings"]
        if g.get("applicable"):
            print(f"  [Go 串]  {g['count']} 条（代码站点 "
                  f"{g.get('code_site_count', 0)} / 数据头 "
                  f"{g.get('data_pair_count', 0)}；站点 {g['sites']}，"
                  f"C 串扫描会读长 {g['naive_would_overread']} 处）")
        pa = r.get("pointer_arrays")
        if pa:
            code = sum(1 for a in pa["arrays"] if a["target_class"] == "code")
            print(f"  [指针数组] {pa['count']} 组（代码表 {code} / 数据表 "
                  f"{pa['count'] - code}），阈值 ≥{pa['min_run']} 项")
            for a in pa["arrays"][:3]:
                ratio = a.get("authority_start_ratio")
                tail = f"  命中权威起点 {ratio * 100:.0f}%" if ratio is not None else ""
                print(f"    0x{a['address']:X}  {a['count']} 项 × {a['stride']}B  "
                      f"{a['target_class']}{tail}")
        sf = r.get("struct_fields")
        if sf:
            if sf.get("supported"):
                print(f"  [结构体] 权威表 {sf['authority']}，"
                      f"{sf['function_count']} 个函数命中 ≥2 个偏移")
                for cl in sf["clusters"][:3]:
                    fields = ", ".join(
                        f"+0x{x['offset']:X}/{x['width']}B" for x in cl["fields"][:8])
                    print(f"    {cl['functions']} 个函数共享 [{fields}]")
            else:
                print(f"  [结构体] 跳过：{sf.get('reason')}")
        print()

    for e in payload["errors"]:
        print(f"[跳过] {e['file']}: {e['error']}", file=sys.stderr)

    if args.json:
        try:
            _write_json(args.json, payload)
            print(f"[JSON] {args.json}")
        except OSError as e:
            print(f"[输出失败] {type(e).__name__}: {e}", file=sys.stderr)
            return 1
    if args.csv:
        rows = [row for r in payload["results"] for row in csv_rows(r)]
        try:
            import csv
            with open(args.csv, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
                w.writeheader()
                w.writerows(rows)
            print(f"[CSV]  {args.csv}（{len(rows)} 行）")
        except OSError as e:
            print(f"[输出失败] {type(e).__name__}: {e}", file=sys.stderr)
            return 1

    return 0 if payload["results"] or not payload["errors"] else 1


def cmd_xref(args: argparse.Namespace) -> int:
    from .analyzers.xref import CSV_FIELDS, csv_rows

    specs: list[dict] = []
    for s in args.string or []:
        specs.append({"kind": "string", "value": s})
    for v in args.va or []:
        specs.append({"kind": "va", "value": int(v, 0)})
    for v in args.rva or []:
        specs.append({"kind": "rva", "value": int(v, 0)})
    for v in args.const or []:
        specs.append({"kind": "const", "value": int(v, 0)})
    if not specs:
        print("[缺少目标] 用 --string / --va / --rva / --const 至少指定一个",
              file=sys.stderr)
        return 2

    payload = REGISTRY["xref"].run(
        args.paths, specs, byte_scan=args.byte_scan,
        pointers=not args.no_pointers, utf16=args.utf16,
        allow_large=args.allow_large)
    payload = _envelope("xref", payload)

    for r in payload["results"]:
        st = r["instruction_stream"]
        print(f"{r['file']}  {r['format']}{r['bits']}  "
              f"ImageBase={r['image_base']}  指令流=funcs 递归下降"
              f"（函数 {st['functions']} / 指令 {st['instructions']}）")
        if args.byte_scan:
            print("  [口径] 已开启 .text 字节扫描：命中一律归入疑似，"
                  "可能落在操作数内部")
        for t in r["targets"]:
            inp = t["input"]
            print(f"  目标 [{inp['kind']}] {inp['value']}")
            if not t["resolved"]:
                print("    [未解析] 没有找到目标位置")
            for res in t["resolved"]:
                if res.get("va") is not None:
                    sec = res.get("section") or "-"
                    print(f"    -> 0x{res['va']:X}  {sec}  {res.get('preview', '')[:60]}")
            for b in t["blocks"]:
                c = b["counts"]
                print(f"    [0x{b['va']:X}] 确定 {c['certain']} / 疑似 "
                      f"{c['suspected']}（引用函数 {c['functions']}）")
                shown = 0
                for ref in b["refs"]:
                    if shown >= 20:
                        print(f"      … 其余 {len(b['refs']) - shown} 条见 JSON/CSV")
                        break
                    fn = "-" if ref["function"] is None else f"0x{ref['function']:X}"
                    tag = "确定" if ref["confidence"] == "certain" else "疑似"
                    print(f"      [{tag}] 0x{ref['va']:X}  {ref['ref_type']:<16}"
                          f"{ref['text'][:52]:<54}函数 {fn}")
                    shown += 1
                if c["certain"] == 0 and c["suspected"]:
                    print("      [注意] 只有疑似引用，不能当作确定引用")
                for n in b["notes"]:
                    print(f"      [注] {n}")
        if r["instruction_stream"]["notes"]:
            for n in r["instruction_stream"]["notes"]:
                if "召回上限" in n:
                    print(f"  [注] {n}")
        print(f"  用时 {r['seconds']}s")
        print()

    for e in payload["errors"]:
        print(f"[跳过] {e['file']}: {e['error']}", file=sys.stderr)

    if args.json:
        try:
            _write_json(args.json, payload)
            print(f"[JSON] {args.json}")
        except OSError as e:
            print(f"[输出失败] {type(e).__name__}: {e}", file=sys.stderr)
            return 1
    if args.csv:
        rows = [row for r in payload["results"] for row in csv_rows(r)]
        try:
            import csv
            with open(args.csv, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
                w.writeheader()
                w.writerows(rows)
            print(f"[CSV]  {args.csv}（{len(rows)} 行）")
        except OSError as e:
            print(f"[输出失败] {type(e).__name__}: {e}", file=sys.stderr)
            return 1

    if payload["results"] or not payload["errors"]:
        return 0
    return 1


def cmd_identify(args: argparse.Namespace) -> int:
    payload = REGISTRY["identify"].run(args.paths, allow_large=args.allow_large)
    payload = _envelope("identify", payload)
    for r in payload["results"]:
        ev = sum(1 for s in r["signals"] if s.get("evidence", {}).get("offset"))
        print(f"{r['file']}  family={r['family']} conf={r['confidence']:.3f} "
              f"verdict={r['verdict']} signals={len(r['signals'])} 带偏移={ev}")
        print(f"  依据: {r['basis']}")
        for s in r["signals"]:
            e = s.get("evidence") or {}
            if e.get("offset"):
                print(f"    [{s['id']}] {e['offset']} ({e['offset_kind']}) {e['value']}")
        for c in r["conflicts"]:
            print(f"  [冲突] {c['between']}: {c['note']}")
    for e in payload["errors"]:
        print(f"[跳过] {e['file']}: {e['error']}", file=sys.stderr)
    if args.json:
        try:
            _write_json(args.json, payload)
            print(f"[JSON] {args.json}")
        except OSError as e:
            print(f"[输出失败] {type(e).__name__}: {e}", file=sys.stderr)
            return 1
    return 0 if payload["results"] or not payload["errors"] else 1


def cmd_report(args: argparse.Namespace) -> int:
    try:
        from .analyzers import report as report_mod
        from .core import rules as rules_mod
    except ImportError as e:  # pragma: no cover - 环境问题
        print(f"[依赖缺失] {e}", file=sys.stderr)
        return 2

    sample_id = args.id or os.path.splitext(os.path.basename(args.sample))[0]
    try:
        payload = report_mod.analyze_file(
            args.sample, sample_id, family=args.family,
            rules_path=args.rules, allow_large=args.allow_large)
    except FileNotFoundError as e:
        print(f"[失败] 样本不存在：{args.sample}", file=sys.stderr)
        _write_report_error(args, e)
        return 1
    except (ValueError, OSError) as e:
        print(f"[失败] {type(e).__name__}: {e}", file=sys.stderr)
        _write_report_error(args, e)
        return 1

    # 只增不改：补齐与其余 7 个子命令一致的顶层字段；报告本身仍不含时间戳。
    payload["schema_version"] = SCHEMA_VERSION["report"]
    payload["analyzer"] = "report"
    payload["version"] = __version__
    payload["errors"] = []

    stats = payload["field_stats"]
    print(f"{payload['sample']['id']}  sha256={payload['sample']['sha256']}  "
          f"家族={payload['family_group']}")
    print(f"  字段 {stats['auto']}/{stats['total']} 自动 + "
          f"{stats['human']} 人工（自动率 {stats['auto_ratio'] * 100:.1f}%）")
    print(f"  规则 {payload['rules']['engine']}；"
          f"命中 {', '.join(payload['rules']['hit_ids']) or '无'}；"
          f"YARA 校验 {payload['rules']['yara_validation']['status']}")

    try:
        if args.markdown:
            with open(args.markdown, "w", encoding="utf-8", newline="\n") as f:
                f.write(report_mod.render_markdown(payload, __version__))
            print(f"[MD]   {args.markdown}")
        if args.json:
            _write_json(args.json, payload)
            print(f"[JSON] {args.json}")
        if args.yar:
            if not args.rules:
                print("[失败] --yar 需要同时给 --rules（同一份规则同源生成）",
                      file=sys.stderr)
                return 2
            text = rules_mod.render_yara(
                rules_mod.load_rules(args.rules),
                rules_mod.load_validation(args.rules))
            with open(args.yar, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            status = rules_mod.load_validation(args.rules)["status"]
            print(f"[YARA] {args.yar}（YARA 校验：{status}；非 YARA 兼容实现）")
    except OSError as e:
        print(f"[输出失败] {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


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
    t.add_argument("--allow-large", action="store_true",
                   help="允许解析超过 512 MiB 的文件（默认拒绝，避免一次吃掉几百 MB）")
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
    m.add_argument("--allow-large", action="store_true",
                   help="允许解析超过 512 MiB 的文件（默认拒绝）")
    m.set_defaults(func=cmd_map)

    f = sub.add_parser("funcs", help=REGISTRY["funcs"].DESCRIPTION)
    f.add_argument("paths", nargs="+", help="文件、目录或通配符")
    f.add_argument("-j", "--json", metavar="PATH", help="输出 JSON")
    f.add_argument("--csv", metavar="PATH", help="输出函数表 CSV（字段见 docs/funcs.md）")
    f.add_argument("--no-pointers", action="store_true", help="关闭函数指针表扫描")
    f.add_argument("--data-sections", metavar="A,B",
                   help="指针表所在节（默认 PE .rdata,.data；ELF .rodata,.data,...）")
    f.add_argument("--exhaust", choices=("fast", "normal", "full"), default=None,
                   help="无引用函数的穷举扫描步长：fast=4 / normal=2 / full=1 字节")
    f.add_argument("--profile", choices=("auto", "legacy", "msvc_x86", "msvc_x64",
                                         "gcc_x64", "go_x64", "generic"),
                   default="auto", help="序言形状库；auto 按工具链判别选择")
    f.add_argument("--no-eh-frame", action="store_true",
                   help="不把 ELF .eh_frame 当权威表（用于量化 B 层）")
    f.add_argument("--reference", metavar="CSV",
                   help="参照表（gh_count.py 的 Ghidra CSV），只用于验算孤立桶精度")
    f.add_argument("--cold-start", action="store_true",
                   help="追加冷启动口径：禁用符号/权威表播种，只用代码与数据本身")
    f.add_argument("--allow-large", action="store_true",
                   help="允许解析超过 512 MiB 的文件（默认拒绝）")
    f.set_defaults(func=cmd_funcs)

    d = sub.add_parser("data", help=REGISTRY["data"].DESCRIPTION)
    d.add_argument("paths", nargs="+", help="文件、目录或通配符")
    d.add_argument("-j", "--json", metavar="PATH", help="输出 JSON")
    d.add_argument("--csv", metavar="PATH", help="输出字符串 CSV（字段见 docs/data.md）")
    d.add_argument("--min-c-len", type=int, default=6, help="C 串最短长度（默认 6）")
    d.add_argument("--min-go-len", type=int, default=4, help="Go 串最短长度（默认 4）")
    d.add_argument("--utf16", action="store_true", help="额外扫描 UTF-16LE 字符串")
    d.add_argument("--min-run", type=int, default=4, help="指针数组最少连续项数")
    d.add_argument("--max-items", type=int, default=20000,
                   help="每类最多输出多少条（默认 20000）")
    d.add_argument("--no-arrays", action="store_true", help="跳过指针数组扫描")
    d.add_argument("--no-structs", action="store_true", help="跳过结构体字段统计")
    d.add_argument("--allow-large", action="store_true",
                   help="允许解析超过 512 MiB 的文件（默认拒绝）")
    d.set_defaults(func=cmd_data)

    x = sub.add_parser("xref", help=REGISTRY["xref"].DESCRIPTION)
    x.add_argument("paths", nargs="+", help="文件、目录或通配符")
    x.add_argument("--string", action="append", metavar="TEXT",
                   help="按字面量定位目标（非可执行节字节匹配），可重复")
    x.add_argument("--va", action="append", metavar="0xVA",
                   help="绝对虚拟地址目标，可重复")
    x.add_argument("--rva", action="append", metavar="0xRVA",
                   help="相对 ImageBase 的地址目标，可重复")
    x.add_argument("--const", action="append", metavar="N",
                   help="常量目标（只查立即数），可重复")
    x.add_argument("--byte-scan", action="store_true",
                   help="补做 .text 字节扫描；命中一律标疑似，可能落在操作数内部")
    x.add_argument("--utf16", action="store_true",
                   help="字面量同时按 UTF-16LE 匹配")
    x.add_argument("--no-pointers", action="store_true",
                   help="关闭指针表扫描（只影响函数发现，不影响引用类型）")
    x.add_argument("-j", "--json", metavar="PATH", help="输出 JSON")
    x.add_argument("--csv", metavar="PATH", help="输出引用表 CSV（字段见 docs/xref.md）")
    x.add_argument("--allow-large", action="store_true",
                   help="允许解析超过 512 MiB 的文件（默认拒绝）")
    x.set_defaults(func=cmd_xref)

    i = sub.add_parser("identify", help=REGISTRY["identify"].DESCRIPTION)
    i.add_argument("paths", nargs="+", help="文件、目录或通配符")
    i.add_argument("-j", "--json", metavar="PATH", help="输出 JSON")
    i.add_argument("--allow-large", action="store_true",
                   help="允许解析超过 512 MiB 的文件（默认拒绝）")
    i.set_defaults(func=cmd_identify)

    rp = sub.add_parser("report", help=REGISTRY["report"].DESCRIPTION)
    rp.add_argument("sample", help="样本路径（报告里只写 sha256，不写这个路径）")
    rp.add_argument("--id", metavar="ID", default=None,
                    help="逻辑样本 id（默认取文件名主干）")
    rp.add_argument("--family", choices=("auto", "dotnet", "go", "native"),
                    default="auto", help="家族分组；auto 按 CLR/Go 元数据判定")
    rp.add_argument("--rules", metavar="JSON", default=None,
                    help="rekit 规则引擎的规则文件（JSON）")
    rp.add_argument("--yar", metavar="PATH", default=None,
                    help="由同一份规则生成 .yar 文本（标注未经 YARA 校验）")
    rp.add_argument("-o", "--markdown", metavar="PATH", help="输出 Markdown 报告")
    rp.add_argument("-j", "--json", metavar="PATH", help="输出 JSON 报告")
    rp.add_argument("--allow-large", action="store_true",
                   help="允许解析超过 512 MiB 的文件（默认拒绝）")
    rp.set_defaults(func=cmd_report)

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
