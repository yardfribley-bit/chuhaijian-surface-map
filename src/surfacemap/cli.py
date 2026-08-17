#!/usr/bin/env python3
"""CLI: surfacemap run | map | components"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from surfacemap.probe import probe_target
from surfacemap.report import write_reports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="surfacemap",
        description="出海鉴攻击面测绘 — 默认不用 FOFA；组件清单可交 codeaudit",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="对授权 URL 做非侵入路径探测")
    run_p.add_argument("--url", required=True)
    run_p.add_argument("--out", default="./out")
    run_p.add_argument("--rps", type=float, default=2.0)
    run_p.add_argument("--i-am-authorized", action="store_true")
    run_p.add_argument("--paths-file")
    run_p.add_argument(
        "--emit-components",
        action="store_true",
        help="同时写出 components.json 供 codeaudit from-inventory",
    )

    map_p = sub.add_parser("map", help="【可选】FOFA 挂图；默认工作流可不使用")
    map_p.add_argument("--domain")
    map_p.add_argument("--org")
    map_p.add_argument("--include-org-query", action="store_true")
    map_p.add_argument("--out", default="./ops-map")
    map_p.add_argument("--max-size", type=int, default=500)
    map_p.add_argument("--page-size", type=int, default=100)
    map_p.add_argument("--full", action="store_true")
    map_p.add_argument("--i-am-authorized", action="store_true")
    map_p.add_argument("--authorization-ref", default="")

    comp_p = sub.add_parser("components", help="从已有 surface.json/探测结果提取组件清单")
    comp_p.add_argument("--from-json", required=True, help="surface.json 或 map_bundle.json")
    comp_p.add_argument("--out", default="./components.json")

    args = parser.parse_args(argv)

    if args.cmd == "run":
        if not args.i_am_authorized:
            print("[ERR] 必须加上 --i-am-authorized", file=sys.stderr)
            return 2
        parsed = urlparse(args.url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            print("[ERR] --url 需要完整 http(s) URL", file=sys.stderr)
            return 1
        extra: list[str] = []
        if args.paths_file:
            p = Path(args.paths_file)
            if p.is_file():
                extra = [
                    ln.strip()
                    for ln in p.read_text(encoding="utf-8").splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                ]
        print(f"[surfacemap] 测绘 {args.url} (只读, rps={args.rps})")
        result = probe_target(args.url, rps=args.rps, extra_paths=extra)
        out = Path(args.out).resolve()
        paths = write_reports(out, result)
        print(f"[OK] 探测 {result['stats']['requests']} 次请求")
        for path in paths:
            print(f"  → {path}")
        if args.emit_components:
            from surfacemap.components import extract_components, inventory_document

            comps = extract_components(result)
            inv = inventory_document(args.url, comps)
            inv_path = out / "components.json"
            inv_path.write_text(json.dumps(inv, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"  → components: {inv_path} ({len(comps)} 项)")
            print("  下一步: codeaudit from-inventory --inventory", str(inv_path))
        return 0

    if args.cmd == "map":
        if not args.i_am_authorized:
            print("[ERR] 必须加上 --i-am-authorized", file=sys.stderr)
            return 2
        if not args.domain and not args.org:
            print("[ERR] 需要 --domain 和/或 --org", file=sys.stderr)
            return 2
        from surfacemap.fofa_client import FofaError, account_info
        from surfacemap.mapper import run_map

        try:
            info = account_info()
            print(
                f"[fofa] 账号 {info.get('email') or info.get('username') or '?'} "
                f"vip={info.get('isvip')}"
            )
        except FofaError as e:
            print(f"[ERR] FOFA: {e}", file=sys.stderr)
            return 1
        try:
            bundle = run_map(
                domain=args.domain,
                org=args.org,
                out_dir=Path(args.out).resolve(),
                max_size=args.max_size,
                page_size=args.page_size,
                include_org_query=args.include_org_query,
                full=args.full,
            )
        except (FofaError, ValueError) as e:
            print(f"[ERR] {e}", file=sys.stderr)
            return 1
        stats = bundle.get("stats") or {}
        print(f"[OK] 资产 {stats.get('assets', 0)}")
        for k, v in (bundle.get("outputs") or {}).items():
            print(f"  → {k}: {v}")
        return 0

    if args.cmd == "components":
        from surfacemap.components import extract_components, inventory_document

        src = Path(args.from_json).resolve()
        if not src.is_file():
            print(f"[ERR] 文件不存在: {src}", file=sys.stderr)
            return 1
        data = json.loads(src.read_text(encoding="utf-8"))
        comps = extract_components(data)
        target = data.get("target") or data.get("seed", {}).get("domain") or ""
        inv = inventory_document(str(target), comps)
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(inv, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[OK] {len(comps)} 个组件线索 → {out}")
        print("下一步: codeaudit from-inventory --inventory", str(out))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
