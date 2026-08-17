#!/usr/bin/env python3
"""CLI: surfacemap run --url URL --out DIR"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from surfacemap.probe import probe_target
from surfacemap.report import write_reports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="surfacemap",
        description="出海鉴攻击面测绘 — 限流只读探测，不执行利用",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="对授权 URL 做非侵入测绘")
    run_p.add_argument("--url", required=True, help="目标基址，如 https://staging.example.com")
    run_p.add_argument("--out", default="./out", help="报告输出目录")
    run_p.add_argument("--rps", type=float, default=2.0, help="每秒最大请求数（默认 2）")
    run_p.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="确认你对目标拥有授权（必填）",
    )
    run_p.add_argument(
        "--paths-file",
        help="额外路径列表文件（每行一个路径，如 /api/health）",
    )

    args = parser.parse_args(argv)

    if args.cmd == "run":
        if not args.i_am_authorized:
            print(
                "[ERR] 必须加上 --i-am-authorized，仅对你拥有或已书面授权的目标使用。",
                file=sys.stderr,
            )
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
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
