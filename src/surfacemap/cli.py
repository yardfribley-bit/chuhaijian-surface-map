#!/usr/bin/env python3
"""CLI: surfacemap run | map"""

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
        description="出海鉴攻击面测绘 — 限流只读 / FOFA 挂图，不执行利用",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="对授权 URL 做非侵入路径探测")
    run_p.add_argument("--url", required=True, help="目标基址，如 https://staging.example.com")
    run_p.add_argument("--out", default="./out", help="报告输出目录")
    run_p.add_argument("--rps", type=float, default=2.0, help="每秒最大请求数（默认 2）")
    run_p.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="确认你对目标拥有授权（必填）",
    )
    run_p.add_argument("--paths-file", help="额外路径列表文件")

    map_p = sub.add_parser("map", help="FOFA 挂图作战：域名/组织 → 资产图谱")
    map_p.add_argument("--domain", help="主域名，如 example.com")
    map_p.add_argument("--org", help="组织名称（可选；加 --include-org-query 才查 title）")
    map_p.add_argument(
        "--include-org-query",
        action="store_true",
        help="启用组织名 title 检索（噪声大，默认关闭）",
    )
    map_p.add_argument("--out", default="./ops-map", help="输出目录")
    map_p.add_argument("--max-size", type=int, default=500, help="最多拉取资产条数（默认 500）")
    map_p.add_argument("--page-size", type=int, default=100, help="FOFA 分页大小")
    map_p.add_argument("--full", action="store_true", help="FOFA full=true（若账号支持）")
    map_p.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="确认书面授权（必填）",
    )
    map_p.add_argument(
        "--authorization-ref",
        default="",
        help="授权依据编号/合同号（写入报告元数据）",
    )

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
        return 0

    if args.cmd == "map":
        if not args.i_am_authorized:
            print("[ERR] 必须加上 --i-am-authorized（仅授权目标）", file=sys.stderr)
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
                f"vip={info.get('isvip')} remain_api_data={info.get('remain_api_data')}"
            )
        except FofaError as e:
            print(f"[ERR] FOFA 凭据/网络: {e}", file=sys.stderr)
            return 1

        print(f"[surfacemap] 挂图 domain={args.domain!r} org={args.org!r}")
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

        if args.authorization_ref:
            # 轻量落盘授权编号
            ref_path = Path(args.out).resolve() / "authorization_ref.txt"
            ref_path.write_text(args.authorization_ref + "\n", encoding="utf-8")

        stats = bundle.get("stats") or {}
        print(
            f"[OK] 资产 {stats.get('assets', 0)} "
            f"(critical={stats.get('critical', 0)} high={stats.get('high', 0)} medium={stats.get('medium', 0)})"
        )
        for k, v in (bundle.get("outputs") or {}).items():
            print(f"  → {k}: {v}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
