"""挂图作战编排：线索 → FOFA → 归一化 → 评分 → 图 → 报告。"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from surfacemap.fofa_client import FofaError, search_all
from surfacemap.graph import build_graph
from surfacemap.map_html import write_ops_map_html
from surfacemap.normalize import normalize_assets
from surfacemap.risk import score_assets


def build_queries(domain: str | None, org: str | None) -> list[tuple[str, str]]:
    """返回 (name, query) 列表。组织名查询仅作补充线索。"""
    queries: list[tuple[str, str]] = []
    if domain:
        d = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        d = d.split(":")[0]
        if not re.match(r"^[a-z0-9.-]+$", d):
            raise ValueError(f"域名不合法: {domain}")
        queries.append(("domain", f'domain="{d}"'))
        # 证书中出现主域（补充，可能扩大范围）
        queries.append(("cert_domain", f'cert="{d}" && domain!="{d}"'))
    if org:
        o = org.strip().replace('"', "")
        if len(o) >= 2:
            # 标题/证书组织线索 — 噪声大，结果标记为 candidate 语境由上层处理
            queries.append(("org_title", f'title="{o}"'))
    if not queries:
        raise ValueError("需要 --domain 和/或 --org")
    return queries


def run_map(
    *,
    domain: str | None,
    org: str | None,
    out_dir: Path,
    max_size: int = 500,
    page_size: int = 100,
    include_org_query: bool = False,
    full: bool = False,
) -> dict[str, Any]:
    queries = build_queries(domain, org if include_org_query else None)
    # 若用户只给了 org 没有 domain，仍允许 org 查询
    if org and not domain and not include_org_query:
        queries = build_queries(None, org)

    all_rows: list[dict[str, Any]] = []
    query_meta: list[dict[str, Any]] = []

    per_query = max(50, max_size // max(len(queries), 1))
    for name, q in queries:
        try:
            rows, meta = search_all(q, max_size=per_query, page_size=page_size, full=full)
        except FofaError as e:
            query_meta.append({"name": name, "query": q, "error": str(e), "fetched": 0})
            continue
        for r in rows:
            r["_query_name"] = name
        all_rows.extend(rows)
        query_meta.append({**meta, "name": name})

    seed = (domain or "").strip() or "unknown"
    assets = normalize_assets(all_rows, source_query=seed)
    assets = score_assets(assets)

    graph = build_graph(seed_domain=seed if domain else (org or "seed"), org=org, assets=assets)

    out_dir.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).isoformat()

    bundle = {
        "generated_at": generated,
        "mode": "fofa-ops-map",
        "exploit": False,
        "authorization_required": True,
        "seed": {"domain": domain, "org": org},
        "queries": query_meta,
        "stats": {
            "assets": len(assets),
            "critical": sum(1 for a in assets if a.get("exposure_severity") == "critical"),
            "high": sum(1 for a in assets if a.get("exposure_severity") == "high"),
            "medium": sum(1 for a in assets if a.get("exposure_severity") == "medium"),
        },
        "assets": assets,
        "graph": graph,
    }

    assets_path = out_dir / "assets.json"
    graph_path = out_dir / "graph.json"
    bundle_path = out_dir / "map_bundle.json"
    assets_path.write_text(json.dumps(assets, ensure_ascii=False, indent=2), encoding="utf-8")
    graph_path.write_text(json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8")
    bundle_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")

    title = f"作战挂图: {org or domain or 'target'}"
    html_path = write_ops_map_html(
        out_dir / "ops-map.html",
        title=title,
        graph=graph,
        assets=assets,
        meta={"query": "; ".join(q for _, q in queries)},
    )

    md_path = out_dir / "report.md"
    md_path.write_text(_markdown_report(bundle), encoding="utf-8")

    bundle["outputs"] = {
        "assets": str(assets_path),
        "graph": str(graph_path),
        "bundle": str(bundle_path),
        "html": str(html_path),
        "report": str(md_path),
    }
    return bundle


def _markdown_report(bundle: dict[str, Any]) -> str:
    seed = bundle.get("seed") or {}
    stats = bundle.get("stats") or {}
    lines = [
        "# 出海鉴 · FOFA 挂图作战报告",
        "",
        f"- 时间: {bundle.get('generated_at')}",
        f"- 域名: {seed.get('domain') or '-'}",
        f"- 组织: {seed.get('org') or '-'}",
        f"- 资产数: {stats.get('assets', 0)}",
        f"- 关注: critical={stats.get('critical', 0)} high={stats.get('high', 0)} medium={stats.get('medium', 0)}",
        f"- 模式: FOFA 只读检索 + 启发式暴露标注（**无利用**）",
        "",
        "## 查询",
        "",
    ]
    for q in bundle.get("queries") or []:
        if q.get("error"):
            lines.append(f"- `{q.get('query')}` → 错误: {q.get('error')}")
        else:
            lines.append(
                f"- `{q.get('query')}` → 拉取 {q.get('fetched', 0)}（FOFA size 提示 {q.get('fofa_size_hint')}）"
            )

    lines.extend(["", "## 优先关注资产", ""])
    focus = [
        a
        for a in bundle.get("assets") or []
        if a.get("exposure_severity") in ("critical", "high", "medium")
    ][:50]
    if not focus:
        lines.append("_无_")
    else:
        for a in focus:
            lines.append(
                f"- **{a.get('exposure_severity')}** `{a.get('ip')}:{a.get('port')}` "
                f"{a.get('host')} — {', '.join(a.get('exposure_reasons') or [])}"
            )

    lines.extend(
        [
            "",
            "---",
            "",
            "**声明**: 数据来自 FOFA 公开索引与本地启发式，可能误报；",
            "仅可用于书面授权范围内的暴露面管理与演练挂图，禁止未授权侦察或攻击。",
            "",
        ]
    )
    return "\n".join(lines)
