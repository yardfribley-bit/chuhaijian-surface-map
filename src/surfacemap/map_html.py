"""生成单文件 HTML 作战挂图（CDN 加载 vis-network）。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_ops_map_html(
    out_path: Path,
    *,
    title: str,
    graph: dict[str, Any],
    assets: list[dict[str, Any]],
    meta: dict[str, Any],
) -> Path:
    color = {
        "critical": "#e11d48",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#38bdf8",
        "info": "#94a3b8",
        "org": "#a78bfa",
        "domain": "#60a5fa",
        "host": "#34d399",
        "ip": "#94a3b8",
        "service": "#f472b6",
    }

    nodes_js = []
    for n in graph.get("nodes") or []:
        ntype = n.get("type") or "info"
        sev = n.get("severity") or "info"
        c = color.get(sev) if ntype == "service" else color.get(ntype, color["info"])
        if ntype == "service" and sev in color:
            c = color[sev]
        nodes_js.append(
            {
                "id": n["id"],
                "label": (n.get("label") or n["id"])[:40],
                "group": ntype,
                "title": _tooltip(n),
                "color": c,
            }
        )

    edges_js = [
        {"from": e["source"], "to": e["target"], "label": e.get("rel") or ""}
        for e in graph.get("edges") or []
    ]

    top = [a for a in assets if a.get("exposure_severity") in ("critical", "high", "medium")][:40]

    html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{_esc(title)}</title>
<script src="https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js"></script>
<style>
  body {{ margin:0; font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
         background:#0b1220; color:#e5e7eb; }}
  header {{ padding:14px 18px; border-bottom:1px solid #1f2937; }}
  header h1 {{ margin:0; font-size:18px; }}
  header p {{ margin:6px 0 0; color:#94a3b8; font-size:12px; }}
  .wrap {{ display:flex; height: calc(100vh - 72px); }}
  #graph {{ flex:1; border-right:1px solid #1f2937; }}
  aside {{ width:380px; overflow:auto; padding:12px 14px; }}
  table {{ width:100%; border-collapse:collapse; font-size:12px; }}
  th, td {{ border-bottom:1px solid #1f2937; padding:6px 4px; text-align:left; vertical-align:top; }}
  .tag {{ display:inline-block; padding:1px 6px; border-radius:6px; font-size:11px; }}
  .critical {{ background:#4c0519; color:#fb7185; }}
  .high {{ background:#7c2d12; color:#fdba74; }}
  .medium {{ background:#713f12; color:#fde047; }}
  .low {{ background:#0c4a6e; color:#7dd3fc; }}
  .info {{ background:#1e293b; color:#94a3b8; }}
  .note {{ font-size:11px; color:#64748b; margin-top:12px; line-height:1.5; }}
</style>
</head>
<body>
<header>
  <h1>{_esc(title)}</h1>
  <p>出海鉴挂图作战 · 只读暴露面视图 · 非漏洞利用 · FOFA 数据需授权使用</p>
  <p>资产 {len(assets)} · 节点 {graph.get('stats',{}).get('nodes',0)} · 边 {graph.get('stats',{}).get('edges',0)} · 查询 {_esc(str(meta.get('query','')))}</p>
</header>
<div class="wrap">
  <div id="graph"></div>
  <aside>
    <h3 style="margin:0 0 8px;font-size:14px;">优先关注（启发式）</h3>
    <table>
      <thead><tr><th>级别</th><th>资产</th><th>线索</th></tr></thead>
      <tbody>
      {"".join(_row(a) for a in top) if top else "<tr><td colspan=3>无高优先级线索</td></tr>"}
      </tbody>
    </table>
    <p class="note">颜色仅表示公开暴露关注度启发式，不代表已验证漏洞或可利用性。
    请仅在书面授权范围内使用，并人工确认后再收敛。</p>
  </aside>
</div>
<script>
const nodes = new vis.DataSet({json.dumps(nodes_js, ensure_ascii=False)});
const edges = new vis.DataSet({json.dumps(edges_js, ensure_ascii=False)});
const container = document.getElementById('graph');
const network = new vis.Network(container, {{nodes, edges}}, {{
  physics: {{ stabilization: true, barnesHut: {{ gravitationalConstant: -12000 }} }},
  nodes: {{ shape: 'dot', size: 14, font: {{ color: '#e5e7eb', size: 12 }} }},
  edges: {{ arrows: 'to', color: {{ color: '#334155' }}, font: {{ size: 9, color: '#64748b' }} }},
  interaction: {{ hover: true, tooltipDelay: 120 }}
}});
</script>
</body>
</html>
"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path


def _tooltip(n: dict[str, Any]) -> str:
    parts = [n.get("type", ""), n.get("label", "")]
    if n.get("title"):
        parts.append(str(n["title"])[:80])
    if n.get("reasons"):
        parts.append("; ".join(n["reasons"][:3]))
    return " | ".join(p for p in parts if p)


def _esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _row(a: dict[str, Any]) -> str:
    sev = a.get("exposure_severity") or "info"
    asset = f"{a.get('ip')}:{a.get('port')} {a.get('host') or ''}".strip()
    reasons = "; ".join(a.get("exposure_reasons") or [])[:80]
    return (
        f"<tr><td><span class='tag {sev}'>{sev}</span></td>"
        f"<td>{_esc(asset)}</td><td>{_esc(reasons)}</td></tr>"
    )
