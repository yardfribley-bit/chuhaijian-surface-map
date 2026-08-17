"""资产 → 挂图用 nodes/edges。"""

from __future__ import annotations

from typing import Any


def build_graph(
    *,
    seed_domain: str,
    org: str | None,
    assets: list[dict[str, Any]],
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []

    def add_node(nid: str, ntype: str, label: str, **extra: Any) -> None:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label, **extra}
        else:
            nodes[nid].update({k: v for k, v in extra.items() if v})

    root_id = f"org:{org}" if org else f"domain:{seed_domain}"
    add_node(root_id, "org" if org else "domain", org or seed_domain, severity="info")

    if org and seed_domain:
        did = f"domain:{seed_domain}"
        add_node(did, "domain", seed_domain)
        edges.append({"source": root_id, "target": did, "rel": "owns"})
        domain_anchor = did
    else:
        domain_anchor = root_id

    for a in assets:
        domain = (a.get("domain") or seed_domain or "").strip()
        host = (a.get("host") or "").strip()
        ip = (a.get("ip") or "").strip()
        port = str(a.get("port") or "").strip()
        sev = a.get("exposure_severity") or "info"

        if domain:
            did = f"domain:{domain}"
            add_node(did, "domain", domain)
            if did != domain_anchor:
                edges.append({"source": domain_anchor, "target": did, "rel": "related"})

        if host:
            hid = f"host:{host}"
            add_node(hid, "host", host, severity=sev, title=a.get("title") or "")
            if domain:
                edges.append({"source": f"domain:{domain}", "target": hid, "rel": "host"})
            else:
                edges.append({"source": domain_anchor, "target": hid, "rel": "host"})

        if ip:
            iid = f"ip:{ip}"
            add_node(iid, "ip", ip, severity=sev)
            if host:
                edges.append({"source": f"host:{host}", "target": iid, "rel": "resolves"})
            else:
                edges.append({"source": domain_anchor, "target": iid, "rel": "ip"})

            if port:
                sid = f"svc:{ip}:{port}"
                label = f"{ip}:{port}/{a.get('protocol') or '?'}"
                add_node(
                    sid,
                    "service",
                    label,
                    severity=sev,
                    title=a.get("title") or "",
                    reasons=a.get("exposure_reasons") or [],
                )
                edges.append({"source": iid, "target": sid, "rel": "listens"})

    # 边去重
    uniq_edges = []
    seen = set()
    for e in edges:
        key = (e["source"], e["target"], e["rel"])
        if key in seen:
            continue
        if e["source"] not in nodes or e["target"] not in nodes:
            continue
        seen.add(key)
        uniq_edges.append(e)

    return {
        "nodes": list(nodes.values()),
        "edges": uniq_edges,
        "stats": {
            "nodes": len(nodes),
            "edges": len(uniq_edges),
            "assets": len(assets),
        },
    }
