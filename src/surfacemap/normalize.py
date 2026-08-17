"""FOFA 原始结果 → 统一资产记录。"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def _as_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()


def normalize_row(row: dict[str, Any], source_query: str = "") -> dict[str, Any]:
    host = _as_str(row.get("host"))
    ip = _as_str(row.get("ip"))
    port = _as_str(row.get("port"))
    protocol = _as_str(row.get("protocol")) or "unknown"
    title = _as_str(row.get("title"))
    server = _as_str(row.get("server"))
    domain = _as_str(row.get("domain"))
    country = _as_str(row.get("country"))
    city = _as_str(row.get("city"))
    asn_org = _as_str(row.get("as_organization") or row.get("org"))
    banner = _as_str(row.get("banner"))[:300]
    cert = _as_str(row.get("cert"))[:500]

    # host 可能是 domain:port 或完整 URL
    display_host = host
    if host.startswith("http://") or host.startswith("https://"):
        parsed = urlparse(host)
        display_host = parsed.netloc or host

    asset_id = f"{ip}:{port}" if ip and port else (display_host or ip or "unknown")

    return {
        "id": asset_id,
        "host": display_host,
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "title": title,
        "server": server,
        "domain": domain,
        "country": country,
        "city": city,
        "as_organization": asn_org,
        "banner_preview": banner,
        "cert_preview": cert,
        "source": "fofa",
        "source_query": source_query,
    }


def normalize_assets(rows: list[dict[str, Any]], source_query: str = "") -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        a = normalize_row(row, source_query=source_query)
        key = f"{a['ip']}|{a['port']}|{a['host']}|{a['protocol']}"
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    return out
