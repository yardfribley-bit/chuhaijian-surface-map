"""暴露面启发式评分（非漏洞利用、非扫描器）。"""

from __future__ import annotations

from typing import Any

# 端口启发式：公开出现时提高关注度（仍需人工确认）
SENSITIVE_PORTS = {
    "22": ("medium", "SSH 端口对公网可见"),
    "23": ("high", "Telnet 对公网可见"),
    "3389": ("high", "RDP 对公网可见"),
    "445": ("high", "SMB 对公网可见"),
    "3306": ("high", "MySQL 对公网可见"),
    "5432": ("high", "PostgreSQL 对公网可见"),
    "6379": ("high", "Redis 对公网可见"),
    "27017": ("high", "MongoDB 对公网可见"),
    "9200": ("high", "Elasticsearch 常见端口对公网可见"),
    "11211": ("high", "Memcached 对公网可见"),
    "2375": ("critical", "Docker API 非 TLS 常见端口"),
    "2376": ("high", "Docker API 端口对公网可见"),
    "5900": ("medium", "VNC 对公网可见"),
    "8080": ("low", "常见替代 HTTP 端口"),
    "8443": ("low", "常见替代 HTTPS 端口"),
}

TITLE_KEYWORDS = [
    ("critical", ["phpmyadmin", "kibana", "jenkins", "apollo", "nacos", "spring boot admin"]),
    ("high", ["登录", "login", "admin", "管理后台", "dashboard", "运维", "swagger", "actuator"]),
    ("medium", ["test", "staging", "dev", "debug", "临时", "内测"]),
]

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def score_asset(asset: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    severity = "info"

    port = str(asset.get("port") or "")
    if port in SENSITIVE_PORTS:
        sev, reason = SENSITIVE_PORTS[port]
        severity = _worse(severity, sev)
        reasons.append(reason)

    blob = " ".join(
        [
            str(asset.get("title") or ""),
            str(asset.get("host") or ""),
            str(asset.get("server") or ""),
            str(asset.get("banner_preview") or ""),
        ]
    ).lower()

    for sev, kws in TITLE_KEYWORDS:
        for kw in kws:
            if kw.lower() in blob:
                severity = _worse(severity, sev)
                reasons.append(f"关键词线索: {kw}")
                break

    if not asset.get("title") and port in {"80", "443", "8080", "8443"}:
        reasons.append("Web 端口无标题，信息不足")

    return {
        **asset,
        "exposure_severity": severity,
        "exposure_reasons": reasons,
        "exposure_score": {"critical": 90, "high": 70, "medium": 40, "low": 20, "info": 5}.get(
            severity, 0
        ),
    }


def score_assets(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scored = [score_asset(a) for a in assets]
    scored.sort(
        key=lambda a: (
            SEVERITY_RANK.get(a.get("exposure_severity", "info"), 9),
            -int(a.get("exposure_score") or 0),
            a.get("ip") or "",
            a.get("port") or "",
        )
    )
    return scored


def _worse(a: str, b: str) -> str:
    return a if SEVERITY_RANK.get(a, 9) <= SEVERITY_RANK.get(b, 9) else b
