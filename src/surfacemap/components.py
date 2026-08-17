"""从探测结果识别「组件线索」→ 输出 codeaudit 可用清单。

说明：
- 黑盒下只能得到弱指纹（Server 头、标题、路径），版本常为 unknown
- 清单交给 codeaudit from-inventory：库中有则跳过，无源码则 needs_source
"""

from __future__ import annotations

import re
from typing import Any

# server 头 / 标题 中的常见组件线索（名称级，版本多未知）
SERVER_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"cloudflare", re.I), "cloudflare", "cdn"),
    (re.compile(r"nginx/?([\d.]+)?", re.I), "nginx", "server"),
    (re.compile(r"apache/?([\d.]+)?", re.I), "apache", "server"),
    (re.compile(r"openresty/?([\d.]+)?", re.I), "openresty", "server"),
    (re.compile(r"microsoft-iis/?([\d.]+)?", re.I), "iis", "server"),
    (re.compile(r"caddy", re.I), "caddy", "server"),
]

TITLE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"grafana", re.I), "grafana", "app"),
    (re.compile(r"jenkins", re.I), "jenkins", "app"),
    (re.compile(r"kibana", re.I), "kibana", "app"),
    (re.compile(r"phpmyadmin", re.I), "phpmyadmin", "app"),
    (re.compile(r"nacos", re.I), "nacos", "app"),
]


def extract_components(probe_or_map: dict[str, Any]) -> list[dict[str, Any]]:
    """从 surfacemap run 结果或简化结构提取组件。"""
    found: dict[str, dict[str, Any]] = {}

    def add(name: str, ecosystem: str, version: str = "unknown", evidence: str = "") -> None:
        key = f"{ecosystem}:{name}:{version}".lower()
        if key in found:
            if evidence and evidence not in found[key].get("evidence", []):
                found[key].setdefault("evidence", []).append(evidence)
            return
        found[key] = {
            "name": name,
            "version": version or "unknown",
            "ecosystem": ecosystem,
            "evidence": [evidence] if evidence else [],
            # 黑盒默认无源码；应用本体由用户补 source_path
            "source_url": None,
            "source_path": None,
        }

    endpoints = probe_or_map.get("endpoints") or probe_or_map.get("assets") or []
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        headers = ep.get("headers") or {}
        server = str(headers.get("server") or ep.get("server") or "")
        title = str(ep.get("title") or "")
        host = str(ep.get("host") or ep.get("url") or "")

        for pat, name, eco in SERVER_PATTERNS:
            m = pat.search(server)
            if m:
                ver = m.group(1) if m.lastindex else "unknown"
                add(name, eco, ver or "unknown", f"server:{server}|{host}")

        for pat, name, eco in TITLE_PATTERNS:
            if pat.search(title):
                add(name, eco, "unknown", f"title:{title[:80]}|{host}")

        ctype = str(headers.get("content-type") or "")
        if "next" in ctype.lower() or "_next" in str(ep.get("body_preview") or ""):
            add("nextjs", "npm", "unknown", f"content:{host}")

    # 目标应用本身占位：便于用户补 source_path 后走 codeaudit
    target = probe_or_map.get("target") or probe_or_map.get("seed", {}).get("domain")
    if target:
        add(
            _app_name(str(target)),
            "application",
            "unknown",
            f"target:{target}",
        )

    return list(found.values())


def inventory_document(target: str, components: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "target": target,
        "note": "黑盒组件仅为线索；请为 application 与开源组件补充 source_path/source_url 后交给 codeaudit",
        "components": components,
    }


def _app_name(target: str) -> str:
    t = target.replace("https://", "").replace("http://", "").split("/")[0]
    return t or "target-app"
