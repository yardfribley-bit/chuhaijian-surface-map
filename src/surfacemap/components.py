"""从探测结果识别组件线索 → codeaudit 清单。"""

from __future__ import annotations

import re
from typing import Any

SERVER_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"cloudflare", re.I), "cloudflare", "cdn"),
    (re.compile(r"nginx/?([\d.]+)?", re.I), "nginx", "server"),
    (re.compile(r"apache/?([\d.]+)?", re.I), "apache", "server"),
    (re.compile(r"openresty/?([\d.]+)?", re.I), "openresty", "server"),
    (re.compile(r"microsoft-iis/?([\d.]+)?", re.I), "iis", "server"),
    (re.compile(r"caddy/?([\d.]+)?", re.I), "caddy", "server"),
    (re.compile(r"envoy", re.I), "envoy", "proxy"),
    (re.compile(r"AmazonS3", re.I), "amazon-s3", "storage"),
]

POWERED_BY_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"express/?([\d.]+)?", re.I), "express", "npm"),
    (re.compile(r"php/?([\d.]+)?", re.I), "php", "runtime"),
    (re.compile(r"ASP\.NET", re.I), "aspnet", "runtime"),
    (re.compile(r"Next\.js", re.I), "nextjs", "npm"),
    (re.compile(r"Django/?([\d.]+)?", re.I), "django", "pypi"),
]

BODY_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"__NEXT_DATA__", re.I), "nextjs", "npm"),
    (re.compile(r"wp-content", re.I), "wordpress", "app"),
    (re.compile(r"Drupal\.settings", re.I), "drupal", "app"),
    (re.compile(r"cdn\.shopify\.com", re.I), "shopify", "saas"),
    (re.compile(r"ghost\\.org|ghost-theme", re.I), "ghost", "app"),
    (re.compile(r"swagger", re.I), "swagger-ui", "app"),
    (re.compile(r"graphql", re.I), "graphql", "api"),
]

TITLE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"grafana", re.I), "grafana", "app"),
    (re.compile(r"jenkins", re.I), "jenkins", "app"),
    (re.compile(r"kibana", re.I), "kibana", "app"),
    (re.compile(r"phpmyadmin", re.I), "phpmyadmin", "app"),
    (re.compile(r"nacos", re.I), "nacos", "app"),
]


def extract_components(probe_or_map: dict[str, Any]) -> list[dict[str, Any]]:
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
            "source_url": None,
            "source_path": None,
        }

    endpoints = probe_or_map.get("endpoints") or probe_or_map.get("assets") or []
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        headers = {str(k).lower(): str(v) for k, v in (ep.get("headers") or {}).items()}
        server = headers.get("server") or str(ep.get("server") or "")
        powered = headers.get("x-powered-by") or ""
        title = str(ep.get("title") or "")
        body = str(ep.get("body_preview") or "")
        host = str(ep.get("host") or ep.get("url") or "")

        for pat, name, eco in SERVER_PATTERNS:
            m = pat.search(server)
            if m:
                ver = m.group(1) if m.lastindex and m.group(1) else "unknown"
                add(name, eco, ver, f"server:{server}|{host}")

        for pat, name, eco in POWERED_BY_PATTERNS:
            m = pat.search(powered)
            if m:
                ver = m.group(1) if m.lastindex and m.group(1) else "unknown"
                add(name, eco, ver, f"x-powered-by:{powered}|{host}")

        if headers.get("cf-ray") or headers.get("cf-cache-status"):
            add("cloudflare", "cdn", "unknown", f"cf-ray|{host}")
        if headers.get("x-nextjs-cache") is not None or headers.get("x-vercel-id"):
            add("nextjs", "npm", "unknown", f"next/vercel-header|{host}")

        for pat, name, eco in TITLE_PATTERNS:
            if pat.search(title):
                add(name, eco, "unknown", f"title:{title[:80]}|{host}")

        for pat, name, eco in BODY_PATTERNS:
            if pat.search(body):
                add(name, eco, "unknown", f"body|{host}")

    for hint in probe_or_map.get("tech_hints") or []:
        h = str(hint)
        if "cloudflare" in h.lower():
            add("cloudflare", "cdn", "unknown", f"tech_hint:{h}")
        if "nextjs" in h.lower():
            add("nextjs", "npm", "unknown", f"tech_hint:{h}")

    target = probe_or_map.get("target") or (probe_or_map.get("seed") or {}).get("domain")
    if target:
        add(_app_name(str(target)), "application", "unknown", f"target:{target}")

    return list(found.values())


def inventory_document(target: str, components: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "target": target,
        "note": "黑盒组件仅为线索；请为 application / 开源组件补充 source_path 或 source_url 后交给 codeaudit from-inventory",
        "components": components,
    }


def _app_name(target: str) -> str:
    t = target.replace("https://", "").replace("http://", "").split("/")[0]
    return t or "target-app"
