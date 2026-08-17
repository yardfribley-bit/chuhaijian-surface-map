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
    (re.compile(r"litespeed", re.I), "litespeed", "server"),
]

POWERED_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"php/?([\d.]+)?", re.I), "php", "runtime"),
    (re.compile(r"asp\.net", re.I), "aspnet", "runtime"),
    (re.compile(r"express", re.I), "express", "npm"),
    (re.compile(r"next\.js", re.I), "nextjs", "npm"),
    (re.compile(r"wordpress", re.I), "wordpress", "php"),
]

TITLE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"grafana", re.I), "grafana", "app"),
    (re.compile(r"jenkins", re.I), "jenkins", "app"),
    (re.compile(r"kibana", re.I), "kibana", "app"),
    (re.compile(r"phpmyadmin", re.I), "phpmyadmin", "app"),
    (re.compile(r"nacos", re.I), "nacos", "app"),
    (re.compile(r"swagger", re.I), "swagger-ui", "app"),
]

BODY_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"__NEXT_DATA__", re.I), "nextjs", "npm"),
    (re.compile(r"wp-content", re.I), "wordpress", "php"),
    (re.compile(r"Drupal\.settings", re.I), "drupal", "php"),
    (re.compile(r"cdn\.jsdelivr\.net/npm/([^/\"']+)", re.I), "jsdelivr-npm", "npm"),
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

    for hint in probe_or_map.get("tech_hints") or []:
        h = str(hint)
        if "cloudflare" in h.lower():
            add("cloudflare", "cdn", "unknown", h)
        if "nextjs" in h.lower() or "vercel" in h.lower():
            add("nextjs", "npm", "unknown", h)

    endpoints = probe_or_map.get("endpoints") or probe_or_map.get("assets") or []
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        headers = {str(k).lower(): str(v) for k, v in (ep.get("headers") or {}).items()}
        server = headers.get("server") or str(ep.get("server") or "")
        powered = headers.get("x-powered-by") or ""
        generator = headers.get("x-generator") or ""
        title = str(ep.get("title") or "")
        host = str(ep.get("host") or ep.get("url") or "")
        body = str(ep.get("body_preview") or "")

        for pat, name, eco in SERVER_PATTERNS:
            m = pat.search(server)
            if m:
                ver = m.group(1) if m.lastindex else "unknown"
                add(name, eco, ver or "unknown", f"server:{server}|{host}")

        for pat, name, eco in POWERED_PATTERNS:
            m = pat.search(powered) or pat.search(generator)
            if m:
                ver = m.group(1) if m.lastindex and m.lastindex >= 1 else "unknown"
                try:
                    ver = m.group(1) or "unknown"
                except IndexError:
                    ver = "unknown"
                add(name, eco, ver, f"powered:{powered or generator}|{host}")

        if headers.get("x-nextjs-cache") is not None or headers.get("x-vercel-id"):
            add("nextjs", "npm", "unknown", f"header-next|{host}")
        if headers.get("cf-ray"):
            add("cloudflare", "cdn", "unknown", f"cf-ray|{host}")
        if headers.get("x-aspnet-version"):
            add("aspnet", "runtime", headers.get("x-aspnet-version", "unknown"), f"aspnet|{host}")

        for pat, name, eco in TITLE_PATTERNS:
            if pat.search(title):
                add(name, eco, "unknown", f"title:{title[:80]}|{host}")

        for pat, name, eco in BODY_PATTERNS:
            m = pat.search(body)
            if m:
                ver = "unknown"
                if name == "jsdelivr-npm" and m.lastindex:
                    pkg = m.group(1)
                    add(pkg.split("@")[0] if pkg else name, "npm", "unknown", f"body-cdn|{host}")
                else:
                    add(name, eco, ver, f"body|{host}")

        path = str(ep.get("url") or "")
        if "/wp-json" in path or "/wp-content" in path:
            add("wordpress", "php", "unknown", f"path|{path}")
        if "/actuator" in path:
            add("spring-boot", "maven", "unknown", f"path|{path}")
        if "/_next/" in path:
            add("nextjs", "npm", "unknown", f"path|{path}")

    target = probe_or_map.get("target") or (probe_or_map.get("seed") or {}).get("domain")
    if target:
        add(_app_name(str(target)), "application", "unknown", f"target:{target}")

    return list(found.values())


def inventory_document(target: str, components: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "target": target,
        "note": "黑盒组件为线索；请补充 source_path/source_url 后交给 codeaudit from-inventory",
        "components": components,
    }


def _app_name(target: str) -> str:
    t = target.replace("https://", "").replace("http://", "").split("/")[0]
    return t or "target-app"
