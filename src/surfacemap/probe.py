"""限流、只读 HTTP 探测 — 仅 GET/HEAD，无利用 payload。"""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urljoin, urlparse

DEFAULT_PATHS = [
    "/",
    "/robots.txt",
    "/favicon.ico",
    "/sitemap.xml",
    "/health",
    "/healthz",
    "/ready",
    "/status",
    "/api",
    "/api/health",
    "/api/v1",
    "/.well-known/security.txt",
    "/login",
    "/admin",
    "/swagger",
    "/swagger-ui.html",
    "/openapi.json",
    "/docs",
    "/graphql",
    "/actuator/health",
]

UA = "chuhaijian-surface-map/0.1 (+non-intrusive recon; authorized use only)"


def _rate_sleep(last: float, rps: float) -> float:
    min_interval = 1.0 / max(rps, 0.1)
    now = time.monotonic()
    wait = min_interval - (now - last)
    if wait > 0:
        time.sleep(wait)
    return time.monotonic()


def _fetch(url: str, method: str = "GET", timeout: float = 12.0) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        method=method,
        headers={"User-Agent": UA, "Accept": "*/*"},
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192)
            elapsed_ms = int((time.monotonic() - started) * 1000)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "url": url,
                "method": method,
                "status": resp.status,
                "elapsed_ms": elapsed_ms,
                "headers": {
                    k: headers[k]
                    for k in (
                        "server",
                        "content-type",
                        "x-powered-by",
                        "strict-transport-security",
                        "content-security-policy",
                        "x-frame-options",
                        "location",
                    )
                    if k in headers
                },
                "body_preview": body[:500].decode("utf-8", errors="replace"),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return {
            "url": url,
            "method": method,
            "status": e.code,
            "elapsed_ms": elapsed_ms,
            "headers": {
                k: headers[k]
                for k in ("server", "content-type", "location")
                if k in headers
            },
            "body_preview": "",
            "error": None,
        }
    except Exception as e:  # noqa: BLE001 — 汇总为探测结果
        return {
            "url": url,
            "method": method,
            "status": None,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "headers": {},
            "body_preview": "",
            "error": str(e)[:200],
        }


def probe_target(
    base_url: str,
    rps: float = 2.0,
    extra_paths: list[str] | None = None,
) -> dict[str, Any]:
    base = base_url.rstrip("/") + "/"
    host = urlparse(base).netloc

    paths: list[str] = []
    seen: set[str] = set()
    for p in DEFAULT_PATHS + (extra_paths or []):
        p = p if p.startswith("/") else "/" + p
        if p not in seen:
            seen.add(p)
            paths.append(p)

    results: list[dict[str, Any]] = []
    last = 0.0
    for path in paths:
        last = _rate_sleep(last, rps)
        url = urljoin(base, path.lstrip("/"))
        # 保持 path 语义
        url = base.rstrip("/") + path
        hit = _fetch(url, method="GET")
        results.append(hit)

    interesting = [
        r
        for r in results
        if r.get("status") is not None and int(r["status"]) < 500 and r["status"] != 404
    ]

    tech: set[str] = set()
    for r in results:
        h = r.get("headers") or {}
        if h.get("server"):
            tech.add(f"server:{h['server']}")
        if h.get("x-powered-by"):
            tech.add(f"x-powered-by:{h['x-powered-by']}")
        if h.get("content-type"):
            tech.add(f"ctype:{h['content-type'].split(';')[0].strip()}")

    return {
        "target": base_url,
        "host": host,
        "mode": "read-only-probe",
        "exploit": False,
        "rps": rps,
        "stats": {
            "requests": len(results),
            "non_404_or_error": len(interesting),
        },
        "tech_hints": sorted(tech),
        "endpoints": results,
        "notable": interesting,
    }
