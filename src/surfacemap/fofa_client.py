"""FOFA API 客户端（标准库实现）。

凭据仅从环境变量读取，禁止写入仓库：
  FOFA_EMAIL / FOFA_KEY
可选：
  FOFA_API_BASE  默认 https://fofa.info
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_FIELDS = (
    "host,ip,port,protocol,title,server,domain,country,city,as_organization,banner,cert"
)


class FofaError(RuntimeError):
    pass


def _credentials() -> tuple[str, str, str]:
    email = (os.environ.get("FOFA_EMAIL") or "").strip()
    key = (os.environ.get("FOFA_KEY") or os.environ.get("FOFA_API_KEY") or "").strip()
    base = (os.environ.get("FOFA_API_BASE") or "https://fofa.info").rstrip("/")
    if not key:
        raise FofaError(
            "未配置 FOFA_KEY（或 FOFA_API_KEY）。请在环境变量中设置超级会员 API Key，勿写入代码仓库。"
        )
    # 新版部分接口仅需 key；email 仍兼容旧账号
    return email, key, base


def account_info() -> dict[str, Any]:
    email, key, base = _credentials()
    qs = {"key": key}
    if email:
        qs["email"] = email
    url = f"{base}/api/v1/info/my?" + urllib.parse.urlencode(qs)
    return _get_json(url)


def search(
    query: str,
    *,
    page: int = 1,
    size: int = 100,
    fields: str = DEFAULT_FIELDS,
    full: bool = False,
) -> dict[str, Any]:
    """单页搜索。results 归一为 list[dict]。"""
    email, key, base = _credentials()
    qbase64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    params: dict[str, str] = {
        "key": key,
        "qbase64": qbase64,
        "page": str(page),
        "size": str(min(max(size, 1), 10000)),
        "fields": fields,
    }
    if email:
        params["email"] = email
    if full:
        params["full"] = "true"

    url = f"{base}/api/v1/search/all?" + urllib.parse.urlencode(params)
    raw = _get_json(url)
    if raw.get("error"):
        raise FofaError(str(raw.get("errmsg") or raw))

    field_list = [f.strip() for f in fields.split(",") if f.strip()]
    results = raw.get("results") or []
    normalized: list[dict[str, Any]] = []
    for row in results:
        if isinstance(row, dict):
            normalized.append(row)
        elif isinstance(row, (list, tuple)):
            item = {field_list[i]: row[i] if i < len(row) else None for i in range(len(field_list))}
            normalized.append(item)
        else:
            continue
    raw["results"] = normalized
    raw["_fields"] = field_list
    raw["_query"] = query
    return raw


def search_all(
    query: str,
    *,
    max_size: int = 500,
    page_size: int = 100,
    fields: str = DEFAULT_FIELDS,
    full: bool = False,
    sleep_s: float = 0.35,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """分页拉取，最多 max_size 条。返回 (assets, meta)。"""
    page_size = min(max(page_size, 1), 1000)
    collected: list[dict[str, Any]] = []
    page = 1
    total_hint = None
    last_raw: dict[str, Any] = {}

    while len(collected) < max_size:
        size = min(page_size, max_size - len(collected))
        raw = search(query, page=page, size=size, fields=fields, full=full)
        last_raw = raw
        batch = raw.get("results") or []
        if total_hint is None:
            total_hint = raw.get("size")
        if not batch:
            break
        collected.extend(batch)
        if len(batch) < size:
            break
        page += 1
        if sleep_s > 0:
            time.sleep(sleep_s)

    meta = {
        "query": query,
        "fetched": len(collected),
        "fofa_size_hint": total_hint,
        "pages": page,
        "fields": fields,
    }
    return collected, meta


def _get_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "chuhaijian-surface-map/0.2 (+authorized ASM)"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        raise FofaError(f"HTTP {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise FofaError(f"网络错误: {e}") from e
