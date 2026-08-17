"""写出 Markdown / JSON 测绘报告。"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_reports(out_dir: Path, result: dict[str, Any]) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **result,
    }
    json_path = out_dir / "surface.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    written.append(json_path)

    lines = [
        "# 出海鉴 · 攻击面测绘报告",
        "",
        f"- 目标: `{result.get('target')}`",
        f"- 时间: {payload['generated_at']}",
        f"- 模式: **只读限流探测**（无利用）",
        f"- 请求数: {result.get('stats', {}).get('requests', 0)}",
        f"- 限速: {result.get('rps')} rps",
        "",
        "## 技术栈线索",
        "",
    ]
    hints = result.get("tech_hints") or []
    if hints:
        for h in hints:
            lines.append(f"- `{h}`")
    else:
        lines.append("_无明显 Server / Content-Type 线索_")

    lines.extend(["", "## 值得关注的响应（非 404）", ""])
    notable = result.get("notable") or []
    if not notable:
        lines.append("_无_")
    else:
        lines.append("| 状态 | 耗时(ms) | URL |")
        lines.append("|------|----------|-----|")
        for r in notable:
            lines.append(
                f"| {r.get('status')} | {r.get('elapsed_ms')} | `{r.get('url')}` |"
            )

    lines.extend(["", "## 全部探测", ""])
    lines.append("| 状态 | URL | 错误 |")
    lines.append("|------|-----|------|")
    for r in result.get("endpoints") or []:
        err = r.get("error") or ""
        lines.append(f"| {r.get('status')} | `{r.get('url')}` | {err} |")

    lines.extend(
        [
            "",
            "---",
            "",
            "**声明**: 仅用于授权目标的非侵入测绘；响应码与路径存在不代表漏洞。",
            "禁止用于未授权扫描或攻击。",
            "",
        ]
    )

    md_path = out_dir / "report.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    written.append(md_path)
    return written
