# 出海鉴 · 攻击面测绘（chuhaijian-surface-map）

对**已授权**目标做非侵入测绘，并支持 **FOFA 挂图作战**：输入主域（可选组织名）→ 拉取公开索引资产 → 关系图谱 + HTML 作战图。

> **不**做漏洞利用 · **不**爆破 · 必须 `--i-am-authorized`  
> FOFA Key **只放环境变量**，不要写入 Git

姊妹项目：[chuhaijian-codeaudit](https://github.com/tajleonbennis-maker/chuhaijian-codeaudit)

---

## 安装

```bash
git clone https://github.com/tajleonbennis-maker/chuhaijian-surface-map.git
cd chuhaijian-surface-map
pip install -e .
```

## 1）单 URL 只读探测

```bash
surfacemap run --url https://staging.example.com --out ./out --i-am-authorized
```

## 2）FOFA 挂图作战（域名 → 资产宇宙）

```bash
export FOFA_EMAIL="you@example.com"
export FOFA_KEY="你的超级会员API_Key"
# 可选: export FOFA_API_BASE=https://fofa.info

surfacemap map \
  --domain example.com \
  --org "示例科技" \
  --out ./ops-map \
  --max-size 500 \
  --i-am-authorized \
  --authorization-ref "PROJ-2026-001"
```

组织名默认**不会**直接打 FOFA `title` 检索（噪声大）。若需要：

```bash
surfacemap map --domain example.com --org "示例科技" --include-org-query --i-am-authorized --out ./ops-map
```

### 输出

| 文件 | 说明 |
|------|------|
| `ops-map/ops-map.html` | **作战挂图**（浏览器打开） |
| `ops-map/assets.json` | 归一化资产 + 暴露启发式 |
| `ops-map/graph.json` | nodes/edges |
| `ops-map/map_bundle.json` | 完整结果包 |
| `ops-map/report.md` | Markdown 摘要 |

---

## 暴露标注说明

对 FOFA 结果做**本地启发式**（敏感端口、标题关键词等），用于挂图着色与优先级。  
**不代表已验证漏洞，不能替代渗透测试。**

---

## 安全与合规

- 仅对书面授权的组织/域名使用  
- FOFA 查询消耗账号配额，注意 `--max-size`  
- 详见 [SAFETY.md](SAFETY.md)

---

## License

AGPL-3.0-or-later
