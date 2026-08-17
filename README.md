# 出海鉴 · 攻击面测绘（chuhaijian-surface-map）

对**已授权**的 Web 目标做**非侵入式**攻击面侦测：可达性、公开端点、技术栈指纹与暴露面摘要。

> 本项目**不**做漏洞利用、**不**默认爆破登录、**不**修改目标业务数据。

姊妹项目：[chuhaijian-codeaudit](https://github.com/tajleonbennis-maker/chuhaijian-codeaudit)（白盒源码只读审计）

---

## 做什么 / 不做什么

| 会做 | 不会做 |
|------|--------|
| 在授权范围内探测公开 URL / 路径 | SQL 注入、XSS、命令执行等攻击 |
| 技术栈与基础响应特征摘要 | 创建用户、改数据、删资源 |
| 端点地图与暴露面报告 | 未授权扫描任意公网站点 |
| 限流、方法白名单（以安全探测为主） | 输出「一键打穿」利用手册 |

---

## 快速开始（规划中）

```bash
cp .env.example .env

# 仅对你拥有或书面授权的目标
python -m surfacemap run --url https://staging.example.com --out ./out
```

当前仓库为**产品骨架与范围定义**。探测流水线将参考 Shannon recon 的只读子集，并重写 prompt / 工具白名单后迁入。

---

## 与完整 AI 渗透的关系

| 项目 | 范围 |
|------|------|
| **chuhaijian-codeaudit** | 源码只读审计 |
| **chuhaijian-surface-map**（本仓库） | 授权目标非侵入测绘 |
| 完整渗透（私有/企业） | 含漏洞验证与利用 — **不在本公开产品内** |

---

## 目录规划

```text
chuhaijian-surface-map/
├── README.md
├── SAFETY.md
├── docs/
│   └── scope.md
├── prompts/               # 测绘 agent 提示词（禁止利用）
├── src/                   # 探测引擎（规划中）
└── scripts/
```

---

## 授权与合规

- **必须**对目标拥有所有权或书面渗透/测绘授权。  
- 优先在 staging / 测试环境使用；生产需额外评估日志与 WAF 影响。  
- 即使是只读探测，仍会产生访问日志与流量，请遵守目标方规则与当地法律。  

详见 [SAFETY.md](SAFETY.md)。

---

## License

计划采用 **AGPL-3.0**。最终以仓库根目录 `LICENSE` 为准。
