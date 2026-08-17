# 出海鉴 · 攻击面测绘（chuhaijian-surface-map）

对**已授权** Web 目标做**非侵入、限流**测绘：常见路径可达性、响应头与技术栈线索。

> **不**做漏洞利用 · **不**爆破登录 · **不**修改业务数据  
> 运行必须显式声明 `--i-am-authorized`

姊妹项目：[chuhaijian-codeaudit](https://github.com/tajleonbennis-maker/chuhaijian-codeaudit)

---

## 现在可用（v0.1）

对目标基址按白名单路径发送 **GET**（默认约 2 请求/秒），汇总状态码与部分响应头，输出 Markdown + JSON。

### 安装

```bash
git clone https://github.com/tajleonbennis-maker/chuhaijian-surface-map.git
cd chuhaijian-surface-map
pip install -e .
```

### 运行

```bash
# 仅对你拥有或书面授权的环境
surfacemap run --url https://staging.example.com --out ./out --i-am-authorized

# 更慢的限速 / 自定义路径文件
surfacemap run --url https://staging.example.com --rps 1 --paths-file paths.txt --out ./out --i-am-authorized
```

输出：

- `out/report.md`  
- `out/surface.json`  

---

## 边界

| 会做 | 不会做 |
|------|--------|
| 限流 GET 常见路径 | 注入 / XSS / 越权利用 |
| 记录状态码与公开头 | 写操作、爆破 |
| 技术栈线索摘要 | 未授权扫描 |

详见 [SAFETY.md](SAFETY.md)、[docs/scope.md](docs/scope.md)。

---

## License

AGPL-3.0-or-later（见 `pyproject.toml`）。
