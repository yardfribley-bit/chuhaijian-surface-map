# src/

测绘引擎实现位置（规划中）。

建议模块划分：

- `scope/` — 授权范围与限流  
- `probe/` — 只读 HTTP / 可选无头浏览器观察  
- `agents/` — LLM 辅助归纳（非利用）  
- `report/` — 端点地图与摘要  

不包含 exploit 模块、漏洞利用 agent、mutative 写操作默认路径。
