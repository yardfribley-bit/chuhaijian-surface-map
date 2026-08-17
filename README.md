# 出海鉴 · 攻击面测绘（chuhaijian-surface-map）

授权目标非侵入测绘。**默认不依赖 FOFA**。

组件线索可交给 [codeaudit](https://github.com/tajleonbennis-maker/chuhaijian-codeaudit)：库中有则跳过，无则补源码再审。

## 安装

```bash
pip install -e .
```

## 主路径（无 FOFA）

```bash
surfacemap run --url https://staging.example.com --out ./out \
  --i-am-authorized --emit-components

# 编辑 out/components.json 补 source_path / source_url
codeaudit from-inventory --inventory ./out/components.json --out ./comp-out
```

## 可选 FOFA 挂图

```bash
export FOFA_KEY=...
surfacemap map --domain example.com --i-am-authorized --out ./ops-map
```

## License

AGPL-3.0-or-later
