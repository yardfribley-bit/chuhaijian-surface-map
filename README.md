# 出海鉴 · 攻击面测绘（chuhaijian-surface-map）

授权目标 **非侵入测绘**。默认路径 **不依赖 FOFA**。

识别到的组件可导出清单，交给 [codeaudit](https://github.com/tajleonbennis-maker/chuhaijian-codeaudit)：**库里有则跳过，没有再拉源码审计**。

---

## 推荐工作流（无 FOFA）

```bash
# 1) 只读探测 + 导出组件线索
surfacemap run --url https://staging.example.com --out ./out \
  --i-am-authorized --emit-components

# 2) 编辑 out/components.json
#    为 application / 开源组件补上 source_path 或 source_url

# 3) codeaudit：已缓存则跳过
codeaudit from-inventory --inventory ./out/components.json --out ./comp-out
```

也可对已有 `surface.json`：

```bash
surfacemap components --from-json ./out/surface.json --out ./components.json
```

---

## 可选：FOFA 挂图

```bash
export FOFA_KEY=...
surfacemap map --domain example.com --i-am-authorized --out ./ops-map
```

主路径不依赖 FOFA；仅在需要组织级公开索引时使用。

---

## License

AGPL-3.0-or-later
