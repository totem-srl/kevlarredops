---
name: ghidra-reverse
tags: [reverse, binary]
description: Use for free/open reverse engineering with Ghidra (headless or GUI), including decompile, cross-refs, and optional Ghidra MCP workflows when IDA is unavailable.
---

# Ghidra Reverse Engineering


## Upstream Notes

Ported from zhaoxuya520/reverse-skill (MIT). Full upstream incl. optional toolchain bootstrap scripts lives in `reverse-skill-reference/skills/`. Only run against authorized targets; dynamic analysis requires owned or explicitly authorized devices.

# 示例：analyzeHeadless 路径因安装而异，MUST 从 tool-index 取
analyzeHeadless /path/to/project Proj -import sample.bin -postScript ExportDecomp.py
```

### 4. MCP（若已配置）

```text
□ 确认 ghidra MCP 端口（常见 8765，以 tool-index 为准）
□ 用 MCP 工具拉反编译 / xrefs，禁止猜端口
```

## 工具链

| 工具 | 用途 | 自举 |
|------|------|------|
| Ghidra | 反编译主工具 | 手动 release / 包管理器 |
| ghidra-mcp | AI 桥 | bootstrap 能力名 `ghidra-mcp` |
| ghidriff | 补丁差分 | 见 `patch-diff-exploit` |

## 参考

- `references/ghidra-cheatsheet.md`
- `../ida-reverse/` `../radare2/` `../binary-diff/`

## 路由上下文

**上游**: MASTER R22  
**下游**: 动态验证 → Frida/GDB；利用 → `pwn-chain`  
**同级**: `ida-reverse`（商业深挖）

## 任务完成自检

- [ ] 是否基于真实 Ghidra/tool-index 路径？
- [ ] 是否标注函数地址与重命名？
- [ ] 是否有可复现步骤？
- [ ] Checklist / journal？