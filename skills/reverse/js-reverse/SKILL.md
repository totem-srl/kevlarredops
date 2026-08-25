---
name: js-reverse
tags: [reverse, web]
description: 在使用 js-reverse-mcp 做前端 JavaScript 逆向时使用，适用于签名链路定位、页面观察取证、运行时采样、本地补环境复现与证据化输出。优先适配当前环境里的 js-reverse_* 工具，需要更强的浏览器/CDP/Hook 面时联动 jshookmcp。
---

# MCP 前端 JS 逆向作业规范


## Upstream Notes

Ported from zhaoxuya520/reverse-skill (MIT). Full upstream incl. optional toolchain bootstrap scripts lives in `reverse-skill-reference/skills/`. Only run against authorized targets; dynamic analysis requires owned or explicitly authorized devices.

# 安装并注册 jshookmcp；Codex 可替换为 Claude 或 Both
powershell -File "<skill-root>\scripts\bootstrap-reverse.ps1" -Capability @('jshookmcp') -McpHostTarget Codex

# 注册并启动 anything-analyzer
powershell -File "<skill-root>\scripts\bootstrap-reverse.ps1" -Capability @('anything-analyzer') -StartServices -McpHostTarget Codex
```

### 注意事项

- `jshookmcp` 注册后仍需在 AI 客户端中**启用**该 MCP server 才能调用
- 不传 `-McpHostTarget` 时只安装/准备能力并返回 registration-required，不修改 Claude 或 Codex 配置
- `anything-analyzer` 需要 pnpm 和项目源码，bootstrap 会自动 clone 并安装依赖
- 如果 Node.js 未安装，bootstrap 会先通过 winget 安装 Node.js 22

<br><br>## 任务完成自检（声称完成前 MUST 通过）

- [ ] 我是否执行了工作流中的每一步（而不是只阅读）？
- [ ] 我是否基于 `tool-index` 使用了真实工具路径？
- [ ] 我是否产出了可复现证据（命令/脚本/截图/报告）？
- [ ] 我是否完成并回写了 RULES 要求的 Checklist 项？
