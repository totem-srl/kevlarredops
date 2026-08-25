---
name: threat-hunting
tags: [defensive]
description: Use for blue-team threat hunting, detection engineering with Sigma/YARA, SIEM query design, and incident detection validation.
---

# Threat Hunting & Detection Engineering


## Upstream Notes

Ported from zhaoxuya520/reverse-skill (MIT). Full upstream incl. optional toolchain bootstrap scripts lives in `reverse-skill-reference/skills/`. Only run against authorized targets; dynamic analysis requires owned or explicitly authorized devices.

# Sigma 骨架见 malware-analysis；本 skill 强调：
# - 误报面
# - 数据源字段映射
# - 响应 playbook 链接
```

### 4. 验证

```text
□ 原子测试（Atomic Red Team）仅在授权实验室
□ 回放历史日志验证召回
```

## 工具链

| 工具 | 用途 |
|------|------|
| Sigma CLI / sigmac | 规则转换 |
| YARA | 文件/内存 |
| SIEM（ELK/Splunk 等） | 查询 |
| osquery | 端点狩猎 |
| Atomic Red Team | 检测验证（实验室） |

## 参考

- `references/hunting-loop.md`
- `../malware-analysis/references/yara-sigma-rules.md`
- `../digital-forensics/`

## 路由上下文

**上游**: MASTER R27  
**下游**: 确认入侵 → forensics；恶意样本 → malware-analysis  
**MUST NOT**: 在无授权生产环境跑攻击模拟

## 任务完成自检

- [ ] 是否有明确假说与结论？
- [ ] 规则是否注明误报与数据源？
- [ ] Checklist？