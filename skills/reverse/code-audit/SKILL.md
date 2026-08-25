---
name: code-audit
tags: [code-review]
description: Use for authorized source-code security review and SAST workflows including Semgrep, CodeQL patterns, dangerous API hunting, and fix verification.
---

# Source Code Security Audit


## Upstream Notes

Ported from zhaoxuya520/reverse-skill (MIT). Full upstream incl. optional toolchain bootstrap scripts lives in `reverse-skill-reference/skills/`. Only run against authorized targets; dynamic analysis requires owned or explicitly authorized devices.

# 或项目规则包
semgrep --config p/owasp-top-ten .
```

### 3. 人工验证（MUST）

```text
□ 每个 SAST 命中：可达性？可利用性？误报？
□ 鉴权：IDOR/越权、缺校验、错误的多租户隔离
□ 注入：SQL/命令/模板/LDAP
□ 加密：硬编码密钥、ECB、自定义 crypto
```

### 4. 产出

```text
Finding：位置 + 数据流 + PoC + 修复建议
可选 ATT&CK / CWE 编号
```

## 工具链

| 工具 | 语言/场景 |
|------|-----------|
| Semgrep | 多语言快速规则 |
| CodeQL | 深数据流（GitHub） |
| Bandit | Python |
| gosec / staticcheck | Go |
| SpotBugs / FindSecBugs | Java |

## 参考

- `references/sast-review-checklist.md`
- `../supply-chain-security/` `../api-security/` `../llm-security/`（Agent 代码）

## 路由上下文

**上游**: MASTER R26  
**角色**: `ops/role-map.md` cae  
**下游**: 依赖漏洞 → supply-chain；运行时验证 → pentest-tools

## 任务完成自检

- [ ] 是否人工验证而非只贴扫描器输出？
- [ ] 是否含修复建议？
- [ ] 是否限定在授权仓库范围？
- [ ] Checklist？