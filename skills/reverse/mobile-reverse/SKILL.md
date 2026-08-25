---
name: mobile-reverse
tags: [reverse, mobile]
description: Use for authorized Android or iOS application reverse engineering and security testing, including APK or IPA analysis, runtime instrumentation, SSL pinning, and platform protection checks.
---
# Mobile Reverse Engineering


## Upstream Notes

Ported from zhaoxuya520/reverse-skill (MIT). Full upstream incl. optional toolchain bootstrap scripts lives in `reverse-skill-reference/skills/`. Only run against authorized targets; dynamic analysis requires owned or explicitly authorized devices.

# Objection（最简）
objection -g "com.app" explore
android sslpinning disable

# Frida 通用脚本
frida -U -l ssl_pinning_bypass.js -f com.app

# Xposed（Android）
TrustMeAlready 模块 → 全局禁用证书校验
```

### Root / 越狱检测

```bash
# Objection
android root disable
ios jailbreak disable

# Frida 自定义（多层检测）
Java.perform(function() {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() { return false; };
    // 额外绕过: Magisk su 检测、frida-server 检测、/proc/self/maps 检测
});
```

### 反调试

```bash
# Android
frida -U -l anti_debug_bypass.js -f com.app
# 绕过: ptrace(TracerPid)、/proc/self/status、isDebuggerConnected()

# iOS
# 绕过: PT_DENY_ATTACH、sysctl CTL_KERN/KERN_PROC/KERN_PROC_PID
frida -U -l ios_anti_debug.js -f com.app
```

## 移动端加密提取

```javascript
// Android — Hook Cipher.getInstance 获取密钥+算法
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log("[Cipher] Algorithm: " + algo);
        return this.getInstance(algo);
    };
    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        console.log("[Cipher] Key: " + bytesToHex(key.getEncoded()));
        return this.init(mode, key);
    };
});

// iOS — Hook CCCrypt
Interceptor.attach(Module.findExportByName("libcommonCrypto.dylib", "CCCrypt"), {
    onEnter: function(args) {
        console.log("CCCrypt op: " + args[0] + " alg: " + args[1]);
        console.log("Key: " + hexdump(args[3], { length: args[4].toInt32() }));
    }
});
```

## 工具链

| 工具 | 平台 | 用途 |
|------|:--:|------|
| JADX-GUI | A | Java 反编译 |
| apktool | A | APK 解包/重建 |
| Ghidra | A+I | 多架构反编译 |
| Hopper | I | iOS 专用反汇编 |
| Frida | A+I | 动态插桩 |
| Objection | A+I | Frida REPL 增强 |
| MobSF | A+I | 自动化 SAST+DAST |
| class-dump | I | ObjC 类导出 |
| frida-ios-dump | I | IPA 解密 |
| jtool2 | I | Mach-O 分析 |
| Burp Suite | A+I | HTTP 拦截 |
| mitmproxy | A+I | 脚本化代理 |

> A=Android, I=iOS

## 参考

- `references/frida-objection-deep.md` — Frida + Objection 深度用法
- `references/ios-reverse-guide.md` — iOS 逆向专项
- `references/anti-detection-bypass.md` — Root/越狱/反调试/SSL Pinning 绕过


## 任务完成自检（声称完成前 MUST 通过）

- [ ] 我是否执行了工作流中的每一步（而不是只阅读）？
- [ ] 我是否基于 `tool-index` 使用了真实工具路径？
- [ ] 我是否产出了可复现证据（命令/脚本/截图/报告）？
- [ ] 我是否完成并回写了 RULES 要求的 Checklist 项？
