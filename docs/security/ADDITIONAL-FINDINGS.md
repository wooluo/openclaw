# Security Audit: Additional Vulnerability Findings

**Audit Date**: 2026-03-12
**Auditor**: wooluo
**Repository**: https://github.com/wooluo/openclaw
**Related Advisory**: GHSA-9r3v-37xh-2cf6 (Command Obfuscation Detection Bypass)

---

## Executive Summary

This document describes additional security vulnerabilities discovered during the comprehensive security audit of OpenClaw, beyond the previously reported command obfuscation detection bypass (90% bypass rate).

### Summary of Findings

| ID | Vulnerability | Severity | Status |
|----|--------------|----------|--------|
| VULN-1 | Command Obfuscation Detection Bypass | **Critical** | ✓ Reported (GHSA-9r3v-37xh-2cf6) |
| VULN-9 | Rate Limit State Lost on Restart | **Medium** | New Finding |
| VULN-10 | Loopback Exemption Bypass Potential | **Low-Medium** | New Finding |
| VULN-11 | Control Plane Rate Limit Per-IP Bypass | **Medium** | New Finding |
| VULN-12 | IP Spoofing via Misconfigured Trusted Proxies | **Medium** | Configuration Issue |
| VULN-13 | Rate Limit Key Collision | **Low** | Edge Case |

---

## Detailed Findings

### VULN-9: Rate Limit State Lost on Restart

**Severity**: Medium
**Affected File**: `src/gateway/auth-rate-limit.ts`
**Affected File**: `src/gateway/control-plane-rate-limit.ts`

#### Description

Both authentication rate limiting and control plane write rate limiting use in-memory data structures (`Map`) to track request counts. This state is **not persisted** across process restarts.

#### Impact

- Attackers who trigger a service restart (via crash, resource exhaustion, or forced restart) can reset their rate limit quota
- In containerized environments with auto-restart policies, this could be exploited for brute force attacks
- The lockout duration (5 minutes by default) is bypassed

#### Code Evidence

```typescript
// src/gateway/auth-rate-limit.ts:102
const entries = new Map<string, RateLimitEntry>();
```

```typescript
// src/gateway/control-plane-rate-limit.ts:11
const controlPlaneBuckets = new Map<string, Bucket>();
```

#### Proof of Concept

See `test/poc-rate-limit-bypass.test.ts` - demonstrates that:
1. Attacker exhausts rate limit (3 attempts for control plane, 10 for auth)
2. Service restarts
3. Rate limit is reset to full quota
4. Attacker can continue brute force attempts

#### Recommendations

1. **Implement persistent rate limiting** using Redis, Memcached, or database backend
2. **Add rate limit state synchronization** for multi-instance deployments
3. **Consider using a dedicated rate limiting service** like CloudFlare API shield

---

### VULN-10: Loopback Exemption Bypass Potential

**Severity**: Low-Medium
**Affected File**: `src/gateway/auth-rate-limit.ts`

#### Description

The rate limiter exempts loopback addresses (127.0.0.1, ::1) from rate limiting by default. This is intentional for local CLI sessions but creates a bypass vector if IP spoofing is possible.

#### Code Evidence

```typescript
// src/gateway/auth-rate-limit.ts:99
const exemptLoopback = config?.exemptLoopback ?? true;

// src/gateway/auth-rate-limit.ts:143-145
if (isExempt(ip)) {
  return { allowed: true, remaining: maxAttempts, retryAfterMs: 0 };
}
```

#### Impact

- If `X-Forwarded-For` header is trusted without proper validation (see VULN-12)
- Attackers can spoof loopback IPs to bypass rate limiting
- Local privilege escalation: any local user can make unlimited auth attempts

#### Mitigation Status

**Partially Mitigated**: The codebase has proper IP resolution in `src/gateway/net.ts`:

```typescript
// src/gateway/net.ts:168-170
if (!isTrustedProxyAddress(remote, params.trustedProxies)) {
  return remote; // Don't trust headers if not from trusted proxy
}
```

However, this depends on correct `trustedProxies` configuration.

---

### VULN-11: Control Plane Rate Limit Per-IP Bypass

**Severity**: Medium
**Affected File**: `src/gateway/control-plane-rate-limit.ts`

#### Description

The control plane write rate limit (3 requests per 60 seconds) is **per-IP, not per-user or per-account**. This allows attackers to bypass the limit by rotating IP addresses.

#### Code Evidence

```typescript
// src/gateway/control-plane-rate-limit.ts:21-32
export function resolveControlPlaneRateLimitKey(client: GatewayClient | null): string {
  const deviceId = normalizePart(client?.connect?.device?.id, "unknown-device");
  const clientIp = normalizePart(client?.clientIp, "unknown-ip");
  return `${deviceId}|${clientIp}`;
}
```

#### Impact

- Attackers with access to multiple IPs (VPN, botnet, cloud instances) can make 3×N requests per minute
- Control plane operations (`config.apply`, `config.patch`, `update.run`) are rate-limited per-IP
- Distributed attack could overwhelm the control plane

#### Proof of Concept

```bash
# Attacker with 5 different IPs can make 15 requests per minute instead of 3
for ip in 1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4 5.5.5.5; do
  curl -H "X-Real-IP: $ip" http://gateway/config.apply -d '{"config": ...}'
done
```

#### Recommendations

1. **Add account-level rate limiting** in addition to IP-based
2. **Implement CAPTCHA** after suspicious patterns
3. **Add progressive backoff** for repeated control plane operations

---

### VULN-12: IP Spoofing via Misconfigured Trusted Proxies

**Severity**: Medium (depends on configuration)
**Affected File**: `src/gateway/net.ts`

#### Description

If `gateway.trustedProxies` is misconfigured to include overly broad CIDR ranges (e.g., `0.0.0.0/0`), attackers can spoof their IP address via the `X-Forwarded-For` header.

#### Code Evidence

```typescript
// src/gateway/net.ts:111-139
export function resolveClientIp(params: {
  remoteAddr?: string;
  forwardedFor?: string;
  trustedProxies?: string[];
}): string | undefined {
  // ...
  if (isTrustedProxyAddress(remote, params.trustedProxies)) {
    const forwardedIp = resolveForwardedClientIp({
      forwardedFor: params.forwardedFor,
      trustedProxies: params.trustedProxies,
    });
    if (forwardedIp) {
      return forwardedIp; // Trust the forwarded header
    }
  }
  return remote;
}
```

#### Attack Scenario

```yaml
# Misconfigured gateway.yml
gateway:
  trustedProxies:
    - "0.0.0.0/0"  # ❌ DANGEROUS: Trusts all IPs
```

```bash
# Attacker spoofs loopback to bypass rate limiting
curl -H "X-Forwarded-For: 127.0.0.1" http://gateway/ -d '{"password": "guess1"}'
```

#### Audit Finding

The codebase includes warnings in security audit (`src/security/audit.ts`):

```typescript
// src/security/audit.ts:673-684
if (bind !== "loopback" && auth.mode !== "trusted-proxy" && !cfg.gateway?.auth?.rateLimit) {
  findings.push({
    checkId: "gateway.auth_no_rate_limit",
    severity: "warn",
    title: "No auth rate limiting configured",
    // ...
  });
}
```

However, **no validation prevents broad CIDR ranges** in `trustedProxies`.

#### Recommendations

1. **Add CIDR range validation** for `trustedProxies` configuration
2. **Warn on overly broad ranges** (anything larger than /24 for IPv4)
3. **Reject 0.0.0.0/0 and ::/0 explicitly**
4. **Document safe proxy configuration** clearly

---

### VULN-13: Rate Limit Key Collision

**Severity**: Low
**Affected File**: `src/gateway/control-plane-rate-limit.ts`

#### Description

The control plane rate limit key combines `deviceId` and `clientIp`. In edge cases where both are "unknown" or empty, different clients may share the same rate limit bucket.

#### Code Evidence

```typescript
// src/gateway/control-plane-rate-limit.ts:21-32
export function resolveControlPlaneRateLimitKey(client: GatewayClient | null): string {
  const deviceId = normalizePart(client?.connect?.device?.id, "unknown-device");
  const clientIp = normalizePart(client?.clientIp, "unknown-ip");
  return `${deviceId}|${clientIp}`;
}
```

#### Impact

- Legitimate users with "unknown" identity may be incorrectly rate limited
- Low severity: affects only improperly configured clients

---

## Positive Security Findings

The following security measures were noted as **properly implemented**:

### ✓ SSRF Protection

**File**: `src/infra/net/ssrf.ts`

- Comprehensive blocking of private/internal IP addresses
- DNS rebinding protection
- Blocked hostnames (localhost, .local, .internal)
- Proper hostname allowlist support

### ✓ Canvas Capability Tokens

**File**: `src/gateway/canvas-capability.ts`

- Uses `randomBytes(18)` for 144-bit entropy (cryptographically secure)
- 10-minute TTL is reasonable
- Proper URL encoding and validation

### ✓ Node Pairing Security

**File**: `src/gateway/server-methods/nodes.ts`

- Proper approval workflow required
- Uses cryptographically random UUIDs
- Rate limiting on wake attempts
- Proper validation of declared commands

### ✓ IP Resolution

**File**: `src/gateway/net.ts`

- Proper X-Forwarded-For chain walking (right-to-left)
- Fail-closed when headers are missing from trusted proxy
- Loopback and private address detection

### ✓ WebSocket Security

**File**: `src/gateway/net.ts`

- Cleartext ws:// only allowed for loopback
- Proper hostname validation
- Optional break-glass for trusted private networks

---

## Recommended Priority Actions

### High Priority

1. **Address Command Obfuscation Bypass** (GHSA-9r3v-37xh-2cf6)
   - Add Unicode normalization before command detection
   - Implement variable indirection pattern detection
   - Add shell builtin obfuscation detection

### Medium Priority

2. **Implement Persistent Rate Limiting**
   - Use Redis or similar for cross-restart persistence
   - Add rate limit synchronization for multi-instance deployments

3. **Add CIDR Validation for trustedProxies**
   - Reject overly broad ranges (0.0.0.0/0, ::/0)
   - Warn on ranges larger than /24

4. **Implement Account-Level Rate Limiting**
   - Add user/account-based limits in addition to IP-based
   - Implement progressive backoff for repeated attempts

### Low Priority

5. **Add Rate Limit Key Salting**
   - Include additional context in rate limit keys to prevent collision
   - Document edge cases for "unknown" identity scenarios

---

## Test Files

Proof of Concept tests are available at:
- `test/poc-security-audit.test.ts` - Command obfuscation bypass (90% bypass rate)
- `test/poc-rate-limit-bypass.test.ts` - Rate limiting and state management bypasses
- `test/poc-touctu-race-condition.test.ts` - TOCTOU race conditions

---

## Timeline

- 2026-03-12: Initial report (this document)
- Awaiting patch release
- Private disclosure until fix is deployed

---

## Credits

Discovered and reported by: **wooluo**
- GitHub: https://github.com/wooluo
- Research repository: https://github.com/wooluo/openclaw
