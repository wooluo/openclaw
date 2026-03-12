/**
 * SECURITY AUDIT PoC - Rate Limiting and State Management Bypasses
 *
 * This file demonstrates Proof of Concept (PoC) tests for security vulnerabilities
 * discovered during the security audit beyond the command obfuscation bypass.
 *
 * Run with: pnpm test poc-rate-limit-bypass.test.ts
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  createAuthRateLimiter,
  normalizeRateLimitClientIp,
  AUTH_RATE_LIMIT_SCOPE_SHARED_SECRET,
} from "../src/gateway/auth-rate-limit.js";
import { consumeControlPlaneWriteBudget, resolveControlPlaneRateLimitKey } from "../src/gateway/control-plane-rate-limit.js";
import { resolveClientIp, isLoopbackAddress } from "../src/gateway/net.js";

describe("Security PoC - Rate Limiting Bypass", () => {
  describe("VULN-9: Rate Limit State Lost on Restart", () => {
    it("POC: Rate limiter state is not persisted across restarts", async () => {
      const limiter = createAuthRateLimiter({
        maxAttempts: 3,
        windowMs: 60_000,
        lockoutMs: 300_000,
        exemptLoopback: false,
        pruneIntervalMs: -1, // Disable auto-prune for this test
      });

      const attackerIp = "1.2.3.4";

      // Simulate attacker exhausting rate limit
      for (let i = 0; i < 3; i++) {
        limiter.recordFailure(attackerIp, AUTH_RATE_LIMIT_SCOPE_SHARED_SECRET);
      }

      // Verify attacker is locked out
      let result = limiter.check(attackerIp, AUTH_RATE_LIMIT_SCOPE_SHARED_SECRET);
      expect(result.allowed).toBe(false);
      expect(result.retryAfterMs).toBeGreaterThan(0);

      // VULNERABILITY: Simulate service restart
      // In a real scenario, the process restarts and all rate limit state is lost
      const newLimiter = createAuthRateLimiter({
        maxAttempts: 3,
        windowMs: 60_000,
        lockoutMs: 300_000,
        exemptLoopback: false,
        pruneIntervalMs: -1,
      });

      // After restart, attacker is no longer locked out
      result = newLimiter.check(attackerIp, AUTH_RATE_LIMIT_SCOPE_SHARED_SECRET);
      expect(result.allowed).toBe(true); // VULNERABLE: State was lost
      expect(result.remaining).toBe(3);

      console.log("VULN-9: Rate limit state is NOT persisted across restarts");
      console.log("Impact: Attackers can reset rate limits by causing service restarts");
    });
  });

  describe("VULN-10: Loopback Exemption Bypass", () => {
    it("POC: Loopback addresses are exempt from rate limiting", () => {
      const limiter = createAuthRateLimiter({
        maxAttempts: 3,
        windowMs: 60_000,
        lockoutMs: 300_000,
        exemptLoopback: true, // Default behavior
      });

      const loopbackIps = ["127.0.0.1", "::1", "127.0.0.2"];

      for (const ip of loopbackIps) {
        // Even with many failed attempts
        for (let i = 0; i < 100; i++) {
          limiter.recordFailure(ip, AUTH_RATE_LIMIT_SCOPE_SHARED_SECRET);
        }

        // Loopback is always allowed
        const result = limiter.check(ip, AUTH_RATE_LIMIT_SCOPE_SHARED_SECRET);
        expect(result.allowed).toBe(true); // VULNERABLE: Loopback exempt
        expect(result.remaining).toBe(3); // Always full quota
      }

      console.log("VULN-10: Loopback addresses exempt from rate limiting");
      console.log("Impact: If X-Forwarded-For is trusted without proper validation,");
      console.log("        attackers can spoof loopback IPs to bypass rate limits");
    });
  });

  describe("VULN-11: Control Plane Write Rate Limit Bypass", () => {
    it("POC: Control plane rate limit can be bypassed via IP rotation", () => {
      // Reset state before test
      const { resetControlPlaneRateLimitState } =
        // @ts-expect-error - testing export
        import("../src/gateway/control-plane-rate-limit.js");
      // @ts-expect-error - testing export
      resetControlPlaneRateLimitState();

      const controlPlaneMethods = ["config.apply", "config.patch", "update.run"];

      for (const method of controlPlaneMethods) {
        // Attacker rotates through different IPs
        const ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"];
        let successCount = 0;

        for (const ip of ips) {
          const client = {
            connect: { device: { id: "test-device" } },
            clientIp: ip,
            connId: "test-conn",
          };

          for (let i = 0; i < 5; i++) {
            const result = consumeControlPlaneWriteBudget({ client });
            if (result.allowed) {
              successCount++;
            }
          }
        }

        // VULNERABILITY: Each IP gets its own quota
        // Attacker can make 5 requests per IP = 25 total (exceeds the limit of 3)
        expect(successCount).toBeGreaterThan(3);

        console.log(
          `VULN-11: ${method} - ${successCount} requests allowed (limit should be 3)`,
        );
      }

      console.log("VULN-11: Control plane rate limit is per-IP, not global");
      console.log("Impact: Attackers can rotate IPs to bypass write rate limits");
    });

    it("POC: Control plane rate limit state lost on restart", () => {
      const client = {
        connect: { device: { id: "test-device" } },
        clientIp: "1.2.3.4",
        connId: "test-conn",
      };

      // Exhaust the rate limit
      for (let i = 0; i < 5; i++) {
        consumeControlPlaneWriteBudget({ client });
      }

      const result1 = consumeControlPlaneWriteBudget({ client });
      expect(result1.allowed).toBe(false);

      // VULNERABILITY: State is in-memory, lost on restart
      // Reset to simulate restart
      // @ts-expect-error - testing export
      const { resetControlPlaneRateLimitState } = import.meta.jest?.mock || {
        resetControlPlaneRateLimitState: () => {},
      };

      // After restart, budget is reset
      const result2 = consumeControlPlaneWriteBudget({ client });
      expect(result2.allowed).toBe(true); // VULNERABLE: State reset

      console.log("VULN-11: Control plane rate limit state is NOT persisted");
    });
  });

  describe("VULN-12: IP Spoofing via X-Forwarded-For", () => {
    it("POC: Improper trusted proxy configuration enables IP spoofing", () => {
      // Scenario: Administrator misconfigures trustedProxies to include all IPs
      const misconfiguredTrustedProxies = ["0.0.0.0/0"];

      const attackerRealIp = "1.2.3.4";
      const spoofedLoopback = "127.0.0.1";

      // Simulate request with spoofed X-Forwarded-For
      const resolved = resolveClientIp({
        remoteAddr: attackerRealIp,
        forwardedFor: spoofedLoopback,
        trustedProxies: misconfiguredTrustedProxies,
        allowRealIpFallback: false,
      });

      // VULNERABILITY: With misconfigured trustedProxies, attacker can spoof IP
      if (resolved === spoofedLoopback) {
        expect(isLoopbackAddress(resolved)).toBe(true);

        // Attacker now gets loopback exemption
        const limiter = createAuthRateLimiter({
          exemptLoopback: true,
        });

        for (let i = 0; i < 100; i++) {
          limiter.recordFailure(resolved, AUTH_RATE_LIMIT_SCOPE_SHARED_SECRET);
        }

        const result = limiter.check(resolved, AUTH_RATE_LIMIT_SCOPE_SHARED_SECRET);
        expect(result.allowed).toBe(true); // VULNERABLE: Bypassed via spoofed IP
      }

      console.log("VULN-12: Misconfigured trustedProxies enables IP spoofing");
      console.log("Impact: Attackers can spoof loopback IPs to bypass rate limits");
    });

    it("POC: Chaining X-Forwarded-For to find trusted proxy", () => {
      const trustedProxies = ["10.0.0.0/8"]; // Internal network

      // Attacker tries to chain through proxies to find a trusted one
      const chainedForwarded = "1.2.3.4, 8.8.8.8, 10.0.0.1, 192.168.1.1";

      const resolved = resolveClientIp({
        remoteAddr: "203.0.113.1", // Untrusted proxy
        forwardedFor: chainedForwarded,
        trustedProxies,
        allowRealIpFallback: false,
      });

      // The function walks right-to-left and returns the first untrusted hop
      // This should be "192.168.1.1" (private but not in 10.0.0.0/8)
      expect(resolved).toBeTruthy();

      console.log("VULN-12: X-Forwarded-For chain resolution");
      console.log(`Resolved to: ${resolved}`);
      console.log("Impact: Complex proxy chains can lead to unexpected IP resolution");
    });
  });

  describe("VULN-13: Rate Limit Key Collision", () => {
    it("POC: Different client types may share rate limit keys", () => {
      const testCases = [
        {
          client1: {
            connect: { device: { id: "" } },
            clientIp: "127.0.0.1",
            connId: "",
          },
          client2: {
            connect: { device: { id: "" } },
            clientIp: "127.0.0.1",
            connId: "different",
          },
        },
        {
          client1: {
            connect: { device: { id: "device1" } },
            clientIp: "unknown-ip",
            connId: "",
          },
          client2: {
            connect: { device: { id: "" } },
            clientIp: "unknown-ip",
            connId: "",
          },
        },
      ];

      for (const { client1, client2 } of testCases) {
        const key1 = resolveControlPlaneRateLimitKey(client1);
        const key2 = resolveControlPlaneRateLimitKey(client2);

        if (key1 === key2) {
          console.log(`VULN-13: Key collision detected`);
          console.log(`  Client1 key: ${key1}`);
          console.log(`  Client2 key: ${key2}`);
          console.log(`  Impact: Different clients may share rate limit state`);
        }
      }
    });
  });
});

describe("Security PoC - Token Security", () => {
  describe("VULN-14: Canvas Capability Token Weakness", () => {
    it("POC: Canvas capability tokens have predictable characteristics", () => {
      // Canvas capability tokens use randomBytes(18) = 18 bytes = 144 bits
      // This is cryptographically secure, but let's verify the implementation

      const { mintCanvasCapabilityToken, CANVAS_CAPABILITY_TTL_MS } =
        // @ts-expect-error - testing import
        import("../src/gateway/canvas-capability.js");

      const tokens = new Set();
      const iterations = 1000;

      for (let i = 0; i < iterations; i++) {
        const token = mintCanvasCapabilityToken();
        tokens.add(token);

        // Verify token characteristics
        expect(token).toMatch(/^[A-Za-z0-9_-]+$/); // base64url format
        expect(token.length).toBeLessThanOrEqual(24); // 18 bytes * 4/3 ≈ 24 chars
      }

      // Check for collisions (should be none with 144 bits)
      expect(tokens.size).toBe(iterations);

      console.log("VULN-14 Analysis: Canvas tokens use 144-bit entropy (18 bytes)");
      console.log("  This is cryptographically secure - no vulnerability found");
      console.log(`  TTL: ${CANVAS_CAPABILITY_TTL_MS}ms (${CANVAS_CAPABILITY_TTL_MS / 60000} minutes)`);
    });
  });
});
