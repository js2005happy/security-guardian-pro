# Security Guardian Pro

> Enterprise-grade full-stack security audit skill for Claude Code — OWASP Top 10, supply chain, cloud-native, secrets detection, and compliance mapping in a single prompt.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Skill-orange)](https://claude.ai/code)
[![Security](https://img.shields.io/badge/Category-Security%20Audit-red)]()

[中文文档](README.zh-CN.md)

---

## What is Security Guardian Pro?

A Claude Code skill that transforms Claude into a **15-year veteran Application Security Architect**. It performs automated reconnaissance, static analysis, manual test-case enumeration, and structured reporting — all following a rigorous 4-phase vulnerability discovery methodology.

**One prompt. Full audit. Actionable report.**

## Features

| Category | Coverage |
|----------|----------|
| **Injection** | SQL, OS command, SSTI, log injection, XSS |
| **Access Control** | IDOR, missing middleware, CORS misconfig |
| **Cryptography** | Weak hashes, hardcoded keys, ECB mode, weak RNG |
| **Design Flaws** | Rate limiting, password reset, mass assignment |
| **Misconfiguration** | Debug mode, default creds, missing security headers |
| **Supply Chain** | Dependency CVE lookup, outdated components |
| **Secrets** | AWS keys, GitHub tokens, private keys, generic credentials |
| **SSRF** | User-controlled URL sinks, internal network exposure |
| **Cloud/K8s** | Privileged containers, host mounts, root users |
| **Framework-Specific** | JS prototype pollution, Python pickle, Java XXE, Go template injection |

## Quick Start

### 1. Install

```bash
# Clone this repo into your Claude Code skills directory
git clone https://github.com/YOUR_USERNAME/security-guardian-pro.git
cp security-guardian-pro/security-guardian-pro.md ~/.claude/skills/
```

Or copy the skill file directly into your project:

```bash
mkdir -p .claude/skills
cp security-guardian-pro.md .claude/skills/
```

### 2. Trigger

Just say any of these in Claude Code:

```
安全审计
security review
帮我检查漏洞
全面安全扫描
dependency scan
hardcoded secrets
```

Claude will automatically load the skill and begin the 4-phase audit.

## The 4-Phase Audit Process

```
RECON → SCAN → VERIFY → REPORT
```

| Phase | Activity | Tools |
|-------|----------|-------|
| **1. Recon** | Tech stack discovery, dependency mapping, dangerous pattern search | Glob, Grep, gitleaks |
| **2. Scan** | Automated SAST + manual test point enumeration | semgrep, manual input tracing |
| **3. Verify** | Generate reproducible security test cases for each finding | curl / request templates |
| **4. Report** | Structured report with scores, priorities, and compliance mapping | Built-in template |

## Example Report Output

```
🔒 Security Audit Report
Project: my-web-app
Scope: src/
Score: 6/10 (Needs Improvement)

Findings Summary
🔴 Critical: 2
🟠 High: 3
🟡 Medium: 5
🟢 Low: 4
✅ Passed: 12

Each finding includes:
  [Severity] Title
  File/Location: auth/login.ts:42
  Description: ...
  Attack Scenario: ...
  Fix: (diff format)
  CWE Reference: CWE-89

Remediation Timeline
  Urgent (24h): [Critical items]
  High Priority: [This sprint]
  Backlog: [Medium/Low]

Appendix: Reproducible Test Cases
```

## Rule Library

The skill ships with **9 rule categories** covering 50+ check patterns:

1. **Injection** — parameterized queries, command sanitization, template auto-escaping
2. **Broken Access Control** — middleware gaps, IDOR, CORS credentials
3. **Cryptographic Failures** — MD5/SHA1 detection, ECB mode, `Math.random()` misuse
4. **Insecure Design** — rate limiting, token entropy, error message leakage
5. **Security Misconfiguration** — debug flags, default accounts, missing CSP/HSTS
6. **Vulnerable Components** — `npm audit` / `pip audit` integration, CVE lookup
7. **Secrets & PII** — regex patterns for AWS, GitHub, private keys, generic credentials
8. **SSRF** — URL parameter tracing, allowlist enforcement
9. **Framework-Specific** — prototype pollution (JS), pickle (Python), XXE (Java), Docker socket mounts

## Prerequisites (Optional)

For best results, install these tools on your system PATH:

| Tool | Purpose |
|------|---------|
| [semgrep](https://semgrep.dev) | Multi-language SAST |
| [gitleaks](https://gitleaks.io) | Hardcoded secret detection |
| `npm audit` / `pip-audit` | Dependency scanning |

The skill works without them — it falls back to manual Grep/Glob analysis.

## Security Boundaries

This skill follows **defensive disclosure** principles:

- Never generates working exploit code or attack scripts
- Masks detected real credentials (e.g., `AKIA****`)
- Attack scenarios described in pseudocode only, for risk understanding
- Declines unauthorized penetration testing requests
- Compliant with responsible disclosure practices

## Contributing

Rule additions and pattern improvements are welcome. See the [rule library section](#rule-library) in the skill file for the structured format.

1. Fork the repo
2. Add or improve check patterns
3. Submit a PR with a description of what new vulnerabilities are covered

## License

MIT © 2026

## Related

- [Claude Code](https://claude.ai/code) — The AI coding assistant this skill runs on
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — The industry standard for web app security
- [Semgrep Rules](https://semgrep.dev/explore) — Community SAST rules
