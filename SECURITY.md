# Security Policy

## Overview

AgentArmor is a security tool — it is therefore held to a higher standard than an
average open-source project. We take vulnerability reports in AgentArmor itself very
seriously and aim to respond and fix confirmed issues faster than any other project.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x (current) | ✅ Active security fixes |
| < 1.0.0 | ❌ End-of-life — please upgrade |

---

## Reporting a Vulnerability

> ⚠️ **Please do NOT open a public GitHub Issue for security vulnerabilities.**
> Public disclosure before a fix is available harms the users of this tool.

### Preferred Contact

Send an email to:

**📧 [enceladus441@gmail.com](mailto:enceladus441@gmail.com)**

Please use the subject line: `[AgentArmor Security] <brief description>`

### What to Include

Your report should contain:

1. **A clear description** of the vulnerability and the potential impact
2. **Affected component** (e.g. `ASTHardener`, `PolicyEngine`, `ShadowChain`)
3. **AgentArmor version** where you found the issue
4. **Steps to reproduce** — a minimal Python snippet that demonstrates the issue
5. **Suggested fix** (optional, but appreciated)

### Example Report Format

```
Subject: [AgentArmor Security] AST Hardener bypass via Unicode identifier

Component: ASTHardener (agent_armor/core/ast_hardener.py)
Version: 1.0.0
Severity: HIGH

Description:
The `_SecurityVisitor.visit_Call()` visitor does not handle Unicode-normalised
function names (e.g. ｅｖａｌ vs eval), allowing a bypass of the eval() detection.

Reproduce:
  from agent_armor.core.ast_hardener import ASTHardener
  h = ASTHardener()
  findings = h.analyze("\uff45\uff56\uff41\uff4c(open('/etc/passwd').read())")
  assert findings == []  # should NOT be empty

Suggested fix:
  Normalise all identifier names with unicodedata.normalize('NFKC', name)
  before comparison.
```

---

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | ≤ 48 hours |
| Initial assessment (confirm/deny) | ≤ 5 business days |
| Fix development | ≤ 14 days for HIGH/CRITICAL |
| Patch release | ≤ 7 days after fix complete |
| Public disclosure (CVE / GitHub Advisory) | Coordinated with reporter |

If you do not receive an acknowledgement within 48 hours, please follow up at the same
email address.

---

## Disclosure Policy

AgentArmor follows **coordinated vulnerability disclosure**:

1. Reporter notifies maintainer privately
2. Maintainer confirms the vulnerability
3. Fix is developed and tested
4. A patch release is published
5. A GitHub Security Advisory is published (including CVE if applicable)
6. Reporter is credited in the advisory and `CHANGELOG.md` (unless they prefer anonymity)

---

## Scope

### In Scope

Vulnerabilities that allow an attacker to:

- **Bypass** a detection engine (false-negative bypass in ASTHardener or PolicyEngine)
- **Crash** the AgentArmor pipeline on crafted input (DoS via malformed code)
- **Escape** the `ShadowChainManager` attestation integrity check
- **Inject** malicious code through the MCP Security Proxy without detection
- **Expose** secrets or sensitive data from the pipeline process
- **Corrupt** the shadow-chain ledger (`shadow-chain.json`)

### Out of Scope

- Vulnerabilities in **third-party dependencies** (report those upstream)
- Issues requiring the attacker to already have code execution on the machine
- Theoretical attacks without a working proof-of-concept
- Reports that duplicate an already-known issue
- Social engineering or phishing attacks

---

## Hall of Fame

We recognise responsible security researchers who help keep AgentArmor secure.
Confirmed and responsibly disclosed vulnerabilities will be credited here:

| Researcher | Finding | Disclosed |
|-----------|---------|-----------|
| *(none yet — be the first!)* | — | — |

---

## Bug Bounty

AgentArmor does not currently offer a monetary bug bounty programme. However,
researchers who discover and responsibly disclose `HIGH` or `CRITICAL` severity
vulnerabilities will receive:

- ✅ Public credit in the GitHub Security Advisory
- ✅ Credit in `CHANGELOG.md`
- ✅ A `security-researcher` badge on their GitHub profile (via GitHub Sponsors)

---

*Security policy maintained by [Tanmay Dikey](mailto:enceladus441@gmail.com)*
*Last updated: March 2026*
