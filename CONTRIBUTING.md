# Contributing to AgentArmor

Thank you for your interest in making AI-generated code safer! 🛡️

AgentArmor is an open project and contributions of all kinds are welcome — bug fixes,
new detection rules, new vulnerability museum cases, documentation improvements, and
performance work.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Running the Tests](#running-the-tests)
- [How to Add a New Detection Rule](#how-to-add-a-new-detection-rule)
- [Pull Request Checklist](#pull-request-checklist)
- [Coding Standards](#coding-standards)
- [Adding a Vulnerability Museum Case](#adding-a-vulnerability-museum-case)
- [Reporting Bugs](#reporting-bugs)
- [Community Guidelines](#community-guidelines)

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/agent-armor.git
   cd agent-armor
   ```
3. **Create a feature branch** — never work directly on `main`:
   ```bash
   git checkout -b feature/my-new-detection
   ```

---

## Development Setup

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
.venv\Scripts\activate             # Windows PowerShell

# Install the package in editable mode with all dev dependencies
pip install -e ".[dev]"

# Verify everything works
pytest tests/ -q
# Expected: 195 passed (or more if you added tests)
```

### Useful tools installed by `.[dev]`

| Tool | Purpose |
|------|---------|
| `pytest` | Test runner |
| `pytest-cov` | Coverage reporting |
| `ruff` | Linting and format checking |
| `build` | Building distribution packages |

---

## Running the Tests

```bash
# Quick run (quiet output)
pytest tests/ -q

# Verbose with coverage
pytest tests/ -v --cov=agent_armor --cov-report=term-missing

# Run a single test module
pytest tests/test_ast_hardener.py -v

# Run tests matching a keyword
pytest tests/ -k "insecure_crypto" -v
```

The test suite must pass with **zero failures** before any PR can be merged.

---

## How to Add a New Detection Rule

AgentArmor has two complementary detection layers. Choose the right one:

| Layer | Use when... | File to edit |
|-------|------------|-------------|
| **AST Hardener** | You can detect the vulnerability purely from code structure (function calls, imports, regex patterns) | `agent_armor/core/ast_hardener.py` |
| **Policy Engine** | You need semantic understanding (e.g., "this query is missing an ownership column") | `agent_armor/core/policy_engine.py` |

### Adding an AST Hardener Detection

1. Open `agent_armor/core/ast_hardener.py`
2. Add any required constants near the top (e.g. a `frozenset` of bad function names)
3. Add detection logic inside `_SecurityVisitor.visit_Call()` or an appropriate `visit_*` method
4. Raise a `SecurityFinding` with fields: `node_type`, `severity`, `line_number`, `description`, `remediation`
5. Add tests in `tests/test_ast_hardener.py` — minimum 4 tests per detection:
   - Flag the vulnerable pattern
   - Pass the safe alternative
   - Verify the correct severity
   - Cover any edge cases

```python
# Example: detecting a new dangerous function foo.bar()
_DANGEROUS_FOO_FUNCS: frozenset = frozenset({"bar", "baz"})

# Inside _SecurityVisitor.visit_Call():
if (
    isinstance(node.func, ast.Attribute)
    and isinstance(node.func.value, ast.Name)
    and node.func.value.id == "foo"
    and node.func.attr in _DANGEROUS_FOO_FUNCS
):
    self.findings.append(SecurityFinding(
        node_type="DangerousFoo",
        severity="HIGH",
        line_number=node.lineno,
        description=f"foo.{node.func.attr}() is dangerous because...",
        remediation="Use foo.safe_alternative() instead.",
    ))
```

### Adding a Policy Engine Rule

1. Open `agent_armor/core/policy_engine.py`
2. Add a new class that subclasses `Rule`:

```python
class MyNewRule(Rule):
    """RULE-011 — Short description."""

    name = "RULE-011-MY-NEW-RULE"
    severity = "HIGH"   # CRITICAL | HIGH | MEDIUM | LOW

    def evaluate(
        self,
        code: str,
        filename: str,
        context: Dict[str, Any],
    ) -> List[PolicyViolation]:
        violations = []
        for i, line in enumerate(code.splitlines(), 1):
            if "dangerous_pattern" in line:
                violations.append(PolicyViolation(
                    rule_name=self.name,
                    severity=self.severity,
                    line_number=i,
                    description="Describes what was found and why it is dangerous.",
                    remediation="Concrete fix the developer should apply.",
                ))
        return violations
```

3. Register it in `PolicyEngine.__init__`:

```python
self._rules: List[Rule] = [
    ...existing rules...
    MyNewRule(),
]
```

4. Add the rule to the table in `README.md`
5. Add at least 4 tests in `tests/test_policy_engine.py`
6. Add the rule description to the docstring at the top of `policy_engine.py`

---

## Pull Request Checklist

Before submitting your PR, verify **all** of the following:

- [ ] All existing tests still pass: `pytest tests/ -q`
- [ ] New tests added for every new feature/rule (minimum 4 per rule)
- [ ] `ruff check agent_armor/ cli/` passes with no errors
- [ ] `ruff format --check agent_armor/ cli/` passes
- [ ] Copyright header added to any new files:
  ```python
  # Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
  # SPDX-License-Identifier: MIT
  ```
- [ ] PR title follows the format: `feat: add RULE-011 for <detection-name>`
- [ ] README.md updated if adding a new detection or rule
- [ ] Description explains *why* the detection is needed, not just *what* it does

---

## Coding Standards

AgentArmor follows a set of conventions to keep the codebase consistent:

| Convention | Standard |
|-----------|---------|
| Formatter | `ruff format` (compatible with Black) |
| Linter | `ruff check` |
| Line length | 100 characters |
| Type hints | Required on all public functions |
| Docstrings | Google style |
| Imports | `from __future__ import annotations` at top of all files |
| Severity levels | `CRITICAL` → `HIGH` → `MEDIUM` → `LOW` (must be one of these exact strings) |

### Severity Guidelines

| Level | When to use |
|-------|------------|
| `CRITICAL` | Direct code execution, authentication bypass, data destruction |
| `HIGH` | Injection, credential exposure, SSRF, broken auth |
| `MEDIUM` | Information leakage, missing validation, weak config |
| `LOW` | Code quality issues that create security surface area |

---

## Adding a Vulnerability Museum Case

The `vulnerability_museum/` folder showcases real AI-generated vulnerable code and the
hardened alternative. Each case is a numbered directory with two files.

To add case number `N`:

```bash
mkdir vulnerability_museum/N_<short_name>/
touch vulnerability_museum/N_<short_name>/vulnerable.py
touch vulnerability_museum/N_<short_name>/hardened.py
```

**`vulnerable.py`** must:
- Show realistic AI-generated code (not a toy example)
- Have a comment at the top explaining the vulnerability
- Include `# [VULNERABLE]` markers on the dangerous lines
- Be runnable (even if it requires a mock import)

**`hardened.py`** must:
- Fix *only* the security issue — no unrelated refactoring
- Have a comment explaining each fix
- Include `# [HARDENED]` markers on the fixed lines
- Import from the same mocks as the vulnerable version

Update the museum table in `README.md` and `vulnerability_museum/README.md`.

---

## Reporting Bugs

Please use **GitHub Issues** with the label `bug`:

1. Title: `[BUG] Short description`
2. Include the Python version and OS
3. Paste the minimal code that triggers the bug
4. Paste the full error output / unexpected finding

For **security vulnerabilities in AgentArmor itself**, please see [SECURITY.md](SECURITY.md)
and report privately before opening a public issue.

---

## Community Guidelines

- Be respectful and professional
- Explain your reasoning in PR reviews
- Security-focused PRs are prioritised
- "Shift left" is our philosophy — catch issues early, automate everything

---

*AgentArmor — written and maintained by [Tanmay Dikey](https://github.com/tanmaydikey)*
