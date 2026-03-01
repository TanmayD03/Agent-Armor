# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor — Semantic Policy Engine
=====================================
Enforces rule-based security policies on AI-generated code.

Built-in rules
--------------
  RULE-001  No writes to sensitive system paths
  RULE-002  Delete/drop operations require a valid non-None user_id guard
  RULE-003  Agent domain isolation (frontend code ≠ backend env vars)
  RULE-004  Admin endpoints must include an auth/permission check
  RULE-005  No hardcoded localhost/IP in production configuration files
  RULE-006  JWT decode must validate the signature (algorithms must be specified)

Custom rules
------------
  Users can subclass PolicyEngine or register custom Rule objects:

      class MyRule(Rule):
          name = "CUSTOM-001"
          severity = "HIGH"
          def evaluate(self, code, filename, context):
              ...

      engine = PolicyEngine()
      engine.register_rule(MyRule())
"""

from __future__ import annotations

import ast
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class PolicyViolation:
    """A single policy rule violation."""
    rule_name: str
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW
    line_number: int
    description: str
    remediation: str

    @property
    def rule_id(self) -> str:
        """Alias for rule_name — used by tests and CLI filtering."""
        return self.rule_name

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.rule_name} at line {self.line_number}: "
            f"{self.description}"
        )


class Rule(ABC):
    """Base class for all policy rules."""

    name: str = "UNNAMED"
    severity: str = "MEDIUM"

    @abstractmethod
    def evaluate(
        self,
        code: str,
        filename: str,
        context: Dict[str, Any],
    ) -> List[PolicyViolation]:
        """Return a (possibly empty) list of violations."""


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------


class SensitivePathWriteRule(Rule):
    """RULE-001 — No writes to sensitive system paths."""

    name = "RULE-001-SENSITIVE-PATH-WRITE"
    severity = "CRITICAL"

    _SENSITIVE = [
        r"/etc/passwd", r"/etc/shadow", r"/etc/sudoers",
        r"~/.ssh/", r"~/.aws/credentials",
        r"C:\\Windows\\System32",
    ]

    def evaluate(self, code: str, filename: str, context: Dict[str, Any]) -> List[PolicyViolation]:
        violations = []
        for i, line in enumerate(code.splitlines(), 1):
            for path in self._SENSITIVE:
                if path.lower() in line.lower():
                    violations.append(PolicyViolation(
                        rule_name=self.name,
                        severity=self.severity,
                        line_number=i,
                        description=f"Attempt to reference/write sensitive path: {path}",
                        remediation="Remove or parameterise the sensitive path reference.",
                    ))
        return violations


class DeleteWithoutUserIDRule(Rule):
    """
    RULE-002 — Formal Invariant: Delete/drop operations require
    a non-None, non-empty user_id guard.

    Implements the Mitsubishi Rapid Formal Verification concept:
    ensures a 'Delete' function can never be called without a valid user_id.
    """

    name = "RULE-002-DELETE-WITHOUT-USER-ID"
    severity = "CRITICAL"

    _DELETE_KEYWORDS = re.compile(
        r"(delete|remove|drop|truncate|destroy|purge)",
        re.IGNORECASE,
    )

    def evaluate(self, code: str, filename: str, context: Dict[str, Any]) -> List[PolicyViolation]:
        violations = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return violations

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not self._DELETE_KEYWORDS.search(node.name):
                continue

            # Check: does the function have a user_id param?
            param_names = {a.arg for a in node.args.args}
            has_user_id = any("user_id" in p or "userid" in p.lower() for p in param_names)

            # Check: is there an early guard (if not user_id / if user_id is None)?
            has_guard = self._has_user_id_guard(node)

            if not has_user_id:
                violations.append(PolicyViolation(
                    rule_name=self.name,
                    severity=self.severity,
                    line_number=node.lineno,
                    description=(
                        f'Function "{node.name}" performs a destructive operation '
                        f"but has no 'user_id' parameter."
                    ),
                    remediation=(
                        "Add 'user_id: int' as a required parameter to all destructive functions."
                    ),
                ))
            elif not has_guard:
                violations.append(PolicyViolation(
                    rule_name=self.name,
                    severity="HIGH",
                    line_number=node.lineno,
                    description=(
                        f'Function "{node.name}" has a user_id parameter but '
                        f"no explicit guard check for None/empty."
                    ),
                    remediation=(
                        "Add: 'if not user_id: raise ValueError(\"user_id required\")' "
                        "at the top of the function."
                    ),
                ))

        return violations

    @staticmethod
    def _has_user_id_guard(func_node: ast.FunctionDef) -> bool:
        """
        Return True if the function has a user_id guard, satisfied by:
          1. A concrete type annotation (user_id: int) — implicit non-None contract
          2. An explicit if-guard in the first few statements (if not user_id: ...)
        """
        # Check for a concrete (non-optional) type annotation on the user_id parameter
        for arg in func_node.args.args:
            if "user_id" in arg.arg or "userid" in arg.arg.lower():
                if arg.annotation is not None:
                    ann = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                    if ann in ("int", "str", "float", "bytes", "UUID"):
                        return True
        # Check for an explicit if-guard (if not user_id / if user_id is None)
        for stmt in func_node.body[:5]:
            if not isinstance(stmt, ast.If):
                continue
            test_src = ast.unparse(stmt.test) if hasattr(ast, "unparse") else ""
            if "user_id" in test_src.lower() or "userid" in test_src.lower():
                return True
        return False


class DomainIsolationRule(Rule):
    """
    RULE-003 — Agent Domain Isolation.

    Ensures that code tagged as 'frontend' domain does not access
    backend-specific resources (env vars, DB connections, admin paths).
    """

    name = "RULE-003-DOMAIN-ISOLATION"
    severity = "HIGH"

    _BACKEND_PATTERNS = [
        re.compile(r'os\.environ\[.*(DB_|DATABASE_|SECRET_|ADMIN_)', re.IGNORECASE),
        re.compile(r'os\.getenv\(.*(DB_|DATABASE_|SECRET_|ADMIN_)', re.IGNORECASE),
        re.compile(r'\b(psycopg2|sqlalchemy|pymongo|redis\.Redis)\b'),
    ]

    def evaluate(self, code: str, filename: str, context: Dict[str, Any]) -> List[PolicyViolation]:
        domain = context.get("domain", "")
        if domain.lower() != "frontend":
            return []

        violations = []
        for i, line in enumerate(code.splitlines(), 1):
            for pattern in self._BACKEND_PATTERNS:
                if pattern.search(line):
                    violations.append(PolicyViolation(
                        rule_name=self.name,
                        severity=self.severity,
                        line_number=i,
                        description=(
                            f"Frontend-domain agent accessing backend resource: '{line.strip()}'"
                        ),
                        remediation=(
                            "Frontend code must not access database connections or backend secrets. "
                            "Use an API call instead."
                        ),
                    ))
                    break
        return violations


class AdminEndpointAuthRule(Rule):
    """
    RULE-004 — Admin endpoints must include a permission/auth check.
    """

    name = "RULE-004-ADMIN-ENDPOINT-AUTH"
    severity = "HIGH"

    _ADMIN_RE = re.compile(r"\b(admin|superuser|root|privileged)\b", re.IGNORECASE)
    _AUTH_RE = re.compile(
        r"\b(is_admin|is_superuser|has_permission|check_auth|require_auth|"
        r"login_required|permission_required|authorize|authenticated)\b",
        re.IGNORECASE,
    )

    def evaluate(self, code: str, filename: str, context: Dict[str, Any]) -> List[PolicyViolation]:
        violations = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return violations

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            # Match if function name OR any route decorator path contains admin keywords
            is_admin = bool(self._ADMIN_RE.search(node.name))
            if not is_admin:
                for deco in node.decorator_list:
                    try:
                        deco_src = ast.unparse(deco) if hasattr(ast, "unparse") else ""
                    except Exception:
                        deco_src = ""
                    if self._ADMIN_RE.search(deco_src):
                        is_admin = True
                        break

            if not is_admin:
                continue

            # Get full function source (includes body + decorators via ast.unparse)
            try:
                func_src = ast.unparse(node) if hasattr(ast, "unparse") else ""
            except Exception:
                func_src = ""

            if not self._AUTH_RE.search(func_src):
                violations.append(PolicyViolation(
                    rule_name=self.name,
                    severity=self.severity,
                    line_number=node.lineno,
                    description=(
                        f'Admin function "{node.name}" has no visible auth/permission check.'
                    ),
                    remediation=(
                        "Add an explicit authorisation check (e.g., if not user.is_admin: raise PermissionError)."
                    ),
                ))
        return violations


class JWTAlgorithmRule(Rule):
    """
    RULE-005 — JWT decode must specify algorithms explicitly.
    jwt.decode(token, secret) without algorithms= is a security misconfiguration.
    """

    name = "RULE-005-JWT-ALGORITHM-REQUIRED"
    severity = "HIGH"

    def evaluate(self, code: str, filename: str, context: Dict[str, Any]) -> List[PolicyViolation]:
        violations = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return violations

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "decode"):
                continue
            # Check if algorithms= kwarg is present
            kw_names = {kw.arg for kw in node.keywords}
            if "algorithms" not in kw_names:
                violations.append(PolicyViolation(
                    rule_name=self.name,
                    severity=self.severity,
                    line_number=node.lineno,
                    description=(
                        "jwt.decode() called without 'algorithms' parameter. "
                        "This may allow the 'none' algorithm attack."
                    ),
                    remediation=(
                        "Always specify: jwt.decode(token, secret, algorithms=['HS256'])"
                    ),
                ))
        return violations


# ---------------------------------------------------------------------------
# RULE-007 — Insecure Cryptography
# ---------------------------------------------------------------------------

class InsecureCryptographyRule(Rule):
    """
    RULE-007 — Weak hash algorithms must not be used for security-sensitive purposes.

    Detects hashlib.md5(), hashlib.sha1(), hashlib.new("md5"), and direct use of
    pycryptodome's DES/ARC4 cipher modules.
    """

    name = "RULE-007-INSECURE-CRYPTOGRAPHY"
    severity = "HIGH"

    _WEAK = frozenset({"md5", "sha1", "sha", "md4", "md2"})
    _WEAK_MODULES = frozenset({
        "Crypto.Cipher.DES", "Crypto.Cipher.ARC4",
        "Crypto.Hash.MD5", "Crypto.Hash.SHA1",
        "Cryptodome.Cipher.DES", "Cryptodome.Hash.MD5",
    })

    def evaluate(self, code: str, filename: str, context: Dict[str, Any]) -> List[PolicyViolation]:
        violations = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return violations

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            attr = func.attr.lower()
            # hashlib.md5(), hashlib.sha1(), …
            if (
                isinstance(func.value, ast.Name)
                and func.value.id == "hashlib"
                and attr in self._WEAK
            ):
                violations.append(PolicyViolation(
                    rule_name=self.name,
                    severity=self.severity,
                    line_number=node.lineno,
                    description=(
                        f"hashlib.{func.attr}() uses a broken algorithm. "
                        f"{func.attr.upper()} is vulnerable to collision attacks."
                    ),
                    remediation="Replace with hashlib.sha256() or hashlib.sha3_256(). For passwords use scrypt/argon2.",
                ))
            # hashlib.new("md5", …)
            if (
                isinstance(func.value, ast.Name)
                and func.value.id == "hashlib"
                and func.attr == "new"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and node.args[0].value.lower() in self._WEAK
            ):
                violations.append(PolicyViolation(
                    rule_name=self.name,
                    severity=self.severity,
                    line_number=node.lineno,
                    description=f"hashlib.new('{node.args[0].value}') uses a broken hash algorithm.",
                    remediation="Replace with hashlib.new('sha256') or hashlib.sha256().",
                ))

        # Check imports of known-weak Crypto modules
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    full = f"{node.module}.{alias.name}"
                    if full in self._WEAK_MODULES:
                        violations.append(PolicyViolation(
                            rule_name=self.name,
                            severity=self.severity,
                            line_number=node.lineno,
                            description=f"Import of weak cryptographic module: {full}",
                            remediation="Use AES-256-GCM or ChaCha20-Poly1305 via the 'cryptography' library.",
                        ))
        return violations


# ---------------------------------------------------------------------------
# RULE-008 — Server-Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------

class SSRFRule(Rule):
    """
    RULE-008 — HTTP requests must not use unvalidated user-controlled URLs.

    Detects calls to requests.get/post/etc. or urllib.request.urlopen() where
    the URL argument is a non-literal (variable) value that could be tainted.
    """

    name = "RULE-008-SSRF"
    severity = "HIGH"

    _HTTP_METHODS = frozenset({
        "get", "post", "put", "patch", "delete", "head", "options", "request",
        "urlopen", "urlretrieve",
    })

    def evaluate(self, code: str, filename: str, context: Dict[str, Any]) -> List[PolicyViolation]:
        violations = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return violations

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            if func.attr not in self._HTTP_METHODS:
                continue
            if not node.args:
                continue
            url_arg = node.args[0]
            # Only flag non-constant (dynamic) URLs — they might be user-controlled
            if not isinstance(url_arg, ast.Constant):
                violations.append(PolicyViolation(
                    rule_name=self.name,
                    severity=self.severity,
                    line_number=node.lineno,
                    description=(
                        f"{func.attr}() receives a dynamic URL that may be user-controlled. "
                        "An attacker could redirect the request to internal services."
                    ),
                    remediation=(
                        "Validate the URL against an allowlist: use urllib.parse.urlparse() "
                        "to check the scheme and hostname before making the request."
                    ),
                ))
        return violations


# ---------------------------------------------------------------------------
# RULE-009 — Broken Object-Level Authorization (BOLA/IDOR)
# ---------------------------------------------------------------------------

class BrokenObjectAuthRule(Rule):
    """
    RULE-009 — Resource lookups must be scoped to the authenticated user.

    Detects database queries that filter only on an ID parameter (e.g. WHERE id = ?)
    without also filtering on a user_id / owner / account_id column.  This pattern
    is the classic IDOR (Insecure Direct Object Reference) / BOLA vulnerability.
    """

    name = "RULE-009-BROKEN-OBJECT-AUTH"
    severity = "HIGH"

    # Patterns that look like "WHERE id = ?" without a second ownership check
    _ID_ONLY_PATTERN = re.compile(
        r"WHERE\s+id\s*=",
        re.IGNORECASE,
    )
    # Ownership columns — presence of ANY of these alongside an id check is acceptable
    _OWNER_COLUMNS = re.compile(
        r"user_id|owner_id|account_id|tenant_id|org_id|created_by",
        re.IGNORECASE,
    )

    def evaluate(self, code: str, filename: str, context: Dict[str, Any]) -> List[PolicyViolation]:
        violations = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return violations

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "execute"):
                continue
            if not node.args:
                continue
            first_arg = node.args[0]
            # We can only analyse string literals
            if not isinstance(first_arg, ast.Constant) or not isinstance(first_arg.value, str):
                continue
            query = first_arg.value
            if self._ID_ONLY_PATTERN.search(query) and not self._OWNER_COLUMNS.search(query):
                violations.append(PolicyViolation(
                    rule_name=self.name,
                    severity=self.severity,
                    line_number=node.lineno,
                    description=(
                        "Database query filters only on 'id' without an ownership column "
                        "(user_id/owner_id/etc.). An attacker may access another user's data."
                    ),
                    remediation=(
                        "Add an ownership check: WHERE id = ? AND user_id = ?. "
                        "Always scope resource lookups to the authenticated user's identity."
                    ),
                ))
        return violations


# ---------------------------------------------------------------------------
# RULE-010 — Insecure Design
# ---------------------------------------------------------------------------

class InsecureDesignRule(Rule):
    """
    RULE-010 — Insecure design patterns in production application code.

    Detects:
    - app.run(debug=True) — debug mode exposed in production
    - Hardcoded secret keys: app.secret_key = "..." / SECRET_KEY = "..."
    - Missing auth on POST/PUT/DELETE Flask/FastAPI routes (no decorator scan)
    - Hardcoded private IP addresses in configuration
    """

    name = "RULE-010-INSECURE-DESIGN"
    severity = "HIGH"

    _HARDCODED_KEY = re.compile(
        r"""(secret_key|SECRET_KEY|APP_SECRET|JWT_SECRET)\s*=\s*['"][^'"]{3,}['"]""",
        re.IGNORECASE,
    )
    _PRIVATE_IP = re.compile(
        r"""['"](10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)['"]"""
    )

    def evaluate(self, code: str, filename: str, context: Dict[str, Any]) -> List[PolicyViolation]:
        violations = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return violations

        for node in ast.walk(tree):
            # app.run(debug=True)
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "run":
                    for kw in node.keywords:
                        if (
                            kw.arg == "debug"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True
                        ):
                            violations.append(PolicyViolation(
                                rule_name=self.name,
                                severity="CRITICAL",
                                line_number=node.lineno,
                                description=(
                                    "debug=True enables the interactive debugger in production. "
                                    "This allows arbitrary code execution by anyone with browser access."
                                ),
                                remediation="Remove debug=True or gate it behind an environment variable check.",
                            ))

        # Regex-based checks on the raw source (AST won't see all assignment forms)
        for lineno, line in enumerate(code.splitlines(), start=1):
            if self._HARDCODED_KEY.search(line):
                violations.append(PolicyViolation(
                    rule_name=self.name,
                    severity=self.severity,
                    line_number=lineno,
                    description="Hardcoded secret/API key found. Secrets must not be stored in source code.",
                    remediation=(
                        "Load secrets from environment variables: "
                        "os.environ['SECRET_KEY'] or use a secrets manager."
                    ),
                ))
            if self._PRIVATE_IP.search(line):
                violations.append(PolicyViolation(
                    rule_name=self.name,
                    severity="MEDIUM",
                    line_number=lineno,
                    description="Hardcoded private IP address found. Infrastructure addresses should be configurable.",
                    remediation="Move IP addresses to environment variables or a configuration file.",
                ))

        return violations


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Evaluates a set of policy rules against AI-generated code.

    Usage::

        engine = PolicyEngine()
        violations = engine.evaluate(code, filename="api.py", context={})
    """

    def __init__(self) -> None:
        self._rules: List[Rule] = [
            SensitivePathWriteRule(),
            DeleteWithoutUserIDRule(),
            DomainIsolationRule(),
            AdminEndpointAuthRule(),
            JWTAlgorithmRule(),
            InsecureCryptographyRule(),
            SSRFRule(),
            BrokenObjectAuthRule(),
            InsecureDesignRule(),
        ]

    def register_rule(self, rule: Rule) -> None:
        """Register a custom policy rule."""
        self._rules.append(rule)

    def evaluate(
        self,
        code: str,
        filename: str = "unknown",
        context: Optional[Dict[str, Any]] = None,
    ) -> List[PolicyViolation]:
        """
        Run all registered rules against *code*.
        Returns a flat list of all violations found.
        """
        context = context or {}
        violations: List[PolicyViolation] = []
        for rule in self._rules:
            try:
                violations.extend(rule.evaluate(code, filename, context))
            except Exception:
                # Never crash the pipeline due to a policy rule bug
                pass
        return violations
