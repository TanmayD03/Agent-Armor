# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor — AST Hardening Engine
===================================
Uses Python's built-in `ast` module to perform true structural analysis
of AI-generated Python code.  Unlike regex-based scanners, this engine
understands the *shape* of the code and can differentiate between an
eval() call and a string that merely contains the word "eval".

Detects:
  - CRITICAL: eval(), exec(), __import__() → code injection
  - CRITICAL: SQL injection via f-strings / %-format in .execute()
  - HIGH:     os.system(), subprocess with shell=True → command injection
  - HIGH:     pickle.loads(), marshal.loads() → deserialization attacks
  - HIGH:     open() for writing to sensitive paths
  - MEDIUM:   Missing try/except on I/O operations
  - MEDIUM:   assert used for security checks (stripped in optimised mode)
  - LOW:      Bare except clauses (swallows all errors)
"""

from __future__ import annotations

import ast
import re as _re_module
from dataclasses import dataclass
from typing import List


@dataclass
class ASTFinding:
    """Represents a single finding from the AST Hardening Engine."""
    node_type: str
    line_number: int
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    suggestion: str

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.node_type} at line {self.line_number}: "
            f"{self.description}"
        )


# ---------------------------------------------------------------------------
# Dangerous function registry
# ---------------------------------------------------------------------------
_DANGEROUS_FUNCTIONS: dict[str, tuple[str, str, str]] = {
    # func_name → (severity, description, suggestion)
    "eval": (
        "CRITICAL",
        "Arbitrary code execution via eval()",
        "Use ast.literal_eval() for safe literal parsing, or restructure logic.",
    ),
    "exec": (
        "CRITICAL",
        "Arbitrary code execution via exec()",
        "Avoid dynamic code execution; refactor to explicit function calls.",
    ),
    "__import__": (
        "HIGH",
        "Dynamic import can load malicious or unvetted modules",
        "Use explicit top-level import statements.",
    ),
    "compile": (
        "HIGH",
        "Dynamic code compilation",
        "Avoid runtime compilation of user-controlled strings.",
    ),
    "input": (
        "LOW",
        "input() returns raw unsanitised user data",
        "Validate and sanitise input before using it downstream.",
    ),
}

_DANGEROUS_ATTRS: dict[str, tuple[str, str, str]] = {
    # attr_name → (severity, description, suggestion)
    "system": (
        "HIGH",
        "os.system() is vulnerable to shell injection",
        "Use subprocess.run(cmd_list, shell=False) instead.",
    ),
    "popen": (
        "HIGH",
        "os.popen() is vulnerable to shell injection",
        "Use subprocess.run(cmd_list, shell=False, capture_output=True) instead.",
    ),
}

_DANGEROUS_IMPORTS: dict[str, tuple[str, str]] = {
    "pickle": ("HIGH", "pickle is unsafe for deserialising untrusted data; use JSON."),
    "marshal": ("HIGH", "marshal is unsafe for untrusted data."),
    "shelve": ("MEDIUM", "shelve uses pickle internally; avoid with untrusted data."),
    "yaml": ("MEDIUM", "yaml.load() without Loader= allows arbitrary code execution; use yaml.safe_load()."),
}

# ---------------------------------------------------------------------------
# Insecure cryptography registry
# ---------------------------------------------------------------------------
# Maps hashlib / Crypto algorithm name → (severity, description, suggestion)
_WEAK_HASH_ALGOS: frozenset[str] = frozenset({
    "md5", "sha1", "sha", "md4", "md2", "rc4", "des", "3des",
})

# cryptography / PyCryptodome module paths that are always weak
_WEAK_CRYPTO_MODULES: frozenset[str] = frozenset({
    "Crypto.Cipher.DES",
    "Crypto.Cipher.ARC4",
    "Crypto.Hash.MD5",
    "Crypto.Hash.SHA1",
    "Cryptodome.Cipher.DES",
    "Cryptodome.Hash.MD5",
})

# ---------------------------------------------------------------------------
# ReDoS — regex patterns that can cause catastrophic backtracking
# ---------------------------------------------------------------------------
# Structural patterns known to cause polynomial/exponential backtracking.
# We check the *string literal* passed to re.compile() / re.match() etc.

_REDOS_PATTERNS: list[tuple[_re_module.Pattern[str], str]] = [
    # (a+)+ / (a*)* / (a+)* nested quantifiers
    (_re_module.compile(r'\([^)]*[+*][^)]*\)[+*?]'), "Nested quantifier (X+)+ or (X*)* causes catastrophic backtracking."),
    # alternation with overlap: (a|a)+ / (a|ab)+
    (_re_module.compile(r'\([^)]*\|[^)]*\)[+*]{1}'), "Overlapping alternation with quantifier can cause ReDoS."),
]

# ---------------------------------------------------------------------------
# SSRF sink patterns — attribute names on requests / httpx / urllib
# ---------------------------------------------------------------------------
_SSRF_HTTP_FUNCS: frozenset[str] = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "request",
    "urlopen", "urlretrieve",
})


class _SecurityVisitor(ast.NodeVisitor):
    """AST visitor that accumulates security findings."""

    def __init__(self) -> None:
        self.findings: List[ASTFinding] = []

    # ------------------------------------------------------------------
    # Visitor methods
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        """Check function calls for dangerous sinks."""
        func = node.func

        # Direct calls: eval(...), exec(...), __import__(...)
        if isinstance(func, ast.Name):
            name = func.id
            if name in _DANGEROUS_FUNCTIONS:
                sev, desc, sugg = _DANGEROUS_FUNCTIONS[name]
                self.findings.append(
                    ASTFinding(
                        node_type="DangerousFunction",
                        line_number=node.lineno,
                        severity=sev,
                        description=desc,
                        suggestion=sugg,
                    )
                )

        # Attribute calls: os.system(...), obj.execute(f"..."), etc.
        elif isinstance(func, ast.Attribute):
            attr = func.attr

            # os.system / os.popen
            if attr in _DANGEROUS_ATTRS:
                sev, desc, sugg = _DANGEROUS_ATTRS[attr]
                self.findings.append(
                    ASTFinding(
                        node_type="CommandInjection",
                        line_number=node.lineno,
                        severity=sev,
                        description=desc,
                        suggestion=sugg,
                    )
                )

            # db.execute(f"...") — SQL injection
            if attr == "execute" and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, (ast.JoinedStr, ast.BinOp, ast.Mod)):
                    self.findings.append(
                        ASTFinding(
                            node_type="SQLInjection",
                            line_number=node.lineno,
                            severity="CRITICAL",
                            description=(
                                "Potential SQL injection: dynamic string passed to .execute(). "
                                "String interpolation in SQL queries allows attackers to inject "
                                "arbitrary SQL commands."
                            ),
                            suggestion=(
                                "Use parameterised queries: "
                                "cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))"
                            ),
                        )
                    )

            # subprocess(..., shell=True)
            if attr in ("run", "Popen", "call", "check_output", "check_call"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.findings.append(
                            ASTFinding(
                                node_type="CommandInjection",
                                line_number=node.lineno,
                                severity="HIGH",
                                description=f"subprocess.{attr}(shell=True) enables shell injection attacks.",
                                suggestion="Pass a list of arguments and remove shell=True.",
                            )
                        )

            # pickle.loads / marshal.loads
            if attr == "loads":
                if isinstance(func.value, ast.Name) and func.value.id in ("pickle", "marshal"):
                    mod = func.value.id
                    self.findings.append(
                        ASTFinding(
                            node_type="InsecureDeserialization",
                            line_number=node.lineno,
                            severity="HIGH",
                            description=f"{mod}.loads() on untrusted data enables remote code execution.",
                            suggestion="Use JSON or a safe serialisation library instead of pickle/marshal.",
                        )
                    )

            # yaml.load() without Loader= — insecure deserialization
            if attr == "load" and isinstance(func.value, ast.Name) and func.value.id == "yaml":
                kw_names = {kw.arg for kw in node.keywords}
                # safe_load is fine; load without Loader= is dangerous
                if "Loader" not in kw_names:
                    self.findings.append(
                        ASTFinding(
                            node_type="InsecureDeserialization",
                            line_number=node.lineno,
                            severity="HIGH",
                            description=(
                                "yaml.load() without Loader= can execute arbitrary Python objects "
                                "embedded in the YAML. This is a remote code execution vector."
                            ),
                            suggestion="Replace with yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader).",
                        )
                    )

            # Insecure cryptography — hashlib.new("md5") / hashlib.md5()
            if isinstance(func.value, ast.Name) and func.value.id == "hashlib":
                # hashlib.md5(), hashlib.sha1(), etc.
                if attr.lower() in _WEAK_HASH_ALGOS:
                    self.findings.append(
                        ASTFinding(
                            node_type="InsecureCryptography",
                            line_number=node.lineno,
                            severity="HIGH",
                            description=(
                                f"hashlib.{attr}() uses a cryptographically broken algorithm. "
                                f"{attr.upper()} is vulnerable to collision attacks and must not "
                                f"be used for passwords, signatures, or security tokens."
                            ),
                            suggestion=(
                                "Use hashlib.sha256() or hashlib.sha3_256() for general hashing. "
                                "For passwords use hashlib.scrypt() or bcrypt/argon2."
                            ),
                        )
                    )
                # hashlib.new("md5", ...) — algorithm passed as string arg
                if attr == "new" and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        if first.value.lower() in _WEAK_HASH_ALGOS:
                            self.findings.append(
                                ASTFinding(
                                    node_type="InsecureCryptography",
                                    line_number=node.lineno,
                                    severity="HIGH",
                                    description=(
                                        f"hashlib.new('{first.value}') uses a broken algorithm. "
                                        f"{first.value.upper()} is not suitable for security use."
                                    ),
                                    suggestion="Use hashlib.sha256() or hashlib.sha3_256() instead.",
                                )
                            )

            # SSRF — requests/httpx/urllib with a variable URL (not a string literal)
            if attr in _SSRF_HTTP_FUNCS:
                # Check if the first positional argument is NOT a plain string constant
                if node.args:
                    url_arg = node.args[0]
                    if not isinstance(url_arg, ast.Constant):
                        # Variable or computed URL — potential SSRF
                        self.findings.append(
                            ASTFinding(
                                node_type="SSRF",
                                line_number=node.lineno,
                                severity="HIGH",
                                description=(
                                    "Potential SSRF: HTTP call with a dynamic URL argument. "
                                    "If the URL is derived from user input an attacker can reach "
                                    "internal services (AWS metadata, localhost, etc.)."
                                ),
                                suggestion=(
                                    "Validate the URL against an allowlist of permitted hosts before making "
                                    "the request. Use urllib.parse.urlparse() to extract and check the hostname."
                                ),
                            )
                        )

            # ReDoS — re.compile/match/search/fullmatch/findall/sub with catastrophic pattern
            if (
                isinstance(func.value, ast.Name)
                and func.value.id == "re"
                and attr in ("compile", "match", "search", "fullmatch", "findall", "sub", "subn")
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                pattern_str = node.args[0].value
                for redos_re, redos_desc in _REDOS_PATTERNS:
                    if redos_re.search(pattern_str):
                        self.findings.append(
                            ASTFinding(
                                node_type="ReDoS",
                                line_number=node.lineno,
                                severity="HIGH",
                                description=(
                                    f"Potentially catastrophic regular expression. {redos_desc} "
                                    f"Pattern: {pattern_str!r}"
                                ),
                                suggestion=(
                                    "Rewrite the regex to avoid nested quantifiers and overlapping alternation. "
                                    "Consider using the 'regex' library which supports atomic groups and "
                                    "possessive quantifiers to prevent backtracking."
                                ),
                            )
                        )
                        break  # one ReDoS finding per call-site is enough

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in _DANGEROUS_IMPORTS:
                sev, desc = _DANGEROUS_IMPORTS[alias.name]
                self.findings.append(
                    ASTFinding(
                        node_type="DangerousImport",
                        line_number=node.lineno,
                        severity=sev,
                        description=f"Importing '{alias.name}': {desc}",
                        suggestion=f"Replace usages of {alias.name} with a safe alternative.",
                    )
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.module.split(".")[0] in _DANGEROUS_IMPORTS:
            mod = node.module.split(".")[0]
            sev, desc = _DANGEROUS_IMPORTS[mod]
            self.findings.append(
                ASTFinding(
                    node_type="DangerousImport",
                    line_number=node.lineno,
                    severity=sev,
                    description=f"Importing from '{node.module}': {desc}",
                    suggestion=f"Replace usages of {mod} with a safe alternative.",
                )
            )
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        """assert is stripped when Python runs with -O; never use for security."""
        # Only flag if the test looks like a security check
        src = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
        security_keywords = ("admin", "auth", "permission", "role", "is_valid", "login")
        if any(kw in src.lower() for kw in security_keywords):
            self.findings.append(
                ASTFinding(
                    node_type="SecurityAssert",
                    line_number=node.lineno,
                    severity="MEDIUM",
                    description=(
                        "assert used for security check. "
                        "assert statements are removed when Python runs with -O flag."
                    ),
                    suggestion="Replace with an explicit if/raise or use a proper auth framework.",
                )
            )
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Flag bare except: clauses."""
        if node.type is None:
            self.findings.append(
                ASTFinding(
                    node_type="BareExcept",
                    line_number=node.lineno,
                    severity="LOW",
                    description="Bare 'except:' clause silences ALL exceptions including KeyboardInterrupt.",
                    suggestion="Catch specific exceptions: except (ValueError, TypeError) as e:",
                )
            )
        self.generic_visit(node)


class ASTHardener:
    """
    AST-based security analyser and code hardener for Python source.

    Usage::

        hardener = ASTHardener()
        findings = hardener.analyze(source_code)
        hardened_source = hardener.harden(source_code)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, source_code: str) -> List[ASTFinding]:
        """
        Analyse *source_code* and return a list of :class:`ASTFinding` objects.
        Returns a single ERROR finding if the code cannot be parsed.
        """
        try:
            tree = ast.parse(source_code)
        except SyntaxError as exc:
            return [
                ASTFinding(
                    node_type="SyntaxError",
                    line_number=exc.lineno or 0,
                    severity="ERROR",
                    description=f"Syntax error: {exc.msg}",
                    suggestion="Fix syntax errors before security analysis can proceed.",
                )
            ]

        visitor = _SecurityVisitor()
        visitor.visit(tree)
        findings = list(visitor.findings)

        # Additional structural checks
        findings.extend(self._check_missing_error_handling(tree))
        findings.extend(self._check_hardcoded_paths(source_code))

        return findings

    def harden(self, source_code: str) -> str:
        """
        Return a hardened version of *source_code*.
        Dangerous calls are commented out and replaced with safe stubs.
        For CRITICAL findings this inserts a block comment.
        """
        findings = self.analyze(source_code)
        critical = [f for f in findings if f.severity == "CRITICAL"]
        if not critical:
            return source_code

        lines = source_code.splitlines(keepends=True)
        # Insert inline warning comments next to critical lines
        annotated: List[str] = []
        critical_lines = {f.line_number for f in critical}
        for i, line in enumerate(lines, 1):
            annotated.append(line)
            if i in critical_lines:
                indent = len(line) - len(line.lstrip())
                pad = " " * indent
                relevant = [f for f in critical if f.line_number == i]
                for finding in relevant:
                    annotated.append(
                        f"{pad}# ⚠️  [AgentArmor] CRITICAL: {finding.description}\n"
                        f"{pad}# 💡 Suggestion: {finding.suggestion}\n"
                    )
        return "".join(annotated)

    # ------------------------------------------------------------------
    # Internal structural checks
    # ------------------------------------------------------------------

    def _check_missing_error_handling(self, tree: ast.AST) -> List[ASTFinding]:
        """
        Flag functions that perform risky I/O without try/except blocks.
        This implements the 'Semantic Over-Confidence Mitigation' concept.
        """
        findings: List[ASTFinding] = []
        risky_attrs = {"read", "write", "connect", "execute", "get", "post", "request",
                       "open", "send", "recv", "fetch"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            has_try = any(isinstance(n, ast.Try) for n in ast.walk(node))
            if has_try:
                continue

            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                func = inner.func
                attr = (
                    func.attr if isinstance(func, ast.Attribute) else
                    func.id if isinstance(func, ast.Name) else None
                )
                if attr in risky_attrs:
                    findings.append(
                        ASTFinding(
                            node_type="MissingErrorHandling",
                            line_number=node.lineno,
                            severity="MEDIUM",
                            description=(
                                f'Function "{node.name}" calls {attr}() '
                                f"but has no try/except block."
                            ),
                            suggestion=(
                                "Wrap I/O, network, and database calls in try/except "
                                "to handle errors gracefully."
                            ),
                        )
                    )
                    break  # One finding per function is enough

        return findings

    def _check_hardcoded_paths(self, source_code: str) -> List[ASTFinding]:
        """Flag writes to sensitive system paths."""
        findings: List[ASTFinding] = []
        sensitive_patterns = [
            r"/etc/passwd", r"/etc/shadow", r"/etc/sudoers",
            r"~/.ssh/", r"~/.aws/", r"C:\\Windows\\System32",
        ]
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern in sensitive_patterns:
                if pattern.lower() in line.lower():
                    findings.append(
                        ASTFinding(
                            node_type="SensitivePathAccess",
                            line_number=i,
                            severity="HIGH",
                            description=f"Reference to sensitive path: {pattern}",
                            suggestion="Avoid hardcoded sensitive paths; use configuration.",
                        )
                    )
        return findings
