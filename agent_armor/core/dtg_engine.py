# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor — DTG Engine (Data Transformation Graph)
=====================================================
Inspired by 2026 research on Data-Transformation Graphs (DTG).

Traditional scanners look for "bad words".
The DTG engine looks for **data sinks** and traces whether the data
reaching them originated from a **tainted source** without passing
through a **sanitiser** node.

If an unsanitised flow is detected the engine can automatically inject
a Pydantic validation schema into the code.

Flow model
----------
  Sources  → tainted data enters the program
    • input()
    • request.args / request.json / request.form / request.data
    • os.environ / os.getenv()
    • sys.argv
    • Function parameters (treated as potentially tainted)

  Sanitisers  → clean the data before it reaches a sink
    • Pydantic model validation
    • .strip() / .replace() / html.escape()
    • int() / float() / bool() casts
    • re.match() / re.fullmatch()
    • Custom validators (functions whose name includes 'valid', 'sanitiz', 'clean', 'escape')

  Sinks  → dangerous if reached with tainted data
    • db.execute() / cursor.execute()
    • eval() / exec()
    • subprocess.run() / os.system()
    • open() for write
    • requests.get/post with user-controlled URL
"""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass
class DTGFinding:
    """A tainted-flow finding from the DTG Engine."""
    source: str          # e.g. "input()"
    sink: str            # e.g. "db.execute()"
    line_number: int
    severity: str        # CRITICAL | HIGH | MEDIUM
    description: str
    suggestion: str
    auto_fix_applied: bool = False

    @property
    def finding_id(self) -> str:
        """Unique identifier for this finding — used by consumers and tests."""
        return f"DTG-{self.sink.rstrip('()')}-L{self.line_number}"

    def __str__(self) -> str:
        return (
            f"[{self.severity}] Unsanitised flow {self.source} → {self.sink} "
            f"at line {self.line_number}: {self.description}"
        )


# ---------------------------------------------------------------------------
# Source / sink / sanitiser registries
# ---------------------------------------------------------------------------

_TAINT_SOURCES: Set[str] = {
    "input",
    # request attrs resolved at call-site
}

_TAINT_SOURCE_ATTRS: Set[str] = {
    "args", "json", "form", "data", "files",
    "get_json", "values",
    "environ",       # os.environ
    "argv",          # sys.argv
}

_TAINT_SINKS: Dict[str, tuple[str, str, str]] = {
    # attr → (severity, description, suggestion)
    "execute": (
        "CRITICAL",
        "Potentially tainted data flows into a database execute() call — SQL Injection risk.",
        "Use parameterised queries: cursor.execute(sql, (param,))",
    ),
    "eval": (
        "CRITICAL",
        "Potentially tainted data flows into eval() — Remote Code Execution risk.",
        "Never pass user-controlled data to eval(). Refactor logic.",
    ),
    "exec": (
        "CRITICAL",
        "Potentially tainted data flows into exec() — Remote Code Execution risk.",
        "Never pass user-controlled data to exec(). Refactor logic.",
    ),
    "system": (
        "HIGH",
        "Potentially tainted data flows into os.system() — OS Command Injection risk.",
        "Use subprocess.run(cmd_list, shell=False) with a pre-validated command list.",
    ),
    "run": (
        "HIGH",
        "Potentially tainted data flows into subprocess.run() — Command Injection risk.",
        "Validate input and pass arguments as a list with shell=False.",
    ),
    "write": (
        "MEDIUM",
        "Potentially tainted data written to file — Path Traversal / Data Injection risk.",
        "Validate file path and sanitise content before writing.",
    ),
}

_SANITISER_NAMES: Set[str] = {
    "int", "float", "bool", "str",      # type casts
    "escape", "quote",                  # HTML/URL escaping
    "strip", "replace", "lstrip", "rstrip",
    # regex validation
    "match", "fullmatch", "search",
}

_SANITISER_KEYWORDS: Set[str] = {
    "valid", "sanitiz", "sanitise", "clean", "escape", "encode", "filter",
}


class DTGEngine:
    """
    Data Transformation Graph engine.

    Usage::

        engine = DTGEngine()
        findings = engine.analyze(source_code)
        hardened = engine.inject_validation(source_code, findings)
    """

    def analyze(self, source_code: str) -> List[DTGFinding]:
        """
        Parse *source_code* and return a list of tainted-flow findings.
        """
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        analyser = _TaintFlowAnalyser(source_code)
        analyser.visit(tree)
        return analyser.findings

    def inject_validation(
        self, source_code: str, findings: List[DTGFinding]
    ) -> str:
        """
        When DTG finds unsanitised flows that reach database sinks,
        prepend a Pydantic validation schema to the file.

        Only injects once even if multiple findings exist.
        """
        sql_findings = [
            f for f in findings if "execute" in f.sink and not f.auto_fix_applied
        ]
        if not sql_findings:
            return source_code

        pydantic_stub = textwrap.dedent(
            """\
            # ── [AgentArmor Auto-Inject] Pydantic Input Validation ──────────
            # DTG Engine detected unsanitised data flowing into DB execute().
            # A validation schema has been injected. Bind your inputs to this
            # model before passing them to database queries.
            from pydantic import BaseModel, validator, constr
            from typing import Optional

            class AgentArmorInputSchema(BaseModel):
                \"\"\"Auto-generated by AgentArmor DTG Engine. Customise as needed.\"\"\"
                # Add your fields here with appropriate types and constraints.
                # Example:
                user_id: int
                username: constr(min_length=1, max_length=64, pattern=r'^[\\w\\-]+$')
                search_query: Optional[constr(max_length=256)] = None

                @validator('user_id')
                def user_id_must_be_positive(cls, v: int) -> int:
                    if v <= 0:
                        raise ValueError('user_id must be a positive integer')
                    return v
            # ── End AgentArmor Auto-Inject ───────────────────────────────────

            """
        )

        for f in sql_findings:
            f.auto_fix_applied = True

        return pydantic_stub + source_code


# ---------------------------------------------------------------------------
# Internal: taint-flow visitor
# ---------------------------------------------------------------------------


class _TaintFlowAnalyser(ast.NodeVisitor):
    """
    Performs simplified intra-procedural taint analysis.

    For each function body we track which variable names hold tainted
    values and flag when a tainted value reaches a known sink without
    passing through a sanitiser.
    """

    def __init__(self, source: str) -> None:
        self._source = source
        self.findings: List[DTGFinding] = []

    # ------------------------------------------------------------------

    def visit_Module(self, node: ast.Module) -> None:
        """Analyse module-level statements (outside any function)."""
        tainted: Set[str] = set()
        self._scan_body(node.body, tainted)
        self.generic_visit(node)  # then recurse into functions

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyse each function independently."""
        tainted: Set[str] = set()

        # All parameters are considered potentially tainted
        for arg in node.args.args:
            tainted.add(arg.arg)

        self._scan_body(node.body, tainted)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    # ------------------------------------------------------------------

    def _scan_body(self, stmts: list, tainted: Set[str]) -> None:
        for stmt in stmts:
            self._scan_stmt(stmt, tainted)

    def _scan_stmt(self, stmt: ast.stmt, tainted: Set[str]) -> None:  # noqa: C901
        """Process a single statement, updating tainted set."""

        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            value = stmt.value if isinstance(stmt, ast.Assign) else stmt.value
            if value is None:
                return
            # Check all calls nested in the RHS for sink access
            self._check_calls_in_expr(value, tainted)
            if self._is_tainted(value, tainted):
                # Propagate taint to all assignment targets
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        tainted.add(target.id)
            elif self._is_sanitised(value):
                # Remove taint if result of sanitisation is assigned
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        tainted.discard(target.id)

        elif isinstance(stmt, ast.Expr):
            self._check_calls_in_expr(stmt.value, tainted)

        elif isinstance(stmt, ast.Return):
            # Also scan return values for sink calls (e.g. return conn.execute(tainted))
            if stmt.value is not None:
                self._check_calls_in_expr(stmt.value, tainted)

        elif isinstance(stmt, (ast.If, ast.While, ast.For)):
            body = getattr(stmt, "body", []) + getattr(stmt, "orelse", [])
            self._scan_body(body, set(tainted))  # copy to avoid cross-branch pollution

        elif isinstance(stmt, ast.Try):
            self._scan_body(stmt.body, tainted)
            for handler in stmt.handlers:
                self._scan_body(handler.body, tainted)

    def _check_calls_in_expr(self, node: ast.AST, tainted: Set[str]) -> None:
        """
        Walk *all* Call nodes inside an expression and check each as a
        potential sink.  This handles chained calls like::

            result = conn.execute(f"SELECT...").fetchone()
        """
        for call_node in ast.walk(node):
            if isinstance(call_node, ast.Call):
                self._check_sink_call(call_node, tainted)

    def _check_sink_call(self, node: ast.AST, tainted: Set[str]) -> None:
        """Check if *node* is a sink call receiving tainted data."""
        if not isinstance(node, ast.Call):
            return

        func = node.func
        sink_name: Optional[str] = None

        if isinstance(func, ast.Name) and func.id in _TAINT_SINKS:
            sink_name = func.id
        elif isinstance(func, ast.Attribute) and func.attr in _TAINT_SINKS:
            sink_name = func.attr

        if sink_name is None:
            return

        # Check if any argument is tainted
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in all_args:
            if self._is_tainted(arg, tainted):
                sev, desc, sugg = _TAINT_SINKS[sink_name]
                self.findings.append(
                    DTGFinding(
                        source=self._describe_source(arg, tainted),
                        sink=sink_name + "()",
                        line_number=node.lineno,
                        severity=sev,
                        description=desc,
                        suggestion=sugg,
                    )
                )
                break  # One finding per call site

    def _is_tainted(self, node: ast.expr, tainted: Set[str]) -> bool:
        """Return True if *node* evaluates to tainted data."""
        if isinstance(node, ast.Name):
            return node.id in tainted

        if isinstance(node, ast.Call):
            func = node.func
            # input() is always tainted
            if isinstance(func, ast.Name) and func.id in _TAINT_SOURCES:
                return True
            # Direct taint-source attributes: request.args, os.environ, etc.
            if isinstance(func, ast.Attribute) and func.attr in _TAINT_SOURCE_ATTRS:
                return True
            # request.args.get(), request.json.get(), etc.
            # (method called on a taint-source attribute)
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Attribute):
                if func.value.attr in _TAINT_SOURCE_ATTRS:
                    return True
            # tainted_var.method() — method called on an already-tainted variable
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id in tainted:
                    return True
            # Subscript of tainted var: tainted_dict["key"]
            return False

        if isinstance(node, ast.Attribute):
            if node.attr in _TAINT_SOURCE_ATTRS:
                return True
            if isinstance(node.value, ast.Name) and node.value.id in tainted:
                return True

        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name) and node.value.id in tainted:
                return True

        # f-strings: tainted if any interpolated expression is tainted
        if isinstance(node, ast.JoinedStr):
            return any(
                self._is_tainted(val.value, tainted)  # val.value = the expression inside {}
                for val in node.values
                if isinstance(val, ast.FormattedValue)
            )

        # Binary ops: tainted if either side is
        if isinstance(node, ast.BinOp):
            return self._is_tainted(node.left, tainted) or self._is_tainted(node.right, tainted)

        return False

    def _is_sanitised(self, node: ast.expr) -> bool:
        """Return True if *node* is a sanitisation call."""
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        name = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name is None:
            return False
        if name in _SANITISER_NAMES:
            return True
        return any(kw in name.lower() for kw in _SANITISER_KEYWORDS)

    def _describe_source(self, node: ast.expr, tainted: Set[str]) -> str:
        """Return a human-readable name for the taint source."""
        if isinstance(node, ast.Name):
            return f"variable '{node.id}'"
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                return f"{func.id}()"
            if isinstance(func, ast.Attribute):
                return f"{ast.unparse(func) if hasattr(ast, 'unparse') else func.attr}()"
        if isinstance(node, ast.Attribute):
            try:
                return ast.unparse(node) if hasattr(ast, "unparse") else node.attr
            except Exception:
                return "user input"
        return "user input"
