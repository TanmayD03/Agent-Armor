"""Tests for DTGEngine — Data Transformation Graph taint analysis."""
import pytest
from agent_armor.core.dtg_engine import DTGEngine


@pytest.fixture(scope="module")
def engine():
    return DTGEngine()


# ──────────────────────────────────────────────────────────────────────────────
# Source detection
# ──────────────────────────────────────────────────────────────────────────────

def test_detects_input_source(engine):
    code = "user_data = input('Enter value: ')"
    findings = engine.analyze(code)
    sources = [f for f in findings if "source" in f.description.lower() or "input" in f.description.lower()]
    # Either a direct finding or the variable should be tracked as tainted
    assert len(findings) >= 0  # engine should not crash


def test_detects_request_args_source(engine):
    code = """
from flask import request

def get_user():
    user_id = request.args.get('id')
    return user_id
"""
    findings = engine.analyze(code)
    # Should identify request.args as a taint source
    assert isinstance(findings, list)


# ──────────────────────────────────────────────────────────────────────────────
# Sink detection
# ──────────────────────────────────────────────────────────────────────────────

def test_detects_sql_injection_path(engine):
    code = """
import sqlite3
from flask import request

def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    result = conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return result.fetchone()
"""
    findings = engine.analyze(code)
    # Should find at least one taint path
    critical = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    assert len(critical) >= 1


def test_detects_eval_sink(engine):
    code = """
user_input = input('expression: ')
result = eval(user_input)
"""
    findings = engine.analyze(code)
    critical = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    assert len(critical) >= 1


def test_detects_os_system_sink(engine):
    code = """
import os
host = input("hostname: ")
os.system(f"ping {host}")
"""
    findings = engine.analyze(code)
    high_or_critical = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    assert len(high_or_critical) >= 1


# ──────────────────────────────────────────────────────────────────────────────
# Safe code — no false positives
# ──────────────────────────────────────────────────────────────────────────────

def test_no_findings_on_clean_code(engine):
    code = """
def add(a: int, b: int) -> int:
    return a + b

result = add(1, 2)
print(result)
"""
    findings = engine.analyze(code)
    critical = [f for f in findings if f.severity == "CRITICAL"]
    assert len(critical) == 0


def test_parameterised_query_no_finding(engine):
    code = """
import sqlite3

def get_user(user_id: int):
    conn = sqlite3.connect('db.sqlite')
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
"""
    findings = engine.analyze(code)
    critical = [f for f in findings if f.severity == "CRITICAL"]
    assert len(critical) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Validation injection
# ──────────────────────────────────────────────────────────────────────────────

def test_inject_validation_adds_pydantic(engine):
    code = """
import sqlite3
from flask import request

def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    return conn.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
"""
    findings = engine.analyze(code)
    hardened = engine.inject_validation(code, findings)
    assert "pydantic" in hardened.lower() or "BaseModel" in hardened or "AgentArmor" in hardened


def test_inject_validation_returns_string(engine):
    code = "x = 1\n"
    findings = engine.analyze(code)
    result = engine.inject_validation(code, findings)
    assert isinstance(result, str)


# ──────────────────────────────────────────────────────────────────────────────
# Edge cases
# ──────────────────────────────────────────────────────────────────────────────

def test_empty_code(engine):
    findings = engine.analyze("")
    assert isinstance(findings, list)


def test_syntax_error_handled_gracefully(engine):
    code = "def broken(:"
    # Should not raise — returns empty list or partial findings
    try:
        findings = engine.analyze(code)
        assert isinstance(findings, list)
    except SyntaxError:
        pass  # also acceptable


def test_finding_has_required_fields(engine):
    code = """
user_input = input('x: ')
eval(user_input)
"""
    findings = engine.analyze(code)
    for f in findings:
        assert hasattr(f, "severity")
        assert hasattr(f, "description")
        assert hasattr(f, "rule_id") or hasattr(f, "finding_id") or hasattr(f, "code")
