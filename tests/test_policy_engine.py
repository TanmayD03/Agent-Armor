"""Tests for PolicyEngine — semantic rule-based enforcement."""
import pytest
from agent_armor.core.policy_engine import PolicyEngine


@pytest.fixture(scope="module")
def engine():
    return PolicyEngine()


# ──────────────────────────────────────────────────────────────────────────────
# RULE-001 — Sensitive path writes
# ──────────────────────────────────────────────────────────────────────────────

def test_rule001_detects_etc_write(engine):
    code = """
with open('/etc/passwd', 'w') as f:
    f.write('hacked')
"""
    violations = engine.evaluate(code, "test.py")
    rule1 = [v for v in violations if "001" in v.rule_id]
    assert len(rule1) >= 1


def test_rule001_allows_safe_path_write(engine):
    code = """
with open('output.txt', 'w') as f:
    f.write('hello')
"""
    violations = engine.evaluate(code, "test.py")
    rule1 = [v for v in violations if "001" in v.rule_id]
    assert len(rule1) == 0


# ──────────────────────────────────────────────────────────────────────────────
# RULE-002 — Delete without user_id (Mitsubishi RFV Concept)
# ──────────────────────────────────────────────────────────────────────────────

def test_rule002_detects_delete_without_user_id(engine):
    code = """
import sqlite3

def delete_user(user_id_param):
    conn = sqlite3.connect('db.sqlite')
    conn.execute("DELETE FROM users")
    conn.commit()
"""
    violations = engine.evaluate(code, "test.py")
    rule2 = [v for v in violations if "002" in v.rule_id]
    assert len(rule2) >= 1


def test_rule002_no_violation_when_scoped(engine):
    code = """
import sqlite3

def delete_user(user_id: int):
    conn = sqlite3.connect('db.sqlite')
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
"""
    violations = engine.evaluate(code, "test.py")
    rule2 = [v for v in violations if "002" in v.rule_id]
    assert len(rule2) == 0


# ──────────────────────────────────────────────────────────────────────────────
# RULE-004 — Admin routes without auth
# ──────────────────────────────────────────────────────────────────────────────

def test_rule004_detects_unprotected_admin_route(engine):
    code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/nuke', methods=['POST'])
def nuke():
    pass
"""
    violations = engine.evaluate(code, "app.py")
    rule4 = [v for v in violations if "004" in v.rule_id]
    assert len(rule4) >= 1


def test_rule004_no_violation_on_public_route(engine):
    code = """
from flask import Flask
app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    return 'ok'
"""
    violations = engine.evaluate(code, "app.py")
    rule4 = [v for v in violations if "004" in v.rule_id]
    assert len(rule4) == 0


# ──────────────────────────────────────────────────────────────────────────────
# RULE-005 — JWT without algorithms=
# ──────────────────────────────────────────────────────────────────────────────

def test_rule005_detects_jwt_without_algorithms(engine):
    code = """
import jwt

def decode(token):
    return jwt.decode(token, 'secret')
"""
    violations = engine.evaluate(code, "auth.py")
    rule5 = [v for v in violations if "005" in v.rule_id]
    assert len(rule5) >= 1


def test_rule005_no_violation_with_algorithms(engine):
    code = """
import jwt

def decode(token, secret):
    return jwt.decode(token, secret, algorithms=['HS256'])
"""
    violations = engine.evaluate(code, "auth.py")
    rule5 = [v for v in violations if "005" in v.rule_id]
    assert len(rule5) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Clean code — zero violations
# ──────────────────────────────────────────────────────────────────────────────

def test_clean_code_no_violations(engine):
    code = """
def add(a: int, b: int) -> int:
    return a + b
"""
    violations = engine.evaluate(code, "math_utils.py")
    assert len(violations) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Violation structure
# ──────────────────────────────────────────────────────────────────────────────

def test_violation_has_required_fields(engine):
    code = """
with open('/etc/shadow', 'w') as f:
    f.write('x')
"""
    violations = engine.evaluate(code, "test.py")
    assert len(violations) >= 1
    v = violations[0]
    assert hasattr(v, "rule_id")
    assert hasattr(v, "severity")
    assert hasattr(v, "description")


# ──────────────────────────────────────────────────────────────────────────────
# Edge cases
# ──────────────────────────────────────────────────────────────────────────────

def test_empty_code(engine):
    violations = engine.evaluate("", "empty.py")
    assert isinstance(violations, list)


def test_non_python_filename(engine):
    violations = engine.evaluate("x = 1", "script.js")
    assert isinstance(violations, list)


# ──────────────────────────────────────────────────────────────────────────────
# RULE-007 — Insecure Cryptography
# ──────────────────────────────────────────────────────────────────────────────

def test_rule007_detects_hashlib_md5(engine):
    code = "import hashlib\nh = hashlib.md5(data)\n"
    violations = engine.evaluate(code, "test.py")
    rule7 = [v for v in violations if "007" in v.rule_id]
    assert len(rule7) >= 1


def test_rule007_detects_hashlib_sha1(engine):
    code = "import hashlib\nh = hashlib.sha1(data)\n"
    violations = engine.evaluate(code, "test.py")
    rule7 = [v for v in violations if "007" in v.rule_id]
    assert len(rule7) >= 1


def test_rule007_detects_hashlib_new_md5(engine):
    code = "import hashlib\nh = hashlib.new('md5', data)\n"
    violations = engine.evaluate(code, "test.py")
    rule7 = [v for v in violations if "007" in v.rule_id]
    assert len(rule7) >= 1


def test_rule007_sha256_not_flagged(engine):
    code = "import hashlib\nh = hashlib.sha256(data)\n"
    violations = engine.evaluate(code, "test.py")
    rule7 = [v for v in violations if "007" in v.rule_id]
    assert len(rule7) == 0


def test_rule007_detects_weak_crypto_import(engine):
    code = "from Crypto.Cipher import DES\n"
    violations = engine.evaluate(code, "test.py")
    rule7 = [v for v in violations if "007" in v.rule_id]
    assert len(rule7) >= 1


def test_rule007_severity_is_high(engine):
    code = "import hashlib\nh = hashlib.md5(data)\n"
    violations = engine.evaluate(code, "test.py")
    rule7 = [v for v in violations if "007" in v.rule_id]
    assert all(v.severity == "HIGH" for v in rule7)


# ──────────────────────────────────────────────────────────────────────────────
# RULE-008 — SSRF
# ──────────────────────────────────────────────────────────────────────────────

def test_rule008_detects_requests_get_variable_url(engine):
    code = "import requests\nresponse = requests.get(user_url)\n"
    violations = engine.evaluate(code, "test.py")
    rule8 = [v for v in violations if "008" in v.rule_id]
    assert len(rule8) >= 1


def test_rule008_detects_requests_post_variable_url(engine):
    code = "import requests\nresponse = requests.post(url, json=body)\n"
    violations = engine.evaluate(code, "test.py")
    rule8 = [v for v in violations if "008" in v.rule_id]
    assert len(rule8) >= 1


def test_rule008_literal_url_not_flagged(engine):
    code = 'import requests\nresponse = requests.get("https://api.example.com")\n'
    violations = engine.evaluate(code, "test.py")
    rule8 = [v for v in violations if "008" in v.rule_id]
    assert len(rule8) == 0


def test_rule008_severity_is_high(engine):
    code = "import requests\nr = requests.get(url)\n"
    violations = engine.evaluate(code, "test.py")
    rule8 = [v for v in violations if "008" in v.rule_id]
    assert all(v.severity == "HIGH" for v in rule8)


# ──────────────────────────────────────────────────────────────────────────────
# RULE-009 — Broken Object-Level Authorization (BOLA/IDOR)
# ──────────────────────────────────────────────────────────────────────────────

def test_rule009_detects_id_only_query(engine):
    code = 'db.execute("SELECT * FROM orders WHERE id = ?", (order_id,))\n'
    violations = engine.evaluate(code, "test.py")
    rule9 = [v for v in violations if "009" in v.rule_id]
    assert len(rule9) >= 1


def test_rule009_query_with_user_id_not_flagged(engine):
    code = 'db.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, user_id))\n'
    violations = engine.evaluate(code, "test.py")
    rule9 = [v for v in violations if "009" in v.rule_id]
    assert len(rule9) == 0


def test_rule009_query_with_owner_id_not_flagged(engine):
    code = 'db.execute("SELECT * FROM docs WHERE id = ? AND owner_id = ?", (doc_id, uid))\n'
    violations = engine.evaluate(code, "test.py")
    rule9 = [v for v in violations if "009" in v.rule_id]
    assert len(rule9) == 0


def test_rule009_severity_is_high(engine):
    code = 'db.execute("SELECT * FROM items WHERE id = ?", (item_id,))\n'
    violations = engine.evaluate(code, "test.py")
    rule9 = [v for v in violations if "009" in v.rule_id]
    assert all(v.severity == "HIGH" for v in rule9)


# ──────────────────────────────────────────────────────────────────────────────
# RULE-010 — Insecure Design
# ──────────────────────────────────────────────────────────────────────────────

def test_rule010_detects_debug_true(engine):
    code = "app.run(debug=True)\n"
    violations = engine.evaluate(code, "test.py")
    rule10 = [v for v in violations if "010" in v.rule_id]
    assert len(rule10) >= 1


def test_rule010_debug_true_severity_is_critical(engine):
    code = "app.run(debug=True)\n"
    violations = engine.evaluate(code, "test.py")
    rule10 = [v for v in violations if "010" in v.rule_id]
    assert any(v.severity == "CRITICAL" for v in rule10)


def test_rule010_debug_false_not_flagged(engine):
    code = "app.run(debug=False)\n"
    violations = engine.evaluate(code, "test.py")
    rule10 = [v for v in violations if "010" in v.rule_id]
    assert len(rule10) == 0


def test_rule010_detects_hardcoded_secret_key(engine):
    code = 'app.secret_key = "my-super-secret"\n'
    violations = engine.evaluate(code, "test.py")
    rule10 = [v for v in violations if "010" in v.rule_id]
    assert len(rule10) >= 1


def test_rule010_env_var_secret_not_flagged(engine):
    code = "import os\napp.secret_key = os.environ['SECRET_KEY']\n"
    violations = engine.evaluate(code, "test.py")
    rule10 = [v for v in violations if "010" in v.rule_id]
    assert len(rule10) == 0


def test_rule010_detects_hardcoded_private_ip(engine):
    code = 'DB_HOST = "192.168.1.100"\n'
    violations = engine.evaluate(code, "test.py")
    rule10 = [v for v in violations if "010" in v.rule_id]
    assert len(rule10) >= 1
