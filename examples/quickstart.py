#!/usr/bin/env python3
# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor — Quickstart Examples
=================================
Self-contained runnable examples for every detection category.
Each example shows:
  - A snippet of vulnerable AI-generated code
  - What AgentArmor detects and why
  - The hardened alternative

Usage:
  python examples/quickstart.py
  python examples/quickstart.py --section ssrf
  python examples/quickstart.py --section crypto
  python examples/quickstart.py --section redos
  python examples/quickstart.py --section deserialization
  python examples/quickstart.py --section bola
  python examples/quickstart.py --section design
  python examples/quickstart.py --section pipeline   # full pipeline demo

Sections: sql, eval, secret, command, crypto, ssrf,
          deserialization, redos, bola, design, pipeline
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_armor.core.ast_hardener import ASTHardener
from agent_armor.core.policy_engine import PolicyEngine
from agent_armor.pipeline import AgentArmor

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False

console = Console(highlight=False) if _RICH else None


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _h(text: str) -> None:
    if console:
        console.print(text)
    else:
        print(text)


def _code(src: str, lang: str = "python") -> None:
    if console:
        console.print(Syntax(src.strip(), lang, theme="monokai", line_numbers=True))
    else:
        print(src)


def _rule(title: str) -> None:
    if console:
        console.rule(f"[bold cyan]{title}[/bold cyan]")
    else:
        print(f"\n{'=' * 60}\n  {title}\n{'=' * 60}")


def _findings_table(findings: list, label: str) -> None:
    if not findings:
        _h(f"  [green]✅  No {label} findings (clean code)[/green]")
        return
    if console:
        t = Table("Type", "Severity", "Line", "Description",
                  box=box.SIMPLE, show_header=True, header_style="bold")
        for f in findings:
            sev = getattr(f, "severity", "?")
            colour = {"CRITICAL": "bold red", "HIGH": "red",
                      "MEDIUM": "yellow", "LOW": "dim"}.get(sev, "white")
            t.add_row(
                getattr(f, "node_type", getattr(f, "rule_name", "?")),
                f"[{colour}]{sev}[/{colour}]",
                str(getattr(f, "line_number", "?")),
                str(f)[:90],
            )
        console.print(t)
    else:
        for f in findings:
            print(f"  [{getattr(f,'severity','?')}] {f}")


# ─────────────────────────────────────────────────────────────────────────────
# Section 1 — SQL Injection
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_SQL = """\
import sqlite3
from flask import request

def get_user(username):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchone()
"""

HARDENED_SQL = """\
import sqlite3

def get_user(username: str):
    conn = sqlite3.connect("users.db")
    # Parameterised query — safe from injection
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
"""

def demo_sql():
    _rule("SQL Injection (CRITICAL)")
    _h("\n[bold red]❌ Vulnerable — AI-generated code:[/bold red]")
    _code(VULNERABLE_SQL)
    h = ASTHardener()
    findings = [f for f in h.analyze(VULNERABLE_SQL) if f.node_type == "SQLInjection"]
    _h("\n[bold]AgentArmor detects:[/bold]")
    _findings_table(findings, "SQL injection")
    _h("\n[bold green]✅ Hardened alternative:[/bold green]")
    _code(HARDENED_SQL)
    _h("")


# ─────────────────────────────────────────────────────────────────────────────
# Section 2 — eval() Code Injection
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_EVAL = """\
from flask import request

def run_formula(expr: str):
    # AI-generated: allows arbitrary Python execution
    return eval(expr)
"""

HARDENED_EVAL = """\
import ast
import operator

_SAFE_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub,
    ast.Mult: operator.mul, ast.Div: operator.truediv,
}

def run_formula(expr: str) -> float:
    \"\"\"Safe arithmetic evaluator — no code execution.\"\"\"
    tree = ast.parse(expr, mode="eval")
    return _eval_node(tree.body)

def _eval_node(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_OPS:
        return _SAFE_OPS[type(node.op)](_eval_node(node.left), _eval_node(node.right))
    raise ValueError(f"Unsafe expression: {ast.dump(node)}")
"""

def demo_eval():
    _rule("eval() Code Injection (CRITICAL)")
    _h("\n[bold red]❌ Vulnerable:[/bold red]")
    _code(VULNERABLE_EVAL)
    h = ASTHardener()
    findings = [f for f in h.analyze(VULNERABLE_EVAL) if f.node_type == "DangerousFunction"]
    _h("\n[bold]AgentArmor detects:[/bold]")
    _findings_table(findings, "eval")
    _h("\n[bold green]✅ Hardened alternative:[/bold green]")
    _code(HARDENED_EVAL)
    _h("")


# ─────────────────────────────────────────────────────────────────────────────
# Section 3 — Hardcoded Secrets
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_SECRET = """\
# AI-generated config — secrets baked in
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
OPENAI_API_KEY        = "sk-proj-abc123def456ghi789jkl012"
DATABASE_URL          = "postgresql://admin:password123@prod-db.internal/app"
"""

HARDENED_SECRET = """\
import os

# Load from environment — never commit secrets to source
AWS_ACCESS_KEY_ID     = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
OPENAI_API_KEY        = os.environ["OPENAI_API_KEY"]
DATABASE_URL          = os.environ["DATABASE_URL"]
"""

def demo_secret():
    _rule("Hardcoded Secrets (HIGH)")
    _h("\n[bold red]❌ Vulnerable:[/bold red]")
    _code(VULNERABLE_SECRET)
    from agent_armor.core.secret_scrubber import SecretScrubber
    scrubber = SecretScrubber()
    findings = scrubber.scan(VULNERABLE_SECRET)
    _h(f"\n[bold]AgentArmor Secret Scrubber detects {len(findings)} secret(s):[/bold]")
    _findings_table(findings, "secrets")
    _h("\n[bold green]✅ Hardened alternative:[/bold green]")
    _code(HARDENED_SECRET)
    _h("")


# ─────────────────────────────────────────────────────────────────────────────
# Section 4 — Command Injection
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_CMD = """\
import os

def ping_host(host: str) -> str:
    # AI-generated: shell injection via os.system
    os.system(f"ping -c 1 {host}")
"""

HARDENED_CMD = """\
import subprocess
import shlex

def ping_host(host: str) -> str:
    # subprocess list form — no shell interpretation
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True, text=True, timeout=10, shell=False
    )
    return result.stdout
"""

def demo_command():
    _rule("Command Injection (HIGH)")
    _h("\n[bold red]❌ Vulnerable:[/bold red]")
    _code(VULNERABLE_CMD)
    h = ASTHardener()
    findings = [f for f in h.analyze(VULNERABLE_CMD) if f.node_type == "CommandInjection"]
    _h("\n[bold]AgentArmor detects:[/bold]")
    _findings_table(findings, "command injection")
    _h("\n[bold green]✅ Hardened alternative:[/bold green]")
    _code(HARDENED_CMD)
    _h("")


# ─────────────────────────────────────────────────────────────────────────────
# Section 5 — Insecure Cryptography  ← NEW
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_CRYPTO = """\
import hashlib

def hash_password(password: str) -> str:
    # AI-generated: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

def hash_file(filepath: str) -> str:
    # SHA-1 is also broken — collision found by Google (SHAttered, 2017)
    h = hashlib.new("sha1")
    with open(filepath, "rb") as f:
        h.update(f.read())
    return h.hexdigest()
"""

HARDENED_CRYPTO = """\
import hashlib
import os
import hmac

def hash_password(password: str) -> str:
    # scrypt is memory-hard and safe for passwords
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return (salt + dk).hex()

def verify_password(password: str, stored: str) -> bool:
    data = bytes.fromhex(stored)
    salt, stored_dk = data[:16], data[16:]
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return hmac.compare_digest(dk, stored_dk)  # constant-time

def hash_file(filepath: str) -> str:
    # SHA-256 is collision-resistant
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
"""

def demo_crypto():
    _rule("Insecure Cryptography — RULE-007 (HIGH)")
    _h("\n[bold red]❌ Vulnerable:[/bold red]")
    _code(VULNERABLE_CRYPTO)
    h = ASTHardener()
    p = PolicyEngine()
    ast_findings = [f for f in h.analyze(VULNERABLE_CRYPTO) if f.node_type == "InsecureCryptography"]
    pol_findings = [v for v in p.evaluate(VULNERABLE_CRYPTO, "auth.py") if "007" in v.rule_id]
    _h("\n[bold]AST Hardener detects:[/bold]")
    _findings_table(ast_findings, "insecure crypto")
    _h("\n[bold]Policy Engine (RULE-007) detects:[/bold]")
    _findings_table(pol_findings, "RULE-007")
    _h("\n[bold green]✅ Hardened alternative:[/bold green]")
    _code(HARDENED_CRYPTO)
    _h("")


# ─────────────────────────────────────────────────────────────────────────────
# Section 6 — SSRF  ← NEW
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_SSRF = """\
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/fetch", methods=["POST"])
def proxy_fetch():
    # AI-generated: attacker can reach http://169.254.169.254 (AWS metadata)
    url = request.json.get("url")
    resp = requests.get(url, timeout=10)
    return jsonify({"body": resp.text})
"""

HARDENED_SSRF = """\
import ipaddress
import socket
from urllib.parse import urlparse
import requests
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

ALLOWED_HOSTS = frozenset({"api.example.com", "hooks.slack.com"})

def _validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        abort(400, "Only HTTPS URLs are permitted")
    if parsed.hostname not in ALLOWED_HOSTS:
        abort(400, f"Host not in allowlist: {parsed.hostname}")
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if ip.is_private or ip.is_loopback:
        abort(400, "Private/loopback IPs are not permitted")
    return url

@app.route("/fetch", methods=["POST"])
def proxy_fetch():
    url = _validate_url(request.json.get("url", ""))
    resp = requests.get(url, timeout=10, allow_redirects=False)
    return jsonify({"body": resp.text})
"""

def demo_ssrf():
    _rule("Server-Side Request Forgery — RULE-008 (HIGH)")
    _h("\n[bold red]❌ Vulnerable:[/bold red]")
    _code(VULNERABLE_SSRF)
    h = ASTHardener()
    p = PolicyEngine()
    ast_findings = [f for f in h.analyze(VULNERABLE_SSRF) if f.node_type == "SSRF"]
    pol_findings = [v for v in p.evaluate(VULNERABLE_SSRF, "fetch.py") if "008" in v.rule_id]
    _h("\n[bold]AST Hardener detects:[/bold]")
    _findings_table(ast_findings, "SSRF")
    _h("\n[bold]Policy Engine (RULE-008) detects:[/bold]")
    _findings_table(pol_findings, "RULE-008")
    _h("\n[bold green]✅ Hardened alternative:[/bold green]")
    _code(HARDENED_SSRF)
    _h("")


# ─────────────────────────────────────────────────────────────────────────────
# Section 7 — Insecure Deserialization (YAML)  ← NEW
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_YAML = """\
import yaml

def load_config(raw: str) -> dict:
    # AI-generated: yaml.load() can execute !!python/object payloads
    # e.g. raw = "!!python/object/apply:os.system ['rm -rf /']"
    return yaml.load(raw)

def load_user_template(tmpl: str) -> dict:
    return yaml.load(tmpl)  # same problem — no Loader=
"""

HARDENED_YAML = """\
import yaml

def load_config(raw: str) -> dict:
    # yaml.safe_load only deserialises basic YAML types
    return yaml.safe_load(raw)

def load_user_template(tmpl: str) -> dict:
    # Explicit SafeLoader — equally safe, slightly more verbose
    return yaml.load(tmpl, Loader=yaml.SafeLoader)
"""

def demo_deserialization():
    _rule("Insecure Deserialization — YAML (HIGH)")
    _h("\n[bold red]❌ Vulnerable:[/bold red]")
    _code(VULNERABLE_YAML)
    h = ASTHardener()
    findings = [f for f in h.analyze(VULNERABLE_YAML) if f.node_type == "InsecureDeserialization"]
    _h("\n[bold]AgentArmor detects:[/bold]")
    _findings_table(findings, "deserialization")
    _h("\n[bold green]✅ Hardened alternative:[/bold green]")
    _code(HARDENED_YAML)
    _h("")


# ─────────────────────────────────────────────────────────────────────────────
# Section 8 — ReDoS  ← NEW
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_REDOS = '''\
import re

# AI-generated: nested quantifier causes catastrophic backtracking
# Input "aaaaaaaaaaaaaaaaaaaaaaaaa!" can take minutes to reject
EMAIL_RE = re.compile(r"^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\\.[a-zA-Z]+$")

def validate_username(value: str) -> bool:
    return bool(re.match(r"(\\w+\\s?)+$", value))
'''

HARDENED_REDOS = '''\
import re

# Rewritten to avoid nested quantifiers
EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9_.+-]*@[a-zA-Z0-9-]+\\.[a-zA-Z]{2,}$"
)

def validate_username(value: str) -> bool:
    # Possessive-style: anchor + character class, no nested groups
    return bool(re.match(r"^[\\w ]{1,64}$", value))
'''

def demo_redos():
    _rule("ReDoS — Catastrophic Regex (HIGH)")
    _h("\n[bold red]❌ Vulnerable:[/bold red]")
    _code(VULNERABLE_REDOS)
    h = ASTHardener()
    findings = [f for f in h.analyze(VULNERABLE_REDOS) if f.node_type == "ReDoS"]
    _h("\n[bold]AgentArmor detects:[/bold]")
    _findings_table(findings, "ReDoS")
    _h("\n[bold green]✅ Hardened alternative:[/bold green]")
    _code(HARDENED_REDOS)
    _h("")


# ─────────────────────────────────────────────────────────────────────────────
# Section 9 — Broken Object-Level Auth  ← NEW
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_BOLA = """\
import sqlite3
from flask import Flask, g, jsonify

app = Flask(__name__)

@app.route("/orders/<int:order_id>")
def get_order(order_id: int):
    # AI-generated: any logged-in user can read any order by guessing IDs
    conn = sqlite3.connect("shop.db")
    row = conn.execute(
        "SELECT * FROM orders WHERE id = ?", (order_id,)
    ).fetchone()
    return jsonify(dict(row))
"""

HARDENED_BOLA = """\
import sqlite3
from flask import Flask, g, jsonify, abort

app = Flask(__name__)

@app.route("/orders/<int:order_id>")
def get_order(order_id: int):
    current_user_id = g.user_id  # from session / JWT middleware
    conn = sqlite3.connect("shop.db")
    # Ownership check — user can only see their own orders
    row = conn.execute(
        "SELECT * FROM orders WHERE id = ? AND user_id = ?",
        (order_id, current_user_id),
    ).fetchone()
    if row is None:
        abort(404)  # same response for "not found" and "not yours" — no oracle
    return jsonify(dict(row))
"""

def demo_bola():
    _rule("Broken Object-Level Authorization — RULE-009 (HIGH)")
    _h("\n[bold red]❌ Vulnerable:[/bold red]")
    _code(VULNERABLE_BOLA)
    p = PolicyEngine()
    findings = [v for v in p.evaluate(VULNERABLE_BOLA, "orders.py") if "009" in v.rule_id]
    _h("\n[bold]Policy Engine (RULE-009) detects:[/bold]")
    _findings_table(findings, "BOLA")
    _h("\n[bold green]✅ Hardened alternative:[/bold green]")
    _code(HARDENED_BOLA)
    _h("")


# ─────────────────────────────────────────────────────────────────────────────
# Section 10 — Insecure Design  ← NEW
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_DESIGN = """\
from flask import Flask

app = Flask(__name__)

# AI-generated: hardcoded secret + debug mode = critical exposure
app.secret_key = "my-hardcoded-session-secret"
DB_HOST = "192.168.1.50"

if __name__ == "__main__":
    # debug=True enables the Werkzeug debugger — arbitrary code execution
    app.run(debug=True, host="0.0.0.0", port=5000)
"""

HARDENED_DESIGN = """\
import os
from flask import Flask

app = Flask(__name__)

# Load all sensitive config from the environment — never hardcode
app.secret_key = os.environ["FLASK_SECRET_KEY"]
DB_HOST        = os.environ.get("DB_HOST", "db")

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, host="127.0.0.1", port=5000)
"""

def demo_design():
    _rule("Insecure Design — RULE-010 (CRITICAL / HIGH)")
    _h("\n[bold red]❌ Vulnerable:[/bold red]")
    _code(VULNERABLE_DESIGN)
    p = PolicyEngine()
    findings = [v for v in p.evaluate(VULNERABLE_DESIGN, "app.py") if "010" in v.rule_id]
    _h("\n[bold]Policy Engine (RULE-010) detects:[/bold]")
    _findings_table(findings, "insecure design")
    _h("\n[bold green]✅ Hardened alternative:[/bold green]")
    _code(HARDENED_DESIGN)
    _h("")


# ─────────────────────────────────────────────────────────────────────────────
# Section 11 — Full Pipeline
# ─────────────────────────────────────────────────────────────────────────────

KITCHEN_SINK = """\
import hashlib
import requests
import yaml

from flask import Flask, request, jsonify

app = Flask(__name__)
app.secret_key = "dev-secret-key"          # hardcoded secret
STRIPE_KEY = "sk_live_fakestripekey123456" # exposed API key

@app.route("/profile/<int:uid>")
def get_profile(uid: int):
    config = yaml.load(request.json.get("cfg"))    # yaml deserialization
    url = request.json.get("avatar_url")
    avatar = requests.get(url).content             # SSRF
    pw_hash = hashlib.md5(b"hunter2").hexdigest()  # weak hash
    conn = app.db
    row = conn.execute(
        "SELECT * FROM users WHERE id = ?", (uid,)
    ).fetchone()                                    # BOLA — no user_id check
    return jsonify(dict(row))

if __name__ == "__main__":
    app.run(debug=True)                            # debug in production
"""

def demo_pipeline():
    _rule("Full Pipeline — Kitchen Sink (all detections at once)")
    _h("\n[bold red]❌ Vulnerable — AI generated 'one function' API:[/bold red]")
    _code(KITCHEN_SINK)

    armor = AgentArmor(validate_packages=False)
    report = armor.process(KITCHEN_SINK, filename="profile_api.py")

    total = (
        len(report.secret_findings or [])
        + len(report.ast_findings or [])
        + len(report.dtg_findings or [])
        + len(report.policy_violations or [])
    )

    _h(f"\n[bold]AgentArmor Pipeline result:[/bold]")
    if console:
        from rich.panel import Panel
        colour = {"BLOCKED": "red", "WARNED": "yellow", "APPROVED": "green"}.get(report.status, "white")
        console.print(Panel(
            f"Status:   [bold {colour}]{report.status}[/bold {colour}]\n"
            f"Findings: [bold]{total}[/bold] total\n"
            f"Secrets:  {len(report.secret_findings or [])}\n"
            f"AST:      {len(report.ast_findings or [])}\n"
            f"Policy:   {len(report.policy_violations or [])}\n"
            f"Time:     {report.processing_time_ms:.1f} ms",
            title="Pipeline Report",
            border_style=colour,
        ))
    else:
        print(f"  Status:   {report.status}")
        print(f"  Findings: {total}")

    if report.ast_findings:
        _h("\n[bold]AST findings:[/bold]")
        _findings_table(report.ast_findings, "AST")
    if report.policy_violations:
        _h("\n[bold]Policy violations:[/bold]")
        _findings_table(report.policy_violations, "policy")
    _h("")


# ─────────────────────────────────────────────────────────────────────────────
# Registry + entry point
# ─────────────────────────────────────────────────────────────────────────────

SECTIONS: dict[str, tuple[str, object]] = {
    "sql":             ("SQL Injection",                         demo_sql),
    "eval":            ("eval() Code Injection",                 demo_eval),
    "secret":          ("Hardcoded Secrets",                     demo_secret),
    "command":         ("Command Injection",                     demo_command),
    "crypto":          ("Insecure Cryptography (RULE-007)",      demo_crypto),
    "ssrf":            ("Server-Side Request Forgery (RULE-008)", demo_ssrf),
    "deserialization": ("Insecure Deserialization YAML",         demo_deserialization),
    "redos":           ("ReDoS Catastrophic Regex",              demo_redos),
    "bola":            ("Broken Object-Level Auth (RULE-009)",   demo_bola),
    "design":          ("Insecure Design (RULE-010)",            demo_design),
    "pipeline":        ("Full Pipeline — Kitchen Sink",          demo_pipeline),
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AgentArmor quickstart examples",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--section",
        choices=list(SECTIONS),
        default=None,
        help="Run only one section (default: run all)",
    )
    args = parser.parse_args()

    if console:
        console.print(
            Panel.fit(
                "[bold cyan]🛡️  AgentArmor — Quickstart Examples[/bold cyan]\n"
                "[dim]Demonstrating all 10 detection categories[/dim]",
                border_style="cyan",
            )
        )
    else:
        print("AgentArmor — Quickstart Examples")

    if args.section:
        name, fn = SECTIONS[args.section]
        fn()  # type: ignore[operator]
    else:
        for key, (name, fn) in SECTIONS.items():
            fn()  # type: ignore[operator]

    if console:
        console.print("[bold green]✅  All quickstart examples complete.[/bold green]")
    else:
        print("All examples complete.")


if __name__ == "__main__":
    main()
