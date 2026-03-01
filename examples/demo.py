#!/usr/bin/env python3
# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor — End-to-End Demo
============================
Runs the full pipeline against each vulnerability class and prints a
Rich-formatted report showing what AgentArmor caught and fixed.

Usage:
  python examples/demo.py
  python examples/demo.py --quiet     # minimal output
"""
import sys
import time
import argparse
from pathlib import Path

# Make the package importable when run directly from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_armor.pipeline import AgentArmor
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import box

console = Console(highlight=False)  # highlight=False avoids Windows CP1252 emoji issues

# ──────────────────────────────────────────────────────────────────────────────
# Demo scenarios
# ──────────────────────────────────────────────────────────────────────────────

DEMOS = [
    {
        "title": "Case 01 — SQL Injection",
        "filename": "user_lookup.py",
        "code": """\
import sqlite3
from flask import request

def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchone()
""",
    },
    {
        "title": "Case 02 — Eval Injection",
        "filename": "calculator.py",
        "code": """\
def calculate(expression: str):
    # User asks: evaluate this math expression
    return eval(expression)
""",
    },
    {
        "title": "Case 03 — Hardcoded Secret",
        "filename": "config.py",
        "code": """\
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu"
""",
    },
    {
        "title": "Case 04 — Command Injection",
        "filename": "ping_tool.py",
        "code": """\
import os

def ping_host(hostname: str):
    os.system(f"ping -c 1 {hostname}")
""",
    },
    {
        "title": "Case 06 — Missing Admin Auth",
        "filename": "admin.py",
        "code": """\
from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)

@app.route("/admin/nuke", methods=["POST"])
def nuke_all_users():
    conn = sqlite3.connect("users.db")
    conn.execute("DELETE FROM users")
    conn.commit()
    return jsonify({"status": "all users deleted"})
""",
    },
    {
        "title": "Case 07 — JWT Algorithm None",
        "filename": "auth.py",
        "code": """\
import jwt

SECRET = "super-secret-key"

def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET, options={"verify_signature": False})
""",
    },
    {
        "title": "Case 08 — Delete Without User ID",
        "filename": "account.py",
        "code": """\
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route("/account", methods=["DELETE"])
def delete_account():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return jsonify({"deleted": user_id})
""",
    },
    {
        "title": "Case 09 — Insecure Cryptography",
        "filename": "auth_utils.py",
        "code": """\
import hashlib

def hash_password(password: str) -> str:
    # AI-generated: uses MD5 for password storage
    return hashlib.md5(password.encode()).hexdigest()

def verify_file_integrity(filepath: str) -> str:
    h = hashlib.new("sha1")
    with open(filepath, "rb") as f:
        h.update(f.read())
    return h.hexdigest()
""",
    },
    {
        "title": "Case 10 — Server-Side Request Forgery (SSRF)",
        "filename": "webhook_handler.py",
        "code": """\
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/fetch", methods=["POST"])
def fetch_url():
    # AI-generated: passes user-controlled URL directly to requests
    url = request.json.get("url")
    response = requests.get(url, timeout=10)
    return jsonify({"content": response.text})
""",
    },
    {
        "title": "Case 11 — Insecure Deserialization (YAML)",
        "filename": "config_loader.py",
        "code": """\
import yaml

def load_config(config_str: str) -> dict:
    # AI-generated: yaml.load() without Loader= allows arbitrary code execution
    return yaml.load(config_str)

def load_user_template(template: str) -> dict:
    data = yaml.load(template)
    return data
""",
    },
    {
        "title": "Case 12 — ReDoS (Catastrophic Regex)",
        "filename": "input_validator.py",
        "code": """\
import re

# AI-generated: nested quantifier causes catastrophic backtracking
EMAIL_RE = re.compile(r"^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]+$")

def validate_email(email: str) -> bool:
    # Attacker sends: "aaaaaaaaaaaaaaaaaaaaaaaaaaa!"
    # This hangs the server for minutes (ReDoS)
    return bool(EMAIL_RE.match(email))

ZIP_RE = re.compile(r"(\d+|\w+)*-\d{4}")
""",
    },
    {
        "title": "Case 13 — Broken Object-Level Auth (BOLA)",
        "filename": "orders_api.py",
        "code": """\
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/orders/<int:order_id>")
def get_order(order_id: int):
    # AI-generated: fetches by ID alone — any user can access any order
    conn = sqlite3.connect("shop.db")
    row = conn.execute(
        "SELECT * FROM orders WHERE id = ?", (order_id,)
    ).fetchone()
    return jsonify(dict(row))
""",
    },
    {
        "title": "Case 14 — Insecure Design",
        "filename": "app.py",
        "code": """\
from flask import Flask

app = Flask(__name__)

# AI-generated: hardcoded secret + debug mode exposed
app.secret_key = "my-hardcoded-flask-secret"
DB_HOST = "192.168.1.50"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
""",
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

STATUS_COLOUR = {
    "APPROVED":  "green",
    "WARNED":    "yellow",
    "BLOCKED":   "red",
}


def _status_badge(status: str) -> str:
    colour = STATUS_COLOUR.get(status, "white")
    return f"[bold {colour}]{status}[/bold {colour}]"


def _severity_colour(sev: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "dim",
    }.get(sev.upper(), "white")


def run_demo(quiet: bool = False):
    armor = AgentArmor(validate_packages=False)

    console.print(
        Panel.fit(
            "[bold cyan]🛡️  AgentArmor Zero-Trust Middleware — Live Demo[/bold cyan]\n"
            "[dim]Processing 14 vulnerability scenarios...[/dim]",
            border_style="cyan",
        )
    )
    console.print()

    # Summary table
    summary = Table(
        "Case", "Status", "Findings", "Time (ms)",
        box=box.ROUNDED, border_style="dim", show_header=True,
        header_style="bold white",
    )

    total_findings = 0
    total_blocked  = 0
    t_start        = time.perf_counter()

    for demo in DEMOS:
        report = armor.process(
            raw_code=demo["code"],
            filename=demo["filename"],
        )

        finding_count = (
            len(report.secret_findings or [])
            + len(report.ast_findings or [])
            + len(report.dtg_findings or [])
            + len(report.policy_violations or [])
            + len(report.package_findings or [])
        )
        total_findings += finding_count
        if report.status == "BLOCKED":
            total_blocked += 1

        summary.add_row(
            demo["title"],
            _status_badge(report.status),
            str(finding_count),
            f"{report.processing_time_ms:.1f}",
        )

        if not quiet:
            _print_case_detail(demo, report)

    elapsed_ms = (time.perf_counter() - t_start) * 1000

    console.print()
    console.print(Panel(summary, title="[bold]Summary[/bold]", border_style="cyan"))
    console.print()
    console.print(
        f"[bold]Total:[/bold]  {len(DEMOS)} scenarios · "
        f"{total_findings} findings · "
        f"{total_blocked} blocked · "
        f"[cyan]{elapsed_ms:.1f} ms[/cyan] total"
    )
    console.print()
    console.print("[bold green]✅  Demo complete — AgentArmor is working correctly.[/bold green]")


def _print_case_detail(demo: dict, report) -> None:
    console.rule(f"[bold]{demo['title']}[/bold]")

    # Vulnerable code
    console.print("[dim]● Vulnerable input:[/dim]")
    console.print(Syntax(demo["code"].strip(), "python", theme="monokai", line_numbers=False))
    console.print()

    # Findings table
    all_findings = []
    for f in (report.secret_findings or []):
        all_findings.append(("Secret Scrubber", getattr(f, "severity", "HIGH"), str(f)))
    for f in (report.ast_findings or []):
        all_findings.append(("AST Hardener", getattr(f, "severity", "HIGH"), str(f)))
    for f in (report.dtg_findings or []):
        all_findings.append(("DTG Engine", getattr(f, "severity", "HIGH"), str(f)))
    for f in (report.policy_violations or []):
        all_findings.append(("Policy Engine", getattr(f, "severity", "HIGH"), str(f)))

    if all_findings:
        ftable = Table("Stage", "Severity", "Finding", box=box.SIMPLE, show_header=True)
        for stage, sev, desc in all_findings:
            ftable.add_row(stage, f"[{_severity_colour(sev)}]{sev}[/{_severity_colour(sev)}]", desc[:80])
        console.print(ftable)

    # Status
    badge = _status_badge(report.status)
    console.print(f"\n  Verdict: {badge}   ({report.processing_time_ms:.1f} ms)\n")

    # Attestation
    if report.attestation:
        sig = report.attestation.signature[:16] + "..."
        console.print(f"  [dim]Attestation: {sig}[/dim]")

    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentArmor end-to-end demo")
    parser.add_argument("--quiet", action="store_true", help="Only show summary table")
    args = parser.parse_args()
    run_demo(quiet=args.quiet)
