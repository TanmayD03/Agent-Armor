# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor CLI — armor
========================
A professional developer experience built with Click + Rich.

Commands
--------
  armor scan <file>            Scan & harden a source file
  armor scan-dir <dir>         Scan all source files in a directory
  armor verify <file>          Verify file attestation against shadow-chain
  armor check-deps <file>      Validate imports against PyPI / npm
  armor mcp-intercept <json>   Intercept an MCP tool-call payload
  armor museum [--id N]        Browse the Vulnerability Museum
  armor badge <repo>           Generate a Secure-by-Agent badge
  armor history <file>         Show shadow-chain history for a file
  armor chain-status           Show overall shadow-chain health
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich import box

console = Console()

BANNER = """
[bold cyan]
  ___                    _      _                               
 / _ \\ __ _  ___ _ __ | |_   / \\ _ __ _ __ ___   ___  _ __ 
/ /_\\/  _` |/ _ \\ '_ \\| __| / _ \\| '__| '_ ` _ \\ / _ \\| '__|
/ /_\\\\ (_| |  __/ | | | |_ / ___ \\ |  | | | | | | (_) | |   
\\____/\\__, |\\___|_| |_|\\__/_/   \\_\\_|  |_| |_| |_|\\___/|_|  
       |___/                                                   
[/bold cyan]
[dim]  Zero-Trust Middleware for Agentic Coding  |  v1.0.0[/dim]
[dim]  ─────────────────────────────────────────────────────[/dim]
[dim]  Intercept → Scrub → Harden → Attest → Ship[/dim]
"""

# ---------------------------------------------------------------------------
# CLI Group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option("1.0.0", prog_name="armor")
@click.option("--quiet", "-q", is_flag=True, help="Suppress banner and non-essential output.")
@click.pass_context
def cli(ctx: click.Context, quiet: bool) -> None:
    """🛡️  AgentArmor — Zero-Trust Middleware for Agentic Coding."""
    ctx.ensure_object(dict)
    ctx.obj["quiet"] = quiet
    if not quiet:
        console.print(BANNER)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--lang", "-l", default=None, help="Override language detection.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write hardened code to this file.")
@click.option("--report", "-r", is_flag=True, help="Print JSON report to stdout.")
@click.option("--report-file", type=click.Path(path_type=Path), default=None,
              help="Write JSON report to this file.")
@click.option("--no-scrub", is_flag=True, help="Skip secret scrubbing.")
@click.option("--no-deps", is_flag=True, help="Skip package dependency check.")
@click.option("--strict", is_flag=True,
              help="Exit with code 1 on any critical finding (for CI/CD).")
@click.pass_context
def scan(
    ctx: click.Context,
    file: Path,
    lang: Optional[str],
    output: Optional[Path],
    report: bool,
    report_file: Optional[Path],
    no_scrub: bool,
    no_deps: bool,
    strict: bool,
) -> None:
    """Scan and harden a single source file."""
    from agent_armor.pipeline import AgentArmor

    quiet = ctx.obj.get("quiet", False)

    armor = AgentArmor(validate_packages=not no_deps)
    raw_code = file.read_text(encoding="utf-8")

    with console.status(f"[bold cyan]Scanning {file}...[/bold cyan]"):
        armor_report = armor.process(raw_code, filename=str(file))

    _print_report(armor_report, file, quiet)

    # Write hardened output
    if output:
        output.write_text(armor_report.hardened_code, encoding="utf-8")
        console.print(f"\n[green]✅  Hardened code written → {output}[/green]")
    elif not quiet:
        console.print(
            Panel(
                Syntax(armor_report.hardened_code, "python", theme="monokai",
                       line_numbers=True),
                title="[bold green]Hardened Output[/bold green]",
                border_style="green",
            )
        )

    # Write / print JSON report
    if report_file:
        report_file.write_text(armor_report.to_json(), encoding="utf-8")
        console.print(f"[dim]Report written → {report_file}[/dim]")
    if report:
        console.print_json(armor_report.to_json())

    # CI/CD exit code
    if strict and armor_report.is_blocked:
        console.print("[bold red]🛑  Strict mode: exiting with code 1 (BLOCKED)[/bold red]")
        sys.exit(1)
    if strict and armor_report.critical_count > 0:
        console.print(
            f"[bold red]🛑  Strict mode: {armor_report.critical_count} critical issue(s) → exit 1[/bold red]"
        )
        sys.exit(1)


@cli.command("scan-dir")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--fail-fast", is_flag=True, help="Stop on first BLOCKED file.")
@click.option("--report-file", type=click.Path(path_type=Path), default=None)
@click.pass_context
def scan_dir(
    ctx: click.Context,
    directory: Path,
    fail_fast: bool,
    report_file: Optional[Path],
) -> None:
    """Scan all source files in a directory recursively."""
    from agent_armor.pipeline import AgentArmor

    extensions = {".py", ".js", ".ts"}
    files = [
        p for p in directory.rglob("*")
        if p.suffix in extensions and ".venv" not in p.parts
    ]

    if not files:
        console.print("[yellow]No source files found.[/yellow]")
        return

    armor = AgentArmor()
    total_blocked = 0
    all_reports = []

    table = Table(title="AgentArmor Scan Results", box=box.ROUNDED, show_lines=True)
    table.add_column("File", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("Issues", justify="right")
    table.add_column("Attestation", style="dim")

    for fp in files:
        raw = fp.read_text(encoding="utf-8", errors="replace")
        r = armor.process(raw, filename=str(fp))
        all_reports.append(r)

        status_str = {
            "APPROVED": "[bold green]APPROVED[/bold green]",
            "WARNED":   "[bold yellow]WARNED[/bold yellow]",
            "BLOCKED":  "[bold red]BLOCKED[/bold red]",
        }.get(r.status, r.status)

        attest = r.attestation.signature[:12] + "..." if r.attestation else "N/A"
        table.add_row(
            str(fp.relative_to(directory)),
            status_str,
            str(r.critical_count) if r.critical_count else "0",
            str(r.total_issues),
            attest,
        )

        if r.is_blocked:
            total_blocked += 1
            if fail_fast:
                console.print(table)
                console.print(f"[bold red]🛑  Fail-fast triggered on {fp}[/bold red]")
                sys.exit(1)

    console.print(table)
    console.print(
        f"\n[bold]Scanned {len(files)} file(s) — "
        f"{total_blocked} BLOCKED, "
        f"{sum(1 for r in all_reports if r.status == 'WARNED')} WARNED, "
        f"{sum(1 for r in all_reports if r.status == 'APPROVED')} APPROVED[/bold]"
    )

    if report_file:
        data = [r.to_dict() for r in all_reports]
        report_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[dim]Report written → {report_file}[/dim]")


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--hash", "expected_hash", default=None,
              help="Expected attestation hash (if not embedded in file).")
@click.pass_context
def verify(
    ctx: click.Context,
    file: Path,
    expected_hash: Optional[str],
) -> None:
    """Verify that a file's attestation has not been tampered with."""
    from agent_armor.pipeline import AgentArmor
    from agent_armor.core.attestation import AttestationEngine

    code = file.read_text(encoding="utf-8")
    engine = AttestationEngine()
    embedded_sig = engine.extract_signature(code)

    if expected_hash:
        target_sig = expected_hash
    elif embedded_sig:
        target_sig = embedded_sig
    else:
        console.print(
            Panel(
                "[yellow]No attestation found in this file.\n"
                "Run [bold]armor scan[/bold] to generate one.[/yellow]",
                title="⚠️  No Attestation",
                border_style="yellow",
            )
        )
        sys.exit(3)

    ok = engine.verify(code, target_sig)

    # Also check shadow-chain
    armor = AgentArmor()
    chain_ok = armor._shadow_chain.verify_file_attestation(str(file), target_sig)

    if ok and chain_ok:
        console.print(
            Panel(
                f"[bold green]✅  Attestation VALID[/bold green]\n"
                f"File: {file}\n"
                f"Hash: [dim]{target_sig}[/dim]\n"
                f"Shadow-chain: [green]INTACT[/green]",
                title="Attestation Verification",
                border_style="green",
            )
        )
    elif ok and not chain_ok:
        console.print(
            Panel(
                f"[bold yellow]⚠️  Code hash valid but NOT in shadow-chain[/bold yellow]\n"
                f"File: {file}\n"
                "The file may have been attested outside this project's chain.",
                title="Verification Warning",
                border_style="yellow",
            )
        )
        sys.exit(2)
    else:
        console.print(
            Panel(
                f"[bold red]🚨  ATTESTATION BROKEN[/bold red]\n"
                f"File: {file}\n"
                "The code has been MODIFIED since it was last attested.\n"
                "Run [bold]armor scan[/bold] to re-attest after security review.",
                title="Verification FAILED",
                border_style="red",
            )
        )
        sys.exit(2)


@cli.command("check-deps")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--strict", is_flag=True, help="Exit 1 on any HIGH+ finding.")
def check_deps(file: Path, strict: bool) -> None:
    """Validate package imports / requirements against live PyPI registry."""
    from agent_armor.guards.slopsquatting_guard import SlopsquattingGuard

    guard = SlopsquattingGuard()
    code = file.read_text(encoding="utf-8")

    with console.status("[bold cyan]Querying PyPI registry...[/bold cyan]"):
        findings = guard.scan(code)

    if not findings:
        console.print("[bold green]✅  All imports verified — no suspicious packages found.[/bold green]")
        return

    table = Table(title="Slopsquatting Guard — Findings", box=box.ROUNDED, show_lines=True)
    table.add_column("Package", style="cyan")
    table.add_column("Check", style="yellow")
    table.add_column("Severity", justify="center")
    table.add_column("Description")
    table.add_column("Recommendation", style="dim")

    has_high = False
    for f in findings:
        sev_color = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(f.severity, "white")
        table.add_row(
            f.package_name,
            f.check_id,
            f"[{sev_color}]{f.severity}[/{sev_color}]",
            f.description,
            f.recommendation,
        )
        if f.severity in ("CRITICAL", "HIGH"):
            has_high = True

    console.print(table)

    if strict and has_high:
        console.print("[bold red]🛑  Strict mode: HIGH+ findings → exit 1[/bold red]")
        sys.exit(1)


@cli.command("mcp-intercept")
@click.argument("payload_file", required=False, type=click.Path(path_type=Path))
@click.option("--domain", "-d", default="default", show_default=True,
              help="Agent domain for isolation checks.")
def mcp_intercept(payload_file: Optional[Path], domain: str) -> None:
    """Intercept an MCP tool-call payload (file or stdin)."""
    from agent_armor.mcp_proxy.interceptor import MCPInterceptor

    if payload_file:
        raw = payload_file.read_text(encoding="utf-8")
    else:
        console.print("[dim]Reading MCP payload from stdin (Ctrl+C to cancel)...[/dim]")
        raw = sys.stdin.read()

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid JSON payload: {exc}[/red]")
        sys.exit(1)

    interceptor = MCPInterceptor(agent_context={"domain": domain})
    result = interceptor.intercept(payload)

    if result.allowed:
        console.print(
            Panel(
                "[bold green]✅  MCP payload CLEARED by Zero-Trust proxy[/bold green]\n"
                + (f"Warnings: {result.warnings}" if result.warnings else "No warnings."),
                title=f"Tool: {result.tool_name}",
                border_style="green",
            )
        )
        if result.modified_payload:
            console.print_json(json.dumps(result.modified_payload, indent=2))
    else:
        console.print(
            Panel(
                f"[bold red]🛑  MCP payload BLOCKED[/bold red]\n"
                f"Reason: {result.block_reason}",
                title=f"Tool: {result.tool_name}",
                border_style="red",
            )
        )
        sys.exit(1)


@cli.command()
@click.option("--id", "museum_id", type=int, default=None,
              help="Show a specific vulnerability case (1-5).")
def museum(museum_id: Optional[int]) -> None:
    """🏛️  Browse the Vulnerability Museum — real AI-generated vulnerabilities."""
    _run_museum(museum_id)


@cli.command()
@click.argument("repo")
def badge(repo: str) -> None:
    """Generate a Secure-by-Agent badge for your README."""
    badge_url = (
        "https://img.shields.io/badge/AgentArmor-Attested%20%26%20Secure-brightgreen"
        "?logo=shield&labelColor=1a1a2e&style=flat-square"
    )
    markdown = f"[![AgentArmor Protected]({badge_url})](https://github.com/TanmayD03/Agent-Armor)"

    console.print(
        Panel(
            f"[bold cyan]Add this badge to your README:[/bold cyan]\n\n"
            f"[dim]{markdown}[/dim]\n\n"
            f"[bold]Preview:[/bold]\n"
            f"  🛡️  [bold green]AgentArmor — Attested & Secure[/bold green]\n\n"
            f"Your repo [bold yellow]{repo}[/bold yellow] is shielded by AgentArmor.",
            title="🏅 Secure-by-Agent Badge",
            border_style="cyan",
        )
    )


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
def history(file: Path) -> None:
    """Show the shadow-chain attestation history for a file."""
    from agent_armor.shadow_chain.chain_manager import ShadowChainManager

    manager = ShadowChainManager()
    entries = manager.get_history(str(file))

    if not entries:
        console.print(f"[yellow]No attestation history for {file}[/yellow]")
        return

    table = Table(
        title=f"Shadow-Chain History — {file}",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Signature (truncated)", style="green")
    table.add_column("Invariants")
    table.add_column("Prev Hash", style="dim")

    for i, e in enumerate(entries, 1):
        inv_summary = ", ".join(
            f"{k}={'✓' if v else '✗'}" for k, v in e.invariants.items()
        )
        table.add_row(
            str(i),
            e.timestamp,
            e.signature[:16] + "...",
            inv_summary or "—",
            e.prev_hash[:16] + "...",
        )

    console.print(table)
    valid = ShadowChainManager().verify_chain()
    console.print(
        f"\nChain integrity: {'[bold green]INTACT ✅[/bold green]' if valid else '[bold red]BROKEN ❌[/bold red]'}"
    )


@cli.command("chain-status")
def chain_status() -> None:
    """Show the overall health of the shadow-chain."""
    from agent_armor.shadow_chain.chain_manager import ShadowChainManager

    manager = ShadowChainManager()
    summary = manager.summary()

    status_color = "green" if summary["chain_valid"] else "red"
    console.print(
        Panel(
            f"[bold]Chain valid:[/bold] [{status_color}]{'✅ YES' if summary['chain_valid'] else '❌ NO'}[/{status_color}]\n"
            f"[bold]Total entries:[/bold] {summary['total_entries']}\n"
            f"[bold]Files attested:[/bold] {summary['files_attested']}\n"
            f"[bold]Latest timestamp:[/bold] {summary['latest_timestamp'] or 'N/A'}",
            title="🔗 Shadow-Chain Status",
            border_style=status_color,
        )
    )


# ---------------------------------------------------------------------------
# Vulnerability Museum content
# ---------------------------------------------------------------------------

_MUSEUM_CASES = [
    {
        "id": 1,
        "title": "SQL Injection via f-string",
        "cvss": "9.8 CRITICAL",
        "vulnerable": """\
# 🤖 AI-Generated (GPT-4) — UNSAFE
def get_user(username: str):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

# Attack: username = "'; DROP TABLE users; --"
""",
        "fix": "Use parameterised queries: cursor.execute(sql, (param,))",
        "hardened": """\
# ✅ AgentArmor Hardened
from pydantic import BaseModel, constr

class UserQuery(BaseModel):
    username: constr(min_length=1, max_length=64, pattern=r'^[\\w]+$')

def get_user(username: str):
    validated = UserQuery(username=username)
    query = "SELECT * FROM users WHERE username = %s"
    return db.execute(query, (validated.username,))
""",
    },
    {
        "id": 2,
        "title": "eval() Code Injection",
        "cvss": "10.0 CRITICAL",
        "vulnerable": """\
# 🤖 AI-Generated — UNSAFE
def calculate(expression: str):
    return eval(expression)   # RCE: eval("__import__('os').system('rm -rf /')")
""",
        "fix": "Use ast.literal_eval() or a safe math parser library.",
        "hardened": """\
# ✅ AgentArmor Hardened
import ast
import operator

_SAFE_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub,
    ast.Mult: operator.mul, ast.Div: operator.truediv,
    ast.Pow: operator.pow,
}

def _safe_eval(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_OPS:
        return _SAFE_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    raise ValueError(f"Unsafe expression: {ast.dump(node)}")

def calculate(expression: str) -> float:
    tree = ast.parse(expression, mode='eval')
    return _safe_eval(tree.body)
""",
    },
    {
        "id": 3,
        "title": "Hardcoded API Secret",
        "cvss": "9.1 CRITICAL",
        "vulnerable": """\
# 🤖 AI-Generated — UNSAFE
import openai

def query_llm(prompt: str) -> str:
    openai.api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
    return openai.ChatCompletion.create(
        model="gpt-4", messages=[{"role": "user", "content": prompt}]
    )
""",
        "fix": "Replace with os.getenv(). Never commit secrets to source control.",
        "hardened": """\
# ✅ AgentArmor Hardened
import os
import openai

def query_llm(prompt: str) -> str:
    openai.api_key = os.getenv("AGENT_ARMOR_OPENAI_API_KEY")
    if not openai.api_key:
        raise EnvironmentError("AGENT_ARMOR_OPENAI_API_KEY env var not set.")
    return openai.ChatCompletion.create(
        model="gpt-4", messages=[{"role": "user", "content": prompt}]
    )
""",
    },
    {
        "id": 4,
        "title": "OS Command Injection",
        "cvss": "9.8 HIGH",
        "vulnerable": """\
# 🤖 AI-Generated — UNSAFE
import os

def list_directory(path: str) -> str:
    return os.popen(f"ls -la {path}").read()

# Attack: path = "/tmp; cat /etc/passwd"
""",
        "fix": "Use subprocess.run() with a list, shell=False, and validated path.",
        "hardened": """\
# ✅ AgentArmor Hardened
import subprocess
from pathlib import Path

def list_directory(path: str) -> str:
    safe_path = Path(path).resolve()
    if not safe_path.exists():
        raise FileNotFoundError(f"Path does not exist: {safe_path}")
    result = subprocess.run(
        ["ls", "-la", str(safe_path)],
        capture_output=True, text=True, shell=False, timeout=10
    )
    return result.stdout
""",
    },
    {
        "id": 5,
        "title": "Dependency Confusion (Slopsquatting)",
        "cvss": "8.1 HIGH",
        "vulnerable": """\
# 🤖 AI-Generated requirements.txt — UNSAFE
# AI invented a package that doesn't exist:
fastapi-auth-middleware==1.0.0
fatsapi==0.100.0         # <-- typosquats 'fastapi'
openai-helpers==0.1.0    # <-- possibly hallucinated
nump==1.24.0             # <-- typosquats 'numpy'
""",
        "fix": "Always validate package names against PyPI before installing.",
        "hardened": """\
# ✅ AgentArmor Validated requirements.txt
# armor check-deps requirements.txt output:
# ✅ fastapi         — 50M+ downloads, 6 years old
# ✅ openai          — 10M+ downloads, 3 years old
# ✅ numpy           — 100M+ downloads, 20 years old
# ❌ BLOCKED: 'fatsapi'   — typosquats 'fastapi' (edit dist: 1)
# ❌ BLOCKED: 'nump'      — typosquats 'numpy' (edit dist: 1)
fastapi==0.110.0
openai>=1.0.0
numpy>=1.24.0
""",
    },
]


def _run_museum(museum_id: Optional[int]) -> None:
    if museum_id:
        cases = [c for c in _MUSEUM_CASES if c["id"] == museum_id]
        if not cases:
            console.print(f"[red]No museum case with id {museum_id}. Valid IDs: 1-5.[/red]")
            return
    else:
        cases = _MUSEUM_CASES

    for case in cases:
        console.print(
            Panel(
                f"[bold red]Vulnerability:[/bold red] {case['title']}\n"
                f"[bold red]CVSS Score:[/bold red]    {case['cvss']}\n"
                f"[bold cyan]Fix:[/bold cyan]          {case['fix']}",
                title=f"🏛️  Museum Case #{case['id']}",
                border_style="red",
            )
        )
        console.print("[bold red]❌ Vulnerable (AI Output):[/bold red]")
        console.print(Syntax(case["vulnerable"], "python", theme="monokai", line_numbers=True))
        console.print("\n[bold green]✅ AgentArmor Hardened:[/bold green]")
        console.print(Syntax(case["hardened"], "python", theme="monokai", line_numbers=True))
        console.print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_report(armor_report, file: Path, quiet: bool) -> None:
    """Print a concise summary table for a single-file scan."""
    status_map = {
        "APPROVED": ("[bold green]✅ APPROVED[/bold green]", "green"),
        "WARNED":   ("[bold yellow]⚠️  WARNED[/bold yellow]",  "yellow"),
        "BLOCKED":  ("[bold red]🛑 BLOCKED[/bold red]",        "red"),
    }
    label, color = status_map.get(armor_report.status, (armor_report.status, "white"))

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("Key", style="bold dim")
    table.add_column("Value")

    table.add_row("File", str(file))
    table.add_row("Status", label)
    table.add_row("Processing", f"{armor_report.processing_time_ms:.1f} ms")
    table.add_row("Critical issues", str(armor_report.critical_count))
    table.add_row("Total findings", str(armor_report.total_issues))
    table.add_row(
        "Attestation",
        (armor_report.attestation.signature[:24] + "...")
        if armor_report.attestation else "[red]N/A (BLOCKED)[/red]",
    )

    console.print(
        Panel(table, title="AgentArmor Report", border_style=color)
    )

    if not quiet and armor_report.ast_findings:
        finding_table = Table(title="AST Findings", box=box.SIMPLE_HEAD, show_lines=True)
        finding_table.add_column("Severity", justify="center")
        finding_table.add_column("Type")
        finding_table.add_column("Line", justify="right")
        finding_table.add_column("Description")
        finding_table.add_column("Suggestion", style="dim")
        for f in armor_report.ast_findings:
            sev_colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "blue"}
            c = sev_colors.get(f.severity, "white")
            finding_table.add_row(
                f"[{c}]{f.severity}[/{c}]",
                f.node_type,
                str(f.line_number),
                f.description,
                f.suggestion,
            )
        console.print(finding_table)


if __name__ == "__main__":
    cli()
