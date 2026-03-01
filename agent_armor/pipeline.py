# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor — Main Pipeline
============================
The AgentArmor class is the central orchestrator.  It chains together:

  Stage 1 — Secret Scrubber       → removes hardcoded credentials
  Stage 2 — AST Hardening Engine  → detects dangerous sinks & patterns
  Stage 3 — DTG Engine            → traces unsanitised data flows
  Stage 4 — Slopsquatting Guard   → validates dependencies
  Stage 5 — Policy Engine         → enforces semantic rules
  Stage 6 — Attestation           → cryptographic signing
  Stage 7 — Shadow-Chain          → persists attestation

The pipeline produces an :class:`ArmorReport` that is either:

  APPROVED — no issues found, code attested and signed
  WARNED   — issues found and auto-mitigated, code attested with caveats
  BLOCKED  — critical issues found that could not be mitigated
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .core.ast_hardener import ASTFinding, ASTHardener
from .core.attestation import Attestation, AttestationEngine
from .core.dtg_engine import DTGEngine, DTGFinding
from .core.policy_engine import PolicyEngine, PolicyViolation
from .core.secret_scrubber import SecretFinding, SecretScrubber
from .guards.slopsquatting_guard import PackageFinding, SlopsquattingGuard
from .shadow_chain.chain_manager import ShadowChainManager


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


@dataclass
class ArmorReport:
    """
    Comprehensive result from the AgentArmor pipeline.

    Attributes
    ----------
    status          : "APPROVED" | "WARNED" | "BLOCKED"
    timestamp       : Unix time when the report was generated
    original_code   : The raw AI-generated code before processing
    hardened_code   : The code after scrubbing, hardening, and annotation
    attestation     : Cryptographic attestation (None if BLOCKED)
    *_findings      : Individual findings from each engine
    processing_time_ms : Wall-clock time for the full pipeline
    """

    status: str
    timestamp: float
    original_code: str
    hardened_code: str
    attestation: Optional[Attestation]
    secret_findings: List[SecretFinding] = field(default_factory=list)
    ast_findings: List[ASTFinding] = field(default_factory=list)
    dtg_findings: List[DTGFinding] = field(default_factory=list)
    policy_violations: List[PolicyViolation] = field(default_factory=list)
    package_findings: List[PackageFinding] = field(default_factory=list)
    processing_time_ms: float = 0.0

    @property
    def is_blocked(self) -> bool:
        return self.status == "BLOCKED"

    @property
    def is_approved(self) -> bool:
        return self.status == "APPROVED"

    @property
    def critical_count(self) -> int:
        n = 0
        n += len(self.secret_findings)
        n += sum(1 for f in self.ast_findings if f.severity == "CRITICAL")
        n += sum(1 for f in self.dtg_findings if f.severity == "CRITICAL")
        n += sum(1 for v in self.policy_violations if v.severity == "CRITICAL")
        n += sum(1 for p in self.package_findings if p.severity == "CRITICAL")
        return n

    @property
    def total_issues(self) -> int:
        return (
            len(self.secret_findings)
            + len(self.ast_findings)
            + len(self.dtg_findings)
            + len(self.policy_violations)
            + len(self.package_findings)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "timestamp": self.timestamp,
            "processing_time_ms": round(self.processing_time_ms, 2),
            "summary": {
                "critical": self.critical_count,
                "total_issues": self.total_issues,
                "secrets_found": len(self.secret_findings),
                "ast_issues": len(self.ast_findings),
                "dtg_issues": len(self.dtg_findings),
                "policy_violations": len(self.policy_violations),
                "suspicious_packages": len(self.package_findings),
            },
            "attestation_hash": (
                self.attestation.signature if self.attestation else None
            ),
            "findings": {
                "secrets": [str(f) for f in self.secret_findings],
                "ast": [str(f) for f in self.ast_findings],
                "dtg": [str(f) for f in self.dtg_findings],
                "policy": [str(v) for v in self.policy_violations],
                "packages": [str(p) for p in self.package_findings],
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def __str__(self) -> str:
        lines = [
            f"┌{'─' * 60}",
            f"│  AgentArmor Report — {self.status}",
            f"│  Processing time: {self.processing_time_ms:.1f}ms",
            f"│  Critical issues: {self.critical_count}",
            f"│  Total findings:  {self.total_issues}",
            f"│  Attestation:     {self.attestation.signature[:16] + '...' if self.attestation else 'N/A (BLOCKED)'}",
            f"└{'─' * 60}",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


class AgentArmor:
    """
    Zero-Trust Middleware for Agentic Coding.

    Parameters
    ----------
    shadow_chain_path   : Path to the shadow-chain JSON file.
    block_on_critical   : Block code if any CRITICAL AST finding exists.
    block_on_dangerous_sinks : Block code with eval()/exec() regardless.
    validate_packages   : Run the Slopsquatting guard on imports.
    language            : Primary language of the code being processed.

    Usage::

        armor = AgentArmor()
        report = armor.process(raw_ai_code, filename="handler.py")
        if report.is_blocked:
            raise SecurityError(report.hardened_code)
        write_file(filename, report.hardened_code)
    """

    def __init__(
        self,
        shadow_chain_path: Optional[Path] = None,
        block_on_critical: bool = True,
        block_on_dangerous_sinks: bool = True,
        validate_packages: bool = True,
        language: str = "python",
    ) -> None:
        self.language = language
        self.block_on_critical = block_on_critical
        self.block_on_dangerous_sinks = block_on_dangerous_sinks
        self.validate_packages = validate_packages

        # Instantiate all engines
        self._secret_scrubber = SecretScrubber()
        self._ast_hardener = ASTHardener()
        self._dtg_engine = DTGEngine()
        self._policy_engine = PolicyEngine()
        self._attestation_engine = AttestationEngine()
        self._shadow_chain = ShadowChainManager(shadow_chain_path)
        self._slopsquatting_guard = SlopsquattingGuard() if validate_packages else None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(
        self,
        raw_code: str,
        filename: str = "unknown.py",
        context: Optional[Dict[str, Any]] = None,
    ) -> ArmorReport:
        """
        Master pipeline: Intercept → Scrub → Harden → Attest → Sign.

        Parameters
        ----------
        raw_code  : The raw AI-generated source code.
        filename  : Intended filename (used for context-aware checks).
        context   : Optional dict, e.g. {"domain": "frontend", "agent": "gpt-4o"}.

        Returns
        -------
        ArmorReport with status APPROVED | WARNED | BLOCKED.
        """
        start = time.time()
        context = context or {}

        print("🛡️  [AgentArmor] Intercepting AI-generated code...")

        # ── Stage 1: Secret Scrubbing ──────────────────────────────────
        print("🔍 [Stage 1/5] Scanning for hardcoded secrets...")
        hardened, secret_findings = self._secret_scrubber.scrub(raw_code)
        if secret_findings:
            print(
                f"   ⚠️  {len(secret_findings)} secret(s) scrubbed → env var references."
            )

        # ── Stage 2: AST Hardening ────────────────────────────────────
        print("🌲 [Stage 2/5] Running AST security analysis...")
        ast_findings = self._ast_hardener.analyze(hardened)
        hardened = self._ast_hardener.harden(hardened)
        for f in ast_findings:
            if f.severity in ("CRITICAL", "HIGH"):
                print(f"   {_severity_icon(f.severity)} {f}")

        # ── Stage 3: DTG Data Flow Analysis ──────────────────────────
        print("📊 [Stage 3/5] Analysing data transformation graph...")
        dtg_findings = self._dtg_engine.analyze(hardened)
        if dtg_findings:
            hardened = self._dtg_engine.inject_validation(hardened, dtg_findings)
            for f in dtg_findings:
                print(f"   {_severity_icon(f.severity)} {f}")

        # ── Stage 4: Slopsquatting Guard ─────────────────────────────
        package_findings: List[PackageFinding] = []
        if self._slopsquatting_guard:
            print("📦 [Stage 4/5] Validating package dependencies...")
            package_findings = self._slopsquatting_guard.scan(hardened)
            for p in package_findings:
                print(f"   {_severity_icon(p.severity)} {p}")
        else:
            print("📦 [Stage 4/5] Package validation skipped.")

        # ── Stage 5: Policy Enforcement ──────────────────────────────
        print("📋 [Stage 5/5] Enforcing semantic security policies...")
        policy_violations = self._policy_engine.evaluate(hardened, filename, context)
        for v in policy_violations:
            print(f"   {_severity_icon(v.severity)} {v}")

        # ── Determine final status ────────────────────────────────────
        status, block_reasons = self._determine_status(
            ast_findings, policy_violations, package_findings
        )

        if status == "BLOCKED":
            hardened = self._build_block_notice(block_reasons) + hardened
            attestation = None
            print("🛑 [AgentArmor] Code BLOCKED by Zero-Trust policy.")
        else:
            # Build and embed attestation
            invariants = self._attestation_engine.derive_invariants(
                secret_findings, ast_findings, dtg_findings, package_findings
            )
            attestation = self._attestation_engine.sign(hardened, invariants, filename)
            hardened = self._attestation_engine.embed(hardened, attestation)
            self._shadow_chain.record(attestation)

            if status == "WARNED":
                print("⚠️  [AgentArmor] Code WARNED — issues found and mitigated.")
            else:
                print("✅ [AgentArmor] Code APPROVED — all checks passed.")

        processing_ms = (time.time() - start) * 1000

        return ArmorReport(
            status=status,
            timestamp=time.time(),
            original_code=raw_code,
            hardened_code=hardened,
            attestation=attestation,
            secret_findings=secret_findings,
            ast_findings=ast_findings,
            dtg_findings=dtg_findings,
            policy_violations=policy_violations,
            package_findings=package_findings,
            processing_time_ms=processing_ms,
        )

    def verify_attestation(self, signed_code: str, expected_hash: str) -> bool:
        """
        Verify that *signed_code* matches *expected_hash*.
        Returns True if the code has not been tampered with since signing.
        """
        return self._attestation_engine.verify(signed_code, expected_hash)

    def verify_file(self, filepath: Path) -> bool:
        """
        Read a file and verify its embedded attestation against the shadow-chain.
        Returns True if the file is intact.
        """
        try:
            code = filepath.read_text(encoding="utf-8")
        except OSError:
            return False

        sig = self._attestation_engine.extract_signature(code)
        if sig is None:
            return False

        # Check against shadow-chain
        chain_ok = self._shadow_chain.verify_file_attestation(str(filepath), sig)
        # Check internal hash
        internal_ok = self._attestation_engine.verify(code, sig)
        return chain_ok and internal_ok

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _determine_status(
        self,
        ast_findings: List[ASTFinding],
        policy_violations: List[PolicyViolation],
        package_findings: List[PackageFinding],
    ):
        block_reasons = []

        if self.block_on_critical:
            critical_ast = [f for f in ast_findings if f.severity == "CRITICAL"]
            if critical_ast:
                block_reasons.extend(
                    f"CRITICAL AST: {f.description}" for f in critical_ast
                )

        if self.block_on_dangerous_sinks:
            dangerous = [
                f
                for f in ast_findings
                if f.node_type in ("DangerousFunction", "CommandInjection")
                and f.severity in ("CRITICAL", "HIGH")
            ]
            if dangerous:
                block_reasons.extend(
                    f"DANGEROUS SINK: {f.description}" for f in dangerous
                )

        critical_policy = [v for v in policy_violations if v.severity == "CRITICAL"]
        if critical_policy:
            block_reasons.extend(
                f"POLICY {v.rule_name}: {v.description}" for v in critical_policy
            )

        critical_pkgs = [p for p in package_findings if p.severity == "CRITICAL"]
        if critical_pkgs:
            block_reasons.extend(
                f"SUPPLY CHAIN {p.check_id}: {p.description}" for p in critical_pkgs
            )

        if block_reasons:
            return "BLOCKED", block_reasons

        # Determine WARNED vs APPROVED
        has_any_finding = bool(
            ast_findings
            or [p for p in package_findings if p.severity == "HIGH"]
            or [v for v in policy_violations if v.severity in ("HIGH", "MEDIUM")]
        )
        return ("WARNED" if has_any_finding else "APPROVED"), []

    @staticmethod
    def _build_block_notice(reasons: List[str]) -> str:
        lines = [
            "# " + "=" * 62,
            "# ❌ [AGENT-ARMOR BLOCKED] — Zero-Trust Policy Violation",
            "# This code was REJECTED by the AgentArmor security pipeline.",
            "# Reasons:",
        ]
        for r in reasons:
            lines.append(f"#   • {r}")
        lines.append("# " + "=" * 62)
        lines.append("")
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_icon(severity: str) -> str:
    return {
        "CRITICAL": "🚨",
        "HIGH": "🔴",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "ERROR": "❌",
    }.get(severity, "⚪")
