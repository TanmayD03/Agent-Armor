# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor — Cryptographic Attestation Engine
===============================================
Implements the "Attestation Shadow-Chain" — the core innovation of AgentArmor.

How it works
------------
1. After a code block has been scrubbed and hardened, the AttestationEngine
   computes a SHA-256 hash over the *hardened source + security invariants*.

2. This hash is embedded as a structured comment at the top of the file:

       # @agent-armor-attestation: <sha256-hex>
       # @invariants: {"auth_required": false, "no_dangerous_sinks": true, ...}
       # @version: 1.0.0  @timestamp: 2026-02-25T12:00:00Z

3. The hash is also recorded in the Shadow-Chain (see shadow_chain/chain_manager.py).

4. If a human or another AI later modifies the code and accidentally removes
   a security check, re-computing the hash will produce a different value.
   The CI/CD pipeline can then call `armor verify <file>` to detect the
   tampering and block the deployment.

Security invariants
-------------------
The invariants are derived automatically from the AgentArmor pipeline results:

  no_secrets          → secret scrubber found 0 findings
  no_dangerous_sinks  → AST hardener found 0 CRITICAL findings
  no_sql_injection    → AST hardener found 0 SQLInjection findings
  no_command_injection→ AST hardener found 0 CommandInjection findings
  no_unsanitised_flows→ DTG engine found 0 findings
  deps_validated      → slopsquatting guard found 0 HIGH+ findings
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

_ATTESTATION_VERSION = "1.0.0"
_HEADER_RE = re.compile(
    r"^#\s*@agent-armor-attestation:\s*([a-f0-9]{64})",
    re.MULTILINE,
)
_INVARIANTS_RE = re.compile(
    r"^#\s*@invariants:\s*(\{.*\})",
    re.MULTILINE,
)


@dataclass
class Attestation:
    """Represents a single cryptographic attestation for a code block."""
    signature: str                      # SHA-256 hex digest
    timestamp: str                      # ISO-8601 UTC
    invariants: Dict[str, Any] = field(default_factory=dict)
    version: str = _ATTESTATION_VERSION
    filename: str = "unknown"

    def to_header_comment(self) -> str:
        """Render the attestation as header comment lines."""
        inv_json = json.dumps(self.invariants, separators=(",", ":"))
        return (
            f"# @agent-armor-attestation: {self.signature}\n"
            f"# @invariants: {inv_json}\n"
            f"# @version: {self.version}  @timestamp: {self.timestamp}\n"
        )

    def to_dict(self) -> dict:
        return {
            "signature": self.signature,
            "timestamp": self.timestamp,
            "invariants": self.invariants,
            "version": self.version,
            "filename": self.filename,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Attestation":
        return cls(
            signature=d["signature"],
            timestamp=d["timestamp"],
            invariants=d.get("invariants", {}),
            version=d.get("version", _ATTESTATION_VERSION),
            filename=d.get("filename", "unknown"),
        )


class AttestationEngine:
    """
    Generates and verifies cryptographic attestations for hardened code.

    Usage::

        engine = AttestationEngine()
        attestation = engine.sign(hardened_code, invariants)
        signed_code  = engine.embed(hardened_code, attestation)
        is_valid     = engine.verify(signed_code, attestation.signature)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sign(
        self,
        hardened_code: str,
        invariants: Dict[str, Any],
        filename: str = "unknown",
    ) -> Attestation:
        """
        Compute a SHA-256 attestation over *hardened_code* + *invariants*.

        The hash covers both the source code and the security invariant map
        so that removing invariant-enforcing code will invalidate it.
        """
        payload = self._build_payload(hardened_code, invariants)
        sig = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return Attestation(
            signature=sig,
            timestamp=ts,
            invariants=invariants,
            filename=filename,
        )

    def embed(self, hardened_code: str, attestation: Attestation) -> str:
        """
        Prepend the attestation header comment to *hardened_code*.
        Replaces any existing attestation header.
        """
        # Strip existing attestation if present
        stripped = self._strip_header(hardened_code)
        return attestation.to_header_comment() + stripped

    def verify(self, signed_code: str, expected_sig: str) -> bool:
        """
        Re-derive the attestation hash from *signed_code* and compare with
        *expected_sig*.  Returns True if the code has not been tampered with.

        The function strips the attestation header before hashing, then
        reconstructs invariants from the stored @invariants comment.
        """
        invariants = self._extract_invariants(signed_code)
        clean_code = self._strip_header(signed_code)
        payload = self._build_payload(clean_code, invariants)
        actual_sig = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return actual_sig == expected_sig

    def extract_signature(self, signed_code: str) -> Optional[str]:
        """Extract the @agent-armor-attestation hash from *signed_code*, if present."""
        match = _HEADER_RE.search(signed_code)
        return match.group(1) if match else None

    def derive_invariants(
        self,
        secret_findings: list,
        ast_findings: list,
        dtg_findings: list,
        package_findings: list,
    ) -> Dict[str, Any]:
        """
        Build an invariants dict from pipeline findings.
        Used so the signature covers the *security posture* of the code.
        """
        critical_ast = [f for f in ast_findings if f.severity == "CRITICAL"]
        sql_issues   = [f for f in ast_findings if f.node_type == "SQLInjection"]
        cmd_issues   = [f for f in ast_findings if f.node_type == "CommandInjection"]
        high_pkgs    = [f for f in package_findings if f.severity in ("CRITICAL", "HIGH")]

        return {
            "no_secrets":           len(secret_findings) == 0,
            "no_dangerous_sinks":   len(critical_ast) == 0,
            "no_sql_injection":     len(sql_issues) == 0,
            "no_command_injection": len(cmd_issues) == 0,
            "no_unsanitised_flows": len(dtg_findings) == 0,
            "deps_validated":       len(high_pkgs) == 0,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload(code: str, invariants: Dict[str, Any]) -> str:
        """Canonical string used as SHA-256 input."""
        inv_str = json.dumps(invariants, sort_keys=True)
        # Normalise line endings for cross-platform stability
        normalised = code.replace("\r\n", "\n").strip()
        return f"AGENT-ARMOR-V1\n{inv_str}\n{normalised}"

    @staticmethod
    def _strip_header(code: str) -> str:
        """Remove existing @agent-armor-* header lines."""
        lines = code.splitlines(keepends=True)
        cleaned = [
            line for line in lines
            if not line.lstrip().startswith("# @agent-armor-")
            and not line.lstrip().startswith("# @invariants:")
            and not line.lstrip().startswith("# @version:")
        ]
        return "".join(cleaned)

    @staticmethod
    def _extract_invariants(code: str) -> Dict[str, Any]:
        """Parse the @invariants JSON comment from *code*."""
        match = _INVARIANTS_RE.search(code)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        return {}
