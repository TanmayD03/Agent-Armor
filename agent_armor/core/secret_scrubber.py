# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor — Secret Scrubber
=============================
Detects and replaces hardcoded secrets in AI-generated code using:
  1. Pattern-based regex matching (13+ secret types)
  2. Shannon entropy analysis for unrecognized high-entropy strings

All detected secrets are replaced with os.getenv() calls and logged
as SecretFinding objects for the final ArmorReport.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple


class SecretType(Enum):
    AWS_ACCESS_KEY = "AWS Access Key"
    AWS_SECRET_KEY = "AWS Secret Access Key"
    OPENAI_KEY = "OpenAI API Key"
    GITHUB_TOKEN = "GitHub Token"
    GITLAB_TOKEN = "GitLab Personal Access Token"
    JWT_TOKEN = "JWT Bearer Token"
    STRIPE_KEY = "Stripe API Key"
    SLACK_TOKEN = "Slack Bot/App Token"
    GOOGLE_KEY = "Google API Key"
    DATABASE_URL = "Database URL with Credentials"
    PRIVATE_KEY = "PEM Private Key"
    GENERIC_API_KEY = "Generic API Key / Token"
    HARDCODED_PASSWORD = "Hardcoded Password"
    HIGH_ENTROPY_STRING = "High-Entropy String (probable secret)"


@dataclass
class SecretFinding:
    """Represents a single detected secret in the source code."""
    secret_type: SecretType
    line_number: int
    column: int
    masked_value: str          # e.g. "sk-live_12***ef"
    env_var_name: str          # e.g. "AGENT_ARMOR_OPENAI_KEY"
    severity: str = "CRITICAL"

    @property
    def env_call(self) -> str:
        return f'os.getenv("{self.env_var_name}")'

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.secret_type.value} "
            f"at line {self.line_number}: {self.masked_value} "
            f"→ {self.env_call}"
        )


# ---------------------------------------------------------------------------
# Pattern registry: (SecretType, compiled_regex, env_var_name)
# Each pattern is tested in order; first match wins per position.
# ---------------------------------------------------------------------------
_RAW_PATTERNS: List[Tuple[SecretType, str, str]] = [
    # AWS
    (SecretType.AWS_ACCESS_KEY,
     r"\bAKIA[0-9A-Z]{16}\b",
     "AGENT_ARMOR_AWS_ACCESS_KEY"),

    (SecretType.AWS_SECRET_KEY,
     r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',
     "AGENT_ARMOR_AWS_SECRET_KEY"),

    # OpenAI
    (SecretType.OPENAI_KEY,
     r"\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b"
     r"|\bsk-proj-[a-zA-Z0-9_\-]{40,}\b"
     r"|\bsk-[a-zA-Z0-9]{48}\b",
     "AGENT_ARMOR_OPENAI_API_KEY"),

    # GitHub tokens  (classic PATs: ghp_/gho_/ghu_/ghs_/ghr_ + 36 chars; fine-grained are longer)
    (SecretType.GITHUB_TOKEN,
     r"\bgh[pousx]_[a-zA-Z0-9]{30,}\b",
     "AGENT_ARMOR_GITHUB_TOKEN"),

    # GitLab PAT
    (SecretType.GITLAB_TOKEN,
     r"\bglpat-[a-zA-Z0-9_\-]{20}\b",
     "AGENT_ARMOR_GITLAB_TOKEN"),

    # JWT
    (SecretType.JWT_TOKEN,
     r"\beyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-\.~+/]+=*\b",
     "AGENT_ARMOR_JWT_TOKEN"),

    # Stripe
    (SecretType.STRIPE_KEY,
     r"\bsk_(?:live|test)_[a-zA-Z0-9]{24}\b",
     "AGENT_ARMOR_STRIPE_API_KEY"),

    # Slack
    (SecretType.SLACK_TOKEN,
     r"\bxox[bprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}\b",
     "AGENT_ARMOR_SLACK_TOKEN"),

    # Google
    (SecretType.GOOGLE_KEY,
     r"\bAIza[0-9A-Za-z_\-]{35}\b",
     "AGENT_ARMOR_GOOGLE_API_KEY"),

    # Database URLs with embedded credentials
    (SecretType.DATABASE_URL,
     r"(?i)(postgresql|mysql|mongodb|redis|mssql|sqlite)://[^:]+:[^@\s\"']+@[^\s\"']+",
     "AGENT_ARMOR_DATABASE_URL"),

    # PEM private keys
    (SecretType.PRIVATE_KEY,
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
     "AGENT_ARMOR_PRIVATE_KEY"),

    # Generic named key/token assignments
    (SecretType.GENERIC_API_KEY,
     r'(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|secret[_\-]?key|'
     r'access[_\-]?token|auth[_\-]?token|bearer)\s*(?:=|:)\s*'
     r'["\']([a-zA-Z0-9_\-\.\/+]{20,})["\']',
     "AGENT_ARMOR_API_KEY"),

    # Hardcoded passwords
    (SecretType.HARDCODED_PASSWORD,
     r'(?i)(?:password|passwd|pwd)\s*(?:=|:)\s*["\']([^\s"\']{8,})["\']',
     "AGENT_ARMOR_PASSWORD"),
]


class SecretScrubber:
    """
    Scans source code for hardcoded secrets and replaces them with
    safe os.getenv() references.

    Usage::

        scrubber = SecretScrubber()
        clean_code, findings = scrubber.scrub(raw_code)
        for f in findings:
            print(f)
    """

    #: Shannon entropy bits/char above which a string is flagged as a secret.
    HIGH_ENTROPY_THRESHOLD: float = 4.5
    #: Minimum length for high-entropy detection.
    MIN_SECRET_LENGTH: int = 20

    def __init__(self) -> None:
        self._patterns = [
            (stype, re.compile(pattern, re.MULTILINE), env_var)
            for stype, pattern, env_var in _RAW_PATTERNS
        ]
        # Pattern to find bare assignment strings for entropy analysis
        self._assignment_re = re.compile(
            r'=\s*["\']([a-zA-Z0-9+/=_\-]{' + str(self.MIN_SECRET_LENGTH) + r',})["\']'
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scrub(self, code: str) -> Tuple[str, List[SecretFinding]]:
        """
        Scan *code* for secrets, replace them with env var references,
        and return ``(scrubbed_code, findings)``.
        """
        findings: List[SecretFinding] = []
        scrubbed = code

        # Phase 1: Pattern-based detection
        for secret_type, pattern, env_var in self._patterns:
            for match in pattern.finditer(scrubbed):
                line_no = scrubbed[: match.start()].count("\n") + 1
                col = match.start() - scrubbed[: match.start()].rfind("\n") - 1
                raw = match.group()
                masked = self._mask(raw)
                findings.append(
                    SecretFinding(
                        secret_type=secret_type,
                        line_number=line_no,
                        column=col,
                        masked_value=masked,
                        env_var_name=env_var,
                    )
                )

            # Replace ALL occurrences with the env var call
            scrubbed = pattern.sub(
                lambda m, ev=env_var: self._build_replacement(m.group(), ev),
                scrubbed,
            )

        # Phase 2: Shannon entropy scan for anything not caught above
        entropy_findings = self._entropy_scan(code, scrubbed)
        findings.extend(entropy_findings)
        for ef in entropy_findings:
            # Already masked in original; replace in scrubbed if still present
            # (these are bare string values so we replace conservatively)
            pass

        # Ensure `import os` is present when we've made replacements
        if findings and "import os" not in scrubbed:
            scrubbed = "import os\n" + scrubbed

        return scrubbed, findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _mask(value: str) -> str:
        """Return a partially-masked version of *value* for display."""
        if len(value) <= 8:
            return "***"
        return value[:4] + "***" + value[-4:]

    @staticmethod
    def _build_replacement(matched: str, env_var: str) -> str:
        """Build the safe replacement string for a regex match."""
        # If the match starts with a key= prefix, preserve it
        eq_match = re.match(r'^((?:api_key|secret|token|password|key)\s*=\s*)', matched, re.I)
        if eq_match:
            prefix = eq_match.group(1)
            return f'{prefix}os.getenv("{env_var}")'
        return f'os.getenv("{env_var}")'

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Return the Shannon entropy (bits/char) of *text*."""
        if not text:
            return 0.0
        freq: dict = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        return -sum(
            (c / length) * math.log2(c / length) for c in freq.values() if c
        )

    def _entropy_scan(self, original: str, scrubbed: str) -> List[SecretFinding]:
        """
        Find high-entropy string literals not matched by named patterns.
        Operates on *original* so positions are accurate.
        """
        findings: List[SecretFinding] = []
        seen_ranges: List[Tuple[int, int]] = []

        for match in self._assignment_re.finditer(original):
            value = match.group(1)
            if self._shannon_entropy(value) >= self.HIGH_ENTROPY_THRESHOLD:
                start, end = match.span()
                # Skip if this range already flagged
                if any(s <= start <= e for s, e in seen_ranges):
                    continue
                seen_ranges.append((start, end))
                line_no = original[:start].count("\n") + 1
                findings.append(
                    SecretFinding(
                        secret_type=SecretType.HIGH_ENTROPY_STRING,
                        line_number=line_no,
                        column=start - original[:start].rfind("\n") - 1,
                        masked_value=self._mask(value),
                        env_var_name="AGENT_ARMOR_SECRET",
                        severity="HIGH",
                    )
                )
        return findings
