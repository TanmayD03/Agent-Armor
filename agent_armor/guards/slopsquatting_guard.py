# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor — Slopsquatting Guard
==================================
Defends against AI "dependency hallucination" attacks.

The Problem
-----------
AI agents sometimes invent package names that:
  1. Don't exist on PyPI/npm (hallucination)
  2. Closely resemble popular packages (typosquatting)
  3. Were registered very recently (supply-chain squatting)
  4. Have suspiciously few downloads (abandoned/malicious)

This guard validates every import statement against the live PyPI
JSON API (with a local cache to avoid hammering the registry).

Checks performed
----------------
  CHECK-1  Package existence on PyPI
  CHECK-2  Download count (< 1,000 total downloads → suspicious)
  CHECK-3  Package age (< 7 days since first release → suspicious)
  CHECK-4  Typosquatting detection via Levenshtein distance
           against a curated list of popular packages
  CHECK-5  Known malicious package blocklist

Offline mode
------------
If the PyPI API is unreachable, the guard operates in OFFLINE mode
and only applies the blocklist and typosquatting checks using the
locally-known popular package list.
"""

from __future__ import annotations

import ast
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

try:
    import requests

    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Curated list of very popular packages — used for typosquatting detection
# ---------------------------------------------------------------------------
_POPULAR_PACKAGES: List[str] = [
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "fastapi",
    "sqlalchemy",
    "boto3",
    "pydantic",
    "pytest",
    "click",
    "rich",
    "httpx",
    "aiohttp",
    "cryptography",
    "pillow",
    "scipy",
    "matplotlib",
    "scikit-learn",
    "tensorflow",
    "torch",
    "transformers",
    "langchain",
    "openai",
    "anthropic",
    "celery",
    "redis",
    "pymongo",
    "psycopg2",
    "alembic",
    "uvicorn",
    "gunicorn",
    "paramiko",
    "fabric",
    "ansible",
    "docker",
    "kubernetes",
    "stripe",
    "twilio",
    "sendgrid",
    "jwt",
    "pyjwt",
    "passlib",
    "bcrypt",
    "lxml",
    "beautifulsoup4",
    "selenium",
    "playwright",
    "httplib2",
]

# ---------------------------------------------------------------------------
# Known malicious package blocklist (subset of documented cases)
# ---------------------------------------------------------------------------
_BLOCKLIST: Set[str] = {
    "colourama",  # typosquats 'colorama'
    "urllib4",  # fake urllib
    "python-sqlite",  # fake sqlite
    "setup-tools",  # fake setuptools
    "pip-install",  # fake pip
    "pyOpenSSL2",  # fake pyOpenSSL
    "request",  # typosquats 'requests'
    # nump / pands intentionally omitted — caught by typosquatting CHECK-4 (edit-distance 1)
    "djnago",  # typosquats 'django'
    "flsk",  # typosquats 'flask'
    "fasapi",  # typosquats 'fastapi'
}

_PYPI_BASE = "https://pypi.org/pypi/{package}/json"
_CACHE_TTL_SECONDS = 3600  # 1 hour


@dataclass
class PackageFinding:
    """A single suspicious package finding."""

    package_name: str
    check_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    recommendation: str

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.check_id} – '{self.package_name}': "
            f"{self.description}"
        )


class SlopsquattingGuard:
    """
    Validates Python import statements against the PyPI registry.

    Usage::

        guard = SlopsquattingGuard()
        findings = guard.scan(source_code)
        for f in findings:
            print(f)
    """

    #: Download threshold below which a package is flagged as suspicious.
    MIN_DOWNLOADS: int = 1_000
    #: Package age in days below which it is flagged.
    MIN_AGE_DAYS: int = 7
    #: Max Levenshtein distance for typosquatting detection.
    MAX_EDIT_DISTANCE: int = 2

    def __init__(
        self,
        cache_path: Optional[Path] = None,
        offline: bool = False,
    ) -> None:
        self._offline = offline
        self._cache: Dict[str, dict] = {}
        self._cache_timestamps: Dict[str, float] = {}
        self._cache_path = cache_path or Path(".kvlr") / "pypi-cache.json"
        if not offline:
            self._load_disk_cache()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, source_code: str) -> List[PackageFinding]:
        """
        Extract all import statements from *source_code* and validate
        each package.  Returns a list of :class:`PackageFinding` objects.
        """
        packages = self._extract_imports(source_code)
        findings: List[PackageFinding] = []
        for pkg in packages:
            findings.extend(self._check_package(pkg))
        return findings

    def check_single(self, package_name: str) -> List[PackageFinding]:
        """Check a single package name."""
        return self._check_package(package_name)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _extract_imports(self, source_code: str) -> List[str]:
        """Return the list of top-level module names imported in *source_code*."""
        packages: List[str] = []
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            # Fallback: regex scan
            for m in re.finditer(r"^import\s+([\w]+)", source_code, re.MULTILINE):
                packages.append(m.group(1))
            for m in re.finditer(r"^from\s+([\w]+)", source_code, re.MULTILINE):
                packages.append(m.group(1))
            return list(dict.fromkeys(packages))  # deduplicate

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    packages.append(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    packages.append(node.module.split(".")[0])

        # Deduplicate, filter stdlib
        return [p for p in dict.fromkeys(packages) if not self._is_stdlib(p)]

    def _check_package(self, package_name: str) -> List[PackageFinding]:
        findings: List[PackageFinding] = []
        pkg_norm = package_name.lower().replace("-", "_")

        # CHECK-5: Blocklist
        if pkg_norm in {b.lower().replace("-", "_") for b in _BLOCKLIST}:
            findings.append(
                PackageFinding(
                    package_name=package_name,
                    check_id="CHECK-5-BLOCKLIST",
                    severity="CRITICAL",
                    description=f"'{package_name}' is on the known-malicious package blocklist.",
                    recommendation="Remove this dependency immediately.",
                )
            )
            return findings  # No need to check further

        # CHECK-4: Typosquatting
        typo_match = self._nearest_popular(pkg_norm)
        if typo_match:
            findings.append(
                PackageFinding(
                    package_name=package_name,
                    check_id="CHECK-4-TYPOSQUATTING",
                    severity="HIGH",
                    description=(
                        f"'{package_name}' is suspiciously similar to popular package "
                        f"'{typo_match}' (edit distance ≤ {self.MAX_EDIT_DISTANCE})."
                    ),
                    recommendation=f"Did you mean '{typo_match}'? Verify this is the correct package.",
                )
            )

        # CHECK-1/2/3: Live PyPI lookup (skipped entirely in offline mode)
        if self._offline:
            return findings

        pypi_data = self._fetch_pypi(package_name)
        if pypi_data is None:
            if _REQUESTS_AVAILABLE:
                findings.append(
                    PackageFinding(
                        package_name=package_name,
                        check_id="CHECK-1-NOT-FOUND",
                        severity="CRITICAL",
                        description=f"'{package_name}' was NOT found on PyPI — possible hallucination.",
                        recommendation="Verify the package name. This may be an AI-invented package.",
                    )
                )
            return findings

        # CHECK-2: Download count
        downloads = self._get_download_count(pypi_data)
        if downloads is not None and downloads < self.MIN_DOWNLOADS:
            findings.append(
                PackageFinding(
                    package_name=package_name,
                    check_id="CHECK-2-LOW-DOWNLOADS",
                    severity="HIGH",
                    description=(
                        f"'{package_name}' has only {downloads:,} total downloads — "
                        f"threshold is {self.MIN_DOWNLOADS:,}."
                    ),
                    recommendation="Use a well-established package instead, or audit this one carefully.",
                )
            )

        # CHECK-3: Package age
        age_days = self._get_age_days(pypi_data)
        if age_days is not None and age_days < self.MIN_AGE_DAYS:
            findings.append(
                PackageFinding(
                    package_name=package_name,
                    check_id="CHECK-3-NEW-PACKAGE",
                    severity="HIGH",
                    description=(
                        f"'{package_name}' was first published only {age_days} day(s) ago — "
                        f"possible supply-chain squatting attack."
                    ),
                    recommendation="Do not install packages published < 7 days ago without thorough review.",
                )
            )

        return findings

    def _fetch_pypi(self, package_name: str) -> Optional[dict]:
        """Fetch PyPI JSON metadata with caching."""
        if self._offline:
            return None  # Offline mode — skip all PyPI calls

        key = package_name.lower()
        now = time.time()

        # Return cached result if fresh
        if (
            key in self._cache
            and (now - self._cache_timestamps.get(key, 0)) < _CACHE_TTL_SECONDS
        ):
            return self._cache[key]

        if not _REQUESTS_AVAILABLE:
            return None  # requests not installed

        try:
            resp = requests.get(
                _PYPI_BASE.format(package=package_name),
                timeout=5,
                headers={"User-Agent": "AgentArmor/1.0"},
            )
            if resp.status_code == 404:
                self._cache[key] = None  # type: ignore[assignment]
                self._cache_timestamps[key] = now
                return None
            resp.raise_for_status()
            data = resp.json()
            self._cache[key] = data
            self._cache_timestamps[key] = now
            self._save_disk_cache()
            return data
        except Exception:
            return None  # Treat as offline

    @staticmethod
    def _get_download_count(pypi_data: dict) -> Optional[int]:
        """Extract total download count from PyPI JSON data."""
        try:
            # PyPI JSON API doesn't include download stats directly;
            # use the 'info' section's known download field if present.
            releases = pypi_data.get("releases", {})
            total = 0
            for version_files in releases.values():
                for file_info in version_files:
                    total += file_info.get("downloads", -1)
            if total == -1:
                return None  # PyPI disabled download stats
            return total if total > 0 else None
        except Exception:
            return None

    @staticmethod
    def _get_age_days(pypi_data: dict) -> Optional[int]:
        """Compute the age in days of the first published release."""
        try:
            releases = pypi_data.get("releases", {})
            if not releases:
                return None
            all_dates = []
            for version_files in releases.values():
                for file_info in version_files:
                    utime = file_info.get("upload_time")
                    if utime:
                        dt = datetime.fromisoformat(utime.replace("Z", "+00:00"))
                        all_dates.append(dt)
            if not all_dates:
                return None
            first = min(all_dates)
            age = (datetime.now(timezone.utc) - first).days
            return age
        except Exception:
            return None

    def _nearest_popular(self, pkg_norm: str) -> Optional[str]:
        """Return the nearest popular package if within MAX_EDIT_DISTANCE."""
        if pkg_norm in {p.lower().replace("-", "_") for p in _POPULAR_PACKAGES}:
            return None  # It IS a popular package, no concern
        best: Optional[str] = None
        best_dist = self.MAX_EDIT_DISTANCE + 1
        for popular in _POPULAR_PACKAGES:
            pop_norm = popular.lower().replace("-", "_")
            d = self._levenshtein(pkg_norm, pop_norm)
            if 0 < d <= self.MAX_EDIT_DISTANCE and d < best_dist:
                best_dist = d
                best = popular
        return best

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Compute the Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            s1, s2 = s2, s1
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(
                    min(
                        prev[j + 1] + 1,  # deletion
                        curr[j] + 1,  # insertion
                        prev[j] + (c1 != c2),  # substitution
                    )
                )
            prev = curr
        return prev[-1]

    @staticmethod
    def _is_stdlib(name: str) -> bool:
        """Return True if *name* is a Python standard library module."""
        import sys

        if hasattr(sys, "stdlib_module_names"):
            return name in sys.stdlib_module_names  # Python 3.10+
        # Fallback for older Python versions
        _STDLIB = {
            "os",
            "sys",
            "re",
            "ast",
            "json",
            "math",
            "time",
            "datetime",
            "pathlib",
            "typing",
            "dataclasses",
            "enum",
            "abc",
            "io",
            "collections",
            "itertools",
            "functools",
            "operator",
            "copy",
            "string",
            "random",
            "hashlib",
            "hmac",
            "base64",
            "struct",
            "socket",
            "http",
            "urllib",
            "email",
            "html",
            "xml",
            "csv",
            "sqlite3",
            "logging",
            "unittest",
            "subprocess",
            "threading",
            "multiprocessing",
            "asyncio",
            "concurrent",
            "contextlib",
            "textwrap",
            "inspect",
            "importlib",
            "pkgutil",
            "zipfile",
            "tarfile",
            "shutil",
            "tempfile",
            "glob",
            "fnmatch",
            "traceback",
            "warnings",
            "gc",
            "weakref",
            "platform",
            "signal",
            "errno",
            "ctypes",
            "builtins",
        }
        return name in _STDLIB

    def _load_disk_cache(self) -> None:
        try:
            if self._cache_path.exists():
                data = json.loads(self._cache_path.read_text(encoding="utf-8"))
                self._cache = data.get("cache", {})
                self._cache_timestamps = {
                    k: float(v) for k, v in data.get("timestamps", {}).items()
                }
        except Exception:
            pass

    def _save_disk_cache(self) -> None:
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            data = {"cache": self._cache, "timestamps": self._cache_timestamps}
            self._cache_path.write_text(json.dumps(data, default=str), encoding="utf-8")
        except Exception:
            pass
