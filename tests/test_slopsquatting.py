"""
Tests for the Slopsquatting Guard.
Tests that don't require network access are marked separately.
"""

import pytest
from agent_armor.guards.slopsquatting_guard import SlopsquattingGuard, PackageFinding


@pytest.fixture
def guard():
    return SlopsquattingGuard()


class TestImportExtraction:

    def test_extracts_simple_import(self, guard):
        code = "import requests\n"
        pkgs = guard._extract_imports(code)
        assert "requests" in pkgs

    def test_extracts_from_import(self, guard):
        code = "from pathlib import Path\n"
        pkgs = guard._extract_imports(code)
        # pathlib is stdlib, should be excluded
        assert "pathlib" not in pkgs

    def test_filters_stdlib_modules(self, guard):
        code = "import os\nimport sys\nimport re\n"
        pkgs = guard._extract_imports(code)
        assert "os" not in pkgs
        assert "sys" not in pkgs
        assert "re" not in pkgs

    def test_multiple_imports(self, guard):
        code = "import requests\nimport click\nimport rich\n"
        pkgs = guard._extract_imports(code)
        for pkg in ["requests", "click", "rich"]:
            assert pkg in pkgs

    def test_deduplicates_imports(self, guard):
        code = "import requests\nimport requests\n"
        pkgs = guard._extract_imports(code)
        assert pkgs.count("requests") == 1

    def test_handles_syntax_error_gracefully(self, guard):
        code = "import requests\ndef broken(:\n    pass\n"
        pkgs = guard._extract_imports(code)
        # Should still extract what it can
        assert isinstance(pkgs, list)


class TestBlocklist:

    def test_colourama_is_blocked(self, guard):
        findings = guard.check_single("colourama")
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert len(critical) > 0

    def test_url_lib4_is_blocked(self, guard):
        findings = guard.check_single("urllib4")
        critical = [f for f in findings if f.check_id == "CHECK-5-BLOCKLIST"]
        assert len(critical) > 0

    def test_legitimate_package_not_blocklisted(self, guard):
        # requests is not on the blocklist
        findings = guard.check_single("requests")
        blocked = [f for f in findings if f.check_id == "CHECK-5-BLOCKLIST"]
        assert len(blocked) == 0


class TestTyposquatting:

    def test_detects_fatsapi_as_typosquat(self, guard):
        findings = guard.check_single("fatsapi")
        typo = [f for f in findings if f.check_id == "CHECK-4-TYPOSQUATTING"]
        assert len(typo) > 0

    def test_detects_nump_as_typosquat_of_numpy(self, guard):
        findings = guard.check_single("nump")
        typo = [f for f in findings if f.check_id == "CHECK-4-TYPOSQUATTING"]
        assert len(typo) > 0

    def test_pands_typosquats_pandas(self, guard):
        findings = guard.check_single("pands")
        typo = [f for f in findings if f.check_id == "CHECK-4-TYPOSQUATTING"]
        assert len(typo) > 0

    def test_exact_popular_package_not_flagged_as_typosquat(self, guard):
        findings = guard.check_single("requests")
        typo = [f for f in findings if f.check_id == "CHECK-4-TYPOSQUATTING"]
        assert len(typo) == 0

    def test_completely_different_name_not_typosquat(self, guard):
        # "zebra" is not similar to any popular package
        findings = guard.check_single("zebrafoo_unique_12345")
        typo = [f for f in findings if f.check_id == "CHECK-4-TYPOSQUATTING"]
        assert len(typo) == 0


class TestLevenshteinDistance:

    def test_distance_same_strings(self, guard):
        assert guard._levenshtein("hello", "hello") == 0

    def test_distance_one_substitution(self, guard):
        assert guard._levenshtein("hello", "helo") == 1

    def test_distance_one_insertion(self, guard):
        assert guard._levenshtein("hello", "helloo") == 1

    def test_distance_one_deletion(self, guard):
        assert guard._levenshtein("flask", "flsk") == 1

    def test_distance_completely_different(self, guard):
        assert guard._levenshtein("abc", "xyz") == 3


class TestStdlibFiltering:

    def test_os_is_stdlib(self, guard):
        assert guard._is_stdlib("os") is True

    def test_sys_is_stdlib(self, guard):
        assert guard._is_stdlib("sys") is True

    def test_requests_is_not_stdlib(self, guard):
        assert guard._is_stdlib("requests") is False

    def test_click_is_not_stdlib(self, guard):
        assert guard._is_stdlib("click") is False


class TestPackageFinding:

    def test_finding_str_representation(self):
        f = PackageFinding(
            package_name="colourama",
            check_id="CHECK-5-BLOCKLIST",
            severity="CRITICAL",
            description="Known malicious package",
            recommendation="Remove it.",
        )
        s = str(f)
        assert "CRITICAL" in s
        assert "colourama" in s


class TestScanWithCode:

    def test_scan_returns_list(self, guard):
        code = "import requests\nimport click\n"
        findings = guard.scan(code)
        assert isinstance(findings, list)

    def test_blocklisted_package_in_code_flagged(self, guard):
        code = "import colourama\n"
        findings = guard.scan(code)
        blocked = [f for f in findings if f.check_id == "CHECK-5-BLOCKLIST"]
        assert len(blocked) > 0

    def test_typosquatting_in_code_flagged(self, guard):
        code = "import fatsapi\n"
        findings = guard.scan(code)
        typo = [f for f in findings if f.check_id == "CHECK-4-TYPOSQUATTING"]
        assert len(typo) > 0
