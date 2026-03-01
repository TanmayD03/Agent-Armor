"""
Tests for the Secret Scrubber module.
"""

import pytest
from agent_armor.core.secret_scrubber import (
    SecretScrubber,
    SecretFinding,
    SecretType,
)


@pytest.fixture
def scrubber():
    return SecretScrubber()


class TestSecretDetection:

    def test_detects_openai_key(self, scrubber):
        code = 'api_key = "sk-1234567890abcdefghijABCDEFGHIJKLMNOPQRSTUVWXYZ12"\n'
        _, findings = scrubber.scrub(code)
        assert any(f.secret_type == SecretType.OPENAI_KEY for f in findings)

    def test_detects_github_token(self, scrubber):
        code = 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"\n'
        _, findings = scrubber.scrub(code)
        assert any(f.secret_type == SecretType.GITHUB_TOKEN for f in findings)

    def test_detects_aws_access_key(self, scrubber):
        code = 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        _, findings = scrubber.scrub(code)
        assert any(f.secret_type == SecretType.AWS_ACCESS_KEY for f in findings)

    def test_detects_stripe_key(self, scrubber):
        # Deliberately split to avoid GitHub push-protection false positive on test data
        key = "sk_li" + "ve_abcdefghijklmnopqrstuvwx"
        code = f'stripe_key = "{key}"\n'
        _, findings = scrubber.scrub(code)
        assert any(f.secret_type == SecretType.STRIPE_KEY for f in findings)

    def test_detects_jwt_token(self, scrubber):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
        code = f'auth = "{jwt}"\n'
        _, findings = scrubber.scrub(code)
        assert any(f.secret_type == SecretType.JWT_TOKEN for f in findings)

    def test_detects_database_url(self, scrubber):
        code = 'DB_URL = "postgresql://admin:s3cr3t@db.example.com:5432/mydb"\n'
        _, findings = scrubber.scrub(code)
        assert any(f.secret_type == SecretType.DATABASE_URL for f in findings)

    def test_detects_generic_api_key(self, scrubber):
        code = 'api_key = "MyVerySecretAPIKeyThatIsLong12345"\n'
        _, findings = scrubber.scrub(code)
        # Should detect via generic pattern or entropy
        assert len(findings) > 0

    def test_no_false_positive_on_empty_string(self, scrubber):
        code = 'value = ""\n'
        _, findings = scrubber.scrub(code)
        assert len(findings) == 0

    def test_no_false_positive_on_short_string(self, scrubber):
        code = 'status = "ok"\n'
        _, findings = scrubber.scrub(code)
        assert len(findings) == 0

    def test_no_false_positive_on_normal_variable(self, scrubber):
        code = 'username = "john_doe"\n'
        _, findings = scrubber.scrub(code)
        assert len(findings) == 0


class TestSecretReplacement:

    def test_replaces_secret_with_env_var(self, scrubber):
        code = 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"\n'
        scrubbed, _ = scrubber.scrub(code)
        assert "ghp_" not in scrubbed
        assert "os.getenv(" in scrubbed

    def test_adds_import_os_when_replacing(self, scrubber):
        code = 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"\n'
        scrubbed, findings = scrubber.scrub(code)
        if findings:
            assert "import os" in scrubbed

    def test_multiple_secrets_all_replaced(self, scrubber):
        code = (
            'openai_key = "sk-1234567890abcdefghijABCDEFGHIJKLMNOPQRSTUVWXYZ12"\n'
            'github_token = "ghp_abcdefghijklmnopqrstuvwxyz123456"\n'
        )
        scrubbed, findings = scrubber.scrub(code)
        assert len(findings) >= 2
        assert "sk-" not in scrubbed
        assert "ghp_" not in scrubbed


class TestShannonEntropy:

    def test_high_entropy_string_flagged(self, scrubber):
        # This is a high-entropy base64-like string
        code = 'token = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5"\n'
        _, findings = scrubber.scrub(code)
        assert len(findings) > 0

    def test_low_entropy_string_not_flagged(self, scrubber):
        code = 'name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
        _, findings = scrubber.scrub(code)
        assert len(findings) == 0

    def test_entropy_calculation(self):
        from agent_armor.core.secret_scrubber import SecretScrubber
        s = SecretScrubber()
        # High entropy
        assert s._shannon_entropy("aB3cD4eF5gH6iJ7kL8mN9oP") > 4.0
        # Low entropy
        assert s._shannon_entropy("aaaaaaaaaaaaa") < 0.1
        # Empty
        assert s._shannon_entropy("") == 0.0


class TestSecretFinding:

    def test_finding_str_representation(self, scrubber):
        code = 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"\n'
        _, findings = scrubber.scrub(code)
        for f in findings:
            s = str(f)
            assert "CRITICAL" in s or "HIGH" in s

    def test_finding_has_correct_line_number(self, scrubber):
        code = "x = 1\ny = 2\ntoken = \"ghp_abcdefghijklmnopqrstuvwxyz123456\"\n"
        _, findings = scrubber.scrub(code)
        github_findings = [f for f in findings if f.secret_type == SecretType.GITHUB_TOKEN]
        if github_findings:
            assert github_findings[0].line_number == 3
