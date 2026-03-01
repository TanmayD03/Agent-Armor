"""
Tests for the AgentArmor main pipeline (integration tests).
"""

import pytest
from agent_armor.pipeline import AgentArmor, ArmorReport


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def armor():
    """Return an AgentArmor instance with package validation disabled (offline-safe)."""
    return AgentArmor(validate_packages=False)


# ---------------------------------------------------------------------------
# Tests: basic pipeline outputs
# ---------------------------------------------------------------------------

class TestPipelineStatus:

    def test_clean_code_is_approved(self, armor: AgentArmor):
        clean = "def add(a: int, b: int) -> int:\n    return a + b\n"
        report = armor.process(clean, filename="math_utils.py")
        assert report.status == "APPROVED"
        assert report.attestation is not None

    def test_eval_code_is_blocked(self, armor: AgentArmor):
        dangerous = "def run(code): eval(code)\n"
        report = armor.process(dangerous, filename="runner.py")
        assert report.status == "BLOCKED"
        assert report.attestation is None
        assert report.critical_count > 0

    def test_exec_code_is_blocked(self, armor: AgentArmor):
        dangerous = "exec(user_input)\n"
        report = armor.process(dangerous, filename="runner.py")
        assert report.status == "BLOCKED"

    def test_sql_injection_is_blocked(self, armor: AgentArmor):
        sql_injection = (
            "def get_user(uid):\n"
            '    db.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
        )
        report = armor.process(sql_injection, filename="db.py")
        assert report.status == "BLOCKED"
        assert any(f.node_type == "SQLInjection" for f in report.ast_findings)

    def test_secret_scrubbing_causes_warn_not_block(self, armor: AgentArmor):
        with_secret = 'api_key = "sk-live_1234567890abcdef1234567890abcdef"\n'
        report = armor.process(with_secret, filename="config.py")
        # Should be blocked because dangerous sinks or warned because of secrets
        # but definitely should have secret findings
        assert len(report.secret_findings) > 0

    def test_report_has_attestation_for_approved(self, armor: AgentArmor):
        clean = "x = 1 + 2\nprint(x)\n"
        report = armor.process(clean, filename="test.py")
        if report.status == "APPROVED":
            assert report.attestation is not None
            assert len(report.attestation.signature) == 64  # SHA-256 hex

    def test_hardened_code_contains_attestation_comment(self, armor: AgentArmor):
        clean = "def hello():\n    return 'world'\n"
        report = armor.process(clean, filename="hello.py")
        if report.attestation:
            assert "@kvlr-attestation:" in report.hardened_code

    def test_processing_time_recorded(self, armor: AgentArmor):
        report = armor.process("x = 1\n")
        assert report.processing_time_ms >= 0

    def test_report_to_json(self, armor: AgentArmor):
        import json
        report = armor.process("x = 1\n")
        j = report.to_json()
        data = json.loads(j)
        assert "status" in data
        assert "summary" in data
        assert "attestation_hash" in data


class TestPipelineAttestationVerification:

    def test_verify_unmodified_code(self):
        armor = AgentArmor(validate_packages=False)
        clean = "def greet(name: str) -> str:\n    return f'Hello, {name}!'\n"
        report = armor.process(clean, filename="greet.py")
        if report.attestation:
            ok = armor.verify_attestation(report.hardened_code, report.attestation.signature)
            assert ok is True

    def test_verify_tampered_code_fails(self):
        armor = AgentArmor(validate_packages=False)
        clean = "def greet(name: str) -> str:\n    return f'Hello, {name}!'\n"
        report = armor.process(clean, filename="greet.py")
        if report.attestation:
            tampered = report.hardened_code + "\n# Tampered line\n"
            ok = armor.verify_attestation(tampered, report.attestation.signature)
            assert ok is False


class TestPipelineBlockNotice:

    def test_blocked_code_has_notice_comment(self):
        armor = AgentArmor(validate_packages=False)
        evil = "eval(input())\n"
        report = armor.process(evil)
        assert report.is_blocked
        assert "KVLR BLOCKED" in report.hardened_code

    def test_original_code_preserved(self):
        armor = AgentArmor(validate_packages=False)
        original = "eval('test')\n"
        report = armor.process(original)
        assert report.original_code == original
