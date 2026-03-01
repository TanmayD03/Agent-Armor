"""
Tests for the Cryptographic Attestation Engine.
"""

import pytest
from agent_armor.core.attestation import AttestationEngine, Attestation


@pytest.fixture
def engine():
    return AttestationEngine()


class TestSignature:

    def test_sign_returns_attestation(self, engine):
        attestation = engine.sign("x = 1\n", {}, "test.py")
        assert isinstance(attestation, Attestation)

    def test_signature_is_64_char_hex(self, engine):
        attestation = engine.sign("x = 1\n", {})
        assert len(attestation.signature) == 64
        int(attestation.signature, 16)  # Should not raise

    def test_different_code_gives_different_signature(self, engine):
        a1 = engine.sign("x = 1\n", {})
        a2 = engine.sign("x = 2\n", {})
        assert a1.signature != a2.signature

    def test_different_invariants_give_different_signature(self, engine):
        a1 = engine.sign("x = 1\n", {"auth_required": True})
        a2 = engine.sign("x = 1\n", {"auth_required": False})
        assert a1.signature != a2.signature

    def test_same_code_same_invariants_same_signature(self, engine):
        a1 = engine.sign("x = 1\n", {"k": True})
        a2 = engine.sign("x = 1\n", {"k": True})
        assert a1.signature == a2.signature

    def test_attestation_has_timestamp(self, engine):
        a = engine.sign("x = 1\n", {})
        assert a.timestamp
        assert "Z" in a.timestamp or "+" in a.timestamp  # ISO format

    def test_attestation_filename_stored(self, engine):
        a = engine.sign("x = 1\n", {}, filename="api.py")
        assert a.filename == "api.py"


class TestEmbedAndExtract:

    def test_embed_adds_header(self, engine):
        code = "x = 1\n"
        a = engine.sign(code, {})
        embedded = engine.embed(code, a)
        assert "@kvlr-attestation:" in embedded

    def test_embed_includes_invariants(self, engine):
        code = "x = 1\n"
        a = engine.sign(code, {"no_secrets": True})
        embedded = engine.embed(code, a)
        assert "@invariants:" in embedded

    def test_extract_signature_from_embedded(self, engine):
        code = "x = 1\n"
        a = engine.sign(code, {})
        embedded = engine.embed(code, a)
        extracted = engine.extract_signature(embedded)
        assert extracted == a.signature

    def test_extract_signature_returns_none_when_absent(self, engine):
        result = engine.extract_signature("x = 1\n")
        assert result is None

    def test_embed_replaces_existing_header(self, engine):
        code = "x = 1\n"
        a1 = engine.sign(code, {})
        embedded_v1 = engine.embed(code, a1)
        a2 = engine.sign(code + "y = 2\n", {})
        embedded_v2 = engine.embed(embedded_v1, a2)
        # Should only have one attestation header
        count = embedded_v2.count("@kvlr-attestation:")
        assert count == 1


class TestVerification:

    def test_verify_unmodified_code_returns_true(self, engine):
        code = "def greet(name):\n    return f'Hello {name}'\n"
        a = engine.sign(code, {"no_secrets": True})
        embedded = engine.embed(code, a)
        assert engine.verify(embedded, a.signature) is True

    def test_verify_tampered_code_returns_false(self, engine):
        code = "def greet(name):\n    return f'Hello {name}'\n"
        a = engine.sign(code, {})
        embedded = engine.embed(code, a)
        tampered = embedded + "\n# remove admin check\n"
        assert engine.verify(tampered, a.signature) is False

    def test_verify_wrong_hash_returns_false(self, engine):
        code = "x = 1\n"
        a = engine.sign(code, {})
        embedded = engine.embed(code, a)
        assert engine.verify(embedded, "a" * 64) is False


class TestDeriveInvariants:

    def test_clean_code_all_invariants_true(self, engine):
        inv = engine.derive_invariants(
            secret_findings=[],
            ast_findings=[],
            dtg_findings=[],
            package_findings=[],
        )
        assert all(inv.values())

    def test_with_secrets_no_secrets_is_false(self, engine):
        from agent_armor.core.secret_scrubber import SecretFinding, SecretType
        fake_finding = SecretFinding(
            secret_type=SecretType.OPENAI_KEY,
            line_number=1,
            column=0,
            masked_value="sk-***",
            env_var_name="TEST",
        )
        inv = engine.derive_invariants([fake_finding], [], [], [])
        assert inv["no_secrets"] is False


class TestAttestationToDict:

    def test_to_dict_has_required_keys(self, engine):
        a = engine.sign("x = 1\n", {"k": True}, "test.py")
        d = a.to_dict()
        assert "signature" in d
        assert "timestamp" in d
        assert "invariants" in d
        assert "version" in d
        assert "filename" in d

    def test_from_dict_round_trip(self, engine):
        a = engine.sign("x = 1\n", {"k": True}, "test.py")
        d = a.to_dict()
        restored = Attestation.from_dict(d)
        assert restored.signature == a.signature
        assert restored.filename == a.filename
