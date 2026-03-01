"""Tests for ShadowChainManager — persistent append-only attestation chain."""
import json
import time
import pytest
from pathlib import Path
from agent_armor.shadow_chain.chain_manager import ShadowChainManager
from agent_armor.core.attestation import AttestationEngine


@pytest.fixture
def chain(tmp_path):
    """Fresh chain backed by a temp directory for each test."""
    return ShadowChainManager(chain_dir=str(tmp_path))


@pytest.fixture(scope="module")
def attest_engine():
    return AttestationEngine()


def _make_attestation(attest_engine, code="x = 1", filename="test.py"):
    return attest_engine.sign(
        hardened_code=code,
        invariants={"filename": filename},
        filename=filename,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Recording entries
# ──────────────────────────────────────────────────────────────────────────────

def test_record_creates_chain_file(chain, attest_engine, tmp_path):
    att = _make_attestation(attest_engine)
    chain.record(att)
    chain_files = list(Path(tmp_path).glob("*.json"))
    assert len(chain_files) >= 1


def test_record_single_entry(chain, attest_engine):
    att = _make_attestation(attest_engine)
    chain.record(att)
    history = chain.get_history("test.py")
    assert len(history) >= 1


def test_record_multiple_entries(chain, attest_engine):
    for i in range(3):
        att = _make_attestation(attest_engine, code=f"x = {i}", filename="multi.py")
        chain.record(att)
    history = chain.get_history("multi.py")
    assert len(history) == 3


def test_record_different_files(chain, attest_engine):
    att1 = _make_attestation(attest_engine, filename="file1.py")
    att2 = _make_attestation(attest_engine, filename="file2.py")
    chain.record(att1)
    chain.record(att2)
    assert len(chain.get_history("file1.py")) >= 1
    assert len(chain.get_history("file2.py")) >= 1


# ──────────────────────────────────────────────────────────────────────────────
# Chain integrity
# ──────────────────────────────────────────────────────────────────────────────

def test_verify_chain_empty(chain):
    assert chain.verify_chain() is True


def test_verify_chain_after_single_entry(chain, attest_engine):
    att = _make_attestation(attest_engine)
    chain.record(att)
    assert chain.verify_chain() is True


def test_verify_chain_after_multiple_entries(chain, attest_engine):
    for i in range(5):
        att = _make_attestation(attest_engine, code=f"val = {i}", filename="chain_test.py")
        chain.record(att)
    assert chain.verify_chain() is True


def test_verify_chain_detects_tampering(chain, attest_engine, tmp_path):
    """Manually corrupt the chain file and expect verify_chain to return False."""
    # Record 2 entries so corrupting entry[0] breaks the prev_hash link of entry[1]
    att1 = _make_attestation(attest_engine, filename="tamper.py")
    att2 = _make_attestation(attest_engine, filename="tamper2.py")
    chain.record(att1)
    chain.record(att2)

    # Find and corrupt the chain file
    chain_files = list(Path(tmp_path).glob("*.json"))
    if not chain_files:
        pytest.skip("No chain file found — skip tamper test")

    chain_file = chain_files[0]
    with open(chain_file, "r") as f:
        data = json.load(f)

    # Corrupt first entry's signature based on the file format
    if isinstance(data, list) and data:
        data[0]["signature"] = "0" * 64
    elif isinstance(data, dict) and "entries" in data and data["entries"]:
        data["entries"][0]["signature"] = "0" * 64
    else:
        # Try dict-keyed-by-filename format
        first_key = next((k for k in data if isinstance(data[k], list) and data[k]), None)
        if first_key is None:
            pytest.skip("Unexpected chain format — skip tamper test")
        data[first_key][0]["signature"] = "0" * 64

    with open(chain_file, "w") as f:
        json.dump(data, f)

    # Load a FRESH manager so it reads the corrupted data from disk
    corrupted_chain = ShadowChainManager(chain_dir=str(tmp_path))
    assert corrupted_chain.verify_chain() is False


# ──────────────────────────────────────────────────────────────────────────────
# File attestation verification
# ──────────────────────────────────────────────────────────────────────────────

def test_verify_file_attestation_valid(chain, attest_engine):
    att = _make_attestation(attest_engine, filename="verified.py")
    chain.record(att)
    assert chain.verify_file_attestation("verified.py", att.signature) is True


def test_verify_file_attestation_wrong_sig(chain, attest_engine):
    att = _make_attestation(attest_engine, filename="wrongsig.py")
    chain.record(att)
    result = chain.verify_file_attestation("wrongsig.py", "0" * 64)
    assert result is False


def test_verify_file_attestation_unknown_file(chain):
    result = chain.verify_file_attestation("nonexistent.py", "a" * 64)
    assert result is False


# ──────────────────────────────────────────────────────────────────────────────
# History retrieval
# ──────────────────────────────────────────────────────────────────────────────

def test_get_history_returns_list(chain, attest_engine):
    att = _make_attestation(attest_engine, filename="hist.py")
    chain.record(att)
    history = chain.get_history("hist.py")
    assert isinstance(history, list)


def test_get_history_unknown_file_returns_empty(chain):
    history = chain.get_history("unknown_xyz.py")
    assert history == [] or history is None


def test_history_entries_have_signature(chain, attest_engine):
    att = _make_attestation(attest_engine, filename="sig_check.py")
    chain.record(att)
    history = chain.get_history("sig_check.py")
    assert len(history) >= 1
    entry = history[0]
    # Entry should contain signature info (dict or object)
    has_sig = (
        (isinstance(entry, dict) and "signature" in entry)
        or hasattr(entry, "signature")
    )
    assert has_sig


# ──────────────────────────────────────────────────────────────────────────────
# Persistence across instances
# ──────────────────────────────────────────────────────────────────────────────

def test_chain_persists_between_instances(attest_engine, tmp_path):
    """Write with one instance, read with a fresh instance."""
    chain_a = ShadowChainManager(chain_dir=str(tmp_path))
    att = _make_attestation(attest_engine, filename="persist.py")
    chain_a.record(att)

    chain_b = ShadowChainManager(chain_dir=str(tmp_path))
    history = chain_b.get_history("persist.py")
    assert len(history) >= 1
