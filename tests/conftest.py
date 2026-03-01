"""
Shared pytest fixtures for AgentArmor test suite.
All test modules import from here automatically via conftest.py discovery.
"""
import pytest
from agent_armor.pipeline import AgentArmor
from agent_armor.core.secret_scrubber import SecretScrubber
from agent_armor.core.ast_hardener import ASTHardener
from agent_armor.core.dtg_engine import DTGEngine
from agent_armor.core.attestation import AttestationEngine
from agent_armor.core.policy_engine import PolicyEngine
from agent_armor.guards.slopsquatting_guard import SlopsquattingGuard
from agent_armor.shadow_chain.chain_manager import ShadowChainManager
from agent_armor.mcp_proxy.interceptor import MCPInterceptor


# ──────────────────────────────────────────────────────────────────────────────
# Engine fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def scrubber():
    return SecretScrubber()


@pytest.fixture(scope="session")
def hardener():
    return ASTHardener()


@pytest.fixture(scope="session")
def dtg():
    return DTGEngine()


@pytest.fixture(scope="session")
def attestation():
    return AttestationEngine()


@pytest.fixture(scope="session")
def policy():
    return PolicyEngine()


@pytest.fixture(scope="session")
def guard():
    """SlopsquattingGuard with network calls disabled for unit tests."""
    return SlopsquattingGuard(offline=True)


@pytest.fixture
def chain(tmp_path):
    """Fresh ShadowChainManager backed by a temp directory."""
    return ShadowChainManager(chain_dir=str(tmp_path))


@pytest.fixture
def mcp(tmp_path):
    """MCPInterceptor with a minimal agent context."""
    return MCPInterceptor(
        agent_context={"workspace": str(tmp_path), "agent_id": "test-agent"}
    )


@pytest.fixture(scope="session")
def armor():
    """Full AgentArmor pipeline with package validation disabled."""
    return AgentArmor(validate_packages=False)


# ──────────────────────────────────────────────────────────────────────────────
# Sample code fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def clean_code():
    return '''
def add(a: int, b: int) -> int:
    """Return a + b."""
    return a + b
'''


@pytest.fixture
def sql_injection_code():
    return '''
import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchone()
'''


@pytest.fixture
def eval_injection_code():
    return '''
def calculate(expression):
    return eval(expression)
'''


@pytest.fixture
def secret_code():
    return '''
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr"
'''


@pytest.fixture
def command_injection_code():
    return '''
import os

def ping_host(host):
    os.system(f"ping -c 1 {host}")
'''
