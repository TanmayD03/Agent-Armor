"""Tests for MCPInterceptor — MCP tool call interception."""
import pytest
from agent_armor.mcp_proxy.interceptor import MCPInterceptor


@pytest.fixture
def interceptor(tmp_path):
    # validate_packages=False → offline slopsquatting (blocklist + typosquatting only)
    # This keeps tests deterministic without requiring network access.
    return MCPInterceptor(
        agent_context={"workspace": str(tmp_path), "agent_id": "test-agent-001"},
        validate_packages=False,
    )


# ──────────────────────────────────────────────────────────────────────────────
# write_to_file — full pipeline runs on file content
# ──────────────────────────────────────────────────────────────────────────────

def test_write_clean_code_passes(interceptor):
    tool_call = {
        "tool": "write_to_file",
        "params": {
            "path": "output.py",
            "content": "def add(a, b):\n    return a + b\n",
        },
    }
    result = interceptor.intercept(tool_call)
    assert result.action in ("allow", "allow_modified")


def test_write_with_secret_is_modified(interceptor):
    tool_call = {
        "tool": "write_to_file",
        "params": {
            "path": "config.py",
            "content": 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n',
        },
    }
    result = interceptor.intercept(tool_call)
    # Should be modified (secret scrubbed) or blocked
    assert result.action in ("allow_modified", "block")


def test_write_eval_code_is_blocked_or_modified(interceptor):
    tool_call = {
        "tool": "write_to_file",
        "params": {
            "path": "calc.py",
            "content": "user_expr = input('expr: ')\neval(user_expr)\n",
        },
    }
    result = interceptor.intercept(tool_call)
    assert result.action in ("allow_modified", "block")


# ──────────────────────────────────────────────────────────────────────────────
# install_package — slopsquatting check
# ──────────────────────────────────────────────────────────────────────────────

def test_install_known_package_passes(interceptor):
    tool_call = {
        "tool": "install_package",
        "params": {"package": "requests"},
    }
    result = interceptor.intercept(tool_call)
    # requests is a known safe package — should pass (or warn at most)
    assert result.action in ("allow", "warn")


def test_install_known_malicious_package_blocked(interceptor):
    tool_call = {
        "tool": "install_package",
        "params": {"package": "colourama"},   # known typosquat of colorama
    }
    result = interceptor.intercept(tool_call)
    assert result.action in ("block", "warn")


# ──────────────────────────────────────────────────────────────────────────────
# read_file — sensitive path detection
# ──────────────────────────────────────────────────────────────────────────────

def test_read_safe_file_passes(interceptor):
    tool_call = {
        "tool": "read_file",
        "params": {"path": "README.md"},
    }
    result = interceptor.intercept(tool_call)
    assert result.action in ("allow", "warn")


def test_read_sensitive_path_is_warned_or_blocked(interceptor):
    tool_call = {
        "tool": "read_file",
        "params": {"path": "/etc/shadow"},
    }
    result = interceptor.intercept(tool_call)
    assert result.action in ("warn", "block")


# ──────────────────────────────────────────────────────────────────────────────
# execute_command — dangerous pattern detection
# ──────────────────────────────────────────────────────────────────────────────

def test_safe_command_passes(interceptor):
    tool_call = {
        "tool": "execute_command",
        "params": {"command": "echo hello"},
    }
    result = interceptor.intercept(tool_call)
    assert result.action in ("allow", "warn")


def test_rm_rf_is_blocked(interceptor):
    tool_call = {
        "tool": "execute_command",
        "params": {"command": "rm -rf /"},
    }
    result = interceptor.intercept(tool_call)
    assert result.action == "block"


def test_fork_bomb_is_blocked(interceptor):
    tool_call = {
        "tool": "execute_command",
        "params": {"command": ":(){ :|:& };:"},
    }
    result = interceptor.intercept(tool_call)
    assert result.action == "block"


# ──────────────────────────────────────────────────────────────────────────────
# Unknown tools
# ──────────────────────────────────────────────────────────────────────────────

def test_unknown_tool_passes(interceptor):
    tool_call = {
        "tool": "some_unknown_tool",
        "params": {"data": "hello"},
    }
    result = interceptor.intercept(tool_call)
    assert result.action in ("allow", "warn")


# ──────────────────────────────────────────────────────────────────────────────
# Result structure
# ──────────────────────────────────────────────────────────────────────────────

def test_result_has_required_fields(interceptor):
    tool_call = {
        "tool": "write_to_file",
        "params": {"path": "x.py", "content": "x = 1\n"},
    }
    result = interceptor.intercept(tool_call)
    assert hasattr(result, "action")
    assert hasattr(result, "findings")
    assert result.action in ("allow", "allow_modified", "warn", "block")


def test_result_findings_is_list(interceptor):
    tool_call = {
        "tool": "write_to_file",
        "params": {"path": "y.py", "content": "y = 2\n"},
    }
    result = interceptor.intercept(tool_call)
    assert isinstance(result.findings, list)
