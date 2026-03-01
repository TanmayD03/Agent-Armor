"""
Tests for the AST Hardening Engine.
"""

import pytest
from agent_armor.core.ast_hardener import ASTHardener, ASTFinding


@pytest.fixture
def hardener():
    return ASTHardener()


class TestDangerousFunctions:

    def test_detects_eval(self, hardener):
        code = "result = eval(user_input)\n"
        findings = hardener.analyze(code)
        assert any(f.node_type == "DangerousFunction" and "eval" in f.description for f in findings)

    def test_detects_exec(self, hardener):
        code = "exec(user_code)\n"
        findings = hardener.analyze(code)
        assert any(f.node_type == "DangerousFunction" and "exec" in f.description for f in findings)

    def test_detects_dynamic_import(self, hardener):
        code = '__import__("os").system("ls")\n'
        findings = hardener.analyze(code)
        assert any(f.node_type == "DangerousFunction" for f in findings)

    def test_eval_severity_is_critical(self, hardener):
        findings = hardener.analyze("eval(x)\n")
        eval_findings = [f for f in findings if "eval" in f.description.lower()]
        assert all(f.severity == "CRITICAL" for f in eval_findings)

    def test_exec_severity_is_critical(self, hardener):
        findings = hardener.analyze("exec(x)\n")
        exec_findings = [f for f in findings if "exec" in f.description.lower()]
        assert all(f.severity == "CRITICAL" for f in exec_findings)

    def test_clean_function_has_no_dangerous_findings(self, hardener):
        clean = "def add(a, b):\n    return a + b\n"
        findings = hardener.analyze(clean)
        dangerous = [f for f in findings if f.node_type == "DangerousFunction"]
        assert len(dangerous) == 0


class TestSQLInjectionDetection:

    def test_detects_fstring_in_execute(self, hardener):
        code = 'db.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        findings = hardener.analyze(code)
        assert any(f.node_type == "SQLInjection" for f in findings)

    def test_detects_percent_format_in_execute(self, hardener):
        code = 'cursor.execute("SELECT * FROM t WHERE name = \'%s\'" % username)\n'
        findings = hardener.analyze(code)
        sql_findings = [f for f in findings if f.node_type == "SQLInjection"]
        assert len(sql_findings) > 0

    def test_parameterised_query_not_flagged(self, hardener):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
        findings = hardener.analyze(code)
        sql = [f for f in findings if f.node_type == "SQLInjection"]
        assert len(sql) == 0

    def test_sql_injection_severity_is_critical(self, hardener):
        code = 'db.execute(f"DELETE FROM logs WHERE id={log_id}")\n'
        findings = hardener.analyze(code)
        sql = [f for f in findings if f.node_type == "SQLInjection"]
        assert all(f.severity == "CRITICAL" for f in sql)


class TestCommandInjectionDetection:

    def test_detects_os_system(self, hardener):
        code = "import os\nos.system(user_cmd)\n"
        findings = hardener.analyze(code)
        assert any(f.node_type == "CommandInjection" for f in findings)

    def test_detects_subprocess_shell_true(self, hardener):
        code = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
        findings = hardener.analyze(code)
        cmd_findings = [f for f in findings if f.node_type == "CommandInjection"]
        assert len(cmd_findings) > 0

    def test_subprocess_shell_false_not_flagged(self, hardener):
        code = "import subprocess\nsubprocess.run(['ls', '-la'], shell=False)\n"
        findings = hardener.analyze(code)
        cmd_findings = [f for f in findings if f.node_type == "CommandInjection"]
        assert len(cmd_findings) == 0


class TestInsecureDeserialization:

    def test_detects_pickle_loads(self, hardener):
        code = "import pickle\ndata = pickle.loads(user_bytes)\n"
        findings = hardener.analyze(code)
        deser = [f for f in findings if f.node_type == "InsecureDeserialization"]
        assert len(deser) > 0

    def test_pickle_import_flagged(self, hardener):
        code = "import pickle\n"
        findings = hardener.analyze(code)
        assert any(f.node_type == "DangerousImport" for f in findings)


class TestMissingErrorHandling:

    def test_flags_io_without_try_except(self, hardener):
        code = (
            "def fetch_data(url):\n"
            "    response = requests.get(url)\n"
            "    return response.json()\n"
        )
        findings = hardener.analyze(code)
        error_handling = [f for f in findings if f.node_type == "MissingErrorHandling"]
        assert len(error_handling) > 0

    def test_no_flag_with_try_except(self, hardener):
        code = (
            "def fetch_data(url):\n"
            "    try:\n"
            "        response = requests.get(url)\n"
            "        return response.json()\n"
            "    except Exception as e:\n"
            "        return None\n"
        )
        findings = hardener.analyze(code)
        error_handling = [f for f in findings if f.node_type == "MissingErrorHandling"]
        assert len(error_handling) == 0


class TestSyntaxErrorHandling:

    def test_syntax_error_returns_single_finding(self, hardener):
        code = "def broken(:\n    pass\n"
        findings = hardener.analyze(code)
        assert len(findings) == 1
        assert findings[0].severity == "ERROR"


class TestHardenMethod:

    def test_harden_injects_warning_comments(self, hardener):
        code = "def run(code):\n    eval(code)\n"
        hardened = hardener.harden(code)
        assert "AgentArmor" in hardened or "CRITICAL" in hardened

    def test_harden_clean_code_unchanged(self, hardener):
        code = "x = 1 + 2\n"
        hardened = hardener.harden(code)
        assert code in hardened


class TestAssertSecurity:

    def test_flags_assert_for_auth(self, hardener):
        code = "assert user.is_admin, 'Not admin'\n"
        findings = hardener.analyze(code)
        security_asserts = [f for f in findings if f.node_type == "SecurityAssert"]
        assert len(security_asserts) > 0


class TestBareExcept:

    def test_flags_bare_except(self, hardener):
        code = "try:\n    risky()\nexcept:\n    pass\n"
        findings = hardener.analyze(code)
        bare = [f for f in findings if f.node_type == "BareExcept"]
        assert len(bare) > 0

    def test_specific_except_not_flagged(self, hardener):
        code = "try:\n    risky()\nexcept ValueError:\n    pass\n"
        findings = hardener.analyze(code)
        bare = [f for f in findings if f.node_type == "BareExcept"]
        assert len(bare) == 0


# ---------------------------------------------------------------------------
# Insecure Cryptography tests
# ---------------------------------------------------------------------------

class TestInsecureCryptography:

    def test_detects_hashlib_md5(self, hardener):
        code = "import hashlib\nh = hashlib.md5(data)\n"
        findings = hardener.analyze(code)
        assert any(f.node_type == "InsecureCryptography" for f in findings)

    def test_detects_hashlib_sha1(self, hardener):
        code = "import hashlib\nh = hashlib.sha1(data)\n"
        findings = hardener.analyze(code)
        assert any(f.node_type == "InsecureCryptography" for f in findings)

    def test_detects_hashlib_new_md5(self, hardener):
        code = "import hashlib\nh = hashlib.new('md5', data)\n"
        findings = hardener.analyze(code)
        assert any(f.node_type == "InsecureCryptography" for f in findings)

    def test_detects_hashlib_new_sha1_uppercase(self, hardener):
        code = "import hashlib\nh = hashlib.new('SHA1', data)\n"
        findings = hardener.analyze(code)
        assert any(f.node_type == "InsecureCryptography" for f in findings)

    def test_sha256_not_flagged(self, hardener):
        code = "import hashlib\nh = hashlib.sha256(data)\n"
        findings = hardener.analyze(code)
        assert not any(f.node_type == "InsecureCryptography" for f in findings)

    def test_sha3_256_not_flagged(self, hardener):
        code = "import hashlib\nh = hashlib.sha3_256(data)\n"
        findings = hardener.analyze(code)
        assert not any(f.node_type == "InsecureCryptography" for f in findings)

    def test_hashlib_new_sha256_not_flagged(self, hardener):
        code = "import hashlib\nh = hashlib.new('sha256', data)\n"
        findings = hardener.analyze(code)
        assert not any(f.node_type == "InsecureCryptography" for f in findings)

    def test_severity_is_high(self, hardener):
        code = "import hashlib\nh = hashlib.md5(data)\n"
        findings = hardener.analyze(code)
        crypto = [f for f in findings if f.node_type == "InsecureCryptography"]
        assert all(f.severity == "HIGH" for f in crypto)


# ---------------------------------------------------------------------------
# SSRF tests
# ---------------------------------------------------------------------------

class TestSSRF:

    def test_detects_requests_get_with_variable_url(self, hardener):
        code = "import requests\nresponse = requests.get(url)\n"
        findings = hardener.analyze(code)
        assert any(f.node_type == "SSRF" for f in findings)

    def test_detects_requests_post_with_variable_url(self, hardener):
        code = "import requests\nresponse = requests.post(user_url, json=data)\n"
        findings = hardener.analyze(code)
        assert any(f.node_type == "SSRF" for f in findings)

    def test_literal_url_not_flagged(self, hardener):
        code = 'import requests\nresponse = requests.get("https://api.example.com/data")\n'
        findings = hardener.analyze(code)
        assert not any(f.node_type == "SSRF" for f in findings)

    def test_severity_is_high(self, hardener):
        code = "import requests\nr = requests.get(user_url)\n"
        findings = hardener.analyze(code)
        ssrf = [f for f in findings if f.node_type == "SSRF"]
        assert all(f.severity == "HIGH" for f in ssrf)

    def test_urlopen_variable_flagged(self, hardener):
        code = "import urllib.request\nresp = urllib.request.urlopen(user_url)\n"
        findings = hardener.analyze(code)
        # urllib.request.urlopen(user_url) is an attribute call → detected as SSRF
        assert any(f.node_type == "SSRF" for f in findings)


# ---------------------------------------------------------------------------
# ReDoS tests
# ---------------------------------------------------------------------------

class TestReDoS:

    def test_detects_nested_quantifier(self, hardener):
        code = 'import re\npattern = re.compile(r"(a+)+")\n'
        findings = hardener.analyze(code)
        assert any(f.node_type == "ReDoS" for f in findings)

    def test_detects_nested_star_quantifier(self, hardener):
        code = 'import re\npattern = re.compile(r"(a*)+")\n'
        findings = hardener.analyze(code)
        assert any(f.node_type == "ReDoS" for f in findings)

    def test_detects_alternation_with_quantifier(self, hardener):
        code = 'import re\npattern = re.compile(r"(a|b)+")\n'
        findings = hardener.analyze(code)
        assert any(f.node_type == "ReDoS" for f in findings)

    def test_safe_regex_not_flagged(self, hardener):
        code = 'import re\npattern = re.compile(r"^[a-z]{1,20}$")\n'
        findings = hardener.analyze(code)
        assert not any(f.node_type == "ReDoS" for f in findings)

    def test_re_match_catastrophic_flagged(self, hardener):
        code = 'import re\nre.match(r"(a+)+", user_input)\n'
        findings = hardener.analyze(code)
        assert any(f.node_type == "ReDoS" for f in findings)

    def test_severity_is_high(self, hardener):
        code = 'import re\nre.compile(r"(a+)+")\n'
        findings = hardener.analyze(code)
        redos = [f for f in findings if f.node_type == "ReDoS"]
        assert all(f.severity == "HIGH" for f in redos)


# ---------------------------------------------------------------------------
# yaml insecure deserialization tests (AST layer)
# ---------------------------------------------------------------------------

class TestYamlDeserialization:

    def test_yaml_load_without_loader_flagged(self, hardener):
        code = "import yaml\ndata = yaml.load(stream)\n"
        findings = hardener.analyze(code)
        deser = [f for f in findings if f.node_type == "InsecureDeserialization"]
        assert len(deser) >= 1

    def test_yaml_load_with_safe_loader_not_flagged(self, hardener):
        code = "import yaml\ndata = yaml.load(stream, Loader=yaml.SafeLoader)\n"
        findings = hardener.analyze(code)
        deser = [f for f in findings if f.node_type == "InsecureDeserialization"]
        assert len(deser) == 0

    def test_yaml_safe_load_not_flagged(self, hardener):
        code = "import yaml\ndata = yaml.safe_load(stream)\n"
        findings = hardener.analyze(code)
        deser = [f for f in findings if f.node_type == "InsecureDeserialization"]
        assert len(deser) == 0

    def test_yaml_load_description_mentions_rce(self, hardener):
        code = "import yaml\ndata = yaml.load(stream)\n"
        findings = hardener.analyze(code)
        deser = [f for f in findings if f.node_type == "InsecureDeserialization"]
        assert any("code execution" in f.description.lower() or "rce" in f.description.lower() for f in deser)
