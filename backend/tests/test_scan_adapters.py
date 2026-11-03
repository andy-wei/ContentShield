"""扫描工具适配器解析测试：用 mock JSON 验证解析逻辑，不依赖真实工具二进制。

通过 monkeypatch subprocess.run 模拟工具输出，验证适配器能正确解析为 FindingRaw。
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock


def _mock_run(stdout: str, returncode: int = 0):
    """构造一个模拟的 subprocess.run 返回值。"""
    m = MagicMock()
    m.stdout = stdout
    m.returncode = returncode
    m.stderr = ""
    return m


# ==================== Bandit 适配器 ====================


class TestBanditAdapter:
    BANDIT_JSON = json.dumps(
        {
            "results": [
                {
                    "test_id": "B602",
                    "issue_severity": "HIGH",
                    "issue_text": "subprocess call with shell=True",
                    "filename": "app/evil.py",
                    "line_number": 42,
                    "issue_cwe": {
                        "id": "CWE-78",
                        "link": "https://cwe.mitre.org/data/definitions/78.html",
                    },
                },
                {
                    "test_id": "B101",
                    "issue_severity": "LOW",
                    "issue_text": "assert statement",
                    "filename": "tests/test_x.py",
                    "line_number": 10,
                    "issue_cwe": {},
                },
            ]
        }
    )

    def test_parses_high_severity(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.BANDIT_JSON))
        from app.scan.tools.bandit import BanditAdapter

        findings = BanditAdapter().run("/tmp")
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 1
        assert high[0].rule_id == "B602"
        assert high[0].file == "app/evil.py"
        assert high[0].line == 42

    def test_parses_low_severity(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.BANDIT_JSON))
        from app.scan.tools.bandit import BanditAdapter

        findings = BanditAdapter().run("/tmp")
        low = [f for f in findings if f.severity == "low"]
        assert len(low) == 1
        assert low[0].rule_id == "B101"

    def test_fingerprint_computed(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.BANDIT_JSON))
        from app.scan.tools.bandit import BanditAdapter

        findings = BanditAdapter().run("/tmp")
        assert all(f.fingerprint for f in findings)

    def test_fix_from_cwe(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.BANDIT_JSON))
        from app.scan.tools.bandit import BanditAdapter

        findings = BanditAdapter().run("/tmp")
        b602 = next(f for f in findings if f.rule_id == "B602")
        assert "CWE-78" in b602.fix

    def test_empty_output(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(""))
        from app.scan.tools.bandit import BanditAdapter

        assert BanditAdapter().run("/tmp") == []

    def test_invalid_json(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run("not json"))
        from app.scan.tools.bandit import BanditAdapter

        assert BanditAdapter().run("/tmp") == []

    def test_no_results_key(self, monkeypatch):
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **kw: _mock_run(json.dumps({"errors": []}))
        )
        from app.scan.tools.bandit import BanditAdapter

        assert BanditAdapter().run("/tmp") == []


# ==================== pip-audit 适配器 ====================


class TestPipAuditAdapter:
    PIP_AUDIT_JSON = json.dumps(
        {
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.20.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2020-1234",
                            "description": "CVE in requests",
                            "fix_versions": ["2.25.0"],
                            "aliases": ["CVE-2020-1234"],
                        }
                    ],
                },
                {
                    "name": "flask",
                    "version": "1.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2021-5678",
                            "description": "Unpatched vuln",
                            "fix_versions": [],
                            "aliases": [],
                        }
                    ],
                },
            ]
        }
    )

    def test_parses_vulnerabilities(self, monkeypatch, tmp_path):
        # pip-audit 需要 requirements 文件存在
        (tmp_path / "requirements.txt").write_text("requests==2.20.0\n")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.PIP_AUDIT_JSON))
        from app.scan.tools.pip_audit import PipAuditAdapter

        findings = PipAuditAdapter().run(str(tmp_path))
        assert len(findings) == 2

    def test_cve_extracted_from_aliases(self, monkeypatch, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.20.0\n")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.PIP_AUDIT_JSON))
        from app.scan.tools.pip_audit import PipAuditAdapter

        findings = PipAuditAdapter().run(str(tmp_path))
        requests_vuln = next(f for f in findings if "requests" in f.title)
        assert requests_vuln.cve == "CVE-2020-1234"

    def test_severity_high_when_no_fix(self, monkeypatch, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==1.0\n")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.PIP_AUDIT_JSON))
        from app.scan.tools.pip_audit import PipAuditAdapter

        findings = PipAuditAdapter().run(str(tmp_path))
        flask_vuln = next(f for f in findings if "flask" in f.title)
        assert flask_vuln.severity == "high"

    def test_severity_medium_when_fix_available(self, monkeypatch, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.20.0\n")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.PIP_AUDIT_JSON))
        from app.scan.tools.pip_audit import PipAuditAdapter

        findings = PipAuditAdapter().run(str(tmp_path))
        requests_vuln = next(f for f in findings if "requests" in f.title)
        assert requests_vuln.severity == "medium"

    def test_no_requirements_file(self, tmp_path):
        """无 requirements 文件时返回空。"""
        from app.scan.tools.pip_audit import PipAuditAdapter

        assert PipAuditAdapter().run(str(tmp_path)) == []

    def test_fix_suggestion_with_version(self, monkeypatch, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.20.0\n")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.PIP_AUDIT_JSON))
        from app.scan.tools.pip_audit import PipAuditAdapter

        findings = PipAuditAdapter().run(str(tmp_path))
        requests_vuln = next(f for f in findings if "requests" in f.title)
        assert "2.25.0" in requests_vuln.fix


# ==================== Gitleaks 适配器 ====================


class TestGitleaksAdapter:
    GITLEAKS_JSON = json.dumps(
        [
            {
                "RuleID": "openai-api-key",
                "Secret": "sk-abcdefghijklmnopqrstuvwxyz1234567890",
                "File": "config.py",
                "StartLine": 15,
            },
            {
                "RuleID": "aws-access-key",
                "Secret": "AKIA12345678",
                "File": ".env",
                "StartLine": 3,
            },
        ]
    )

    def test_parses_leaks(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.GITLEAKS_JSON))
        from app.scan.tools.gitleaks import GitleaksAdapter

        findings = GitleaksAdapter().run("/tmp")
        assert len(findings) == 2
        assert all(f.severity == "high" for f in findings)
        assert all(f.category == "secret" for f in findings)

    def test_secret_masked(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.GITLEAKS_JSON))
        from app.scan.tools.gitleaks import GitleaksAdapter

        findings = GitleaksAdapter().run("/tmp")
        # 完整密钥不应出现在 message 里
        assert "sk-abcdefghijklmnopqrstuvwxyz1234567890" not in findings[0].message
        # 但应包含脱敏片段
        assert "sk-a" in findings[0].message  # 前 4 字符

    def test_short_secret_fully_masked(self, monkeypatch):
        short_json = json.dumps([{"RuleID": "x", "Secret": "abc", "File": "f", "StartLine": 1}])
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(short_json))
        from app.scan.tools.gitleaks import GitleaksAdapter

        findings = GitleaksAdapter().run("/tmp")
        assert "abc" not in findings[0].message
        assert "***" in findings[0].message

    def test_fix_suggests_rotation(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.GITLEAKS_JSON))
        from app.scan.tools.gitleaks import GitleaksAdapter

        findings = GitleaksAdapter().run("/tmp")
        assert "轮换" in findings[0].fix


# ==================== Trivy 适配器 ====================


class TestTrivyAdapter:
    TRIVY_JSON = json.dumps(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Class": "lang-pkgs",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-1234",
                            "Severity": "CRITICAL",
                            "PkgName": "requests",
                            "InstalledVersion": "2.20.0",
                            "FixedVersion": "2.25.0",
                            "Title": "RCE in requests",
                            "Description": "Remote code execution vulnerability",
                        }
                    ],
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "Severity": "HIGH",
                            "Title": "Dockerfile runs as root",
                            "Description": "Container runs as root user",
                            "StartLine": 1,
                            "Resolution": "Add USER directive",
                        }
                    ],
                    "Secrets": [
                        {
                            "RuleID": "aws-key",
                            "Severity": "HIGH",
                            "Match": "AKIA...",
                            "StartLine": 5,
                        }
                    ],
                }
            ]
        }
    )

    def test_parses_vulnerabilities(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.TRIVY_JSON))
        from app.scan.tools.trivy import TrivyAdapter

        findings = TrivyAdapter().run("/tmp")
        vulns = [f for f in findings if f.category == "container"]
        assert len(vulns) == 1
        assert vulns[0].severity == "critical"
        assert vulns[0].cve == "CVE-2021-1234"
        assert "2.25.0" in vulns[0].fix

    def test_parses_misconfigurations(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.TRIVY_JSON))
        from app.scan.tools.trivy import TrivyAdapter

        findings = TrivyAdapter().run("/tmp")
        misconf = [f for f in findings if f.category == "config"]
        assert len(misconf) == 1
        assert misconf[0].severity == "high"
        assert misconf[0].line == 1

    def test_parses_secrets(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _mock_run(self.TRIVY_JSON))
        from app.scan.tools.trivy import TrivyAdapter

        findings = TrivyAdapter().run("/tmp")
        secrets = [f for f in findings if f.category == "secret"]
        assert len(secrets) == 1
        assert secrets[0].rule_id == "aws-key"

    def test_empty_results(self, monkeypatch):
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **kw: _mock_run(json.dumps({"Results": []}))
        )
        from app.scan.tools.trivy import TrivyAdapter

        assert TrivyAdapter().run("/tmp") == []
