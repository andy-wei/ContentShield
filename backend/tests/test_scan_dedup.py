"""跨工具 finding 去重逻辑测试。"""

from __future__ import annotations

from app.scan.dedup import dedup_findings
from app.scan.tools.base import FindingRaw


class TestDedupByFingerprint:
    def test_empty_input(self):
        assert dedup_findings([]) == []

    def test_same_fingerprint_deduped(self):
        """完全相同指纹（同工具同位置同规则）去重。"""
        f1 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        f2 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        f1.compute_fingerprint()
        f2.compute_fingerprint()
        result = dedup_findings([f1, f2])
        assert len(result) == 1

    def test_different_fingerprint_kept(self):
        f1 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        f2 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=11, rule_id="B602"
        )
        f1.compute_fingerprint()
        f2.compute_fingerprint()
        result = dedup_findings([f1, f2])
        assert len(result) == 2


class TestDedupCrossTool:
    def test_same_position_different_tool_merged(self):
        """同 file+line+category 但不同工具 → 合并，severity 取高。"""
        f1 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        f2 = FindingRaw(
            tool="trivy", severity="high", category="sast", file="a.py", line=10, rule_id="CVE-X"
        )
        f1.compute_fingerprint()
        f2.compute_fingerprint()
        result = dedup_findings([f1, f2])
        assert len(result) == 1
        # 合并后 severity 取最高
        assert result[0].severity == "high"
        # tool 字段含两个工具
        assert "bandit" in result[0].tool
        assert "trivy" in result[0].tool

    def test_same_position_different_category_not_merged(self):
        """同 file+line 但 category 不同（如 sast vs secret）→ 不合并。"""
        f1 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        f2 = FindingRaw(
            tool="gitleaks",
            severity="high",
            category="secret",
            file="a.py",
            line=10,
            rule_id="GL-1",
        )
        f1.compute_fingerprint()
        f2.compute_fingerprint()
        result = dedup_findings([f1, f2])
        assert len(result) == 2

    def test_merged_finding_includes_other_messages(self):
        f1 = FindingRaw(
            tool="bandit",
            severity="low",
            category="sast",
            file="a.py",
            line=10,
            rule_id="B602",
            title="bandit 问题",
        )
        f2 = FindingRaw(
            tool="trivy",
            severity="high",
            category="sast",
            file="a.py",
            line=10,
            rule_id="CVE-X",
            title="trivy 漏洞",
        )
        f1.compute_fingerprint()
        f2.compute_fingerprint()
        result = dedup_findings([f1, f2])
        assert len(result) == 1
        # 合并后的 message 应包含另一工具的发现
        assert "trivy" in result[0].message or "bandit" in result[0].message


class TestDedupEdgeCases:
    def test_no_file_not_clustered(self):
        """无 file 的 finding 不参与聚类（保留）。"""
        f1 = FindingRaw(
            tool="pip-audit", severity="medium", category="sca", file="", line=0, rule_id="PYSEC-1"
        )
        f2 = FindingRaw(
            tool="pip-audit", severity="medium", category="sca", file="", line=0, rule_id="PYSEC-2"
        )
        f1.compute_fingerprint()
        f2.compute_fingerprint()
        result = dedup_findings([f1, f2])
        assert len(result) == 2

    def test_line_zero_not_clustered(self):
        """line=0 的 finding 不参与聚类（SCA 类常见）。"""
        f1 = FindingRaw(
            tool="pip-audit",
            severity="medium",
            category="sca",
            file="req.txt",
            line=0,
            rule_id="PYSEC-1",
        )
        f2 = FindingRaw(
            tool="npm", severity="high", category="sca", file="req.txt", line=0, rule_id="CVE-2"
        )
        f1.compute_fingerprint()
        f2.compute_fingerprint()
        result = dedup_findings([f1, f2])
        assert len(result) == 2

    def test_preserves_max_severity_in_cluster(self):
        """聚类中取最高严重度。"""
        f_low = FindingRaw(
            tool="a", severity="low", category="sast", file="x", line=1, rule_id="r1"
        )
        f_crit = FindingRaw(
            tool="b", severity="critical", category="sast", file="x", line=1, rule_id="r2"
        )
        f_med = FindingRaw(
            tool="c", severity="medium", category="sast", file="x", line=1, rule_id="r3"
        )
        for f in [f_low, f_crit, f_med]:
            f.compute_fingerprint()
        result = dedup_findings([f_low, f_crit, f_med])
        assert len(result) == 1
        assert result[0].severity == "critical"
