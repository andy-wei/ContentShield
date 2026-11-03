"""Bandit 适配器：Python SAST（静态安全扫描）。

调用 `bandit -r <workdir> -f json`，解析 JSON 输出为标准化 FindingRaw。
严重度映射：Bandit HIGH/MEDIUM/LOW → high/medium/low。
"""

from __future__ import annotations

import json
import subprocess

from .base import FindingRaw, ToolAdapter, register

# Bandit 严重度字符串 → 标准化
_SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


@register
class BanditAdapter(ToolAdapter):
    name = "bandit"
    category = "sast"
    description = "Python 静态安全扫描（SAST），检测常见安全反模式"

    def run(self, workdir: str) -> list[FindingRaw]:
        proc = subprocess.run(
            [
                "bandit",
                "-r",
                workdir,
                "-f",
                "json",
                "-q",  # 安静模式，只输出 JSON
                "-x",  # 排除测试/虚拟环境
                "tests,test,venv,.venv,node_modules,dist,build",
            ],
            capture_output=True,
            text=True,
            timeout=600,
            # bandit 发现问题会返回非零退出码，属正常
        )
        # 即使退出码非零，stdout 仍有 JSON 结果
        if not proc.stdout:
            return self._finalize([])

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return self._finalize([])

        findings: list[FindingRaw] = []
        for issue in data.get("results", []):
            sev = _SEVERITY_MAP.get(issue.get("issue_severity", "LOW"), "low")
            findings.append(
                FindingRaw(
                    tool=self.name,
                    severity=sev,  # type: ignore[arg-type]
                    category="sast",
                    rule_id=issue.get("test_id", ""),
                    title=issue.get("issue_text", "")[:200],
                    message=issue.get("issue_text", ""),
                    file=issue.get("filename", ""),
                    line=issue.get("line_number", 0),
                    fix=self._cwe_to_fix(issue.get("issue_cwe", {})),
                )
            )
        return self._finalize(findings)

    @staticmethod
    def _cwe_to_fix(cwe: dict) -> str:
        """从 CWE 信息生成简短修复建议。"""
        cwe_id = cwe.get("id", "")
        cwe_url = cwe.get("link", "")
        if cwe_id:
            return f"参考 {cwe_id}: {cwe_url}"
        return ""
