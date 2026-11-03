"""Gitleaks 适配器：密钥/凭证泄露扫描。

调用 `gitleaks detect --source <workdir> --report-format json --report-path -`，
解析 JSON 输出。所有发现统一为 high 严重度（密钥泄露默认高危）。
"""

from __future__ import annotations

import json
import subprocess

from .base import FindingRaw, ToolAdapter, register


@register
class GitleaksAdapter(ToolAdapter):
    name = "gitleaks"
    category = "secret"
    description = "扫描代码中的密钥/凭证泄露（API Key、Token、私钥等）"

    def run(self, workdir: str) -> list[FindingRaw]:
        proc = subprocess.run(
            [
                "gitleaks",
                "detect",
                "--source",
                workdir,
                "--report-format",
                "json",
                "--report-path",
                "-",  # 输出到 stdout
                "--no-banner",
                "--verbose",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        # gitleaks 发现泄露时退出码为 1，无泄露为 0
        if not proc.stdout:
            return self._finalize([])

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return self._finalize([])

        findings: list[FindingRaw] = []
        for leak in data:
            rule_id = leak.get("RuleID", "")
            secret = leak.get("Secret", "")
            # 脱敏：只保留前后 4 字符
            masked = self._mask_secret(secret)
            findings.append(
                FindingRaw(
                    tool=self.name,
                    severity="high",  # 密钥泄露默认高危
                    category="secret",
                    rule_id=rule_id,
                    title=f"检测到疑似密钥泄露: {rule_id}",
                    message=f"文件 {leak.get('File', '')}:{leak.get('StartLine', 0)} "
                    f"发现匹配规则 {rule_id}，密钥片段: {masked}",
                    file=leak.get("File", ""),
                    line=leak.get("StartLine", 0),
                    fix="立即轮换该密钥，并从 git 历史中清除（git filter-repo / BFG）",
                )
            )
        return self._finalize(findings)

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """脱敏：长密钥只展示首尾，短密钥完全遮挡。"""
        if not secret:
            return "***"
        if len(secret) <= 8:
            return "*" * len(secret)
        return f"{secret[:4]}...{secret[-4:]}"
