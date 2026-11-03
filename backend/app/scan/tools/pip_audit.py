"""pip-audit 适配器：Python 依赖漏洞扫描（SCA）。

调用 `pip-audit -r <requirements> -f json`，解析已知 CVE 漏洞。
严重度从 CVE 数据提取，无 CVSS 时默认 medium。
"""

from __future__ import annotations

import json
import os
import subprocess

from .base import FindingRaw, ToolAdapter, register

# 依赖文件探测顺序
_REQUIREMENTS_FILES = ["requirements.txt", "pyproject.toml", "Pipfile.lock"]


@register
class PipAuditAdapter(ToolAdapter):
    name = "pip-audit"
    category = "sca"
    description = "Python 依赖漏洞扫描（SCA），检测已知 CVE"

    def run(self, workdir: str) -> list[FindingRaw]:
        req_file = self._find_requirements(workdir)
        if not req_file:
            return self._finalize([])

        cmd = ["pip-audit", "-r", req_file, "-f", "json"]
        # pyproject.toml 需用 -r 指向文件本身（pip-audit 支持）
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=workdir,
            timeout=600,
        )
        if not proc.stdout:
            return self._finalize([])

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return self._finalize([])

        findings: list[FindingRaw] = []
        for dep in data.get("dependencies", []):
            name = dep.get("name", "")
            version = dep.get("version", "")
            for vuln in dep.get("vulns", []):
                severity = self._severity_from_vuln(vuln)
                findings.append(
                    FindingRaw(
                        tool=self.name,
                        severity=severity,
                        category="sca",
                        rule_id=vuln.get("id", ""),
                        cve=self._extract_cve(vuln),
                        title=f"{name}=={version} 存在漏洞 {vuln.get('id', '')}",
                        message=vuln.get("description", "")[:500],
                        file=req_file,
                        line=0,
                        fix=self._fix_from_ranges(name, vuln.get("fix_versions", [])),
                    )
                )
        return self._finalize(findings)

    @staticmethod
    def _find_requirements(workdir: str) -> str:
        """探测项目使用的依赖文件，返回路径（相对 workdir）。"""
        for fname in _REQUIREMENTS_FILES:
            if os.path.isfile(os.path.join(workdir, fname)):
                return fname
        return ""

    @staticmethod
    def _extract_cve(vuln: dict) -> str:
        """从漏洞信息提取 CVE 编号。"""
        # pip-audit 的 id 字段可能直接是 CVE 或 PYSEC 编号
        vid = vuln.get("id", "")
        if vid.startswith("CVE-"):
            return vid
        # aliases 数组里找 CVE
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                return alias
        return ""

    @staticmethod
    def _severity_from_vuln(vuln: dict) -> str:
        """从漏洞信息推断严重度。pip-audit 不直接给 CVSS，用 heuristic。"""
        # 启发式：无修复版本 → high；有修复 → medium
        fix_versions = vuln.get("fix_versions", [])
        if not fix_versions:
            return "high"
        return "medium"

    @staticmethod
    def _fix_from_ranges(name: str, fix_versions: list) -> str:
        if not fix_versions:
            return f"暂无已知修复版本，评估是否继续使用 {name}"
        versions = " / ".join(fix_versions)
        return f"升级 {name} 至 {versions} 或更高版本"
