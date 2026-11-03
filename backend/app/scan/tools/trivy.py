"""Trivy 适配器：容器镜像 + 文件系统漏洞扫描 + 配置检测。

trivy 功能丰富，本适配器聚焦两条路径：
- 镜像扫描：trivy image --format json <image>
- 文件系统扫描：trivy fs --format json <workdir>（用于扫 IaC / 配置）

严重度映射 Trivy CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN → 标准化。
"""

from __future__ import annotations

import json
import subprocess

from .base import FindingRaw, ToolAdapter, register

# Trivy 严重度 → 标准化
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
    "NONE": "info",
}


@register
class TrivyAdapter(ToolAdapter):
    name = "trivy"
    category = "container"
    description = "容器镜像 / 文件系统漏洞扫描 + IaC 配置检测"

    def run(self, workdir: str, image: str | None = None) -> list[FindingRaw]:  # type: ignore[override]
        """执行扫描。

        Args:
            workdir: 文件系统扫描的目录（target_type=path/git 时使用）。
            image: 镜像 tag（target_type=image 时使用，优先于 workdir）。
        """
        if image:
            cmd = ["trivy", "image", "--format", "json", "--quiet", image]
        else:
            # fs 扫描同时检测漏洞 + 配置问题（IaC）
            cmd = [
                "trivy",
                "fs",
                "--format",
                "json",
                "--quiet",
                "--scanners",
                "vuln,config,secret",
                workdir,
            ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900,  # 镜像扫描可能较慢
        )
        if not proc.stdout:
            return self._finalize([])

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return self._finalize([])

        findings: list[FindingRaw] = []
        for result in data.get("Results", []):
            target = result.get("Target", "")
            for vuln in result.get("Vulnerabilities") or []:
                sev = _SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "info")
                pkg = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                cve = vuln.get("VulnerabilityID", "")
                title = vuln.get("Title", "") or f"{pkg}@{installed}: {cve}"
                findings.append(
                    FindingRaw(
                        tool=self.name,
                        severity=sev,  # type: ignore[arg-type]
                        category="container",
                        rule_id=vuln.get("VulnerabilityID", ""),
                        cve=cve if cve.startswith("CVE-") else "",
                        title=title[:200],
                        message=vuln.get("Description", "")[:500],
                        file=target,
                        line=0,
                        fix=f"升级 {pkg} 从 {installed} 到 {fixed}" if fixed else "暂无修复版本",
                    )
                )
            # config 类结果（IaC 配置问题，如暴露的 S3 bucket）
            for misconf in result.get("Misconfigurations") or []:
                sev = _SEVERITY_MAP.get(misconf.get("Severity", "UNKNOWN"), "info")
                findings.append(
                    FindingRaw(
                        tool=self.name,
                        severity=sev,  # type: ignore[arg-type]
                        category="config",
                        rule_id=misconf.get("ID", ""),
                        title=misconf.get("Title", "")[:200],
                        message=misconf.get("Description", "")[:500],
                        file=target,
                        line=misconf.get("StartLine", 0),
                        fix=misconf.get("Resolution", ""),
                    )
                )
            # secret 类结果（trivy 自带 secret 扫描，与 gitleaks 互补）
            for sec in result.get("Secrets") or []:
                sev = _SEVERITY_MAP.get(sec.get("Severity", "HIGH"), "high")
                findings.append(
                    FindingRaw(
                        tool=self.name,
                        severity=sev,  # type: ignore[arg-type]
                        category="secret",
                        rule_id=sec.get("RuleID", ""),
                        title=f"Trivy 发现密钥泄露: {sec.get('RuleID', '')}",
                        message=sec.get("Match", "")[:200],
                        file=target,
                        line=sec.get("StartLine", 0),
                        fix="轮换并清除泄露的密钥",
                    )
                )
        return self._finalize(findings)
