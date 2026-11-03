"""npm audit 适配器：前端依赖漏洞扫描（SCA）。

调用 `npm audit --json`，解析已知漏洞。
"""

from __future__ import annotations

import json
import os
import subprocess

from .base import FindingRaw, ToolAdapter, register

# npm audit severity → 标准化
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "low": "low",
    "info": "info",
}


@register
class NpmAuditAdapter(ToolAdapter):
    name = "npm"
    category = "sca"
    description = "前端依赖漏洞扫描（npm audit），检测已知 CVE"

    def run(self, workdir: str) -> list[FindingRaw]:
        if not os.path.isfile(os.path.join(workdir, "package-lock.json")):
            return self._finalize([])

        proc = subprocess.run(
            ["npm", "audit", "--json"],
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
        # npm audit v2+v3 格式：vulnerabilities 字典
        vulns = data.get("vulnerabilities", {})
        for pkg_name, info in vulns.items():
            severity = _SEVERITY_MAP.get(info.get("severity", "low"), "low")
            via_list = info.get("via", [])
            for via in via_list:
                # via 可能是字符串（依赖名）或 dict（漏洞详情）
                if isinstance(via, dict):
                    cve = via.get("cwe", "")
                    title = via.get("title", "")
                    url = via.get("url", "")
                    findings.append(
                        FindingRaw(
                            tool=self.name,
                            severity=severity,  # type: ignore[arg-type]
                            category="sca",
                            rule_id=via.get("source", ""),
                            cve=cve,
                            title=f"{pkg_name}: {title}"[:200],
                            message=f"{title}\n参考: {url}",
                            file="package-lock.json",
                            line=0,
                            fix=self._fix_from_info(info),
                        )
                    )
                else:
                    # 字符串 via：传递性依赖，记录但信息较少
                    findings.append(
                        FindingRaw(
                            tool=self.name,
                            severity=severity,  # type: ignore[arg-type]
                            category="sca",
                            rule_id=pkg_name,
                            title=f"{pkg_name}（传递依赖）存在漏洞",
                            message=f"通过 {via} 引入",
                            file="package-lock.json",
                            line=0,
                            fix=self._fix_from_info(info),
                        )
                    )
        return self._finalize(findings)

    @staticmethod
    def _fix_from_info(info: dict) -> str:
        fix_range = info.get("fixAvailable")
        if fix_range is False:
            return "暂无可用修复，评估是否可移除该依赖"
        if isinstance(fix_range, dict):
            return f"升级至 {fix_range.get('name', '')}@{fix_range.get('version', '')}"
        return "运行 npm audit fix 尝试自动修复"

    def is_available(self) -> bool:
        # npm 可执行文件名为 npm
        import shutil

        return shutil.which("npm") is not None
