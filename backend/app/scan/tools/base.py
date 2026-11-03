"""扫描工具适配器抽象基类与注册表。

设计契约：
- 每个工具（bandit/gitleaks/trivy...）实现一个 ToolAdapter 子类。
- run(workdir) 执行扫描，返回标准化的 FindingRaw 列表。
- 标准化由各适配器自己完成（解析 JSON/文本输出 → FindingRaw）。
- 指纹计算统一在 base 完成，确保跨工具一致。

工具发现结果用 FindingRaw（dataclass）传递，落库时转为 ORM Finding。
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Category = Literal["sast", "sca", "secret", "container", "config", "license"]


@dataclass
class FindingRaw:
    """工具产出的标准化漏洞（落库前的中间结构）。"""

    tool: str
    severity: Severity
    category: Category
    rule_id: str = ""
    cve: str = ""
    title: str = ""
    message: str = ""
    file: str = ""
    line: int = 0
    fix: str = ""
    # 指纹由 base.compute_fingerprint 计算，适配器一般不填
    fingerprint: str = field(default="", repr=False)

    def compute_fingerprint(self) -> str:
        """计算去重指纹：hash(tool + file + line + rule_id)。

        同一文件同一行同一规则的多次扫描，指纹相同，可用于：
        - 跨工具去重（不同工具报同一漏洞）
        - 跨次扫描对比（新增/修复的漏洞）
        """
        raw = f"{self.tool}|{self.file}|{self.line}|{self.rule_id}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:32]
        return self.fingerprint


class ToolAdapter:
    """扫描工具适配器抽象基类。

    子类必须实现：
        name: 工具名（唯一标识，如 "bandit"）
        category: 默认漏洞类别
        run(workdir) -> list[FindingRaw]
    """

    name: str = ""
    category: Category = "sast"
    description: str = ""

    def run(self, workdir: str) -> list[FindingRaw]:
        """执行扫描。workdir 为待扫描目录（已拉取代码/挂载路径）。

        返回标准化的 FindingRaw 列表（指纹由 _finalize 统一计算）。
        子类实现时调用原始工具、解析输出、构造 FindingRaw。
        """
        raise NotImplementedError

    def is_available(self) -> bool:
        """工具二进制是否可用（默认检查 PATH 是否存在同名可执行文件）。"""
        if not self.name:
            return False
        return shutil.which(self.name) is not None

    def _finalize(self, findings: list[FindingRaw]) -> list[FindingRaw]:
        """统一后处理：计算指纹、补全 tool 字段。"""
        for f in findings:
            if not f.tool:
                f.tool = self.name
            f.compute_fingerprint()
        return findings


# ==================== 注册表 ====================

# name → adapter 实例（单例）
registry: dict[str, ToolAdapter] = {}


def register(adapter_cls: type[ToolAdapter]) -> type[ToolAdapter]:
    """类装饰器：实例化并注册到 registry。"""
    instance = adapter_cls()
    if instance.name:
        registry[instance.name] = instance
    return adapter_cls


def get_adapter(name: str) -> ToolAdapter | None:
    return registry.get(name)


def list_available_tools() -> list[dict]:
    """列出所有已注册工具及其可用性（供 API 返回）。"""
    return [
        {
            "name": name,
            "category": adapter.category,
            "description": adapter.description,
            "available": adapter.is_available(),
        }
        for name, adapter in sorted(registry.items())
    ]
