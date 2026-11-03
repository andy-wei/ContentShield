"""扫描工具适配器包。"""

# 各适配器在 import 时自动注册到 registry
from .bandit import BanditAdapter
from .base import FindingRaw, ToolAdapter, get_adapter, list_available_tools, registry
from .gitleaks import GitleaksAdapter
from .npm_audit import NpmAuditAdapter
from .pip_audit import PipAuditAdapter
from .trivy import TrivyAdapter

__all__ = [
    "ToolAdapter",
    "FindingRaw",
    "registry",
    "get_adapter",
    "list_available_tools",
    "BanditAdapter",
    "GitleaksAdapter",
    "PipAuditAdapter",
    "NpmAuditAdapter",
    "TrivyAdapter",
]
