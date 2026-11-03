"""L5 CodeShield 检测器：对 LLM 生成/执行的危险代码原语做静态审计。

灵感来源：Meta LlamaFirewall 的 CodeShield 扫描器——在 Agent 执行或
LLM 输出代码前做静态分析，识别危险 API/恶意模式，拦截于执行之前。

检测方向与现有层互补：
- L4 交叉验证检测「恶意代码请求」（user 侧，请求生成病毒/木马）
- L5 CodeShield 检测「生成的危险代码」（assistant 侧，eval/exec/反序列化等）
- DLP 管文本 PII 泄露，CodeShield 管**代码执行原语**，二者正交

检测方式：纯本地正则匹配（零网络、零依赖）。规则硬编码不可改（v1），
启用状态与动作（warn/block）通过 UI 动态配置，默认关闭。
"""

from __future__ import annotations

import logging
import re
import time

from ..result import DetectorHit, DetectorResult
from .base import BaseDetector

logger = logging.getLogger(__name__)

# 严重度 → 命中置信度（喂入风险评分）
SEVERITY_SCORE = {"high": 0.9, "medium": 0.6}

# 内置规则：(name, category, pattern, severity)
# 覆盖 LLM 生成代码的高危原语：RCE / 反序列化 / shell 注入 / SSTI / 外发 / 密钥泄露
RULES: list[tuple[str, str, str, str]] = [
    # ---- 任意代码执行（RCE）----
    ("eval", "code:rce", r"eval\s*\(", "high"),
    ("exec", "code:rce", r"exec\s*\(", "high"),
    ("os.system", "code:rce", r"os\.system\s*\(", "high"),
    (
        "subprocess.*",
        "code:rce",
        r"subprocess\.(run|call|Popen|check_output|check_call)\s*\(",
        "high",
    ),
    ("os.popen", "code:rce", r"os\.popen\s*\(", "high"),
    ("__import__", "code:rce", r"__import__\s*\(", "high"),
    ("os.exec*", "code:rce", r"os\.exec[lv]p?e?\s*\(", "high"),
    # ---- 不安全反序列化 ----
    ("pickle.loads", "code:deserialization", r"pickle\.loads?\s*\(", "high"),
    ("marshal.loads", "code:deserialization", r"marshal\.loads?\s*\(", "high"),
    ("yaml.load(no Loader)", "code:deserialization", r"yaml\.load\s*\(", "high"),
    # ---- shell 注入面 ----
    ("shell=True", "code:shell", r"shell\s*=\s*True", "high"),
    # ---- SSTI（服务端模板注入）----
    (
        "jinja2 from_string",
        "code:ssti",
        r"jinja2\.from_string|Environment\(\)\.from_string",
        "high",
    ),
    ("Template(用户输入)", "code:ssti", r"Template\s*\(", "medium"),
    # ---- 数据外发（中危，正常场景也会用，故 medium）----
    (
        "requests.* 外发",
        "code:network",
        r"requests\.(get|post|put|delete|patch|head)\s*\(",
        "medium",
    ),
    # ---- 密钥/凭据泄露 ----
    (
        "PEM 私钥头",
        "code:secret",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "high",
    ),
    (
        "硬编码 token 赋值",
        "code:secret",
        r"(?i)(api_key|secret|token)\s*=\s*[\"'][A-Za-z0-9+/=]{16,}[\"']",
        "medium",
    ),
]


class CodeShieldDetector(BaseDetector):
    """L5 代码安全检测器。

    配置来源：动态配置（SystemConfig，UI 可改）
    - code_shield.enabled：总开关，默认 false
    - code_shield.action：命中动作 warn/block，默认 warn

    规则硬编码不可改，无需 invalidate()/warmup()/_load()（零状态）。
    """

    name = "code_shield"

    def __init__(self) -> None:
        # 编译正则（一次性，进程内常驻）
        self._rules: list[tuple[re.Pattern, str, str, str]] = [
            (re.compile(p), name, category, severity) for name, category, p, severity in RULES
        ]

    async def warmup(self) -> None:
        # 无状态，无需预热
        return

    async def detect(self, text: str, *, source: str = "user_prompt") -> DetectorResult:
        result = DetectorResult(name=self.name)

        # 每次检测读动态配置（UI 改完立即生效，无需重启/重建）
        from ...services.config_service import config_service

        enabled = await config_service.get_bool("code_shield.enabled", default=False)
        if not enabled:
            result.decision = "skipped"
            result.raw = {"reason": "code_shield disabled"}
            return result

        action = await config_service.get("code_shield.action", default="warn")
        # 容错：非 block 一律按 warn（补充意见），避免误拦
        action = "block" if action == "block" else "warn"

        t0 = time.perf_counter()
        hits: list[DetectorHit] = []
        for pattern, name, category, severity in self._rules:
            for m in pattern.finditer(text):
                snippet = m.group(0)
                # 截断超长片段，避免审计膨胀
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                hits.append(
                    DetectorHit(
                        category=category,
                        snippet=snippet,
                        score=SEVERITY_SCORE.get(severity, 0.6),
                        extra={
                            "severity": severity,
                            "rule_name": name,
                            "action": action,
                        },
                    )
                )

        result.hit = bool(hits)
        result.decision = action if hits else "pass"
        result.hits = hits
        result.latency_ms = int((time.perf_counter() - t0) * 1000)
        return result
