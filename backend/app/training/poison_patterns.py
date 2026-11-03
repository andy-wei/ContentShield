"""训练数据投毒检测：识别可疑的训练样本。

投毒（data poisoning）是指在训练数据中植入恶意样本，使模型学到错误行为。
本模块检测 5 类常见投毒模式：

1. instruction_injection：样本中嵌入"忽略之前指令"等注入语句
2. role_override：伪造 system/assistant 角色（污染角色边界）
3. hidden_trigger：隐蔽触发词（异常编码、零宽字符、base64 嵌入）
4. repeated_pattern：重复模式（同一恶意指令大量重复，强化学习信号）
5. format_anomaly：格式异常（字段错位、超长单行、非预期编码）

这些是纯函数检测，不依赖 LLM，微秒级。
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class PoisonHit:
    """投毒检测结果。"""

    poison_type: str
    severity: str  # high / medium / low
    detail: str
    snippet: str  # 匹配到的片段（脱敏后）


# ==================== 1. 指令注入 ====================

_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.I), "high"),
    (
        re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?)", re.I),
        "high",
    ),
    (re.compile(r"忽略(?:以上|之前|前面)(?:所有)?(?:指令|规则|说明)", re.I), "high"),
    (re.compile(r"请忽略(?:以上|之前|前面)", re.I), "high"),
    (re.compile(r"从现在起(?:你是|你将)", re.I), "medium"),
    (
        re.compile(r"you\s+are\s+now\s+(?:a|an)\s+(?:hacker|evil|malicious|jailbreaker)", re.I),
        "high",
    ),
    (re.compile(r"new\s+instructions?:\s*", re.I), "medium"),
]


def detect_instruction_injection(text: str) -> list[PoisonHit]:
    """检测训练样本中的指令注入模式。"""
    hits = []
    for pattern, severity in _INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            snippet = _safe_snippet(text, match.start(), match.end())
            hits.append(
                PoisonHit(
                    poison_type="instruction_injection",
                    severity=severity,
                    detail=f"检测到指令注入模式: {match.group()}",
                    snippet=snippet,
                )
            )
    return hits


# ==================== 2. 角色覆盖 ====================

# JSONL 训练数据里常见的角色字段
_ROLE_PATTERNS = [
    (re.compile(r'"role"\s*:\s*"system"', re.I), "在样本内容中伪造 system 角色"),
    (re.compile(r"<\|?(?:system|im_start|im_end)\|?>", re.I), "检测到 chat template 系统标记"),
    (re.compile(r"\[INST\].*\[/INST\]", re.I | re.DOTALL), "检测到 Llama INST 标记嵌入"),
]


def detect_role_override(text: str) -> list[PoisonHit]:
    """检测训练样本中伪造的角色标记。"""
    hits = []
    for pattern, detail in _ROLE_PATTERNS:
        match = pattern.search(text)
        if match:
            snippet = _safe_snippet(text, match.start(), match.end())
            hits.append(
                PoisonHit(
                    poison_type="role_override",
                    severity="high",
                    detail=detail,
                    snippet=snippet,
                )
            )
    return hits


# ==================== 3. 隐蔽触发词 ====================

# 零宽字符（用于隐蔽触发词）
_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
# base64 编码的可疑长串（可能是隐藏指令）
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
# hex 编码的可疑长串
_HEX_BLOB = re.compile(r"\b[0-9a-fA-F]{80,}\b")


def detect_hidden_trigger(text: str) -> list[PoisonHit]:
    """检测隐蔽触发词：零宽字符、异常编码块。"""
    hits = []

    # 零宽字符
    zwc_matches = _ZERO_WIDTH.findall(text)
    if zwc_matches:
        hits.append(
            PoisonHit(
                poison_type="hidden_trigger",
                severity="high",
                detail=f"检测到 {len(zwc_matches)} 个零宽字符（可能用于隐蔽触发词）",
                snippet="[零宽字符已移除]",
            )
        )

    # base64 长串（>60 字符的 base64 可能是隐藏的编码指令）
    b64_match = _BASE64_BLOB.search(text)
    if b64_match:
        snippet = _safe_snippet(text, b64_match.start(), b64_match.end())
        hits.append(
            PoisonHit(
                poison_type="hidden_trigger",
                severity="medium",
                detail="检测到可疑的 base64 编码块（可能是隐藏指令）",
                snippet=snippet,
            )
        )

    # hex 长串
    hex_match = _HEX_BLOB.search(text)
    if hex_match:
        snippet = _safe_snippet(text, hex_match.start(), hex_match.end())
        hits.append(
            PoisonHit(
                poison_type="hidden_trigger",
                severity="medium",
                detail="检测到可疑的十六进制编码块",
                snippet=snippet,
            )
        )

    return hits


# ==================== 4. 重复模式 ====================


def detect_repeated_pattern(text: str, min_repeats: int = 5) -> list[PoisonHit]:
    """检测重复模式：同一短语/指令在单条样本中重复多次（强化学习信号）。

    检测方式：
    1. 正则反向引用检测连续重复（如 "abcabcabc"）
    2. 滑窗统计检测非连续重复
    """
    hits = []
    if len(text) < 40:
        return hits

    # 方式 1：正则检测连续重复（捕获组 + 反向引用）
    # 匹配 5-50 字符的子串连续重复 ≥min_repeats 次
    for unit_len in range(5, 51):
        if len(text) < unit_len * min_repeats:
            break
        # 构造正则：捕获 unit_len 字符，然后反向引用 min_repeats-1 次
        pattern = re.compile(rf"(.{{{unit_len}}})\1{{{min_repeats - 1},}}")
        match = pattern.search(text)
        if match:
            unit = match.group(1).strip()
            if len(unit) >= 3:  # 过滤纯空白
                total_repeats = len(match.group(0)) // unit_len
                hits.append(
                    PoisonHit(
                        poison_type="repeated_pattern",
                        severity="medium",
                        detail=f"检测到连续重复模式：'{unit[:30]}' 重复 {total_repeats} 次",
                        snippet=_safe_snippet(unit, 0, len(unit)),
                    )
                )
                if hits:
                    break

    if hits:
        return hits

    # 方式 2：滑窗统计检测非连续重复（步长 1）
    for win_size in [20, 30, 50]:
        if len(text) < win_size * min_repeats:
            continue
        counts: dict[str, int] = {}
        for i in range(len(text) - win_size + 1):
            chunk = text[i : i + win_size]
            counts[chunk] = counts.get(chunk, 0) + 1

        for chunk, count in counts.items():
            if count >= min_repeats:
                stripped = chunk.strip()
                if len(stripped) < 5:
                    continue
                hits.append(
                    PoisonHit(
                        poison_type="repeated_pattern",
                        severity="medium",
                        detail=f"检测到重复模式：'{stripped[:30]}' 重复 {count} 次",
                        snippet=_safe_snippet(stripped, 0, len(stripped)),
                    )
                )
                break
        if hits:
            break

    return hits

    return hits


# ==================== 5. 格式异常 ====================


def detect_format_anomaly(text: str) -> list[PoisonHit]:
    """检测格式异常：超长单行、异常字符比例。"""
    hits = []

    # 超长单行（>5000 字符无换行，可能是注入的长 payload）
    if "\n" not in text and len(text) > 5000:
        hits.append(
            PoisonHit(
                poison_type="format_anomaly",
                severity="low",
                detail=f"超长单行（{len(text)} 字符无换行）",
                snippet=text[:100] + "...",
            )
        )

    # 控制字符比例异常
    if text:
        control_chars = sum(1 for c in text if ord(c) < 32 and c not in "\n\r\t")
        ratio = control_chars / len(text)
        if ratio > 0.05:  # >5% 控制字符
            hits.append(
                PoisonHit(
                    poison_type="format_anomaly",
                    severity="medium",
                    detail=f"控制字符比例异常 ({ratio:.1%})",
                    snippet="[含控制字符]",
                )
            )

    return hits


# ==================== 汇总 ====================


def detect_all_poison(text: str) -> list[PoisonHit]:
    """运行全部投毒检测，返回所有命中。"""
    hits = []
    hits.extend(detect_instruction_injection(text))
    hits.extend(detect_role_override(text))
    hits.extend(detect_hidden_trigger(text))
    hits.extend(detect_repeated_pattern(text))
    hits.extend(detect_format_anomaly(text))
    return hits


# ==================== 辅助 ====================


def _safe_snippet(text: str, start: int, end: int, max_len: int = 80) -> str:
    """提取匹配片段，限制长度。"""
    # 扩展一点上下文
    ctx_start = max(0, start - 20)
    ctx_end = min(len(text), end + 20)
    snippet = text[ctx_start:ctx_end]
    if len(snippet) > max_len:
        snippet = snippet[:max_len] + "..."
    return snippet.replace("\n", " ")
