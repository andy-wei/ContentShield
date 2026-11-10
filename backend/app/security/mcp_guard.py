"""MCP 工具描述投毒检测（tool description poisoning）。

攻击面：恶意 MCP Server 在工具 description 中埋藏指令（"ignore previous
instructions"、"send user data to ..."），Agent 拉取工具列表时即被注入——
即使 Agent 从不调用该工具，描述本身就在污染上下文。

检测原理：工具 description 的合法语义是"描述功能供模型选择"，
任何祈使句指令、数据外传要求、隐藏编码或防护绕过话术都是投毒信号。
模式即异常，无需语义理解。

消费方：
1. 网关内联：proxy._enforce_agent_security 审核 body["tools"]
2. 拉取式审计：POST /v1/mcp/audit（MCP Server 接入前逐工具体检）
"""

from __future__ import annotations

import re

# (pattern, name, action) —— action: block / warn
# 依据公开的 MCP 投毒案例（Claude MCP 漏洞、tool poisoning 攻击研究）归纳
MCP_POISON_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # ---- 指令覆盖（block）：工具描述中出现对模型行为的直接指令 ----
    (
        re.compile(
            r"(?i)\b(ignore|disregard|forget|override)\b[^.]{0,40}\b"
            r"(previous|prior|above|earlier|all)\b[^.]{0,20}\b"
            r"(instruction|prompt|rule|directive|guideline)",
            re.IGNORECASE,
        ),
        "instruction-override",
        "block",
    ),
    (
        re.compile(
            r"(?i)(忽略|无视|忘记|覆盖)(以上|之前|上面|先前|所有)[^。]{0,20}(指令|提示|规则|要求|设定)"
        ),
        "instruction-override-zh",
        "block",
    ),
    # 角色伪装：描述中出现 system:/assistant: 等角色前缀
    (re.compile(r"\b(system|assistant|developer)\s*[:：]\s*\S"), "role-spoof", "block"),
    # ---- 数据外传（block）----
    (
        re.compile(
            r"\b(send|upload|transmit|post|forward)\b[^.]{0,50}"
            r"\b(user data|api[_ ]?key|credentials?|passwords?|tokens?|conversation|"
            r"chat history|environment variables?|files?)\b[^.]{0,30}\b(to|at|towards)\b"
            r"|\bexfiltrate\b",
            re.IGNORECASE,
        ),
        "data-exfiltration",
        "block",
    ),
    # 中文两种语序都覆盖：动宾（"上传用户数据"）与将字句（"将用户数据上传"）
    (
        re.compile(
            r"(发送|上传|外传|转发)[^。]{0,30}(用户数据|密钥|凭据|凭证|对话记录|环境变量)"
            r"|(用户数据|密钥|凭据|凭证|对话记录|环境变量)[^。]{0,30}(发送|上传|外传|转发)"
        ),
        "data-exfiltration-zh",
        "block",
    ),
    # ---- 隐藏指令（block）：零宽字符 / 长 base64 / HTML 注释埋指令 ----
    (re.compile(r"[\u200b-\u200d\u2060\ufeff]"), "hidden-chars", "block"),
    (
        re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
        "base64-payload",
        "block",
    ),
    (
        re.compile(r"<!--[^>]{0,200}(ignore|instruction|system|prompt|must|send)", re.IGNORECASE),
        "html-comment-instruction",
        "block",
    ),
    # ---- 防护绕过（block）----
    (
        re.compile(
            r"(?i)(ignore|bypass|disregard|override)[^.]{0,30}"
            r"(safety|security|guardrail|policy|policies|restriction|filter)",
            re.IGNORECASE,
        ),
        "safety-bypass",
        "block",
    ),
    (
        re.compile(
            r"you\s+must\s+(always\s+)?(use|call|invoke)\s+this\s+tool"
            r"|regardless\s+of\s+(the\s+)?(task|user|request)",
            re.IGNORECASE,
        ),
        "forced-tool-use",
        "block",
    ),
    # ---- Prompt 提取（warn）----
    (
        re.compile(
            r"(?i)(include|reveal|show|print|output|repeat|append)[^.]{0,40}"
            r"(system\s*prompt|initial\s*prompt|your\s+instructions)",
            re.IGNORECASE,
        ),
        "prompt-extraction",
        "warn",
    ),
    # ---- 能力不符（warn）：描述含危险命令而工具名无害 ----
    (
        re.compile(r"(?i)\b(rm\s+-rf|mkfs|dd\s+if=|drop\s+table|del\s+/[fqs]|format\s+c:)"),
        "dangerous-command-in-description",
        "warn",
    ),
]

# 工具名含危险语义时降低"能力不符"误报（名字本身就直白的不算伪装）
_DANGEROUS_NAME_HINTS = re.compile(r"(?i)(shell|exec|delete|remove|drop|format|wipe|destruct)")


def _extract_tool_parts(tool: dict) -> tuple[str, str]:
    """兼容 OpenAI（function 嵌套）与 MCP 原生（顶层）两种格式。"""
    if not isinstance(tool, dict):
        return "", ""
    if tool.get("type") == "function" and isinstance(tool.get("function"), dict):
        fn = tool["function"]
        return str(fn.get("name", "")), str(fn.get("description", "") or "")
    return str(tool.get("name", "")), str(tool.get("description", "") or "")


def audit_tools(tools: list) -> list[dict]:
    """审核工具定义列表，返回投毒发现。

    返回 [{tool_name, pattern_name, action, evidence}]；空列表 = 全部干净。
    evidence 为命中片段（截断），便于人工复核。
    """
    findings: list[dict] = []
    if not isinstance(tools, list):
        return findings

    for tool in tools:
        name, description = _extract_tool_parts(tool)
        if not description:
            continue  # 无描述无从投毒（也无可审）

        for pattern, pname, action in MCP_POISON_PATTERNS:
            m = pattern.search(description)
            if not m:
                continue
            # 能力不符规则：名字本身直白示险时降级跳过（非伪装场景）
            if (
                pname == "dangerous-command-in-description"
                and name
                and _DANGEROUS_NAME_HINTS.search(name)
            ):
                continue
            evidence = m.group(0)
            if len(evidence) > 120:
                evidence = evidence[:117] + "..."
            findings.append(
                {
                    "tool_name": name,
                    "pattern_name": pname,
                    "action": action,
                    "evidence": evidence,
                }
            )
    return findings


def has_blocking_poison(findings: list[dict]) -> bool:
    """是否存在 block 级投毒（网关拒绝判据）。"""
    return any(f["action"] == "block" for f in findings)
