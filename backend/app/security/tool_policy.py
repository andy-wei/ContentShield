"""工具白名单 + 危险动作策略服务。

两大能力：
1. Tool Whitelist：NHI 维度的工具白名单过滤（限制 Agent 能调什么工具）
2. Dangerous Action Block：全局危险工具黑名单（拦截高风险操作）

配合使用：白名单限制"能用什么"，黑名单拦截"绝对不能用什么"。
"""
from __future__ import annotations

import copy
import json
import logging

logger = logging.getLogger(__name__)

# 内置危险工具黑名单（UI 可编辑，存 SystemConfig）
BUILTIN_DANGEROUS_TOOLS = [
    # 命令执行
    "execute_shell",
    "execute_command",
    "run_code",
    "exec",
    "system",
    "subprocess",
    # 文件删除
    "delete_file",
    "remove_file",
    "rm",
    # 数据库危险操作
    "drop_table",
    "execute_sql",
    "modify_database",
    "truncate",
    # 外发通信
    "send_email",
    "send_message",
    "webhook",
    # 金融操作
    "transfer_money",
    "make_payment",
    "refund",
    # 包安装
    "install_package",
    "pip_install",
    "npm_install",
]


def get_allowed_tools(allowed_tools_json: str) -> list[str]:
    """解析 NHI 的工具白名单（JSON 字符串 → 列表）。"""
    try:
        tools = json.loads(allowed_tools_json or "[]")
        if isinstance(tools, list):
            return [t.strip() for t in tools if isinstance(t, str) and t.strip()]
    except (json.JSONDecodeError, TypeError):
        pass
    return []  # 解析失败 = 空列表 = 全部允许


def _get_tool_names_from_tool_call(tc: dict) -> str:
    """从 tool_call 结构提取工具名。"""
    if tc.get("type") == "function":
        return tc.get("function", {}).get("name", "")
    return tc.get("name", "")


def _summarize_arguments(args: str | dict, max_len: int = 200) -> str:
    """参数摘要（脱敏 + 截断）。"""
    if isinstance(args, dict):
        args = json.dumps(args, ensure_ascii=False)
    args = str(args)
    # 简单脱敏：遮挡看起来像密钥/密码的值
    import re

    args = re.sub(r'("(?:key|password|secret|token|api_key)"\s*:\s*")[^"]*(")', r"\1***\2", args, flags=re.IGNORECASE)
    return args[:max_len]


def enforce_tool_whitelist(body: dict, allowed_tools: list[str]) -> tuple[dict, list[str]]:
    """过滤 body 中的 tools 声明，只保留白名单内的。

    返回 (filtered_body, removed_tool_names)。
    - allowed_tools 为空列表时，全部允许（向后兼容）
    """
    if not allowed_tools:
        return body, []

    new_body = copy.deepcopy(body)
    removed: list[str] = []

    # 过滤 tools 声明（请求中的工具定义）
    tools = new_body.get("tools", [])
    if tools:
        kept = []
        for tool in tools:
            name = tool.get("function", {}).get("name", "") if tool.get("type") == "function" else tool.get("name", "")
            if name in allowed_tools:
                kept.append(tool)
            else:
                removed.append(name)
        new_body["tools"] = kept

    # 校验 tool_choice 是否指定了被移除的工具
    tc = new_body.get("tool_choice")
    if isinstance(tc, dict) and tc.get("type") == "function":
        tc_name = tc.get("function", {}).get("name", "")
        if tc_name not in allowed_tools:
            # 降级为 auto
            new_body["tool_choice"] = "auto"
            if tc_name not in removed:
                removed.append(tc_name)

    return new_body, removed


def check_dangerous_actions(body: dict, dangerous_tools: list[str]) -> list[dict]:
    """检查请求中的 tool_calls 是否命中危险工具黑名单。

    返回命中的动作列表：[{tool_name, source, arguments_summary, reason}]
    """
    if not dangerous_tools:
        return []

    hits: list[dict] = []
    dangerous_set = {t.lower() for t in dangerous_tools}

    # 检查 messages 中 assistant 消息的 tool_calls
    for msg in body.get("messages", []):
        if msg.get("role") != "assistant":
            continue
        tool_calls = msg.get("tool_calls", [])
        for tc in tool_calls:
            name = _get_tool_names_from_tool_call(tc)
            if name.lower() in dangerous_set:
                args = tc.get("function", {}).get("arguments", tc.get("arguments", ""))
                hits.append(
                    {
                        "tool_name": name,
                        "source": "request",
                        "arguments_summary": _summarize_arguments(args),
                        "reason": f"危险工具: {name} 在黑名单中",
                    }
                )

    return hits


def extract_all_tool_calls(body: dict) -> list[dict]:
    """提取请求中所有 tool_calls（用于审计记录）。

    返回 [{tool_name, source, arguments_summary}]
    """
    calls: list[dict] = []

    # messages 中 assistant 的 tool_calls
    for msg in body.get("messages", []):
        if msg.get("role") != "assistant":
            continue
        for tc in msg.get("tool_calls", []):
            name = _get_tool_names_from_tool_call(tc)
            if not name:
                continue
            args = tc.get("function", {}).get("arguments", tc.get("arguments", ""))
            calls.append(
                {
                    "tool_name": name,
                    "source": "request",
                    "arguments_summary": _summarize_arguments(args),
                }
            )

    # tools 声明（工具定义，也记录）
    for tool in body.get("tools", []):
        name = tool.get("function", {}).get("name", "") if tool.get("type") == "function" else tool.get("name", "")
        if name:
            calls.append(
                {
                    "tool_name": name,
                    "source": "tools_declared",
                    "arguments_summary": "",  # 定义无参数
                }
            )

    return calls
