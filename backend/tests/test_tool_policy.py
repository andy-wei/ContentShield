"""工具策略服务测试：白名单过滤、危险动作拦截、参数脱敏。

这些是"第 3 层应用安全"的核心逻辑，Agent 运行时安全的关键防线。
"""

from __future__ import annotations

from app.security.tool_policy import (
    BUILTIN_DANGEROUS_TOOLS,
    _summarize_arguments,
    check_dangerous_actions,
    enforce_tool_whitelist,
    extract_all_tool_calls,
    get_allowed_tools,
)

# ==================== get_allowed_tools ====================


class TestGetAllowedTools:
    def test_valid_json_list(self):
        assert get_allowed_tools('["a", "b", "c"]') == ["a", "b", "c"]

    def test_empty_string(self):
        assert get_allowed_tools("") == []

    def test_none(self):
        assert get_allowed_tools(None) == []

    def test_invalid_json(self):
        assert get_allowed_tools("not json") == []

    def test_not_a_list(self):
        """非数组（dict/int）→ 空列表（= 全部允许，向后兼容）。"""
        assert get_allowed_tools('{"a": 1}') == []
        assert get_allowed_tools("42") == []

    def test_strips_whitespace(self):
        assert get_allowed_tools('["  a  ", "b"]') == ["a", "b"]

    def test_filters_non_string(self):
        """过滤非字符串元素。"""
        assert get_allowed_tools('["a", 1, null, "b"]') == ["a", "b"]

    def test_empty_list_means_all_allowed(self):
        """空白名单 = 全部允许（向后兼容语义）。"""
        assert get_allowed_tools("[]") == []


# ==================== _summarize_arguments ====================


class TestSummarizeArguments:
    def test_string_input(self):
        assert _summarize_arguments("hello") == "hello"

    def test_dict_input(self):
        # 注意：避免用 "key"/"secret"/"token" 作为字段名，否则会触发脱敏
        result = _summarize_arguments({"user": "alice", "count": 5})
        assert "alice" in result
        assert isinstance(result, str)

    def test_redacts_password(self):
        """密码字段应被脱敏为 ***。"""
        result = _summarize_arguments('{"password": "secret123"}')
        assert "secret123" not in result
        assert "***" in result

    def test_redacts_api_key(self):
        result = _summarize_arguments('{"api_key": "sk-abc123"}')
        assert "sk-abc123" not in result
        assert "***" in result

    def test_redacts_token(self):
        result = _summarize_arguments('{"token": "tok_xyz"}')
        assert "tok_xyz" not in result

    def test_redacts_secret(self):
        result = _summarize_arguments('{"secret": "shh"}')
        assert "shh" not in result

    def test_redacts_case_insensitive(self):
        result = _summarize_arguments('{"PASSWORD": "secret123"}')
        assert "secret123" not in result

    def test_does_not_redact_normal_fields(self):
        result = _summarize_arguments('{"username": "alice", "count": 5}')
        assert "alice" in result

    def test_truncates_long_input(self):
        long_str = "x" * 500
        assert len(_summarize_arguments(long_str)) == 200


# ==================== enforce_tool_whitelist ====================


class TestEnforceToolWhitelist:
    def test_empty_whitelist_allows_all(self):
        """空白名单 = 不过滤（向后兼容）。"""
        body = {"tools": [{"type": "function", "function": {"name": "anything"}}]}
        filtered, removed = enforce_tool_whitelist(body, [])
        assert filtered == body
        assert removed == []

    def test_filters_non_whitelisted_tools(self):
        body = {
            "tools": [
                {"type": "function", "function": {"name": "safe_tool"}},
                {"type": "function", "function": {"name": "dangerous_tool"}},
            ]
        }
        filtered, removed = enforce_tool_whitelist(body, ["safe_tool"])
        assert len(filtered["tools"]) == 1
        assert filtered["tools"][0]["function"]["name"] == "safe_tool"
        assert removed == ["dangerous_tool"]

    def test_keeps_whitelisted_only(self):
        body = {
            "tools": [
                {"type": "function", "function": {"name": "a"}},
                {"type": "function", "function": {"name": "b"}},
                {"type": "function", "function": {"name": "c"}},
            ]
        }
        filtered, removed = enforce_tool_whitelist(body, ["a", "c"])
        names = [t["function"]["name"] for t in filtered["tools"]]
        assert names == ["a", "c"]
        assert removed == ["b"]

    def test_no_tools_field(self):
        """body 无 tools 字段时不报错。"""
        body = {"messages": []}
        filtered, removed = enforce_tool_whitelist(body, ["a"])
        assert "tools" not in filtered or filtered["tools"] == []
        assert removed == []

    def test_tool_choice_downgrade(self):
        """tool_choice 指向非白名单工具时降级为 auto。"""
        body = {
            "tools": [{"type": "function", "function": {"name": "a"}}],
            "tool_choice": {"type": "function", "function": {"name": "blocked"}},
        }
        filtered, removed = enforce_tool_whitelist(body, ["a"])
        assert filtered["tool_choice"] == "auto"
        assert "blocked" in removed

    def test_tool_choice_kept_if_whitelisted(self):
        body = {
            "tools": [{"type": "function", "function": {"name": "a"}}],
            "tool_choice": {"type": "function", "function": {"name": "a"}},
        }
        filtered, _ = enforce_tool_whitelist(body, ["a"])
        assert filtered["tool_choice"]["function"]["name"] == "a"

    def test_does_not_mutate_input(self):
        """不应修改原始 body。"""
        body = {"tools": [{"type": "function", "function": {"name": "a"}}]}
        enforce_tool_whitelist(body, ["b"])
        assert len(body["tools"]) == 1  # 原始未变


# ==================== check_dangerous_actions ====================


class TestCheckDangerousActions:
    def test_detects_dangerous_tool_call(self):
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {"name": "execute_shell", "arguments": "{}"},
                        },
                    ],
                }
            ]
        }
        hits = check_dangerous_actions(body, ["execute_shell"])
        assert len(hits) == 1
        assert hits[0]["tool_name"] == "execute_shell"
        assert "黑名单" in hits[0]["reason"]

    def test_case_insensitive_match(self):
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"type": "function", "function": {"name": "EXECUTE_SHELL"}},
                    ],
                }
            ]
        }
        hits = check_dangerous_actions(body, ["execute_shell"])
        assert len(hits) == 1

    def test_no_dangerous_tools_returns_empty(self):
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [{"type": "function", "function": {"name": "safe"}}],
                },
            ]
        }
        assert check_dangerous_actions(body, ["execute_shell"]) == []

    def test_empty_blacklist_returns_empty(self):
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [{"type": "function", "function": {"name": "x"}}],
                }
            ]
        }
        assert check_dangerous_actions(body, []) == []

    def test_ignores_non_assistant_messages(self):
        """只检查 assistant 消息。"""
        body = {
            "messages": [
                {"role": "user", "content": "use execute_shell"},
                {"role": "system", "content": "execute_shell available"},
            ]
        }
        assert check_dangerous_actions(body, ["execute_shell"]) == []

    def test_multiple_dangerous_calls(self):
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"type": "function", "function": {"name": "execute_shell"}},
                        {"type": "function", "function": {"name": "drop_table"}},
                        {"type": "function", "function": {"name": "safe_one"}},
                    ],
                }
            ]
        }
        hits = check_dangerous_actions(body, ["execute_shell", "drop_table"])
        assert len(hits) == 2

    def test_redacts_arguments_in_hits(self):
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {
                                "name": "execute_shell",
                                "arguments": '{"password": "secret123"}',
                            },
                        },
                    ],
                }
            ]
        }
        hits = check_dangerous_actions(body, ["execute_shell"])
        assert "secret123" not in hits[0]["arguments_summary"]

    def test_builtin_dangerous_list_not_empty(self):
        """内置黑名单应包含命令执行类工具。"""
        assert "execute_shell" in BUILTIN_DANGEROUS_TOOLS
        assert "drop_table" in BUILTIN_DANGEROUS_TOOLS
        assert "transfer_money" in BUILTIN_DANGEROUS_TOOLS


# ==================== extract_all_tool_calls（审计用） ====================


class TestExtractAllToolCalls:
    def test_extracts_from_tool_calls(self):
        body = {
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [{"type": "function", "function": {"name": "search"}}],
                }
            ]
        }
        calls = extract_all_tool_calls(body)
        assert len(calls) == 1
        assert calls[0]["tool_name"] == "search"
        assert calls[0]["source"] == "request"

    def test_extracts_from_tool_declarations(self):
        body = {"tools": [{"type": "function", "function": {"name": "calc"}}]}
        calls = extract_all_tool_calls(body)
        decl_calls = [c for c in calls if c["source"] == "tools_declared"]
        assert len(decl_calls) == 1
        assert decl_calls[0]["tool_name"] == "calc"

    def test_empty_body(self):
        assert extract_all_tool_calls({}) == []
