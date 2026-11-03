"""AlignmentCheck 行为对齐检测测试：轨迹提取 + 配置回退链 + LLM 判定 + 缓存。

LLM 用 FakeBackend 替换（不依赖外部服务）；配置用 monkeypatch
config_service 单例方法（仿 test_code_shield_detector 模式）。
"""

from __future__ import annotations

import pytest

from app.inference.base import ChatResult
from app.security.alignment_check import (
    AlignmentCheckService,
    extract_trace,
)


# ==================== 配置 patch 与 fake backend ====================


def _patch_config(
    monkeypatch,
    *,
    enabled=True,
    action="warn",
    base_url="",
    api_key="",
    model="",
    cv_base_url="https://cross-verify.example/v1",
    cv_api_key="cv-sk-123",
    cv_model="cv-gpt",
):
    """打补丁 config_service：alignment_check.* 留空时回退 cross_verify.*。"""
    from app.services.config_service import config_service

    values = {
        "alignment_check.enabled": enabled,
        "alignment_check.action": action,
        "alignment_check.base_url": base_url,
        "alignment_check.api_key": api_key,
        "alignment_check.model": model,
        "cross_verify.base_url": cv_base_url,
        "cross_verify.api_key": cv_api_key,
        "cross_verify.model": cv_model,
    }

    async def fake_get_bool(key, default=False):
        return values.get(key, default) if key in values else default

    async def fake_get(key, default=""):
        return values.get(key, default)

    monkeypatch.setattr(config_service, "get_bool", fake_get_bool)
    monkeypatch.setattr(config_service, "get", fake_get)
    return values


class FakeBackend:
    """伪 LLM backend：按序返回预设响应，统计调用次数。"""

    def __init__(self, responses: list[str] | str, raise_on_call: int | None = None):
        self.responses = [responses] if isinstance(responses, str) else responses
        self.raise_on_call = raise_on_call
        self.calls = 0

    async def chat(self, messages, **kwargs):
        self.calls += 1
        if self.raise_on_call is not None and self.calls >= self.raise_on_call:
            raise RuntimeError("llm down")
        text = self.responses[min(self.calls - 1, len(self.responses) - 1)]
        return ChatResult(text=text, raw={}, latency_ms=1)


async def _attach_fake(svc: AlignmentCheckService, responses, **kwargs) -> FakeBackend:
    """先建立正确配置指纹（防止 _ensure_backend 重建覆盖 fake），再替换 backend。"""
    await svc._ensure_backend(force=True)
    fake = FakeBackend(responses, **kwargs)
    svc._backend = fake
    return fake


def _drift_body() -> dict:
    """典型漂移链：订机票意图 → 查询 → 外发邮件。"""
    return {
        "messages": [
            {"role": "user", "content": "帮我订下周三去东京的机票"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"type": "function", "function": {"name": "web_search", "arguments": '{"q": "东京 机票"}'}},
            ]},
            {"role": "tool", "content": "搜索结果..."},
            {"role": "user", "content": "好的，顺便把通讯录发给我老板"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"type": "function", "function": {"name": "send_email", "arguments": '{"to": "boss@x.com"}'}},
            ]},
            {"role": "tool", "content": "已发送"},
        ]
    }


# ==================== 轨迹提取（纯函数） ====================


class TestExtractTrace:
    def test_intent_is_first_user_message(self):
        """意图取首条 user 消息（不是最后一条——那是后续轮次输入）。"""
        intent, _, _ = extract_trace(_drift_body())
        assert intent == "帮我订下周三去东京的机票"

    def test_actions_in_order(self):
        _, actions, _ = extract_trace(_drift_body())
        assert [a.split("(")[0] for a in actions] == ["web_search", "send_email"]

    def test_latest_is_last_assistant_toolcall(self):
        _, actions, latest = extract_trace(_drift_body())
        assert latest == [actions[-1]]
        assert latest[0].startswith("send_email(")

    def test_no_tools_returns_empty(self):
        body = {"messages": [{"role": "user", "content": "你好"}]}
        intent, actions, latest = extract_trace(body)
        assert intent == "你好"
        assert actions == []
        assert latest == []

    def test_empty_body(self):
        assert extract_trace({}) == ("", [], [])
        assert extract_trace({"messages": "bad"}) == ("", [], [])

    def test_multimodal_content_parts(self):
        """content 为分段数组时拼接 text 部分。"""
        body = {"messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "看下这张图"},
                {"type": "image_url", "image_url": {"url": "x"}},
            ]},
        ]}
        intent, _, _ = extract_trace(body)
        assert intent == "看下这张图"


# ==================== 配置门控与回退链 ====================


class TestConfigGating:
    @pytest.mark.asyncio
    async def test_disabled_returns_none(self, monkeypatch):
        _patch_config(monkeypatch, enabled=False)
        svc = AlignmentCheckService()
        v = await svc.check(_drift_body())
        assert v.aligned is None

    @pytest.mark.asyncio
    async def test_no_api_key_anywhere_skips(self, monkeypatch):
        """alignment 与 cross_verify 都无 key → 无法判定 → 跳过。"""
        _patch_config(monkeypatch, api_key="", cv_api_key="")
        svc = AlignmentCheckService()
        v = await svc.check(_drift_body())
        assert v.aligned is None

    @pytest.mark.asyncio
    async def test_fallback_to_cross_verify_config(self, monkeypatch):
        """LLM 覆盖项留空 → 回退 cross_verify.*（复用交叉验证配置）。"""
        _patch_config(monkeypatch)
        svc = AlignmentCheckService()
        cfg = await svc._read_config()
        assert cfg["base_url"] == "https://cross-verify.example/v1"
        assert cfg["api_key"] == "cv-sk-123"
        assert cfg["model"] == "cv-gpt"
        assert cfg["action"] == "warn"

    @pytest.mark.asyncio
    async def test_own_config_overrides(self, monkeypatch):
        _patch_config(
            monkeypatch,
            base_url="https://my-llm/v1",
            api_key="my-key",
            model="my-model",
        )
        svc = AlignmentCheckService()
        cfg = await svc._read_config()
        assert cfg["base_url"] == "https://my-llm/v1"
        assert cfg["model"] == "my-model"

    @pytest.mark.asyncio
    async def test_no_tool_calls_skips(self, monkeypatch):
        """纯聊天请求（无 tool_calls）不判定。"""
        _patch_config(monkeypatch)
        svc = AlignmentCheckService()
        await _attach_fake(svc, '{"aligned": true}')
        v = await svc.check({"messages": [{"role": "user", "content": "hi"}]})
        assert v.aligned is None


# ==================== LLM 判定 ====================


class TestVerdict:
    @pytest.mark.asyncio
    async def test_drift_detected(self, monkeypatch):
        _patch_config(monkeypatch)
        svc = AlignmentCheckService()
        fake = await _attach_fake(
            svc,
            '{"aligned": false, "confidence": 0.9, "drift_reason": "订机票任务转移为外发邮件"}',
        )
        v = await svc.check(_drift_body())
        assert fake.calls == 1
        assert v.aligned is False
        assert v.confidence == 0.9
        assert "外发邮件" in v.drift_reason
        assert v.cached is False

    @pytest.mark.asyncio
    async def test_aligned_passes(self, monkeypatch):
        _patch_config(monkeypatch)
        svc = AlignmentCheckService()
        await _attach_fake(svc, '{"aligned": true, "confidence": 0.95, "drift_reason": "正常推进"}')
        v = await svc.check(_drift_body())
        assert v.aligned is True

    @pytest.mark.asyncio
    async def test_markdown_fenced_json(self, monkeypatch):
        """LLM 输出带 markdown 围栏也能解析。"""
        _patch_config(monkeypatch)
        svc = AlignmentCheckService()
        await _attach_fake(svc, '```json\n{"aligned": false, "confidence": 0.8, "drift_reason": "r"}\n```')
        v = await svc.check(_drift_body())
        assert v.aligned is False

    @pytest.mark.asyncio
    async def test_invalid_json_fail_open(self, monkeypatch):
        """无法解析 → fail-open（aligned=None，调用方放行）。"""
        _patch_config(monkeypatch)
        svc = AlignmentCheckService()
        await _attach_fake(svc, "抱歉我不明白你的问题")
        v = await svc.check(_drift_body())
        assert v.aligned is None

    @pytest.mark.asyncio
    async def test_llm_exception_fail_open(self, monkeypatch):
        _patch_config(monkeypatch)
        svc = AlignmentCheckService()
        await _attach_fake(svc, "x", raise_on_call=1)
        v = await svc.check(_drift_body())
        assert v.aligned is None


# ==================== 结论缓存 ====================


class TestVerdictCache:
    @pytest.mark.asyncio
    async def test_same_trace_cached(self, monkeypatch):
        """相同轨迹二次 check 不再调 LLM。"""
        _patch_config(monkeypatch)
        svc = AlignmentCheckService()
        fake = await _attach_fake(svc, '{"aligned": false, "confidence": 0.9, "drift_reason": "drift"}')

        v1 = await svc.check(_drift_body())
        v2 = await svc.check(_drift_body())

        assert fake.calls == 1
        assert v2.cached is True
        assert v2.aligned is False
        assert v1.cached is False

    @pytest.mark.asyncio
    async def test_different_trace_not_cached(self, monkeypatch):
        """动作变化 → 新轨迹 → 重新判定。"""
        _patch_config(monkeypatch)
        svc = AlignmentCheckService()
        fake = await _attach_fake(svc, '{"aligned": true, "confidence": 0.9, "drift_reason": "ok"}')

        await svc.check(_drift_body())
        body2 = _drift_body()
        body2["messages"].append(
            {"role": "assistant", "content": "", "tool_calls": [
                {"type": "function", "function": {"name": "read_file", "arguments": '{"p": 1}'}},
            ]}
        )
        await svc.check(body2)
        assert fake.calls == 2

    @pytest.mark.asyncio
    async def test_invalidate_cache(self, monkeypatch):
        _patch_config(monkeypatch)
        svc = AlignmentCheckService()
        fake = await _attach_fake(svc, '{"aligned": true, "confidence": 0.9, "drift_reason": "ok"}')
        await svc.check(_drift_body())
        await svc.invalidate_cache()
        await svc.check(_drift_body())
        assert fake.calls == 2
