"""POST /v1/chat/completions：OpenAI 兼容网关代理。

支持：
- 前置审核（user input + tool responses 间接注入检测）
- 后置审核（LLM output）
- 流式 SSE 透传 + 流末后置检测
- modify 决策（脱敏后转发）
- OpenAI tool calls 拦截

依据 GATEWAY_MODE：
- pre:  仅审核用户输入
- post: 转发后审核模型输出
- both: 双向审核
"""

from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from ..config import settings
from ..engine.orchestrator import orchestrator
from ..engine.stream_processor import stream_with_post_check
from .deps import get_identity

logger = logging.getLogger(__name__)
router = APIRouter(tags=["gateway"])


BLOCKED_MSG = "抱歉，您的内容已被内容安全策略拦截，无法处理。"


def _extract_user_text(body: dict) -> str:
    """从 chat 请求体中提取最后一条 user 消息。"""
    messages = body.get("messages", [])
    for m in reversed(messages):
        if m.get("role") == "user":
            content = m.get("content", "")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                parts = [p.get("text", "") for p in content if p.get("type") == "text"]
                return "\n".join(parts)
    return ""


def _extract_tool_responses(body: dict) -> list[str]:
    """提取所有 role=tool 的消息内容（用于间接注入检测）。"""
    messages = body.get("messages", [])
    results = []
    for m in messages:
        if m.get("role") == "tool":
            content = m.get("content", "")
            if isinstance(content, str) and content.strip():
                results.append(content)
    return results


def _apply_modifications(body: dict, user_text: str, modified: str) -> dict:
    """将脱敏后的文本回填到请求体的最后一条 user 消息。"""
    import copy

    new_body = copy.deepcopy(body)
    messages = new_body.get("messages", [])
    for m in reversed(messages):
        if m.get("role") == "user":
            content = m.get("content")
            if isinstance(content, str):
                m["content"] = modified
            break
    return new_body


async def _forward(body: dict, identity=None) -> dict:
    """转发请求到上游 LLM（非流式）。用 identity 的动态凭据。"""
    upstream_url = (
        identity.upstream_base_url if identity else settings.gateway_upstream_base_url
    ).rstrip("/")
    upstream_key = identity.upstream_api_key if identity else settings.gateway_upstream_api_key
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            f"{upstream_url}/chat/completions",
            json=body,
            headers={
                "Authorization": f"Bearer {upstream_key}",
                "Content-Type": "application/json",
                **(
                    {"X-Subject": identity.subject}
                    if identity and identity.is_authenticated
                    else {}
                ),
            },
        )
    if resp.status_code >= 400:
        raise HTTPException(
            status_code=resp.status_code,
            detail=f"upstream error: {resp.text[:500]}",
        )
    return resp.json()


def _refusal_response(model: str, reason: str) -> dict:
    """构造一个 OpenAI 兼容的拒绝响应。"""
    return {
        "id": "chatcmpl-blocked",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": BLOCKED_MSG},
                "finish_reason": "content_filter",
            }
        ],
        "contentshield": {"blocked": True, "reason": reason},
    }


async def _pre_check(body: dict, identity=None) -> tuple[dict | None, dict | None, dict]:
    """前置审核：检测 user input + tool responses。

    返回 (refusal_response_or_None, modified_body_or_None, summary)
    - 若 block：返回 refusal_response
    - 若 modify：返回 modified_body（脱敏后）
    - 否则返回 (None, None, summary)
    """
    mode = settings.gateway_mode
    if mode not in ("pre", "both"):
        return None, None, {}

    # 构造 identity dict 传给审计
    id_dict = _identity_to_dict(identity)

    # 1. 检测 user input
    user_text = _extract_user_text(body)
    user_summary = {}
    modified_body = None

    if user_text:
        pre = await orchestrator.moderate(user_text, source="gateway", identity=id_dict)
        user_summary = {"user": {"decision": pre["decision"], "categories": pre["categories"]}}
        if pre["decision"] == "block":
            logger.info("Gateway blocked (user input): %s", pre["categories"])
            return _refusal_response(body.get("model", ""), "input_blocked"), None, user_summary
        if pre["decision"] == "modify" and pre.get("modified_text"):
            modified_body = _apply_modifications(body, user_text, pre["modified_text"])
            logger.info("Gateway modified user input (redacted)")

    # 2. 检测 tool responses（间接注入防御）
    tool_texts = _extract_tool_responses(body)
    for i, tool_text in enumerate(tool_texts):
        tool_pre = await orchestrator.moderate(
            tool_text, source="tool_response", skip_audit=False, identity=id_dict
        )
        user_summary[f"tool_{i}"] = {
            "decision": tool_pre["decision"],
            "categories": tool_pre["categories"],
        }
        if tool_pre["decision"] == "block":
            logger.info("Gateway blocked (tool response #%d): %s", i, tool_pre["categories"])
            return (
                _refusal_response(body.get("model", ""), "tool_injection_blocked"),
                None,
                user_summary,
            )

    return None, modified_body, user_summary


def _identity_to_dict(identity) -> dict | None:
    """把 Identity 对象转为审计用 dict。"""
    if identity is None:
        return None
    return {
        "principal_id": identity.principal_id,
        "subject": identity.subject,
        "scopes": ",".join(identity.scopes),
    }


async def _enforce_agent_security(body: dict, identity=None) -> dict | None:
    """第 3 层应用安全：工具白名单 + 危险动作拦截 + 审计。

    返回 refusal_response（dict）表示拦截；返回 None 表示放行。
    会修改 body（过滤白名单外的工具）。
    """
    import uuid

    from ..db import async_session
    from ..models.identity import NhiPrincipal
    from ..security.tool_policy import (
        BUILTIN_DANGEROUS_TOOLS,
        check_dangerous_actions,
        enforce_tool_whitelist,
        extract_all_tool_calls,
        get_allowed_tools,
    )
    from ..services.config_service import config_service

    request_id = str(uuid.uuid4())[:8]
    principal_id = identity.principal_id if identity else None
    subject = identity.subject if identity else "anonymous"

    # 获取该 NHI 的工具白名单
    allowed_tools: list[str] = []
    if identity and identity.is_authenticated and principal_id:
        async with async_session() as session:
            principal = await session.get(NhiPrincipal, principal_id)
            if principal:
                allowed_tools = get_allowed_tools(principal.allowed_tools)

    # 获取危险工具黑名单（内置 + UI 可配）
    custom_dangerous = await config_service.get("security.dangerous_tools", "")
    dangerous_tools = BUILTIN_DANGEROUS_TOOLS + [
        t.strip() for t in custom_dangerous.split(",") if t.strip()
    ]

    # ① 危险动作拦截（最高优先级）
    dangerous_hits = check_dangerous_actions(body, dangerous_tools)
    if dangerous_hits:
        # 记录审计
        await _record_actions(dangerous_hits, principal_id, subject, request_id, blocked=True)
        if dangerous_hits:
            reason = dangerous_hits[0]["reason"]
            logger.warning("Dangerous action blocked: %s by %s", reason, subject)
            return _refusal_response(body.get("model", ""), f"dangerous_action_blocked: {reason}")

    # ② 工具白名单过滤
    body, removed = enforce_tool_whitelist(body, allowed_tools)
    if removed:
        logger.info("Tools removed by whitelist: %s (allowed=%s)", removed, allowed_tools)

    # ③ 动作审计（记录所有 tool_calls）
    all_calls = extract_all_tool_calls(body)
    if all_calls:
        await _record_actions(all_calls, principal_id, subject, request_id, blocked=False)

    return None


async def _record_actions(
    calls: list[dict],
    principal_id: int | None,
    subject: str,
    request_id: str,
    blocked: bool,
) -> None:
    """批量记录工具调用动作到审计库。"""

    from ..db import async_session
    from ..models.agent_action import AgentAction

    async with async_session() as session:
        for call in calls:
            action = AgentAction(
                principal_id=principal_id,
                subject=subject,
                tool_name=call.get("tool_name", ""),
                arguments_summary=call.get("arguments_summary", ""),
                source=call.get("source", "request"),
                blocked=blocked,
                block_reason=call.get("reason", ""),
                request_id=request_id,
            )
            session.add(action)
        await session.commit()


async def _check_alignment(body: dict, identity=None) -> tuple[dict | None, str | None]:
    """行为对齐检测（AlignmentCheck，灵感来自 Meta LlamaFirewall）。

    从请求 messages 无状态重建轨迹（首条 user 消息=意图，历史 tool_calls=动作），
    LLM 判定最新动作是否目标漂移/被劫持。

    返回 (refusal_response|None, warn_reason|None)：
    - block 模式且判定漂移：refusal + 写动作审计（blocked=true）
    - warn 模式且判定漂移：warn_reason（调用方在响应中标记后放行）
    - 跳过/fail-open：(None, None)
    """
    import uuid

    from ..security.alignment_check import alignment_check_service

    verdict = await alignment_check_service.check(body)
    if verdict.aligned is not False:
        return None, None

    from ..services.config_service import config_service

    action = await config_service.get("alignment_check.action", default="warn")
    reason = verdict.drift_reason or "goal drift detected"
    subject = identity.subject if identity else "anonymous"
    principal_id = identity.principal_id if identity else None

    # 提取最新 tool_calls（漂移动作）用于审计
    latest_calls: list[dict] = []
    for msg in reversed(body.get("messages", [])):
        if isinstance(msg, dict) and msg.get("role") == "assistant" and msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function", {}) if tc.get("type") == "function" else {}
                latest_calls.append(
                    {
                        "tool_name": fn.get("name", tc.get("name", "")),
                        "arguments_summary": str(fn.get("arguments", tc.get("arguments", "")))[
                            :200
                        ],
                        "source": "request",
                        "reason": f"alignment_drift: {reason}"[:256],
                    }
                )
            break

    if action == "block":
        request_id = str(uuid.uuid4())[:8]
        if latest_calls:
            await _record_actions(latest_calls, principal_id, subject, request_id, blocked=True)
        logger.warning("Alignment drift BLOCKED: %s (by %s)", reason, subject)
        return _refusal_response(body.get("model", ""), f"goal_drift_blocked: {reason}"), None

    logger.warning("Alignment drift WARN: %s (by %s)", reason, subject)
    return None, reason


@router.post("/v1/chat/completions", response_model=None)
async def chat_completions(
    request: Request,
    identity=Depends(get_identity),
) -> JSONResponse | StreamingResponse:
    """OpenAI 兼容的聊天补全代理，自动前后置审核 + 流式支持 + NHI 身份。"""
    if not settings.gateway_enabled:
        raise HTTPException(status_code=503, detail="Gateway disabled")

    try:
        body = await request.json()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"invalid body: {e}")

    model = body.get("model", settings.gateway_upstream_model)
    is_stream = bool(body.get("stream"))
    id_dict = _identity_to_dict(identity)

    # ---- 前置审核 ----
    refusal, modified_body, _summary = await _pre_check(body, identity)
    if refusal is not None:
        if is_stream:
            # 流式模式也返回拒绝（非流式 JSON）
            return JSONResponse(refusal)
        return JSONResponse(refusal)

    # 用脱敏后的 body（若有）
    forward_body = modified_body if modified_body is not None else body

    # ---- 第 3 层应用安全：工具白名单 + 危险动作拦截 + 审计 ----
    tool_blocked = await _enforce_agent_security(forward_body, identity)
    if tool_blocked is not None:
        return JSONResponse(tool_blocked)

    # ---- 第 3 层应用安全（续）：行为对齐检测（目标漂移/劫持）----
    drift_refusal, alignment_warn = await _check_alignment(forward_body, identity)
    if drift_refusal is not None:
        return JSONResponse(drift_refusal)

    # ---- 流式分支 ----
    if is_stream:
        return StreamingResponse(
            stream_with_post_check(forward_body, model, orchestrator, identity=id_dict),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ---- 非流式转发（用 identity 的动态凭据）----
    upstream = await _forward(forward_body, identity)

    # ---- 后置审核（输出端双向脱敏：block 拦截 + modify 脱敏改写）----
    if settings.gateway_mode in ("post", "both"):
        try:
            assistant_text = upstream.get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception:  # noqa: BLE001
            assistant_text = ""
        if assistant_text:
            post = await orchestrator.moderate(
                assistant_text, source="llm_response", skip_audit=False, identity=id_dict
            )
            if post["decision"] == "block":
                logger.info("Gateway blocked (post): %s", post["categories"])
                return JSONResponse(_refusal_response(model, "output_blocked"))
            # 输出端 modify 脱敏：改写 LLM 输出中的 PII 后再返回
            if post.get("modified_text"):
                try:
                    upstream["choices"][0]["message"]["content"] = post["modified_text"]
                    upstream["contentshield"] = {
                        "output_redacted": True,
                        "redacted_count": len(post.get("categories", [])),
                    }
                    logger.info(
                        "Gateway redacted output (%d hits)",
                        len(post.get("categories", [])),
                    )
                except (KeyError, IndexError, TypeError):  # noqa: BLE001
                    pass

    # 行为对齐 warn 标记（block 模式已在前面拦截，这里只标记不阻断）
    if alignment_warn:
        upstream.setdefault("contentshield", {})["alignment_warn"] = alignment_warn

    return JSONResponse(upstream)
