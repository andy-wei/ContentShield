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
    upstream_url = (identity.upstream_base_url if identity else settings.gateway_upstream_base_url).rstrip("/")
    upstream_key = identity.upstream_api_key if identity else settings.gateway_upstream_api_key
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            f"{upstream_url}/chat/completions",
            json=body,
            headers={
                "Authorization": f"Bearer {upstream_key}",
                "Content-Type": "application/json",
                **({"X-Subject": identity.subject} if identity and identity.is_authenticated else {}),
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
            logger.info(
                "Gateway blocked (tool response #%d): %s", i, tool_pre["categories"]
            )
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
            assistant_text = (
                upstream.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
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

    return JSONResponse(upstream)
