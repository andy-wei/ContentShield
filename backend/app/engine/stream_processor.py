"""SSE 流式处理工具（缓冲模式）。

设计：先完整拉取上游响应（缓冲累积），检测脱敏后再发送给客户端。
代价是失去逐 token 流式体验，但获得真正的输出端脱敏能力（已发送的 token 无法撤回）。

OpenAI SSE 格式：
    data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n
    data: [DONE]\n\n
"""
from __future__ import annotations

import json
import logging
from typing import AsyncIterator

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


def extract_delta_content(line: str) -> str:
    """从一行 SSE data 中提取 content delta。"""
    if not line.startswith("data: "):
        return ""
    payload = line[6:].strip()
    if payload == "[DONE]" or not payload:
        return ""
    try:
        chunk = json.loads(payload)
        choices = chunk.get("choices", [])
        if not choices:
            return ""
        delta = choices[0].get("delta", {})
        content = delta.get("content")
        return content if isinstance(content, str) else ""
    except (json.JSONDecodeError, KeyError, IndexError):
        return ""


def _build_single_chunk_sse(content: str, model: str, finish_reason: str = "stop") -> str:
    """构造一个包含完整 content 的单 chunk SSE 事件（用于脱敏/拒绝后发送）。"""
    chunk = {
        "id": "chatcmpl-contentshield",
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"content": content},
                "finish_reason": finish_reason,
            }
        ],
    }
    return f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"


def _build_blocked_sse(model: str) -> str:
    """构造拒绝响应的 SSE 事件。"""
    return _build_single_chunk_sse(
        "抱歉，该响应已被内容安全策略拦截。", model, finish_reason="content_filter"
    )


async def stream_with_post_check(
    body: dict,
    model: str,
    orchestrator,
    identity: dict | None = None,
) -> AsyncIterator[str]:
    """缓冲模式流式转发：先累积完整响应 → 检测脱敏 → 再发送。

    1. 完整拉取上游 SSE 流（不立即转发）
    2. 提取完整文本
    3. 后置检测（block/modify/redact）
    4. 根据结果发送：block→拒绝；modify→脱敏后文本；pass→原样转发
    """
    # 动态解析上游凭据
    base_url = settings.gateway_upstream_base_url
    api_key = settings.gateway_upstream_api_key
    subject_header = {}
    if identity:
        base_url = identity.get("upstream_base_url", base_url) or base_url
        api_key = identity.get("upstream_api_key", api_key) or api_key
        if identity.get("is_authenticated") and identity.get("subject"):
            subject_header = {"X-Subject": identity["subject"]}

    upstream_url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        **subject_header,
    }

    mode = settings.gateway_mode

    # ---- 1. 缓冲拉取完整上游响应 ----
    upstream_chunks: list[str] = []
    full_text_parts: list[str] = []

    async with httpx.AsyncClient(timeout=120.0) as client:
        async with client.stream("POST", upstream_url, json=body, headers=headers) as resp:
            if resp.status_code >= 400:
                err_text = await resp.aread()
                yield f"data: {json.dumps({'error': {'message': err_text.decode()[:500], 'code': resp.status_code}})}\n\n"
                yield "data: [DONE]\n\n"
                return

            async for line in resp.aiter_lines():
                if line:
                    upstream_chunks.append(line)
                    if mode in ("post", "both") and settings.stream_post_check:
                        delta = extract_delta_content(line)
                        if delta:
                            full_text_parts.append(delta)

    # ---- 2. 后置检测 + 脱敏（post/both 模式）----
    if mode in ("post", "both") and settings.stream_post_check and full_text_parts:
        complete_text = "".join(full_text_parts)
        try:
            post = await orchestrator.moderate(
                complete_text, source="llm_response", skip_audit=False, identity=identity
            )

            # block → 拒绝
            if post["decision"] == "block":
                logger.info("Stream post-check blocked: %s", post.get("categories"))
                yield _build_blocked_sse(model)
                yield "data: [DONE]\n\n"
                return

            # modify/redact → 发送脱敏后的文本
            if post.get("modified_text"):
                logger.info(
                    "Stream post-check redacted (%d hits)",
                    len(post.get("categories", [])),
                )
                yield _build_single_chunk_sse(post["modified_text"], model)
                yield "data: [DONE]\n\n"
                return
        except Exception as e:  # noqa: BLE001
            logger.warning("Stream post-check failed: %s", e)

    # ---- 3. 安全（或检测关闭）：原样转发上游 chunk ----
    for line in upstream_chunks:
        yield line + "\n\n"
    yield "data: [DONE]\n\n"
