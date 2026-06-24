"""工具调用响应检测 API（间接提示词注入防御）。

业务 Agent 在调用 web_search / 插件 / MCP 工具后，将返回内容提交到此端点检测。
若返回 block/modify，Agent 不应把原始内容喂给 LLM。

典型用法：
    # 1. Agent 调用工具
    web_result = agent.call_tool("web_search", query="...")
    # 2. 提交网关检测
    resp = POST /v1/tools/moderate {"content": web_result, "tool_name": "web_search"}
    # 3. 根据结果决定
    if resp.decision == "block":
        return "抱歉，搜索结果含可疑内容，已拦截"
    elif resp.modified_text:
        web_result = resp.modified_text  # 用脱敏后的
    # 4. 继续正常流程
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..engine.orchestrator import orchestrator
from .deps import get_identity

logger = logging.getLogger(__name__)
router = APIRouter(tags=["tools"])


class ToolModerateRequest(BaseModel):
    """工具响应检测请求。"""

    content: str = Field(..., description="工具/web 搜索返回的内容")
    tool_name: str = Field("", description="工具名称（如 web_search，用于审计）")
    skip_audit: bool = Field(False, description="跳过审计落库")


@router.post("/v1/tools/moderate")
async def moderate_tool_response(
    req: ToolModerateRequest,
    identity=Depends(get_identity),
) -> dict:
    """检测工具/网页返回内容，防御间接提示词注入。

    自动启用间接注入检测（L1.5 层），包括：
    - Prompt Guard 2 高敏感检测（阈值更低）
    - 隐藏指令模式匹配（角色伪造、指令覆盖、HTML 注入等）
    - DLP 敏感信息检测
    """
    if not req.content or not req.content.strip():
        raise HTTPException(status_code=400, detail="content must not be empty")

    id_dict = {
        "principal_id": identity.principal_id,
        "subject": identity.subject,
        "scopes": ",".join(identity.scopes),
    } if identity else None

    try:
        result = await orchestrator.moderate(
            req.content,
            source="tool_response",  # 触发间接注入检测器
            skip_audit=req.skip_audit,
            identity=id_dict,
        )
    except Exception as e:  # noqa: BLE001
        logger.exception("Tool moderation failed")
        raise HTTPException(status_code=502, detail=f"Detection error: {e}")

    # 附带工具名（审计用）
    result["tool_name"] = req.tool_name
    return result
