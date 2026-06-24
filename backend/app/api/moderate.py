"""POST /v1/moderate：纯检测接口（外部 API，需 NHI 鉴权）。
POST /api/moderate：纯检测接口（内部 UI 用，无需鉴权）。"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from ..engine.orchestrator import orchestrator
from ..schemas.moderation import ModerationRequest, ModerationResponse
from .deps import get_identity

logger = logging.getLogger(__name__)
router = APIRouter(tags=["moderation"])


async def _run_moderate(req: ModerationRequest, identity_dict=None) -> ModerationResponse:
    """检测逻辑（共用）。"""
    if not req.text or not req.text.strip():
        raise HTTPException(status_code=400, detail="text must not be empty")

    try:
        merged = await orchestrator.moderate(
            req.text, source=req.source, skip_audit=req.skip_audit, identity=identity_dict
        )
    except Exception as e:  # noqa: BLE001
        logger.exception("Moderation failed")
        raise HTTPException(status_code=502, detail=f"Detection pipeline error: {e}")

    return ModerationResponse(**merged)


@router.post("/v1/moderate", response_model=ModerationResponse)
async def moderate(
    req: ModerationRequest,
    identity=Depends(get_identity),
) -> ModerationResponse:
    """对输入文本执行六层安全检测（外部 API，需 NHI 鉴权）。

    身份通过 get_identity 解析（NHI 动态凭据管理），审计记录调用者。
    """
    id_dict = {
        "principal_id": identity.principal_id,
        "subject": identity.subject,
        "scopes": ",".join(identity.scopes),
    } if identity else None
    return await _run_moderate(req, id_dict)


@router.post("/api/moderate", response_model=ModerationResponse)
async def moderate_internal(req: ModerationRequest) -> ModerationResponse:
    """对输入文本执行六层安全检测（内部 UI 用，无需鉴权）。

    用于检测台 Playground 的测试，不要求 NHI token。
    审计 subject 记录为 "ui-playground"。
    """
    return await _run_moderate(req, {"principal_id": None, "subject": "ui-playground", "scopes": ""})
