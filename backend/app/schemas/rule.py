"""规则管理相关的请求/响应模型。"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class CategoryRuleRead(BaseModel):
    id: int
    code: str
    name: str
    enabled: bool
    action: Literal["block", "warn", "off"]
    description: str
    layer: str
    order: int
    updated_at: datetime

    model_config = {"from_attributes": True}


class CategoryRuleUpdate(BaseModel):
    enabled: bool | None = None
    action: Literal["block", "warn", "off"] | None = None
    description: str | None = None


class LexiconEntryCreate(BaseModel):
    term: str = Field(..., max_length=128)
    category: str = "profanity"
    lang: Literal["zh", "en"] = "zh"
    action: Literal["block", "warn"] = "block"
    enabled: bool = True


class LexiconEntryRead(BaseModel):
    id: int
    term: str
    category: str
    lang: str
    action: str
    enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class DlpRuleCreate(BaseModel):
    name: str
    pattern: str
    category: str = "secret"
    action: Literal["block", "warn", "modify"] = "block"
    weight: float = Field(0.5, ge=0.0, le=1.0)
    enabled: bool = True


class DlpRuleRead(BaseModel):
    id: int
    name: str
    pattern: str
    category: str
    action: str
    weight: float
    enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}
