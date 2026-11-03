"""威胁建模请求/响应模型。"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# ---- 枚举常量（前端 TS 会镜像） ----
ThreatCategory = Literal[
    "S",  # Spoofing 伪装
    "T",  # Tampering 篡改
    "R",  # Repudiation 抵赖
    "I",  # Information Disclosure 信息泄露
    "D",  # Denial of Service 拒绝服务
    "E",  # Elevation of Privilege 权限提升
    "prompt_injection",  # 提示注入
    "data_poisoning",  # 数据投毒
    "model_inversion",  # 模型反转
    "alignment_bypass",  # 对齐绕过
    "loss_of_provenance",  # 来源丢失
]

AssetType = Literal[
    "external_entity",
    "process",
    "data_store",
    "data_flow",
    "trust_boundary",
]


# ---- 项目 ----
class ThreatProjectCreate(BaseModel):
    name: str = Field(..., max_length=128)
    description: str = ""
    status: Literal["draft", "active", "archived"] = "draft"


class ThreatProjectUpdate(BaseModel):
    name: str | None = Field(None, max_length=128)
    description: str | None = None
    status: Literal["draft", "active", "archived"] | None = None


class ThreatProjectRead(BaseModel):
    id: int
    name: str
    description: str
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ThreatProjectWithStats(ThreatProjectRead):
    """项目列表项（含资产/威胁统计）。"""

    asset_count: int = 0
    threat_count: int = 0
    open_count: int = 0
    critical_count: int = 0


# ---- 资产 ----
class AssetCreate(BaseModel):
    name: str = Field(..., max_length=128)
    description: str = ""
    asset_type: AssetType = "process"
    tech_stack: list[str] = Field(default_factory=list)
    properties: dict = Field(default_factory=dict)


class AssetUpdate(BaseModel):
    name: str | None = Field(None, max_length=128)
    description: str | None = None
    asset_type: AssetType | None = None
    tech_stack: list[str] | None = None
    properties: dict | None = None


class AssetRead(BaseModel):
    id: int
    project_id: int
    name: str
    description: str
    asset_type: str
    tech_stack: list[str]
    properties: dict
    created_at: datetime

    model_config = {"from_attributes": True}


# ---- 威胁 ----
class ThreatCreate(BaseModel):
    project_id: int
    asset_id: int | None = None
    title: str = Field(..., max_length=256)
    description: str = ""
    category: ThreatCategory = "S"
    likelihood: int = Field(3, ge=1, le=5)
    impact: int = Field(3, ge=1, le=5)
    mitigation: str = ""
    status: Literal["open", "mitigating", "mitigated", "accepted"] = "open"
    source: Literal["llm_generated", "manual"] = "manual"


class ThreatUpdate(BaseModel):
    asset_id: int | None = None
    title: str | None = Field(None, max_length=256)
    description: str | None = None
    category: ThreatCategory | None = None
    likelihood: int | None = Field(None, ge=1, le=5)
    impact: int | None = Field(None, ge=1, le=5)
    mitigation: str | None = None
    status: Literal["open", "mitigating", "mitigated", "accepted"] | None = None


class ThreatStatusUpdate(BaseModel):
    status: Literal["open", "mitigating", "mitigated", "accepted"]


class ThreatRead(BaseModel):
    id: int
    project_id: int
    asset_id: int | None
    title: str
    description: str
    category: str
    likelihood: int
    impact: int
    risk_level: str
    mitigation: str
    status: str
    source: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---- 缓解控制 ----
class ControlCreate(BaseModel):
    threat_id: int
    control_type: Literal["detection_rule", "audit_evidence", "agent_policy", "manual"] = "manual"
    ref_layer: Literal[
        "lexicon",
        "prompt_guard",
        "llama_guard",
        "dlp",
        "cross_verify",
        "tool_whitelist",
        "rate_limiter",
        "manual",
    ] = "manual"
    ref_id: str = ""
    description: str = ""
    effectiveness: Literal["planned", "in_effect", "verified", "failed"] = "planned"


class ControlUpdate(BaseModel):
    control_type: str | None = None
    ref_layer: str | None = None
    ref_id: str | None = None
    description: str | None = None
    effectiveness: Literal["planned", "in_effect", "verified", "failed"] | None = None


class ControlRead(BaseModel):
    id: int
    threat_id: int
    control_type: str
    ref_layer: str
    ref_id: str
    description: str
    effectiveness: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ControlEvidence(BaseModel):
    """单个控制的实际拦截证据（联动核心）。"""

    control_id: int
    ref_layer: str
    effectiveness: str
    # 近 30 天因该层规则拦截/告警的次数
    blocked_count_30d: int = 0
    warned_count_30d: int = 0
    total_count_30d: int = 0
    last_triggered: datetime | None = None
    note: str = ""


class ThreatEvidenceResponse(BaseModel):
    """威胁的缓解证据汇总。"""

    threat_id: int
    controls: list[ControlEvidence] = []


# ---- LLM 生成 ----
class GenerateRequest(BaseModel):
    """LLM 生成威胁请求。force_regenerate=True 时先清空旧的 LLM 威胁。"""

    force_regenerate: bool = False


class GenerateResponse(BaseModel):
    success: bool
    generated: int = 0
    threats: list[ThreatRead] = Field(default_factory=list)
    detail: str = ""
