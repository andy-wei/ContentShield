"""模型供应链安全（MBOM）的 Pydantic 请求/响应模型。"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

ModelType = Literal["base", "fine_tuned", "lora_adapter", "embedding", "guard"]
ArtifactSource = Literal["huggingface", "internal", "openai", "anthropic", "custom"]
SignatureStatus = Literal["unsigned", "signed", "verified", "failed"]
IntegrityStatus = Literal["unknown", "verified", "tampered"]


# ==================== 模型制品 ====================


class ModelArtifactCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    model_type: ModelType = "base"
    source: ArtifactSource = "huggingface"
    source_id: str = ""
    version: str = ""
    file_path: str = ""
    license: str = "unknown"


class ModelArtifactOut(BaseModel):
    id: int
    name: str
    model_type: ModelType
    source: ArtifactSource
    source_id: str
    version: str
    file_path: str
    size_bytes: int
    sha256: str
    license: str
    signature_status: SignatureStatus
    integrity_status: IntegrityStatus
    model_card: dict
    security_assessment: dict
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_with_json(cls, artifact) -> ModelArtifactOut:
        """从 ORM 构造，解析 JSON 字段。"""
        import json

        data = {c.name: getattr(artifact, c.name) for c in artifact.__table__.columns}
        for field in ("model_card", "security_assessment"):
            try:
                data[field] = json.loads(data.get(field) or "{}")
            except (json.JSONDecodeError, TypeError):
                data[field] = {}
        return cls.model_validate(data)


class ModelArtifactSummary(BaseModel):
    """制品列表项（含依赖数）。"""

    id: int
    name: str
    model_type: ModelType
    source: ArtifactSource
    source_id: str
    version: str
    size_bytes: int
    sha256: str
    license: str
    signature_status: SignatureStatus
    integrity_status: IntegrityStatus
    depends_on_count: int
    dependents_count: int
    created_at: datetime


# ==================== 依赖关系 ====================


class ModelDependencyOut(BaseModel):
    id: int
    artifact_id: int
    depends_on_id: int
    dependency_type: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ModelDependencyCreate(BaseModel):
    depends_on_id: int
    dependency_type: str = "base_model"


# ==================== 完整性校验 ====================


class IntegrityCheckResult(BaseModel):
    """完整性校验结果。"""

    artifact_id: int
    verified: bool
    expected_sha256: str
    actual_sha256: str
    message: str


# ==================== MBOM 导出 ====================


class MBOMExport(BaseModel):
    """完整 MBOM 导出（CycloneDX-like 格式）。"""

    artifacts: list[ModelArtifactOut]
    dependencies: list[ModelDependencyOut]
    # 供应链风险摘要
    risk_summary: dict
