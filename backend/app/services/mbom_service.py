"""MBOM 服务：模型制品管理 + 完整性校验 + 风险评估。"""

from __future__ import annotations

import json
import os

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..mbom.generator import (
    assess_supply_chain_risk,
    compute_file_hash,
    verify_integrity,
)
from ..models.mbom import ModelArtifact, ModelDependency
from ..schemas.mbom import (
    IntegrityCheckResult,
    MBOMExport,
    ModelArtifactCreate,
    ModelArtifactOut,
    ModelArtifactSummary,
    ModelDependencyCreate,
    ModelDependencyOut,
)

# ==================== 制品管理 ====================


async def create_artifact(session: AsyncSession, data: ModelArtifactCreate) -> ModelArtifact:
    """创建模型制品记录，并自动计算哈希（如果有文件路径）。"""
    artifact = ModelArtifact(
        name=data.name,
        model_type=data.model_type,
        source=data.source,
        source_id=data.source_id,
        version=data.version,
        file_path=data.file_path,
        license=data.license,
    )

    # 如果有文件路径，计算哈希和大小
    if data.file_path:
        full_path = os.path.join(settings.data_dir, data.file_path)
        if os.path.isfile(full_path):
            artifact.sha256 = compute_file_hash(full_path)
            artifact.size_bytes = os.path.getsize(full_path)
            artifact.integrity_status = "verified"

    session.add(artifact)
    await session.commit()
    await session.refresh(artifact)
    return artifact


async def list_artifacts(
    session: AsyncSession,
    model_type: str | None = None,
    source: str | None = None,
) -> list[ModelArtifactSummary]:
    """列出模型制品（含依赖统计）。"""
    stmt = select(ModelArtifact).order_by(ModelArtifact.created_at.desc())
    if model_type:
        stmt = stmt.where(ModelArtifact.model_type == model_type)
    if source:
        stmt = stmt.where(ModelArtifact.source == source)

    result = await session.execute(stmt)
    artifacts = list(result.scalars().all())

    summaries = []
    for a in artifacts:
        # 统计依赖
        dep_count = (
            await session.execute(
                select(func.count())
                .select_from(ModelDependency)
                .where(ModelDependency.artifact_id == a.id)
            )
        ).scalar() or 0

        dependents_count = (
            await session.execute(
                select(func.count())
                .select_from(ModelDependency)
                .where(ModelDependency.depends_on_id == a.id)
            )
        ).scalar() or 0

        summaries.append(
            ModelArtifactSummary(
                id=a.id,
                name=a.name,
                model_type=a.model_type,  # type: ignore[arg-type]
                source=a.source,  # type: ignore[arg-type]
                source_id=a.source_id,
                version=a.version,
                size_bytes=a.size_bytes,
                sha256=a.sha256,
                license=a.license,
                signature_status=a.signature_status,  # type: ignore[arg-type]
                integrity_status=a.integrity_status,  # type: ignore[arg-type]
                depends_on_count=dep_count,
                dependents_count=dependents_count,
                created_at=a.created_at,
            )
        )
    return summaries


async def get_artifact(session: AsyncSession, artifact_id: int) -> ModelArtifact | None:
    return await session.get(ModelArtifact, artifact_id)


async def update_artifact(
    session: AsyncSession,
    artifact_id: int,
    updates: dict,
) -> ModelArtifact | None:
    """更新制品字段。"""
    artifact = await session.get(ModelArtifact, artifact_id)
    if not artifact:
        return None

    for key, value in updates.items():
        if hasattr(artifact, key) and value is not None:
            if key in ("model_card", "security_assessment"):
                setattr(artifact, key, json.dumps(value, ensure_ascii=False))
            else:
                setattr(artifact, key, value)

    await session.commit()
    await session.refresh(artifact)
    return artifact


async def delete_artifact(session: AsyncSession, artifact_id: int) -> bool:
    artifact = await session.get(ModelArtifact, artifact_id)
    if not artifact:
        return False
    await session.delete(artifact)
    await session.commit()
    return True


# ==================== 完整性校验 ====================


async def check_integrity(session: AsyncSession, artifact_id: int) -> IntegrityCheckResult:
    """校验模型文件完整性。"""
    artifact = await session.get(ModelArtifact, artifact_id)
    if not artifact:
        raise ValueError(f"制品 {artifact_id} 不存在")

    if not artifact.file_path:
        return IntegrityCheckResult(
            artifact_id=artifact_id,
            verified=False,
            expected_sha256=artifact.sha256,
            actual_sha256="",
            message="无关联文件，无法校验",
        )

    full_path = os.path.join(settings.data_dir, artifact.file_path)
    result = verify_integrity(full_path, artifact.sha256)

    # 更新完整性状态
    artifact.integrity_status = "verified" if result.verified else "tampered"
    if result.actual_sha256 and not artifact.sha256:
        artifact.sha256 = result.actual_sha256
    await session.commit()

    return IntegrityCheckResult(
        artifact_id=artifact_id,
        verified=result.verified,
        expected_sha256=result.expected_sha256,
        actual_sha256=result.actual_sha256,
        message=result.message,
    )


async def recompute_hash(session: AsyncSession, artifact_id: int) -> str:
    """重新计算并更新哈希。"""
    artifact = await session.get(ModelArtifact, artifact_id)
    if not artifact:
        raise ValueError(f"制品 {artifact_id} 不存在")

    if not artifact.file_path:
        raise ValueError("无关联文件")

    full_path = os.path.join(settings.data_dir, artifact.file_path)
    new_hash = compute_file_hash(full_path)
    if new_hash:
        artifact.sha256 = new_hash
        artifact.size_bytes = os.path.getsize(full_path)
        artifact.integrity_status = "verified"
        await session.commit()
    return new_hash


# ==================== 依赖管理 ====================


async def add_dependency(
    session: AsyncSession, artifact_id: int, data: ModelDependencyCreate
) -> ModelDependency:
    # 校验双方存在
    if not await session.get(ModelArtifact, artifact_id):
        raise ValueError(f"制品 {artifact_id} 不存在")
    if not await session.get(ModelArtifact, data.depends_on_id):
        raise ValueError(f"依赖目标 {data.depends_on_id} 不存在")

    dep = ModelDependency(
        artifact_id=artifact_id,
        depends_on_id=data.depends_on_id,
        dependency_type=data.dependency_type,
    )
    session.add(dep)
    await session.commit()
    await session.refresh(dep)
    return dep


async def list_dependencies(session: AsyncSession, artifact_id: int) -> list[ModelDependencyOut]:
    result = await session.execute(
        select(ModelDependency).where(ModelDependency.artifact_id == artifact_id)
    )
    return [ModelDependencyOut.model_validate(d) for d in result.scalars().all()]


# ==================== 风险评估 ====================


async def get_risk_assessment(session: AsyncSession, artifact_id: int) -> dict:
    """获取单个制品的供应链风险评估。"""
    artifact = await session.get(ModelArtifact, artifact_id)
    if not artifact:
        raise ValueError(f"制品 {artifact_id} 不存在")

    artifact_dict = {
        "source": artifact.source,
        "license": artifact.license,
        "integrity_status": artifact.integrity_status,
        "signature_status": artifact.signature_status,
    }
    risk = assess_supply_chain_risk(artifact_dict)
    return {
        "risk_level": risk.risk_level,
        "risk_score": risk.risk_score,
        "issues": risk.issues,
        "recommendations": risk.recommendations,
    }


# ==================== MBOM 导出 ====================


async def export_mbom(session: AsyncSession) -> MBOMExport:
    """导出完整 MBOM（所有制品 + 依赖 + 风险摘要）。"""
    artifacts_result = await session.execute(select(ModelArtifact))
    artifacts = list(artifacts_result.scalars().all())

    deps_result = await session.execute(select(ModelDependency))
    deps = list(deps_result.scalars().all())

    # 风险摘要
    risk_summary = {"total": len(artifacts), "critical": 0, "high": 0, "medium": 0, "low": 0}
    unsigned_count = 0
    unverified_count = 0
    for a in artifacts:
        artifact_dict = {
            "source": a.source,
            "license": a.license,
            "integrity_status": a.integrity_status,
            "signature_status": a.signature_status,
        }
        risk = assess_supply_chain_risk(artifact_dict)
        risk_summary[risk.risk_level] = risk_summary.get(risk.risk_level, 0) + 1
        if a.signature_status == "unsigned":
            unsigned_count += 1
        if a.integrity_status == "unknown":
            unverified_count += 1

    risk_summary["unsigned"] = unsigned_count
    risk_summary["unverified_integrity"] = unverified_count

    return MBOMExport(
        artifacts=[ModelArtifactOut.from_orm_with_json(a) for a in artifacts],
        dependencies=[ModelDependencyOut.model_validate(d) for d in deps],
        risk_summary=risk_summary,
    )
