"""OWASP LLM Top 10 审计 checklist 测试。

覆盖：
1. OWASP LLM Top 10 数据完整性（10 项、编号连续、字段齐全）
2. 服务层（seed 幂等、查询过滤、状态更新、摘要计算）
"""

from __future__ import annotations

import json

import pytest

from app.services.audit_checklist_service import (
    OWASP_LLM_TOP10,
    ensure_checklist_seeded,
    get_checklist_summary,
    list_checklist,
    update_checklist_item,
)

# ==================== OWASP LLM Top 10 数据完整性 ====================


class TestOwaspDataIntegrity:
    def test_has_10_items(self):
        assert len(OWASP_LLM_TOP10) == 10

    def test_owasp_ids_sequential(self):
        """编号应为 LLM01 ~ LLM10。"""
        ids = [item["owasp_id"] for item in OWASP_LLM_TOP10]
        assert ids == [f"LLM{i:02d}" for i in range(1, 11)]

    def test_owasp_ids_unique(self):
        ids = [item["owasp_id"] for item in OWASP_LLM_TOP10]
        assert len(ids) == len(set(ids))

    def test_all_have_required_fields(self):
        required = {
            "owasp_id",
            "name",
            "threat_category",
            "audit_points",
            "check_method",
            "ref_layer",
        }
        for item in OWASP_LLM_TOP10:
            assert required.issubset(item.keys()), f"{item['owasp_id']} 缺字段"

    def test_all_names_nonempty(self):
        for item in OWASP_LLM_TOP10:
            assert item["name"], f"{item['owasp_id']} name 为空"

    def test_all_have_audit_points(self):
        for item in OWASP_LLM_TOP10:
            assert len(item["audit_points"]) >= 2, f"{item['owasp_id']} 审计要点过少"

    def test_check_methods_valid(self):
        valid = {"code_review", "config_check", "tool_scan", "pentest"}
        for item in OWASP_LLM_TOP10:
            assert item["check_method"] in valid

    def test_ref_layers_align_with_system(self):
        """ref_layer 应对应系统已有的检测层。"""
        valid_layers = {
            "prompt_guard",
            "dlp",
            "llama_guard",
            "tool_whitelist",
            "cross_verify",
            "rate_limiter",
            "manual",
        }
        for item in OWASP_LLM_TOP10:
            assert item["ref_layer"] in valid_layers, (
                f"{item['owasp_id']} ref_layer={item['ref_layer']} 无效"
            )

    def test_covers_key_llm_risks(self):
        """应覆盖关键的 LLM 风险类别。"""
        names = " ".join(item["name"] for item in OWASP_LLM_TOP10).lower()
        assert "prompt injection" in names
        assert "sensitive" in names or "information" in names
        assert "supply chain" in names
        assert "poisoning" in names
        assert "agency" in names


# ==================== 服务层（内存 DB 集成）====================


@pytest.fixture
async def seeded_checklist():
    """构造内存 DB 并 seed checklist。"""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.db import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async with sessionmaker() as session:
        await ensure_checklist_seeded(session)

    yield sessionmaker

    await engine.dispose()


class TestSeedIdempotency:
    @pytest.mark.asyncio
    async def test_seed_creates_10_items(self, seeded_checklist):
        async with seeded_checklist() as session:
            items = await list_checklist(session)
            assert len(items) == 10

    @pytest.mark.asyncio
    async def test_seed_idempotent(self, seeded_checklist):
        """二次 seed 不应重复创建。"""
        async with seeded_checklist() as session:
            await ensure_checklist_seeded(session)
            items = await list_checklist(session)
            assert len(items) == 10

    @pytest.mark.asyncio
    async def test_all_items_initially_pending(self, seeded_checklist):
        async with seeded_checklist() as session:
            items = await list_checklist(session)
            assert all(i.status == "pending" for i in items)


class TestListFilter:
    @pytest.mark.asyncio
    async def test_filter_by_status(self, seeded_checklist):
        async with seeded_checklist() as session:
            # 先把第一项改成 pass
            items = await list_checklist(session)
            await update_checklist_item(session, items[0].id, "pass")

            passed = await list_checklist(session, status="pass")
            pending = await list_checklist(session, status="pending")
            assert len(passed) == 1
            assert len(pending) == 9

    @pytest.mark.asyncio
    async def test_ordered_by_owasp_id(self, seeded_checklist):
        async with seeded_checklist() as session:
            items = await list_checklist(session)
            ids = [i.owasp_id for i in items]
            assert ids == sorted(ids)


class TestUpdateItem:
    @pytest.mark.asyncio
    async def test_update_to_pass(self, seeded_checklist):
        async with seeded_checklist() as session:
            items = await list_checklist(session)
            updated = await update_checklist_item(
                session, items[0].id, "pass", evidence="已验证有 Prompt Guard", auditor="alice"
            )
            assert updated.status == "pass"
            assert "Prompt Guard" in updated.evidence
            assert updated.auditor == "alice"

    @pytest.mark.asyncio
    async def test_update_to_fail(self, seeded_checklist):
        async with seeded_checklist() as session:
            items = await list_checklist(session)
            updated = await update_checklist_item(session, items[1].id, "fail", "未做脱敏")
            assert updated.status == "fail"

    @pytest.mark.asyncio
    async def test_update_to_na(self, seeded_checklist):
        async with seeded_checklist() as session:
            items = await list_checklist(session)
            updated = await update_checklist_item(session, items[2].id, "na")
            assert updated.status == "na"

    @pytest.mark.asyncio
    async def test_invalid_status_rejected(self, seeded_checklist):
        async with seeded_checklist() as session:
            items = await list_checklist(session)
            with pytest.raises(ValueError, match="无效状态"):
                await update_checklist_item(session, items[0].id, "invalid")

    @pytest.mark.asyncio
    async def test_nonexistent_item_returns_none(self, seeded_checklist):
        async with seeded_checklist() as session:
            result = await update_checklist_item(session, 99999, "pass")
            assert result is None

    @pytest.mark.asyncio
    async def test_evidence_optional(self, seeded_checklist):
        """更新状态时不强制要求 evidence。"""
        async with seeded_checklist() as session:
            items = await list_checklist(session)
            updated = await update_checklist_item(session, items[0].id, "pass")
            assert updated.status == "pass"


class TestSummary:
    @pytest.mark.asyncio
    async def test_initial_summary_all_pending(self, seeded_checklist):
        async with seeded_checklist() as session:
            s = await get_checklist_summary(session)
            assert s["total"] == 10
            assert s["pending"] == 10
            assert s["pass"] == 0
            assert s["pass_rate"] == 0.0

    @pytest.mark.asyncio
    async def test_pass_rate_calculation(self, seeded_checklist):
        async with seeded_checklist() as session:
            items = await list_checklist(session)
            # 5 pass, 2 na, 3 pending
            for i in range(5):
                await update_checklist_item(session, items[i].id, "pass")
            for i in range(5, 7):
                await update_checklist_item(session, items[i].id, "na")

            s = await get_checklist_summary(session)
            assert s["pass"] == 5
            assert s["na"] == 2
            assert s["pending"] == 3
            # pass_rate = pass / (total - na) = 5 / 8
            assert s["pass_rate"] == round(5 / 8, 3)

    @pytest.mark.asyncio
    async def test_pass_rate_excludes_na(self, seeded_checklist):
        """na 项不计入通过率分母。"""
        async with seeded_checklist() as session:
            items = await list_checklist(session)
            # 全部 na
            for item in items:
                await update_checklist_item(session, item.id, "na")

            s = await get_checklist_summary(session)
            assert s["na"] == 10
            assert s["pass_rate"] == 0.0  # 无可审计项


class TestAuditPointsParsing:
    @pytest.mark.asyncio
    async def test_audit_points_are_json_list(self, seeded_checklist):
        async with seeded_checklist() as session:
            items = await list_checklist(session)
            for item in items:
                points = json.loads(item.audit_points)
                assert isinstance(points, list)
                assert len(points) >= 2
