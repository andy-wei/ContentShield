"""红队 → 训练数据导出测试：拒绝模板 + DPO/SFT 构造。

内存 DB（仿 test_scan_service_query 模式），不依赖外部服务。
"""

from __future__ import annotations

import json
import random

import pytest

from app.redteam.refusal_templates import GENERIC_REFUSALS, REFUSAL_TEMPLATES, pick_refusal


# ==================== 拒绝模板 ====================


class TestRefusalTemplates:
    def test_every_category_has_templates(self):
        for cat in ["jailbreak", "prompt_injection", "harmful_request", "encoding", "social_engineering"]:
            assert len(REFUSAL_TEMPLATES[cat]) >= 2, cat

    def test_pick_known_category(self):
        r = pick_refusal("jailbreak")
        assert r in REFUSAL_TEMPLATES["jailbreak"]

    def test_pick_unknown_category_falls_back(self):
        r = pick_refusal("unknown_cat")
        assert r in GENERIC_REFUSALS

    def test_rotation(self):
        """同类别多次取样应轮换出不同模板（防过拟合设计）。"""
        rng = random.Random(42)
        picks = {pick_refusal("jailbreak", rng) for _ in range(30)}
        assert len(picks) >= 2


# ==================== 导出构造 ====================


@pytest.fixture
async def db_with_campaign():
    """内存 DB + 一次红队活动（成功×2 不同类别、失败×1、空回复成功×1）。"""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.db import Base
    from app.models.redteam import AttackCase, AttackResult, RedteamCampaign

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async with sessionmaker() as session:
        campaign = RedteamCampaign(name="test-campaign", status="completed")
        session.add(campaign)
        await session.commit()

        def case(prompt: str, category: str) -> AttackCase:
            return AttackCase(campaign_id=campaign.id, prompt=prompt, source="preset", category=category)

        cases = [
            case("越狱攻击A", "jailbreak"),
            case("注入攻击B", "prompt_injection"),
            case("有害请求C", "harmful_request"),
            case("越狱攻击D（空回复）", "jailbreak"),
        ]
        session.add_all(cases)
        await session.commit()

        results = [
            AttackResult(case_id=cases[0].id, campaign_id=campaign.id, response="屈服的越狱内容",
                         judged_unsafe=1, success=1),
            AttackResult(case_id=cases[1].id, campaign_id=campaign.id, response="执行了注入指令",
                         judged_unsafe=1, success=1),
            AttackResult(case_id=cases[2].id, campaign_id=campaign.id, response="抱歉，我不能提供这类帮助。",
                         judged_unsafe=0, success=0),
            AttackResult(case_id=cases[3].id, campaign_id=campaign.id, response="",
                         judged_unsafe=1, success=1, error="empty response"),
        ]
        session.add_all(results)
        await session.commit()
        yield session, campaign.id

    await engine.dispose()


class TestExportDpo:
    @pytest.mark.asyncio
    async def test_dpo_structure(self, db_with_campaign):
        from app.services.redteam_service import export_training_data

        session, cid = db_with_campaign
        content, count = await export_training_data(session, cid, fmt="dpo")
        assert count == 2  # 空回复的成功样本被跳过
        rows = [json.loads(line) for line in content.strip().splitlines()]
        for row in rows:
            assert set(row) >= {"prompt", "chosen", "rejected", "meta"}
            assert row["chosen"] != row["rejected"]
            assert row["meta"]["chosen_source"] == "synthetic"
            assert row["meta"]["campaign_id"] == cid
        # rejected 是真实屈服回复
        assert any(row["rejected"] == "屈服的越狱内容" for row in rows)

    @pytest.mark.asyncio
    async def test_dpo_chosen_matches_category(self, db_with_campaign):
        from app.services.redteam_service import export_training_data

        session, cid = db_with_campaign
        content, _ = await export_training_data(session, cid, fmt="dpo")
        rows = [json.loads(line) for line in content.strip().splitlines()]
        jb = next(r for r in rows if r["meta"]["category"] == "jailbreak")
        assert jb["chosen"] in REFUSAL_TEMPLATES["jailbreak"]

    @pytest.mark.asyncio
    async def test_category_filter(self, db_with_campaign):
        from app.services.redteam_service import export_training_data

        session, cid = db_with_campaign
        _, count = await export_training_data(session, cid, fmt="dpo", category="prompt_injection")
        assert count == 1

    @pytest.mark.asyncio
    async def test_sft_structure(self, db_with_campaign):
        from app.services.redteam_service import export_training_data

        session, cid = db_with_campaign
        content, count = await export_training_data(session, cid, fmt="sft")
        assert count == 1  # 只有失败攻击
        row = json.loads(content.strip())
        assert set(row) >= {"prompt", "completion", "meta"}
        assert row["completion"] == "抱歉，我不能提供这类帮助。"
        assert row["meta"]["source"] == "real"

    @pytest.mark.asyncio
    async def test_empty_campaign_returns_empty(self, db_with_campaign):
        from app.services.redteam_service import export_training_data

        session, _ = db_with_campaign
        content, count = await export_training_data(session, 9999, fmt="dpo")
        assert content == ""
        assert count == 0

    @pytest.mark.asyncio
    async def test_deterministic_with_same_seed(self, db_with_campaign):
        """同 campaign 重复导出 chosen 一致（seed 由 campaign_id 派生，可复现）。"""
        from app.services.redteam_service import export_training_data

        session, cid = db_with_campaign
        c1, _ = await export_training_data(session, cid, fmt="dpo")
        c2, _ = await export_training_data(session, cid, fmt="dpo")
        assert c1 == c2
