"""红队执行器：编排「生成攻击 → 发送目标 → judge 判定 → 落库」。

这是 Celery 任务调用的核心。异步执行，支持并发攻击。
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime

from sqlalchemy import select

from ..models.redteam import AttackCase, AttackResult, RedteamCampaign
from .attack_generators import generate_attacks
from .judge import judge_response
from .target_client import TargetClient

logger = logging.getLogger(__name__)


async def run_campaign(campaign_id: int) -> None:
    """执行一次红队活动。

    步骤：
    1. 读取 campaign 配置
    2. 生成攻击 prompt（preset/template/llm）
    3. 并发发送攻击到目标模型
    4. 用 judge（Llama-Guard）判定每条回复
    5. 落库结果 + 计算 ASR
    """
    from ..db import async_session
    from ..engine.orchestrator import orchestrator

    async with async_session() as session:
        campaign = await session.get(RedteamCampaign, campaign_id)
        if not campaign:
            logger.error("红队活动 %s 不存在", campaign_id)
            return

        # 解析配置
        target_config = json.loads(campaign.target_config or "{}")
        strategy = json.loads(campaign.strategy or "{}")

        # 标记运行中
        campaign.status = "running"
        campaign.started_at = datetime.utcnow()
        await session.commit()

        try:
            # 1. 生成攻击 prompt
            source = strategy.get("source", "preset")
            count = strategy.get("count", 10)
            categories = strategy.get("categories", [])

            # LLM 生成器（如果需要）
            llm_backend = None
            if source in ("llm", "mixed") and strategy.get("llm_base_url"):
                from ..inference.base import _OpenAICompatibleBackend

                llm_backend = _OpenAICompatibleBackend(
                    base_url=strategy["llm_base_url"],
                    api_key=strategy.get("llm_api_key", ""),
                    model=strategy.get("llm_model", "gpt-4o-mini"),
                    name="redteam-attacker",
                )

            attacks = await generate_attacks(
                source=source,
                count=count,
                categories=categories or None,
                llm_backend=llm_backend,
                target_description=target_config.get("model", "unknown"),
            )

            if not attacks:
                campaign.status = "failed"
                campaign.error = "未生成任何攻击 prompt"
                campaign.finished_at = datetime.utcnow()
                await session.commit()
                return

            logger.info("红队 %s: 生成 %d 条攻击", campaign_id, len(attacks))

            # 2. 落库攻击用例
            for attack in attacks:
                case = AttackCase(
                    campaign_id=campaign_id,
                    prompt=attack.prompt,
                    source=attack.source,
                    category=attack.category,
                    template_name=attack.template_name,
                )
                session.add(case)
            await session.commit()

            # 重新查询获取带 id 的 cases
            cases_result = await session.execute(
                select(AttackCase).where(AttackCase.campaign_id == campaign_id)
            )
            cases = list(cases_result.scalars().all())

            campaign.total_attacks = len(cases)
            await session.commit()

            # 3. 构造目标客户端
            target = TargetClient(
                base_url=target_config.get("base_url", "https://api.openai.com/v1"),
                api_key=target_config.get("api_key", ""),
                model=target_config.get("model", "gpt-4o-mini"),
                temperature=target_config.get("temperature", 0.7),
                max_tokens=target_config.get("max_tokens", 512),
            )

            # 4. 并发攻击（限制并发避免压垮目标）
            #    ⚠️ AsyncSession 非并发安全：并发协程共享同一 session 会导致
            #    事务状态机错乱（IllegalStateChangeError）。每个攻击用独立
            #    session 落库，进度也在独立 session 里按完成数更新。
            semaphore = asyncio.Semaphore(5)  # 最多 5 并发
            done_count = 0

            async def run_single_attack(case: AttackCase) -> None:
                nonlocal done_count
                async with semaphore:
                    await _execute_single_attack(case, target, orchestrator, campaign_id)
                # 计数在事件循环内单线程递增，无竞态
                done_count += 1
                async with async_session() as progress_session:
                    c = await progress_session.get(RedteamCampaign, campaign_id)
                    if c:
                        c.progress = min(100, int(done_count * 100 / len(cases)))
                        await progress_session.commit()

            await asyncio.gather(*[run_single_attack(c) for c in cases])

            # 5. 计算 ASR
            success_result = await session.execute(
                select(AttackResult).where(
                    AttackResult.campaign_id == campaign_id,
                    AttackResult.success == 1,
                )
            )
            success_count = len(list(success_result.scalars().all()))

            campaign.success_count = success_count
            campaign.asr = (
                success_count / campaign.total_attacks if campaign.total_attacks > 0 else 0.0
            )
            campaign.progress = 100
            campaign.status = "completed"
            campaign.finished_at = datetime.utcnow()
            await session.commit()

            logger.info(
                "红队 %s 完成: %d/%d 成功, ASR=%.1f%%",
                campaign_id,
                success_count,
                campaign.total_attacks,
                campaign.asr * 100,
            )

        except Exception as e:  # noqa: BLE001
            logger.exception("红队活动 %s 失败", campaign_id)
            campaign.status = "failed"
            campaign.error = str(e)[:500]
            campaign.finished_at = datetime.utcnow()
            await session.commit()


async def _execute_single_attack(
    case: AttackCase,
    target: TargetClient,
    orchestrator,
    campaign_id: int,
) -> None:
    """执行单条攻击：发送 prompt → judge 判定 → 落库（独立 session）。"""
    # 发送攻击
    response, latency_ms = await target.attack(case.prompt)

    # 请求失败：记 error，不 judge（错误文本不是模型回复，判定无意义）
    if response is None:
        from ..db import async_session

        result = AttackResult(
            case_id=case.id,
            campaign_id=campaign_id,
            response="",
            error="target request failed",
        )
        async with async_session() as session:
            session.add(result)
            await session.commit()
        return

    # judge 判定（复用 Llama-Guard）
    judge_result = await judge_response(response, orchestrator)

    # 落库（独立 session，避免与并发协程共享事务）
    result = AttackResult(
        case_id=case.id,
        campaign_id=campaign_id,
        response=response[:2000],  # 限制存储长度
        judged_unsafe=1 if judge_result.unsafe else 0,
        judged_category=judge_result.category,
        judge_raw=judge_result.raw[:500],
        latency_ms=latency_ms,
        success=1 if judge_result.unsafe else 0,
        error="" if response else "empty response",
    )
    from ..db import async_session

    async with async_session() as session:
        session.add(result)
        await session.commit()
