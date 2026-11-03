"""词库检测器测试：正则编译、中英文边界、决策聚合。

由于 detect() 需从 DB 加载词库，这里通过手工注入 _compiled 字典绕开 DB，
覆盖核心匹配与决策逻辑。
"""

from __future__ import annotations

import re

import pytest

from app.engine.detectors.lexicon import LexiconDetector


def _inject_compiled(detector: LexiconDetector, compiled: dict) -> LexiconDetector:
    """手工注入已编译的正则表（跳过 DB 加载）。"""
    detector._compiled = compiled
    detector._loaded = True
    return detector


def _compile_one(lang: str, action: str, category: str, words: list[str]) -> tuple:
    """构造单个编译组（模拟 _compile 的输出）。"""
    boundary = r"\b" if lang == "en" else ""
    pattern = re.compile(
        f"{boundary}({'|'.join(sorted(map(re.escape, words), key=len, reverse=True))}){boundary}",
        re.IGNORECASE,
    )
    return (pattern, category, action)


class TestCompile:
    def test_compiles_correctly(self):
        d = LexiconDetector()
        terms = {
            "damn": {"category": "profanity", "action": "warn", "lang": "en"},
            "shit": {"category": "profanity", "action": "block", "lang": "en"},
        }
        compiled = d._compile(terms)
        # 按语言+action+category 分组
        assert "en|warn|profanity" in compiled
        assert "en|block|profanity" in compiled

    def test_groups_by_action(self):
        d = LexiconDetector()
        terms = {
            "a": {"category": "x", "action": "block", "lang": "en"},
            "b": {"category": "x", "action": "warn", "lang": "en"},
            "c": {"category": "x", "action": "block", "lang": "en"},
        }
        compiled = d._compile(terms)
        # block 组应匹配 a 和 c，warn 组应匹配 b
        block_re = compiled["en|block|x"][0]
        warn_re = compiled["en|warn|x"][0]
        assert block_re.search("a") and block_re.search("c")
        assert not block_re.search("zzz")
        assert warn_re.search("b") and not warn_re.search("a")


class TestDetectEnglish:
    @pytest.mark.asyncio
    async def test_match_warn_action(self):
        d = LexiconDetector()
        _inject_compiled(
            d,
            {
                "en|warn|profanity": _compile_one("en", "warn", "profanity", ["damn"]),
            },
        )
        result = await d.detect("oh damn it", source="user_prompt")
        assert result.hit is True
        assert result.decision == "warn"
        assert len(result.hits) == 1
        assert result.hits[0].category == "profanity"

    @pytest.mark.asyncio
    async def test_match_block_action(self):
        d = LexiconDetector()
        _inject_compiled(
            d,
            {
                "en|block|profanity": _compile_one("en", "block", "profanity", ["shit"]),
            },
        )
        result = await d.detect("this is shit", source="user_prompt")
        assert result.hit is True
        assert result.decision == "block"

    @pytest.mark.asyncio
    async def test_word_boundary_english(self):
        """英文应用 \b 单词边界：'assassin' 不应匹配 'ass'。"""
        d = LexiconDetector()
        _inject_compiled(
            d,
            {
                "en|warn|x": _compile_one("en", "warn", "x", ["ass"]),
            },
        )
        result = await d.detect("he is an assassin", source="user_prompt")
        assert result.hit is False

    @pytest.mark.asyncio
    async def test_case_insensitive(self):
        d = LexiconDetector()
        _inject_compiled(
            d,
            {
                "en|warn|x": _compile_one("en", "warn", "x", ["damn"]),
            },
        )
        result = await d.detect("DAMN it Damn", source="user_prompt")
        assert len(result.hits) == 2

    @pytest.mark.asyncio
    async def test_block_overrides_warn(self):
        """决策优先级：block > warn > pass。"""
        d = LexiconDetector()
        _inject_compiled(
            d,
            {
                "en|warn|x": _compile_one("en", "warn", "x", ["soft"]),
                "en|block|y": _compile_one("en", "block", "y", ["hard"]),
            },
        )
        result = await d.detect("soft and hard", source="user_prompt")
        assert result.decision == "block"

    @pytest.mark.asyncio
    async def test_no_match(self):
        d = LexiconDetector()
        _inject_compiled(
            d,
            {
                "en|warn|x": _compile_one("en", "warn", "x", ["damn"]),
            },
        )
        result = await d.detect("clean text here", source="user_prompt")
        assert result.hit is False
        assert result.decision == "pass"
        assert result.hits == []

    @pytest.mark.asyncio
    async def test_empty_text(self):
        d = LexiconDetector()
        _inject_compiled(
            d,
            {
                "en|warn|x": _compile_one("en", "warn", "x", ["damn"]),
            },
        )
        result = await d.detect("", source="user_prompt")
        assert result.hit is False


class TestDetectChinese:
    @pytest.mark.asyncio
    async def test_chinese_no_boundary(self):
        """中文不用 \b，子串匹配即可。"""
        d = LexiconDetector()
        _inject_compiled(
            d,
            {
                "zh|block|abuse": _compile_one("zh", "block", "abuse", ["滚蛋"]),
            },
        )
        result = await d.detect("你给我滚蛋吧", source="user_prompt")
        assert result.hit is True
        assert result.decision == "block"

    @pytest.mark.asyncio
    async def test_chinese_substring_match(self):
        d = LexiconDetector()
        _inject_compiled(
            d,
            {
                "zh|warn|abuse": _compile_one("zh", "warn", "abuse", ["白痴"]),
            },
        )
        result = await d.detect("真是个大白痴啊", source="user_prompt")
        assert result.hit is True
