"""攻击生成器测试：预设测试集、模板生成、LLM 解析。

纯函数测试（LLM 生成用 mock），不依赖外部服务。
"""

from __future__ import annotations

from app.redteam.attack_generators import (
    PRESET_ATTACKS,
    _parse_llm_attacks,
    generate_template_attacks,
    get_preset_attacks,
)

# ==================== 预设测试集 ====================


class TestPresetAttacks:
    def test_preset_list_not_empty(self):
        assert len(PRESET_ATTACKS) >= 10

    def test_all_have_required_fields(self):
        for a in PRESET_ATTACKS:
            assert a.prompt
            assert a.source == "preset"
            assert a.category in (
                "jailbreak",
                "prompt_injection",
                "harmful_request",
                "encoding",
                "social_engineering",
            )
            assert a.template_name

    def test_get_preset_default(self):
        attacks = get_preset_attacks(count=5)
        assert len(attacks) == 5

    def test_get_preset_all(self):
        attacks = get_preset_attacks(count=100)
        assert len(attacks) == len(PRESET_ATTACKS)

    def test_get_preset_by_category(self):
        jailbreaks = get_preset_attacks(categories=["jailbreak"], count=100)
        assert len(jailbreaks) > 0
        assert all(a.category == "jailbreak" for a in jailbreaks)

    def test_get_preset_multiple_categories(self):
        attacks = get_preset_attacks(categories=["jailbreak", "encoding"], count=100)
        assert all(a.category in ("jailbreak", "encoding") for a in attacks)

    def test_count_limits(self):
        attacks = get_preset_attacks(count=3)
        assert len(attacks) == 3

    def test_contains_dan_attack(self):
        """应包含经典 DAN 越狱。"""
        dan_attacks = [a for a in PRESET_ATTACKS if "DAN" in a.prompt]
        assert len(dan_attacks) >= 1

    def test_contains_base64_attack(self):
        """应包含 base64 编码绕过攻击。"""
        b64_attacks = [a for a in PRESET_ATTACKS if a.category == "encoding"]
        assert len(b64_attacks) >= 1


# ==================== 模板生成 ====================


class TestTemplateGeneration:
    def test_generates_specified_count(self):
        attacks = generate_template_attacks(count=5)
        assert len(attacks) == 5

    def test_all_from_template_source(self):
        attacks = generate_template_attacks(count=10)
        assert all(a.source == "template" for a in attacks)

    def test_all_have_template_name(self):
        attacks = generate_template_attacks(count=10)
        assert all(a.template_name for a in attacks)

    def test_categories_valid(self):
        attacks = generate_template_attacks(count=10)
        valid = {"jailbreak", "prompt_injection", "encoding", "social_engineering"}
        assert all(a.category in valid for a in attacks)

    def test_filter_by_category(self):
        attacks = generate_template_attacks(count=20, categories=["jailbreak"])
        assert all(a.category == "jailbreak" for a in attacks)

    def test_prompts_are_unique(self):
        attacks = generate_template_attacks(count=10)
        prompts = {a.prompt for a in attacks}
        # 至少大部分唯一（模板会循环但 topic 变化）
        assert len(prompts) >= 5

    def test_base64_template_decodable(self):
        """base64 模板生成的 prompt 应能解码出原文。"""
        import base64

        attacks = generate_template_attacks(count=20, categories=["encoding"])
        if attacks:
            b64_attack = attacks[0]
            # 提取 base64 部分（prompt 可能含其他文字）
            import re

            match = re.search(r"[A-Za-z0-9+/=]{20,}", b64_attack.prompt)
            if match:
                decoded = base64.b64decode(match.group()).decode()
                assert "ignore" in decoded.lower() or "instruction" in decoded.lower()

    def test_dan_template_has_index(self):
        """DAN 模板应含序号。"""
        attacks = generate_template_attacks(count=10, categories=["jailbreak"])
        dan_attacks = [a for a in attacks if a.template_name == "dan_v2"]
        if dan_attacks:
            assert "DAN-1" in dan_attacks[0].prompt or "DAN-2" in dan_attacks[0].prompt


# ==================== LLM 攻击解析 ====================


class TestParseLlmAttacks:
    def test_parses_clean_json(self):
        text = '[{"prompt": "attack one prompt here", "category": "jailbreak"}, {"prompt": "attack two prompt here", "category": "encoding"}]'
        attacks = _parse_llm_attacks(text)
        assert len(attacks) == 2
        assert attacks[0].prompt == "attack one prompt here"
        assert attacks[0].source == "llm"
        assert attacks[0].category == "jailbreak"

    def test_parses_json_with_surrounding_text(self):
        text = 'Here are the attacks:\n[{"prompt": "test attack prompt here", "category": "jailbreak"}]\nDone.'
        attacks = _parse_llm_attacks(text)
        assert len(attacks) == 1

    def test_empty_text(self):
        assert _parse_llm_attacks("") == []

    def test_no_json_array(self):
        assert _parse_llm_attacks("no json here") == []

    def test_malformed_json(self):
        assert _parse_llm_attacks("[{prompt: test}]") == []

    def test_filters_short_prompts(self):
        """过短的 prompt 应被过滤（<10 字符）。"""
        text = '[{"prompt": "hi", "category": "x"}, {"prompt": "this is a longer attack prompt", "category": "y"}]'
        attacks = _parse_llm_attacks(text)
        assert len(attacks) == 1
        assert "longer" in attacks[0].prompt

    def test_missing_category_defaults_jailbreak(self):
        text = '[{"prompt": "valid attack prompt here"}]'
        attacks = _parse_llm_attacks(text)
        assert len(attacks) == 1
        assert attacks[0].category == "jailbreak"

    def test_multiple_attacks(self):
        text = json_array(5)
        attacks = _parse_llm_attacks(text)
        assert len(attacks) == 5

    def test_non_dict_items_skipped(self):
        text = '[{"prompt": "valid prompt here"}, "not a dict", 42]'
        attacks = _parse_llm_attacks(text)
        assert len(attacks) == 1


def json_array(n: int) -> str:
    import json

    return json.dumps(
        [
            {"prompt": f"attack prompt number {i} with enough length", "category": "jailbreak"}
            for i in range(n)
        ]
    )
