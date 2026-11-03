"""DLP 检测器测试：Luhn 算法、身份证校验、正则匹配、脱敏。

由于 detect() 需从 DB 加载规则（需 DB fixture），这里聚焦测纯函数：
- luhn_valid / id_card_valid（校验算法）
- 内置规则的正则正确性
- redact 方法（手工注入规则绕开 DB）

未来扩展：DB 集成测试覆盖完整 detect() 流程。
"""

from __future__ import annotations

import re

import pytest

from app.engine.detectors.dlp import (
    BUILTIN_RULES,
    DlpDetector,
    id_card_valid,
    luhn_valid,
)

# ==================== luhn_valid ====================


class TestLuhnValid:
    def test_valid_visa(self):
        # 经典 Visa 测试卡号（通过 Luhn）
        assert luhn_valid("4111111111111111") is True

    def test_valid_mastercard(self):
        assert luhn_valid("5555555555554444") is True

    def test_valid_amex(self):
        assert luhn_valid("378282246310005") is True

    def test_invalid_checksum(self):
        assert luhn_valid("4111111111111112") is False

    def test_too_short(self):
        assert luhn_valid("123456") is False

    def test_with_separators(self):
        """分隔符（空格/连字符）应被忽略。"""
        assert luhn_valid("4111 1111 1111 1111") is True
        assert luhn_valid("4111-1111-1111-1111") is True

    def test_empty(self):
        assert luhn_valid("") is False

    def test_all_zeros(self):
        assert luhn_valid("0000000000000") is True  # Luhn(0)=0


# ==================== id_card_valid ====================


class TestIdCardValid:
    def test_valid_id(self):
        # 真实格式身份证（北京 110105 + 19491231 + 000 + 校验位）
        # 用一个已知校验位正确的：11010519491231002X
        assert id_card_valid("11010519491231002X") is True

    def test_lowercase_x_accepted(self):
        assert id_card_valid("11010519491231002x") is True

    def test_wrong_length(self):
        assert id_card_valid("11010519491231002") is False  # 17 位
        assert id_card_valid("11010519491231002334") is False  # 20 位

    def test_wrong_checksum(self):
        # 改最后一位
        assert id_card_valid("110105194912310021") is False

    def test_invalid_chars(self):
        # 含非数字字符在非末位
        assert id_card_valid("11010519491231X002") is False


# ==================== 内置规则正确性 ====================


class TestBuiltinRules:
    def test_openai_key_pattern(self):
        rule = next(r for r in BUILTIN_RULES if r["name"] == "OpenAI API Key")
        pat = re.compile(rule["pattern"])
        assert pat.search("my key is sk-abc123defGHI456jklMNOp")  # ≥20 字符
        assert not pat.search("sk-short")  # 太短

    def test_github_token_pattern(self):
        rule = next(r for r in BUILTIN_RULES if r["name"] == "GitHub Token")
        pat = re.compile(rule["pattern"])
        assert pat.search("ghp_" + "a" * 36)
        assert not pat.search("ghp_short")

    def test_aws_key_pattern(self):
        rule = next(r for r in BUILTIN_RULES if r["name"] == "AWS Access Key")
        pat = re.compile(rule["pattern"])
        assert pat.search("AKIA" + "ABCDEFGHJKLMNPQR")  # 16 位
        assert not pat.search("AKIASHORT")

    def test_phone_pattern(self):
        rule = next(r for r in BUILTIN_RULES if r["name"] == "中国手机号")
        pat = re.compile(rule["pattern"])
        assert pat.search("contact: 13812345678")
        # 11 位且第二位 3-9
        assert not pat.search("10812345678")  # 第二位 0 非法

    def test_email_pattern(self):
        rule = next(r for r in BUILTIN_RULES if r["name"] == "邮箱")
        pat = re.compile(rule["pattern"])
        assert pat.search("reach me at alice@example.com")
        assert not pat.search("no email here")

    def test_all_rules_have_required_fields(self):
        for r in BUILTIN_RULES:
            assert "name" in r
            assert "pattern" in r
            assert "category" in r
            assert "action" in r
            assert "weight" in r
            assert r["action"] in {"block", "warn", "modify", "off"}

    def test_all_patterns_compile(self):
        """所有内置正则必须能编译。"""
        for r in BUILTIN_RULES:
            try:
                re.compile(r["pattern"])
            except re.error as e:
                pytest.fail(f"内置规则 {r['name']} 正则编译失败: {e}")


# ==================== redact（绕开 DB） ====================


class TestRedact:
    """通过手工注入规则测 redact 逻辑。"""

    def _make_detector(self, rules):
        """构造一个已加载的检测器（跳过 DB）。"""
        d = DlpDetector()
        d._rules = [
            (re.compile(r["pattern"]), r["name"], r["category"], r["action"], r.get("weight", 1.0))
            for r in rules
        ]
        d._loaded = True
        return d

    def test_redacts_modify_rule(self):
        d = self._make_detector(
            [
                {
                    "name": "Email",
                    "pattern": r"\b[\w.]+@[\w.]+\b",
                    "category": "pii",
                    "action": "modify",
                }
            ]
        )
        text = "联系 alice@example.com 谢谢"
        redacted, hits = d.redact(text)
        assert "alice@example.com" not in redacted
        assert "[REDACTED-EMAIL]" in redacted
        assert len(hits) == 1
        assert "alice" not in hits[0].snippet  # snippet 已打码

    def test_does_not_redact_block_rule(self):
        """block 规则不脱敏（应在 detect 阶段拦截）。"""
        d = self._make_detector(
            [
                {
                    "name": "Secret",
                    "pattern": r"sk-[a-z]+",
                    "category": "secret",
                    "action": "block",
                }
            ]
        )
        text = "key sk-abcdefghij"
        redacted, hits = d.redact(text)
        assert redacted == text
        assert hits == []

    def test_redacts_warn_rule(self):
        d = self._make_detector(
            [
                {
                    "name": "Phone",
                    "pattern": r"\b1[3-9]\d{9}\b",
                    "category": "pii",
                    "action": "warn",
                }
            ]
        )
        text = "call 13812345678"
        redacted, _ = d.redact(text)
        assert "13812345678" not in redacted
        assert "[REDACTED-PHONE]" in redacted

    def test_multiple_redactions(self):
        d = self._make_detector(
            [
                {"name": "A", "pattern": r"AAA", "category": "pii", "action": "modify"},
                {"name": "B", "pattern": r"BBB", "category": "pii", "action": "modify"},
            ]
        )
        text = "AAA and BBB"
        redacted, hits = d.redact(text)
        assert "AAA" not in redacted
        assert "BBB" not in redacted
        assert len(hits) == 2

    def test_not_loaded_returns_original(self):
        d = DlpDetector()
        d._loaded = False
        text = "unchanged"
        assert d.redact(text) == (text, [])

    def test_credit_card_with_luhn_skip(self):
        """信用卡规则：未通过 Luhn 的数字串不应被脱敏。"""
        d = self._make_detector(
            [
                {
                    "name": "Credit Card",
                    "pattern": r"\b(?:\d[ -]*?){13,19}\b",
                    "category": "pii",
                    "action": "modify",
                }
            ]
        )
        # 4111111111111111 通过 Luhn → 脱敏
        text_valid = "card 4111111111111111 here"
        r1, h1 = d.redact(text_valid)
        assert "4111111111111111" not in r1
        # 4111111111111112 不通过 Luhn → 保留
        text_invalid = "card 4111111111111112 here"
        r2, h2 = d.redact(text_invalid)
        assert "4111111111111112" in r2
        assert h2 == []
